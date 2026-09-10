//! Storing what a full transaction revealed.
//!
//! This is the write half of enhancement. It takes a decrypted transaction and
//! folds it into the wallet, and almost every statement it makes is an upsert
//! that *fills gaps and never erases*. That asymmetry is the whole discipline
//! of this module: scanning got there first and knows things enhancement does
//! not — where a note sits in the commitment tree — while enhancement knows
//! things scanning can never learn, like the memo and who was paid. Either one
//! overwriting the other's work with a null loses data that has no second
//! source.

use orchard::note::Nullifier;
use rusqlite::{OptionalExtension, named_params};
use zakura_wallet_core::{
    AccountId,
    account::KeyScope,
    enhanced::{EnhancedTx, TransferType},
    pool::PoolId,
    retrieval::Locator,
};
use zcash_address::{
    ToAddress, ZcashAddress,
    unified::{Address as UnifiedAddr, Encoding, Receiver},
};
use zcash_protocol::{
    TxId,
    consensus::{BlockHeight, Parameters},
    value::Zatoshis,
};

use crate::{
    apply::note_version_code,
    error::Error,
    retrieval::{clear_private_work, delete, queue},
    schema::CACHE_SCHEMA,
};

/// What the wallet knows about a transaction from outside its bytes.
#[derive(Debug, Clone, Copy, Default)]
pub struct TxMeta {
    /// Where it was mined, if it was.
    pub mined_height: Option<BlockHeight>,
    /// The height it was built for. Set only by the send path, which makes it
    /// a reliable marker that *this* installation created the transaction —
    /// another installation on the same seed would leave it null.
    pub target_height: Option<BlockHeight>,
    /// Unix seconds at which the wallet first had it.
    pub created_time: Option<u32>,
    /// The fee, when it can be known exactly.
    ///
    /// Left `None` rather than guessed. For a transaction with transparent
    /// inputs the fee depends on prevout values the wallet may not hold, and a
    /// wrong fee shown to somebody is worse than a blank one.
    pub fee: Option<Zatoshis>,
}

/// What storing a transaction did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    /// It touched the wallet, and was stored.
    Stored {
        /// Its row in `transactions`.
        tx_ref: i64,
    },
    /// It touched the wallet nowhere, and nothing was written.
    Irrelevant,
}

/// Folds a decrypted transaction into the wallet.
pub(crate) fn put_enhanced_tx<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    chain_tip: Option<BlockHeight>,
    tx: &EnhancedTx,
    meta: TxMeta,
) -> Result<PutOutcome, Error> {
    // Which of the wallet's accounts funded this. Attribution is a result of
    // decryption, never a caller's choice: whichever account holds a note being
    // spent is the one that paid.
    let funding = funding_accounts(conn, &tx.spent_nullifiers)?;

    // The relevance gate, before a single row is written anywhere — including
    // the durable database. A transaction reached through enhancement is not
    // necessarily the wallet's; without this the wallet accumulates strangers'
    // transactions in the one file it never drops.
    if funding.is_none() && tx.outputs.is_empty() && tx.transparent_received.is_empty() {
        delete(conn, Locator::Transaction(tx.txid))?;
        return Ok(PutOutcome::Irrelevant);
    }

    // The mempool height stands in for "now" when the transaction is not mined,
    // which is what gives an unmined transaction a floor to expire from.
    let observed = meta
        .mined_height
        .or_else(|| chain_tip.map(|t| t + 1))
        .unwrap_or_else(|| BlockHeight::from_u32(0));

    let tx_ref = put_tx_data(conn, tx, &meta, observed)?;
    put_raw_transaction(conn, tx.txid, &tx.raw)?;

    for (pool, nf) in &tx.spent_nullifiers {
        mark_spent(conn, tx_ref, *pool, nf)?;
    }

    // The transparent side, in the same order the apply stage writes it: the
    // outputs first, because marking a spend looks up the output it consumes.
    // Coinbase-ness is known exactly here rather than inferred from the
    // transaction's index, which is the one thing a full transaction says that
    // a compact one has to guess at.
    for output in &tx.transparent_received {
        crate::apply::put_transparent_output(
            conn,
            tx_ref,
            output,
            tx.is_coinbase,
            chain_tip,
            observed,
        )?;
    }

    // Every input, not only those already recognised as the wallet's. The
    // statement links the ones that turn out to be, and records all of them in
    // the spend map so a later-arriving output can find its spender.
    for outpoint in &tx.candidate_spends {
        crate::apply::mark_transparent_spent(conn, tx_ref, outpoint)?;
    }

    for output in &tx.outputs {
        match output.transfer_type {
            // Recovered under an outgoing viewing key: money left. There is no
            // received note to write — the wallet does not own this output —
            // only a record of what it paid and to whom.
            TransferType::Outgoing => {
                let to = encode_orchard(params, &output.recipient);
                put_sent_output(
                    conn,
                    tx.txid,
                    output.pool,
                    output.action_index,
                    funding.unwrap_or(output.account),
                    Some(&to),
                    None,
                    output.note.value().inner(),
                    Some(&output.memo),
                )?;
            }
            // The wallet's own change: both a note it holds and a record of the
            // send, so history can show the transaction paying out rather than
            // paying in.
            TransferType::AccountInternal => {
                graft_received_note(conn, tx_ref, output, KeyScope::Internal, true)?;
                put_sent_output(
                    conn,
                    tx.txid,
                    output.pool,
                    output.action_index,
                    funding.unwrap_or(output.account),
                    None,
                    Some(output.account),
                    output.note.value().inner(),
                    Some(&output.memo),
                )?;
            }
            // Somebody paid the wallet. If the wallet also funded the
            // transaction, it paid itself, and that is recorded as a send too:
            // otherwise history shows a payment arriving from nowhere.
            TransferType::Incoming => {
                graft_received_note(conn, tx_ref, output, KeyScope::External, false)?;
                if let Some(from) = funding {
                    let to = encode_orchard(params, &output.recipient);
                    put_sent_output(
                        conn,
                        tx.txid,
                        output.pool,
                        output.action_index,
                        from,
                        Some(&to),
                        Some(output.account),
                        output.note.value().inner(),
                        Some(&output.memo),
                    )?;
                }
            }
        }
    }

    // Only the enhancement intent is answered. A status intent, if there is
    // one, is a different question with a different lifetime.
    delete(conn, Locator::Transaction(tx.txid))?;

    // The private work for this transaction is now redundant: every field a
    // position-keyed request would have recovered is in the bytes just stored.
    clear_private_work(conn, tx.txid)?;

    if meta.mined_height.is_none() {
        queue(conn, Locator::Status(tx.txid), None)?;
    }

    Ok(PutOutcome::Stored { tx_ref })
}

/// The account that funded this transaction, if the wallet can tell.
///
/// More than one is possible and is not an error the wallet can resolve: it
/// attributes to the lowest account id so the choice is at least deterministic.
fn funding_accounts(
    conn: &rusqlite::Transaction<'_>,
    spent: &[(PoolId, Nullifier)],
) -> Result<Option<AccountId>, Error> {
    let mut lowest: Option<i64> = None;
    for (pool, nf) in spent {
        let found: Option<i64> = conn
            .prepare_cached(&format!(
                "SELECT account_id FROM {CACHE_SCHEMA}.received_notes
                 WHERE pool = :pool AND nf = :nf"
            ))?
            .query_row(
                named_params![":pool": pool.code(), ":nf": &nf.to_bytes()[..]],
                |row| row.get(0),
            )
            .optional()
            .map_err(Error::Query)?;

        if let Some(account) = found {
            lowest = Some(lowest.map_or(account, |l: i64| l.min(account)));
        }
    }
    Ok(lowest.map(|id| AccountId(id as u32)))
}

/// Upserts the transaction row.
///
/// Every column here is filled in rather than replaced, because this row is
/// written by three different paths — scanning, enhancement, and the send path
/// — and each knows things the others do not.
fn put_tx_data(
    conn: &rusqlite::Transaction<'_>,
    tx: &EnhancedTx,
    meta: &TxMeta,
    observed: BlockHeight,
) -> Result<i64, Error> {
    conn.prepare_cached(&format!(
        "INSERT INTO {CACHE_SCHEMA}.transactions
            (txid, expiry_height, mined_height, min_observed_height,
             target_height, fee, created_time)
         VALUES (:txid, :expiry, :mined, :observed, :target, :fee, :created)
         ON CONFLICT (txid) DO UPDATE SET
            expiry_height = IFNULL(:expiry, expiry_height),
            mined_height  = IFNULL(:mined, mined_height),
            -- Cleared only when this write is what mines it. Learning a
            -- transaction is mined contradicts the earlier proof that it was
            -- not, and the schema forbids keeping both.
            confirmed_unmined_at_height = CASE
                WHEN :mined IS NOT NULL THEN NULL
                ELSE confirmed_unmined_at_height
            END,
            target_height = IFNULL(:target, target_height),
            fee           = IFNULL(:fee, fee),
            created_time  = IFNULL(:created, created_time),
            -- Monotone downward, always. This is the floor an unmined
            -- transaction of unknown expiry is eventually declared dead from,
            -- so letting it rise would keep such a transaction alive forever.
            min_observed_height =
                MIN(IFNULL(min_observed_height, :observed), :observed)"
    ))?
    .execute(named_params![
        ":txid": tx.txid.as_ref(),
        ":expiry": tx.expiry_height.map(u32::from),
        ":mined": meta.mined_height.map(u32::from),
        ":observed": u32::from(observed),
        ":target": meta.target_height.map(u32::from),
        ":fee": meta.fee.map(|f| u64::from(f) as i64),
        ":created": meta.created_time,
    ])?;

    conn.prepare_cached(&format!(
        "SELECT id FROM {CACHE_SCHEMA}.transactions WHERE txid = :txid"
    ))?
    .query_row(named_params![":txid": tx.txid.as_ref()], |row| row.get(0))
    .map_err(Error::Query)
}

/// Stores the transaction's bytes in the durable database.
///
/// Unconditional: the bytes for an identifier are unique by construction, so
/// there is nothing an overwrite could destroy. This is what makes a layout
/// change a local reindex rather than a chain rescan.
fn put_raw_transaction(
    conn: &rusqlite::Transaction<'_>,
    txid: TxId,
    raw: &[u8],
) -> Result<(), Error> {
    conn.prepare_cached(
        "INSERT INTO main.raw_transactions (txid, bytes) VALUES (:txid, :bytes)
         ON CONFLICT (txid) DO UPDATE SET bytes = :bytes",
    )?
    .execute(named_params![":txid": txid.as_ref(), ":bytes": raw])?;
    Ok(())
}

fn mark_spent(
    conn: &rusqlite::Transaction<'_>,
    tx_ref: i64,
    pool: PoolId,
    nf: &Nullifier,
) -> Result<(), Error> {
    conn.prepare_cached(&format!(
        "INSERT OR IGNORE INTO {CACHE_SCHEMA}.received_note_spends
            (received_note_id, transaction_id)
         SELECT id, :tx FROM {CACHE_SCHEMA}.received_notes
          WHERE pool = :pool AND nf = :nf"
    ))?
    .execute(named_params![
        ":tx": tx_ref,
        ":pool": pool.code(),
        ":nf": &nf.to_bytes()[..],
    ])?;
    Ok(())
}

/// Writes a received note, or grafts what enhancement learned onto one that
/// scanning already stored.
///
/// The two columns this must never touch are `commitment_tree_position` and
/// `witness_stabilized`. They are derived from tree geometry, which a raw
/// transaction knows nothing about; when enhancement sees a note first the
/// position stays null and the note is visible but unspendable until scanning
/// supplies it. That is correct, not a limitation.
fn graft_received_note(
    conn: &rusqlite::Transaction<'_>,
    tx_ref: i64,
    output: &zakura_wallet_core::enhanced::DecryptedOutput,
    scope: KeyScope,
    is_change: bool,
) -> Result<(), Error> {
    conn.prepare_cached(&format!(
        "INSERT INTO {CACHE_SCHEMA}.received_notes
            (transaction_id, pool, action_index, account_id, diversifier, value,
             rho, rseed, note_version, is_change, key_scope, memo, nf)
         VALUES (:tx, :pool, :action, :account, :diversifier, :value,
                 :rho, :rseed, :version, :is_change, :scope, :memo, :nf)
         ON CONFLICT (transaction_id, pool, action_index) DO UPDATE SET
            memo      = IFNULL(:memo, memo),
            is_change = MAX(:is_change, is_change),
            nf        = IFNULL(nf, :nf)"
    ))?
    .execute(named_params![
        ":tx": tx_ref,
        ":pool": output.pool.code(),
        ":action": output.action_index as i64,
        ":account": output.account.0,
        ":diversifier": &output.note.recipient().diversifier().as_array()[..],
        ":value": output.note.value().inner() as i64,
        ":rho": &output.note.rho().to_bytes()[..],
        ":rseed": &output.note.rseed().as_bytes()[..],
        ":version": note_version_code(output.note.version()),
        ":is_change": is_change,
        ":scope": scope.code(),
        ":memo": &output.memo[..],
        // Without this the note never enters the nullifier snapshot, so it can
        // never be matched as spent and sits in the balance forever. The
        // existing value wins on conflict: scanning derives the same nullifier
        // and got here first.
        ":nf": output.nullifier.as_ref().map(|nf| nf.to_bytes().to_vec()),
    ])?;
    Ok(())
}

/// Records one output of a transaction the wallet funded.
#[allow(clippy::too_many_arguments)]
fn put_sent_output(
    conn: &rusqlite::Transaction<'_>,
    txid: TxId,
    pool: PoolId,
    output_index: usize,
    from: AccountId,
    to_address: Option<&str>,
    to_account: Option<AccountId>,
    value: u64,
    memo: Option<&[u8; 512]>,
) -> Result<(), Error> {
    conn.prepare_cached(
        "INSERT INTO main.sent_outputs
            (txid, output_pool, output_index, from_account_id, to_address,
             to_account_id, value, memo)
         VALUES (:txid, :pool, :index, :from, :to_address, :to_account, :value, :memo)
         ON CONFLICT (txid, output_pool, output_index) DO UPDATE SET
            to_address    = IFNULL(:to_address, to_address),
            to_account_id = IFNULL(:to_account, to_account_id),
            memo          = IFNULL(:memo, memo)",
    )?
    .execute(named_params![
        ":txid": txid.as_ref(),
        ":pool": pool.code(),
        ":index": output_index as i64,
        ":from": from.0,
        ":to_address": to_address,
        ":to_account": to_account.map(|a| a.0),
        ":value": value as i64,
        ":memo": memo.map(|m| &m[..]),
    ])?;
    Ok(())
}

/// Encodes a recovered Orchard address as a unified address.
///
/// This is the address the *protocol* saw, which is not necessarily the string
/// somebody typed: a unified address carrying several receivers arrives here as
/// only the one that was paid. What the user typed belongs in `user_metadata`.
fn encode_orchard<P: Parameters>(params: &P, address: &orchard::Address) -> String {
    let ua = UnifiedAddr::try_from_items(vec![Receiver::Orchard(address.to_raw_address_bytes())])
        .expect("an Orchard receiver alone is a valid unified address");
    ZcashAddress::from_unified(params.network_type(), ua).encode()
}
