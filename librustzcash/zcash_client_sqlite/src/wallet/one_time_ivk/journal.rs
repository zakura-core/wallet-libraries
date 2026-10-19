//! The spend journal: every Ironwood nullifier of every transaction the block scan
//! recognizes.
//!
//! A spend of a one-time-key note always carries an output to the spending account's
//! internal address (see `zcash_client_backend::fees::orchard::InputView::is_one_time`),
//! so the scan recognizes it. For a block covered for an account, meaning stored by a
//! scan that used that account's keys, the journal therefore holds every nullifier
//! that could spend one of the account's one-time notes. See
//! `wallet::one_time_rewind::truncate` for rewinds.

use std::ops::Range;

use rusqlite::{Connection, OptionalExtension, named_params};
use zcash_client_backend::data_api::ScannedBlock;
use zcash_protocol::consensus::BlockHeight;

use crate::{AccountUuid, error::SqliteClientError};

/// One recognized transaction, taken from a scanned block before storage consumes it.
pub(crate) struct Entry {
    height: BlockHeight,
    tx_index: u16,
    txid: [u8; 32],
    nullifiers: Vec<[u8; 32]>,
}

/// What a batch of scanned blocks adds to the journal: its recognized transactions, and
/// the ranges it covers for each account that scanned them.
pub(crate) struct Batch {
    entries: Vec<Entry>,
    coverage: Vec<(AccountUuid, Range<BlockHeight>)>,
    receipts: Vec<orchard::note::Nullifier>,
}

/// Collects the journal entries and coverage of `blocks`, a contiguous batch. A
/// transaction without Ironwood nullifiers can't spend a one-time note, so it gets no
/// entry, though its block is still covered.
pub(crate) fn collect(blocks: &[ScannedBlock<AccountUuid>]) -> Batch {
    let entries = blocks
        .iter()
        .flat_map(|block| {
            block.transactions().iter().filter_map(move |tx| {
                let nullifiers = tx.ironwood_nullifiers().filter(|nfs| !nfs.is_empty())?;
                Some(Entry {
                    height: block.height(),
                    tx_index: tx.block_index().into(),
                    txid: *tx.txid().as_ref(),
                    nullifiers: nullifiers.iter().map(|nf| nf.to_bytes()).collect(),
                })
            })
        })
        .collect();
    // Each block names the accounts whose keys scanned it, so one batch can cover different
    // ranges for different accounts. A block scanned without that record covers nothing.
    let mut coverage: Vec<(AccountUuid, Range<BlockHeight>)> = vec![];
    for block in blocks {
        for account in block.scanned_accounts() {
            match coverage
                .iter_mut()
                .rev()
                .find(|(a, range)| a == account && range.end == block.height())
            {
                Some((_, range)) => range.end = block.height() + 1,
                None => coverage.push((*account, block.height()..block.height() + 1)),
            }
        }
    }
    let receipts = blocks
        .iter()
        .flat_map(|b| b.transactions())
        .flat_map(|t| t.ironwood_outputs())
        .filter(|o| o.one_time_key_id().is_some())
        .filter_map(|o| o.nf().copied())
        .collect();
    Batch {
        entries,
        coverage,
        receipts,
    }
}

/// Records `batch` after its blocks are stored, in the same database transaction, and links
/// each stored Ironwood note one of its transactions spends. The scanner matched spends
/// against the notes it loaded before the batch; a note stored since then, such as a late
/// discovery payment, is linked here, so it never shows unspent.
pub(crate) fn record(
    conn: &rusqlite::Transaction<'_>,
    tpir_session: &crate::wallet::transparent_ledger::session::SessionState,
    batch: Batch,
) -> Result<(), SqliteClientError> {
    let mut entry = conn.prepare_cached(
        "INSERT OR REPLACE INTO ironwood_spend_journal (block_height, tx_index, txid)
         VALUES (:height, :tx_index, :txid)",
    )?;
    let mut clear = conn.prepare_cached(
        "DELETE FROM ironwood_spend_journal_nullifiers
         WHERE block_height = :height AND tx_index = :tx_index",
    )?;
    let mut nullifier = conn.prepare_cached(
        "INSERT INTO ironwood_spend_journal_nullifiers
            (block_height, tx_index, action_index, nf)
         VALUES (:height, :tx_index, :action_index, :nf)",
    )?;
    for e in batch.entries {
        link_spends(conn, tpir_session, &e)?;
        let height = u32::from(e.height);
        entry.execute(named_params! {
            ":height": height,
            ":tx_index": e.tx_index,
            ":txid": e.txid,
        })?;
        // A block scanned again replaces its entries.
        clear.execute(named_params! {":height": height, ":tx_index": e.tx_index})?;
        for (action_index, nf) in e.nullifiers.iter().enumerate() {
            nullifier.execute(named_params! {
                ":height": height,
                ":tx_index": e.tx_index,
                ":action_index": action_index,
                ":nf": nf,
            })?;
        }
    }
    // A delayed replay may outlive the temporary nullifier map while the durable journal advances.
    for nf in batch.receipts {
        let spending = conn.query_row("SELECT t.id_tx FROM ironwood_spend_journal_nullifiers n JOIN ironwood_spend_journal j USING(block_height,tx_index) JOIN transactions t ON t.txid=j.txid AND t.mined_height=j.block_height AND t.tx_index=j.tx_index WHERE n.nf=?1 LIMIT 1", [nf.to_bytes()], |r| r.get(0).map(crate::TxRef)).optional()?;
        if let Some(tx_ref) = spending {
            link_note(conn, tpir_session, tx_ref, &nf)?;
        }
    }
    for (account, range) in batch.coverage {
        cover(conn, account, range)?;
    }
    Ok(())
}

/// Links each stored Ironwood note whose nullifier `entry` reveals to its transaction.
fn link_spends(
    conn: &rusqlite::Transaction<'_>,
    tpir_session: &crate::wallet::transparent_ledger::session::SessionState,
    entry: &Entry,
) -> Result<(), SqliteClientError> {
    let mut known =
        conn.prepare_cached("SELECT EXISTS(SELECT 1 FROM ironwood_received_notes WHERE nf = ?1)")?;
    let spends: Vec<orchard::note::Nullifier> = entry
        .nullifiers
        .iter()
        .filter_map(|nf| match known.query_row([nf], |r| r.get::<_, bool>(0)) {
            Ok(true) => Option::from(orchard::note::Nullifier::from_bytes(nf)).map(Ok),
            Ok(false) => None,
            Err(e) => Some(Err(e)),
        })
        .collect::<Result<_, _>>()?;
    if spends.is_empty() {
        return Ok(());
    }
    let tx_ref: crate::TxRef = conn.query_row(
        "SELECT id_tx FROM transactions WHERE txid = ?1",
        [entry.txid],
        |r| r.get(0).map(crate::TxRef),
    )?;
    for nf in spends {
        link_note(conn, tpir_session, tx_ref, &nf)?;
    }
    Ok(())
}

/// Links a canonical journaled spend through the same bookkeeping as ordinary scanning.
fn link_note(
    conn: &rusqlite::Transaction<'_>,
    tpir_session: &crate::wallet::transparent_ledger::session::SessionState,
    tx_ref: crate::TxRef,
    nf: &orchard::note::Nullifier,
) -> Result<(), SqliteClientError> {
    let inserted = crate::wallet::orchard::mark_ironwood_note_spent(conn, tx_ref, nf)?;
    crate::wallet::ironwood_hooks::put_received_note_spend(
        conn,
        tpir_session,
        zcash_protocol::ShieldedPool::Ironwood,
        tx_ref,
        usize::from(inserted),
    )?;
    Ok(())
}

/// Marks `range` covered for `account`, merging it with the ranges it overlaps or
/// touches. An account deleted since the scan began is skipped.
fn cover(
    conn: &Connection,
    account: AccountUuid,
    range: Range<BlockHeight>,
) -> Result<(), SqliteClientError> {
    let params = named_params! {
        ":uuid": account.0,
        ":start": u32::from(range.start),
        ":end": u32::from(range.end),
    };
    conn.execute(
        "INSERT INTO ironwood_journal_coverage (account_id, start_height, end_height)
         SELECT a.id,
                MIN(:start, IFNULL(MIN(c.start_height), :start)),
                MAX(:end, IFNULL(MAX(c.end_height), :end))
         FROM accounts a
         LEFT JOIN ironwood_journal_coverage c
           ON c.account_id = a.id AND c.start_height <= :end AND c.end_height >= :start
         WHERE a.uuid = :uuid
         GROUP BY a.id
         ON CONFLICT (account_id, start_height) DO UPDATE SET end_height = excluded.end_height",
        params,
    )?;
    // Drop the ranges the merged one absorbed.
    conn.execute(
        "DELETE FROM ironwood_journal_coverage AS c
         WHERE c.account_id = (SELECT id FROM accounts WHERE uuid = :uuid)
           AND EXISTS (
               SELECT 1 FROM ironwood_journal_coverage m
               WHERE m.account_id = c.account_id
                 AND m.start_height <= c.start_height AND m.end_height >= c.end_height
                 AND (m.start_height, m.end_height) != (c.start_height, c.end_height)
           )",
        named_params! {":uuid": account.0},
    )?;
    Ok(())
}
