//! Applying a detected batch to storage.
//!
//! One batch is one SQLite transaction, and the scan queue is updated inside
//! it. That single fact is what makes the sync engine's cancellation and
//! resumption trivial: there is no partially-applied state to reason about,
//! because a batch either lands whole or not at all, and what landed is exactly
//! what the queue says was scanned.

use std::collections::{BTreeMap, BTreeSet};

use incrementalmerkletree::{Address, Level, Position};
use rusqlite::{OptionalExtension, named_params};
use zakura_wallet_core::retrieval::Locator;
use zakura_wallet_core::scanning::{ScanPriority, ScanRange};
use zakura_wallet_core::{
    ANCHOR_GRID, AccountId, BlockAnchor, BlockHash, DetectedBatch, DetectedBlock, KeyScope,
    NullifierSnapshot,
    pool::{PoolId, TreeSizes},
};
use zcash_protocol::{
    TxId,
    consensus::{BlockHeight, Parameters},
};

use shardtree::store::{Checkpoint, ShardStore, TreeState};

use crate::{
    error::{Error, TreeError},
    scan_queue,
    schema::CACHE_SCHEMA,
    tree::{PRUNING_DEPTH, WalletShardStore, tree},
};

/// Transactions above the rewind holding data the chain cannot reproduce.
///
/// A rewind must not destroy what only this wallet knows: the fee and target
/// height of a transaction it built, an outgoing recipient recovered under an
/// outgoing viewing key, a memo. None of that comes back from scanning, so
/// these rows are un-mined and kept.
///
/// The three tests are exactly the three ways such data arrives: the wallet
/// built the transaction (`target_height`), an enhancement stored its bytes,
/// or an enhancement recorded what it paid.
const IRREPLACEABLE: &str = "SELECT t.id FROM cache.transactions t
     WHERE t.mined_height > :height
       AND (t.target_height IS NOT NULL
            OR EXISTS (SELECT 1 FROM main.raw_transactions r WHERE r.txid = t.txid)
            OR EXISTS (SELECT 1 FROM main.sent_outputs s WHERE s.txid = t.txid))";

/// Transactions above the rewind that scanning would rebuild exactly.
///
/// These are deleted, and that is what keeps the wallet's state after a reorg
/// identical to a fresh scan of the winning chain. Keeping them would leave
/// notes from a chain that lost sitting in the balance, held against a spend
/// that can never be proved dead because the transaction holding it was only
/// ever a rumour.
const REPRODUCIBLE: &str = "SELECT t.id FROM cache.transactions t
     WHERE t.mined_height > :height
       AND t.target_height IS NULL
       AND NOT EXISTS (SELECT 1 FROM main.raw_transactions r WHERE r.txid = t.txid)
       AND NOT EXISTS (SELECT 1 FROM main.sent_outputs s WHERE s.txid = t.txid)";

/// Applies `batch` and marks its range scanned, in one transaction.
pub(crate) fn put_batch<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    birthday: Option<BlockHeight>,
    chain_tip: Option<BlockHeight>,
    batch: &DetectedBatch,
) -> Result<(), TreeError> {
    if batch.blocks.is_empty() {
        return Ok(());
    }

    // Before anything is written: the batch is inserted into the trees at the
    // absolute position its anchor names, so an anchor the wallet can
    // contradict must be rejected here rather than silently misplacing every
    // commitment in it.
    check_anchors(conn, batch)?;

    let mut note_positions: Vec<(PoolId, Position)> = Vec::new();

    for block in &batch.blocks {
        put_block(conn, block)?;

        for tx in &block.transactions {
            let tx_ref = put_transaction(conn, block, tx.txid, tx.index)?;

            for note in &tx.received {
                put_received_note(conn, tx_ref, note)?;
                note_positions.push((note.pool, note.position));
            }

            for spend in &tx.spends {
                mark_note_spent(conn, tx_ref, spend.pool, &spend.nullifier)?;
            }

            // Scanning discovers no transparent outputs: the private ledger
            // in `zakura-wallet-transparent` is the only thing that does, and
            // it is what a compact block's `vout` used to be read for. See
            // `docs/zakura_transparent_pir.md`.
            //
            // What is still recorded is what this transaction consumed. Every
            // outpoint, not only those already recognised as the wallet's:
            // under descending recovery the output being spent is usually
            // still below the scanned range, so at this moment the wallet
            // cannot tell that it owns it, and the record is what lets the
            // spend attach itself when the output finally arrives.
            for outpoint in &tx.candidate_spends {
                mark_transparent_spent(conn, tx_ref, outpoint)?;
            }

            for candidate in &tx.enhance_candidates {
                put_enhance_candidate(conn, tx_ref, candidate)?;
                // The position-keyed request that a private backend answers.
                // Queued beside the material rather than derived from it later:
                // the two have different lifetimes — a rewind drops the claim
                // while the material stays — and deriving one from the other
                // would tie them together again.
                crate::retrieval::queue_about(
                    conn,
                    Locator::Action {
                        pool: PoolId::Ironwood,
                        position: candidate.position,
                    },
                    Some(tx.txid),
                    None,
                )?;
            }

            // Anything the wallet touched needs its full transaction fetched,
            // to recover memos and outgoing data the compact form omits. This
            // is the request private enhancement later intercepts.
            crate::retrieval::queue(conn, Locator::Transaction(tx.txid), None)?;
        }

        // Nullifiers that matched nothing are kept, not discarded: under
        // descending recovery the note a spend refers to may not have been
        // scanned yet, and this is what lets the two be linked when it is.
        for pool in PoolId::ALL {
            for (tx_index, txid, nullifiers) in &block.commitments(pool).unlinked_nullifiers {
                for nf in nullifiers {
                    put_unlinked_nullifier(conn, pool, nf, *txid, block.height, *tx_index)?;
                }
                // The spend may refer to a note found earlier in this same
                // batch, or in an earlier one.
                for nf in nullifiers {
                    link_nullifier(conn, pool, nf, *txid, block.height, *tx_index)?;
                }
            }
        }
    }

    // And the mirror image: a note stored by *this* batch may be spent by a
    // nullifier recorded long ago. Descending recovery makes this the common
    // direction, not the exceptional one — the send is scanned first and the
    // note that funded it arrives later. Running the check here, inside the
    // applying transaction, is also what repairs a caller whose nullifier
    // snapshot had gone stale while the batch was in flight.
    //
    // Driven by the batch's own notes rather than by the stored nullifiers:
    // during a long recovery the nullifier map grows over the whole scanned
    // span, and scanning it once per batch would make the total work quadratic
    // in the length of the recovery.
    for note in batch.received_notes() {
        link_stored_nullifier(conn, note.pool, &note.nullifier)?;
    }

    // Commitments go into the trees after all notes are stored, so that a note
    // and its marked commitment are always written together or not at all.
    put_commitments(conn, batch)?;

    // Shard end heights must be current before the queue is updated: widening
    // reads them to decide how far a found note's shard extends, and stale
    // values would leave the note unwitnessable.
    update_shard_end_heights(conn, batch)?;

    // Grid boundaries this batch covered are retained against ordinary pruning.
    // A ZIP 318 crossing proves against the tree state at a boundary block, and
    // it is built long after that block has passed: pruning it on the plain
    // depth rule makes the transfer permanently unprovable. Recorded in the
    // same transaction as the checkpoints it protects, so a boundary cannot be
    // written and then lost before its retention is.
    retain_grid_boundaries(conn, batch, chain_tip.unwrap_or(batch.end_anchor.height))?;

    let range = batch.blocks[0].height..(batch.end_anchor.height + 1);
    scan_queue::scan_complete(conn, params, birthday, range, &note_positions)?;
    // Burial is measured against the chain's tip, not this batch's. Using the
    // batch would make spend eligibility depend on scan order: a wallet that
    // finished recovery on a historic range would leave notes near the tip
    // shown in the balance and refused by selection until some unrelated high
    // batch happened to land.
    mark_stabilized_notes(conn, chain_tip.unwrap_or(batch.end_anchor.height))?;

    Ok(())
}

fn put_block(conn: &rusqlite::Transaction<'_>, block: &DetectedBlock) -> Result<(), Error> {
    conn.prepare_cached(&format!(
        "INSERT INTO {CACHE_SCHEMA}.blocks
            (height, hash, time, orchard_tree_size, ironwood_tree_size,
             orchard_action_count, ironwood_action_count)
         VALUES (:height, :hash, :time, :orchard_size, :ironwood_size,
                 :orchard_actions, :ironwood_actions)
         ON CONFLICT (height) DO UPDATE SET
            hash = :hash, time = :time,
            orchard_tree_size = :orchard_size, ironwood_tree_size = :ironwood_size,
            orchard_action_count = :orchard_actions,
            ironwood_action_count = :ironwood_actions"
    ))?
    .execute(named_params![
        ":height": u32::from(block.height),
        ":hash": &block.hash.0[..],
        ":time": block.time,
        ":orchard_size": block.tree_sizes.orchard,
        ":ironwood_size": block.tree_sizes.ironwood,
        ":orchard_actions": block.orchard.commitments.len() as u32,
        ":ironwood_actions": block.ironwood.commitments.len() as u32,
    ])?;
    Ok(())
}

/// Inserts or updates a transaction row, returning its identifier.
fn put_transaction(
    conn: &rusqlite::Transaction<'_>,
    block: &DetectedBlock,
    txid: TxId,
    index: u64,
) -> Result<i64, Error> {
    conn.prepare_cached(&format!(
        "INSERT INTO {CACHE_SCHEMA}.transactions
            (txid, block_height, tx_index, mined_height)
         VALUES (:txid, :height, :index, :height)
         ON CONFLICT (txid) DO UPDATE SET
            block_height = :height, tx_index = :index, mined_height = :height,
            -- Cleared whenever a transaction becomes mined. It records proof
            -- the transaction was *not* mined, the schema forbids holding both,
            -- and a transaction can be reported missing by a server that has
            -- not seen it yet and then mined a moment later. Without this the
            -- scan of the block carrying it fails a CHECK and the range never
            -- completes.
            confirmed_unmined_at_height = NULL"
    ))?
    .execute(named_params![
        ":txid": txid.as_ref(),
        ":height": u32::from(block.height),
        ":index": index,
    ])?;

    tx_ref(conn, txid)
}

fn tx_ref(conn: &rusqlite::Transaction<'_>, txid: TxId) -> Result<i64, Error> {
    // Cached: this runs once per transaction in every batch, and re-preparing a
    // single-row lookup that often costs more than the lookup.
    conn.prepare_cached(&format!(
        "SELECT id FROM {CACHE_SCHEMA}.transactions WHERE txid = :txid"
    ))?
    .query_row(named_params![":txid": txid.as_ref()], |row| row.get(0))
    .map_err(Error::Query)
}

fn put_received_note(
    conn: &rusqlite::Transaction<'_>,
    tx_ref: i64,
    note: &zakura_wallet_core::DetectedNote,
) -> Result<(), Error> {
    conn.prepare_cached(&format!(
        "INSERT INTO {CACHE_SCHEMA}.received_notes
            (transaction_id, pool, action_index, account_id, diversifier, value,
             rho, rseed, note_version, nf, is_change, key_scope,
             commitment_tree_position)
         VALUES (:tx, :pool, :action, :account, :diversifier, :value,
                 :rho, :rseed, :version, :nf, :is_change, :scope, :position)
         ON CONFLICT (transaction_id, pool, action_index) DO UPDATE SET
            commitment_tree_position = :position, nf = :nf, is_change = :is_change"
    ))?
    .execute(named_params![
        ":tx": tx_ref,
        ":pool": note.pool.code(),
        ":action": note.action_index as i64,
        ":account": note.account.0,
        ":diversifier": &note.note.recipient().diversifier().as_array()[..],
        ":value": note.note.value().inner() as i64,
        ":rho": &note.note.rho().to_bytes()[..],
        ":rseed": &note.note.rseed().as_bytes()[..],
        ":version": note_version_code(note.note.version()),
        ":nf": &note.nullifier.to_bytes()[..],
        ":is_change": note.is_change,
        ":scope": note.scope.code(),
        ":position": u64::from(note.position),
    ])?;
    Ok(())
}

/// Records that `tx_ref` spends the note with this nullifier, if we hold it.
fn mark_note_spent(
    conn: &rusqlite::Transaction<'_>,
    tx_ref: i64,
    pool: PoolId,
    nf: &orchard::note::Nullifier,
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

fn put_unlinked_nullifier(
    conn: &rusqlite::Transaction<'_>,
    pool: PoolId,
    nf: &orchard::note::Nullifier,
    txid: TxId,
    height: BlockHeight,
    tx_index: u64,
) -> Result<(), Error> {
    conn.prepare_cached(&format!(
        "INSERT INTO {CACHE_SCHEMA}.nullifier_map (pool, nf, txid, block_height, tx_index)
         VALUES (:pool, :nf, :txid, :height, :index)
         ON CONFLICT (pool, nf) DO UPDATE SET
            txid = :txid, block_height = :height, tx_index = :index"
    ))?
    .execute(named_params![
        ":pool": pool.code(),
        ":nf": &nf.to_bytes()[..],
        ":txid": txid.as_ref(),
        ":height": u32::from(height),
        ":index": tx_index,
    ])?;
    Ok(())
}

/// Links a stored nullifier to a note the wallet turns out to hold.
///
/// This is the other half of descending recovery. Detection could not link the
/// spend because the note had not been scanned when the batch ran; by the time
/// the batch is applied it may have been, either earlier in this batch or in an
/// earlier one. Re-checking here, inside the applying transaction, is also what
/// covers the case where the caller's nullifier snapshot had gone stale.
fn link_nullifier(
    conn: &rusqlite::Transaction<'_>,
    pool: PoolId,
    nf: &orchard::note::Nullifier,
    txid: TxId,
    height: BlockHeight,
    tx_index: u64,
) -> Result<(), Error> {
    let note_id: Option<i64> = conn
        .query_row(
            &format!(
                "SELECT id FROM {CACHE_SCHEMA}.received_notes WHERE pool = :pool AND nf = :nf"
            ),
            named_params![":pool": pool.code(), ":nf": &nf.to_bytes()[..]],
            |row| row.get(0),
        )
        .optional()?;

    let Some(note_id) = note_id else {
        return Ok(());
    };

    // The spending transaction may not have a row yet: it had no wallet
    // activity we could see at scan time, which is exactly the situation this
    // exists to repair.
    conn.prepare_cached(&format!(
        "INSERT INTO {CACHE_SCHEMA}.transactions (txid, block_height, tx_index, mined_height)
         VALUES (:txid, :height, :index, :height)
         ON CONFLICT (txid) DO NOTHING"
    ))?
    .execute(named_params![
        ":txid": txid.as_ref(),
        ":height": u32::from(height),
        ":index": tx_index,
    ])?;

    let spending = tx_ref(conn, txid)?;
    conn.prepare_cached(&format!(
        "INSERT OR IGNORE INTO {CACHE_SCHEMA}.received_note_spends
            (received_note_id, transaction_id) VALUES (:note, :tx)"
    ))?
    .execute(named_params![":note": note_id, ":tx": spending])?;

    Ok(())
}

/// Links one newly stored note to a spend recorded earlier, if there is one.
///
/// This is the reverse of [`link_nullifier`]: that one runs when a spend
/// arrives and the note is already held, this one when the note arrives and the
/// spend was seen earlier. Both are needed, and under descending recovery this
/// is the one that fires.
fn link_stored_nullifier(
    conn: &rusqlite::Transaction<'_>,
    pool: PoolId,
    nf: &orchard::note::Nullifier,
) -> Result<(), Error> {
    let spend: Option<(Vec<u8>, u32, u64)> = conn
        .prepare_cached(&format!(
            "SELECT txid, block_height, tx_index FROM {CACHE_SCHEMA}.nullifier_map
             WHERE pool = :pool AND nf = :nf"
        ))?
        .query_row(
            named_params![":pool": pool.code(), ":nf": &nf.to_bytes()[..]],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;

    let Some((txid, height, tx_index)) = spend else {
        return Ok(());
    };

    // The spending transaction may have had no wallet activity visible at scan
    // time, so it may need a row of its own before the spend can reference it.
    // All three statements here run once per received note in a batch, so they
    // are cached rather than re-prepared each time.
    conn.prepare_cached(&format!(
        "INSERT INTO {CACHE_SCHEMA}.transactions (txid, block_height, tx_index, mined_height)
         VALUES (:txid, :height, :index, :height)
         ON CONFLICT (txid) DO NOTHING"
    ))?
    .execute(named_params![":txid": &txid, ":height": height, ":index": tx_index])?;

    conn.prepare_cached(&format!(
        "INSERT OR IGNORE INTO {CACHE_SCHEMA}.received_note_spends
            (received_note_id, transaction_id)
         SELECT n.id, t.id
         FROM {CACHE_SCHEMA}.received_notes n, {CACHE_SCHEMA}.transactions t
         WHERE n.pool = :pool AND n.nf = :nf AND t.txid = :txid"
    ))?
    .execute(named_params![
        ":pool": pool.code(),
        ":nf": &nf.to_bytes()[..],
        ":txid": &txid,
    ])?;

    // The spend is only now known to be the wallet's, so this is the first
    // moment anything has a reason to fetch the transaction that made it.
    // Under descending recovery a send is scanned before the note that funded
    // it, so for a send with no change this is the *only* moment: at scan time
    // the transaction looked like a stranger's and was dropped.
    let bytes: [u8; 32] = txid.as_slice().try_into().map_err(|_| {
        Error::Corrupt("a nullifier map entry has a malformed transaction id".into())
    })?;
    let spender = TxId::from_bytes(bytes);
    crate::retrieval::queue_unless_fetched(conn, Locator::Transaction(spender), spender)?;

    // The other half of what this moment costs. At scan time this transaction's
    // funding was unknown, so `collect_enhance_candidates` recorded nothing for
    // it — for exactly the transactions private enhancement exists to serve.
    // Those fields cannot be reconstructed from anything the wallet stores, so
    // the block has to be read again now that the funding is known. The hash is
    // the wallet's own record of that height, so the answer can be checked
    // rather than trusted.
    if let Some(anchor) = block_anchor(conn, BlockHeight::from_u32(height))? {
        crate::retrieval::queue_unless_fetched(
            conn,
            Locator::Block {
                height: anchor.height,
                hash: anchor.hash,
            },
            spender,
        )?;
    }

    Ok(())
}

pub(crate) fn put_transparent_output(
    conn: &rusqlite::Transaction<'_>,
    tx_ref: i64,
    output: &zakura_wallet_core::DetectedTransparentOutput,
    is_coinbase: bool,
    unspent_at: Option<BlockHeight>,
    observed_at: BlockHeight,
) -> Result<(), Error> {
    let script = output.txout.script_pubkey().0.0.clone();
    conn.prepare_cached(&format!(
        "INSERT INTO {CACHE_SCHEMA}.transparent_received_outputs
            (transaction_id, output_index, account_id, address_id, script, value,
             is_coinbase, max_observed_unspent_height)
         VALUES (:tx, :index, :account, :address_id, :script, :value,
                 :is_coinbase, :unspent_at)
         ON CONFLICT (transaction_id, output_index) DO UPDATE SET
            value = :value,
            -- Monotone: a later sighting can only extend how far the wallet
            -- knows the output was unspent, never retract it.
            max_observed_unspent_height =
                MAX(IFNULL(max_observed_unspent_height, 0), IFNULL(:unspent_at, 0)),
            is_coinbase = IFNULL(is_coinbase, :is_coinbase)"
    ))?
    .execute(named_params![
        ":tx": tx_ref,
        ":index": output.output_index,
        ":account": output.account.0,
        ":address_id": output.address_id,
        ":script": script,
        ":value": output.txout.value().into_u64() as i64,
        // Known exactly here, because a compact block carries the
        // transaction's index and a coinbase is index zero.
        ":is_coinbase": is_coinbase,
        ":unspent_at": unspent_at.map(u32::from),
    ])?;

    // A spend of this output may already have been seen. Under descending
    // recovery that is the common case rather than the exception: the wallet
    // scans downwards, so it meets the transaction that spent an output before
    // the one that created it. Without this replay the spend would have been
    // recorded in the map and never acted on, and the output would sit in the
    // balance as though it were still there.
    //
    // Ordered by mined height so that a confirmed spend wins over a competing
    // unmined one; several conflicting transactions may claim the same output,
    // which is why the map does not constrain the outpoint to be unique.
    // Looked up rather than taken from `last_insert_rowid`, which reports the
    // last row *inserted* and says nothing useful when the statement above
    // updated an existing row instead.
    let output_id: i64 = conn
        .prepare_cached(&format!(
            "SELECT id FROM {CACHE_SCHEMA}.transparent_received_outputs
             WHERE transaction_id = :tx AND output_index = :index"
        ))?
        .query_row(
            named_params![":tx": tx_ref, ":index": output.output_index],
            |row| row.get(0),
        )?;

    conn.prepare_cached(&format!(
        "INSERT OR IGNORE INTO {CACHE_SCHEMA}.transparent_received_output_spends
            (output_id, transaction_id)
         SELECT :output_id, m.spending_transaction_id
         FROM {CACHE_SCHEMA}.transparent_spend_map m
         JOIN {CACHE_SCHEMA}.transactions t ON t.id = m.spending_transaction_id
         JOIN {CACHE_SCHEMA}.transactions p ON p.id = :tx
         WHERE m.prevout_txid = p.txid AND m.prevout_output_index = :index
         ORDER BY t.mined_height IS NULL, t.mined_height
         LIMIT 1"
    ))?
    .execute(named_params![
        ":output_id": output_id,
        ":tx": tx_ref,
        ":index": output.output_index,
    ])?;

    // Last, because it reads the row just written: being paid at an address is
    // what obliges the wallet to watch further ahead.
    crate::gap::observe_use(conn, output.address_id, observed_at)?;

    Ok(())
}

/// Writes one output the private ledger recovered.
///
/// Separate from [`put_transparent_output`] because the two know different
/// things. That one is handed an output found inside a block the wallet
/// scanned, so the block row, the transaction row and the address are all
/// already present. This one is handed an event that names a transaction the
/// wallet may never have seen, so the transaction row has to be made before
/// there is anything to point at.
pub(crate) fn put_recovered_output(
    conn: &rusqlite::Transaction<'_>,
    output: &crate::RecoveredOutput,
    address_id: i64,
    account: u32,
) -> Result<(), Error> {
    let tx_ref = put_recovered_transaction(conn, output.txid, output.mined_height)?;

    conn.prepare_cached(&format!(
        "INSERT INTO {CACHE_SCHEMA}.transparent_received_outputs
            (transaction_id, output_index, account_id, address_id, script, value,
             is_coinbase, max_observed_unspent_height)
         VALUES (:tx, :index, :account, :address_id, :script, :value,
                 :is_coinbase, :observed)
         ON CONFLICT (transaction_id, output_index) DO UPDATE SET
            value = :value,
            max_observed_unspent_height =
                MAX(IFNULL(max_observed_unspent_height, 0), :observed),
            -- An unknown answer must not overwrite a known one. A row created
            -- by a transaction this wallet built knows the flag exactly; a
            -- recovered spend does not know it at all.
            is_coinbase = IFNULL(:is_coinbase, is_coinbase)"
    ))?
    .execute(named_params![
        ":tx": tx_ref,
        ":index": output.output_index,
        ":account": account,
        ":address_id": address_id,
        ":script": &output.script,
        ":value": output.value as i64,
        ":is_coinbase": output.coinbase,
        ":observed": u32::from(output.observed_at),
    ])?;

    // A spend of this output may already be in the map. The ledger replays in
    // chain order, but a spend recorded when this installation broadcast it
    // predates any of that, and so does one recorded by scanning a block that
    // spent it.
    let output_id: i64 = conn
        .prepare_cached(&format!(
            "SELECT id FROM {CACHE_SCHEMA}.transparent_received_outputs
             WHERE transaction_id = :tx AND output_index = :index"
        ))?
        .query_row(
            named_params![":tx": tx_ref, ":index": output.output_index],
            |row| row.get(0),
        )?;

    conn.prepare_cached(&format!(
        "INSERT OR IGNORE INTO {CACHE_SCHEMA}.transparent_received_output_spends
            (output_id, transaction_id)
         SELECT :output_id, m.spending_transaction_id
         FROM {CACHE_SCHEMA}.transparent_spend_map m
         JOIN {CACHE_SCHEMA}.transactions t ON t.id = m.spending_transaction_id
         JOIN {CACHE_SCHEMA}.transactions p ON p.id = :tx
         WHERE m.prevout_txid = p.txid AND m.prevout_output_index = :index
         ORDER BY t.mined_height IS NULL, t.mined_height
         LIMIT 1"
    ))?
    .execute(named_params![
        ":output_id": output_id,
        ":tx": tx_ref,
        ":index": output.output_index,
    ])?;

    crate::gap::observe_use(conn, address_id, output.observed_at)?;
    Ok(())
}

/// Writes one spend the private ledger recovered.
pub(crate) fn put_recovered_spend(
    conn: &rusqlite::Transaction<'_>,
    spend: &crate::RecoveredSpend,
) -> Result<(), Error> {
    let tx_ref = put_recovered_transaction(conn, spend.spending_txid, Some(spend.height))?;
    let outpoint =
        transparent::bundle::OutPoint::new(*spend.spent_txid.as_ref(), spend.spent_output_index);
    // Remembered as well as marked. The output this consumes may arrive in a
    // later commit — a page fetched after a budget ran out, or an old receive
    // found for a script the gap limit only just reached — and the map is what
    // lets `put_recovered_output` attach this spend to it then.
    remember_spend(conn, tx_ref, &outpoint)?;
    mark_transparent_spent(conn, tx_ref, &outpoint)
}

/// Inserts the transaction row a recovered event needs, returning its id.
///
/// Neither `block_height` nor `tx_index` is written. A recovered event names a
/// height, not a block row, and `block_height` is a foreign key into `blocks` —
/// which holds what the wallet *scanned*, and need not hold every height the
/// ledger read over. `tx_index` is dropped by the ledger's replay before this
/// sees it, and a zero there would say "coinbase" to anything that read it.
///
/// A known height clears any earlier proof the transaction was unmined: the
/// schema forbids holding both, and a transaction can be reported missing by a
/// server that had not seen it yet and then mined a moment later.
fn put_recovered_transaction(
    conn: &rusqlite::Transaction<'_>,
    txid: TxId,
    mined_height: Option<BlockHeight>,
) -> Result<i64, Error> {
    match mined_height {
        Some(height) => conn
            .prepare_cached(&format!(
                "INSERT INTO {CACHE_SCHEMA}.transactions (txid, mined_height)
                 VALUES (:txid, :height)
                 ON CONFLICT (txid) DO UPDATE SET
                    mined_height = :height,
                    confirmed_unmined_at_height = NULL"
            ))?
            .execute(named_params![
                ":txid": txid.as_ref(),
                ":height": u32::from(height),
            ])?,
        // Nothing is asserted about a transaction whose height the run does not
        // know. `DO NOTHING` rather than an update, so a row that already knows
        // more is left alone.
        None => conn
            .prepare_cached(&format!(
                "INSERT INTO {CACHE_SCHEMA}.transactions (txid)
                 VALUES (:txid)
                 ON CONFLICT (txid) DO NOTHING"
            ))?
            .execute(named_params![":txid": txid.as_ref()])?,
    };
    tx_ref(conn, txid)
}

/// Remembers that a transaction spends an outpoint, whether or not the wallet
/// knows the output.
///
/// Deliberately without a unique constraint on the outpoint alone: several
/// conflicting transactions may each claim to spend the same output, and only
/// one of them can be right. Which one is decided when the output is stored,
/// by preferring a mined spender over an unmined one.
pub(crate) fn remember_spend(
    conn: &rusqlite::Transaction<'_>,
    tx_ref: i64,
    outpoint: &transparent::bundle::OutPoint,
) -> Result<(), Error> {
    conn.prepare_cached(&format!(
        "INSERT OR IGNORE INTO {CACHE_SCHEMA}.transparent_spend_map
            (spending_transaction_id, prevout_txid, prevout_output_index)
         VALUES (:tx, :prevout_txid, :prevout_index)"
    ))?
    .execute(named_params![
        ":tx": tx_ref,
        ":prevout_txid": &outpoint.hash()[..],
        ":prevout_index": outpoint.n(),
    ])?;
    Ok(())
}

pub(crate) fn mark_transparent_spent(
    conn: &rusqlite::Transaction<'_>,
    tx_ref: i64,
    outpoint: &transparent::bundle::OutPoint,
) -> Result<(), Error> {
    conn.prepare_cached(&format!(
        "INSERT OR IGNORE INTO {CACHE_SCHEMA}.transparent_received_output_spends
            (output_id, transaction_id)
         SELECT o.id, :tx
         FROM {CACHE_SCHEMA}.transparent_received_outputs o
         JOIN {CACHE_SCHEMA}.transactions t ON t.id = o.transaction_id
         WHERE t.txid = :prevout_txid AND o.output_index = :prevout_index"
    ))?
    .execute(named_params![
        ":tx": tx_ref,
        ":prevout_txid": &outpoint.hash()[..],
        ":prevout_index": outpoint.n(),
    ])?;

    remember_spend(conn, tx_ref, outpoint)?;
    Ok(())
}

fn put_enhance_candidate(
    conn: &rusqlite::Transaction<'_>,
    tx_ref: i64,
    candidate: &zakura_wallet_core::EnhanceCandidate,
) -> Result<(), Error> {
    conn.prepare_cached(&format!(
        "INSERT INTO {CACHE_SCHEMA}.enhance_candidates
            (commitment_tree_position, transaction_id, action_index,
             nullifier, cmx, ephemeral_key, compact_ciphertext)
         VALUES (:position, :tx, :action, :nf, :cmx, :epk, :ciphertext)
         -- Every column, not just the identifying pair. A position is only
         -- reoccupied when a reorg put a different action there, and the
         -- cryptographic fields are exactly what authenticates a later private
         -- lookup's response against what was scanned. Carrying one action's
         -- nullifier, commitment and ciphertext under another's transaction is
         -- how that authentication would be defeated.
         ON CONFLICT (commitment_tree_position) DO UPDATE SET
            transaction_id = :tx, action_index = :action,
            nullifier = :nf, cmx = :cmx,
            ephemeral_key = :epk, compact_ciphertext = :ciphertext"
    ))?
    .execute(named_params![
        ":position": u64::from(candidate.position),
        ":tx": tx_ref,
        ":action": candidate.action_index as i64,
        ":nf": &candidate.nullifier.to_bytes()[..],
        ":cmx": &candidate.cmx.to_bytes()[..],
        ":epk": &candidate.ephemeral_key[..],
        ":ciphertext": &candidate.compact_ciphertext[..],
    ])?;

    let mut stmt = conn.prepare_cached(&format!(
        "INSERT OR IGNORE INTO {CACHE_SCHEMA}.enhance_candidate_accounts
            (commitment_tree_position, account_id) VALUES (:position, :account)"
    ))?;
    for account in &candidate.funding_accounts {
        stmt.execute(named_params![
            ":position": u64::from(candidate.position),
            ":account": account.0,
        ])?;
    }
    Ok(())
}

/// Inserts the batch's commitments into both pools' trees.
///
/// Insertion is *position-addressed*, not appended. `ShardTree::append` places a
/// leaf after the tree's current rightmost one and rejects a checkpoint that is
/// not above every existing checkpoint, which makes it usable only for a batch
/// that continues from the tree's tip. Under descending recovery — tip to
/// birthday, which is how this wallet recovers — an earlier range is applied
/// after a later one, so almost no batch continues from the tip.
///
/// The batch's starting anchor supplies the position, and each block's own tree
/// sizes carry it forward.
///
/// Every scanned block gets a checkpoint, including blocks that added no
/// commitments to a pool. That is not bookkeeping for its own sake: a rewind to
/// height `h` needs a checkpoint at `h`, and a tree that only checkpoints blocks
/// containing its own notes can only rewind to approximately the right place.
/// An imprecise rewind is how a tree becomes quietly wrong.
fn put_commitments(
    conn: &rusqlite::Transaction<'_>,
    batch: &DetectedBatch,
) -> Result<(), TreeError> {
    for pool in PoolId::ALL {
        let mut store = tree(WalletShardStore::new(conn, pool));
        let start = u64::from(batch.start_anchor.tree_sizes.get(pool));

        // The whole batch goes in as *one* insertion. Inserting block by block
        // means one `get_shard`/`put_shard` cycle per block, and each of those
        // deserialises and re-serialises the entire shard — up to 2^16 leaves —
        // so the cost grows with the product of blocks and shard size rather
        // than with the number of commitments. Measured on mainnet, that made
        // storage roughly two thirds of recovery time.
        //
        // The per-block checkpoints ride along inside the retentions, which
        // `batch_insert` already understands.
        let mut commitments = Vec::new();
        let mut position = start;
        let mut empty_blocks = Vec::new();

        for block in &batch.blocks {
            let block_commitments = &block.commitments(pool).commitments;
            if block_commitments.is_empty() {
                // Nothing in this block carries a checkpoint, so its height has
                // to be recorded against the tree state as it stands.
                empty_blocks.push((block.height, position));
                continue;
            }
            commitments.extend(block_commitments.iter().map(|(cmx, retention)| {
                (orchard::tree::MerkleHashOrchard::from_cmx(cmx), *retention)
            }));
            position += block_commitments.len() as u64;
        }

        if !commitments.is_empty() {
            store
                .batch_insert(Position::from(start), commitments.into_iter())
                .map_err(TreeError::Tree)?;
        }

        for (height, position) in empty_blocks {
            let state = if position == 0 {
                TreeState::Empty
            } else {
                TreeState::AtPosition(Position::from(position - 1))
            };
            store
                .store_mut()
                .add_checkpoint(height, Checkpoint::from_parts(state, BTreeSet::new()))
                .map_err(TreeError::Store)?;
        }
    }
    Ok(())
}

/// Marks notes stabilized once their shard is fully scanned and buried.
///
/// A stabilized note is one whose witness a reorg can no longer invalidate,
/// which is what makes it safe to select for spending. A note in the tip shard
/// can never qualify: that shard is by definition incomplete.
fn mark_stabilized_notes(
    conn: &rusqlite::Transaction<'_>,
    chain_tip: BlockHeight,
) -> Result<(), Error> {
    let stable = u32::from(chain_tip).saturating_sub(PRUNING_DEPTH as u32);

    // A note is stable when its shard's end height is buried, and every block
    // up to that height has been scanned.
    conn.execute(
        &format!(
            "UPDATE {CACHE_SCHEMA}.received_notes SET witness_stabilized = 1
             WHERE witness_stabilized = 0
               AND commitment_tree_position IS NOT NULL
               AND EXISTS (
                   SELECT 1 FROM {CACHE_SCHEMA}.tree_shards s
                   WHERE s.pool = received_notes.pool
                     AND s.shard_index = commitment_tree_position >> :shard_height
                     AND s.subtree_end_height IS NOT NULL
                     AND s.subtree_end_height <= :stable
               )"
        ),
        named_params![
            ":shard_height": crate::tree::SHARD_HEIGHT,
            ":stable": stable,
        ],
    )?;
    Ok(())
}

/// A transparent output's unspent-as-of height cannot outlive a cut at
/// `height`. If the transaction that created it is still mined at or below
/// the cut, the wallet knows the output existed and was unspent as of there;
/// otherwise it knows nothing about it at all.
pub(crate) fn clamp_unspent_observation(
    conn: &rusqlite::Transaction<'_>,
    height: BlockHeight,
) -> Result<(), Error> {
    conn.execute(
        &format!(
            "UPDATE {CACHE_SCHEMA}.transparent_received_outputs
             SET max_observed_unspent_height = CASE
                    WHEN (SELECT mined_height FROM {CACHE_SCHEMA}.transactions t
                          WHERE t.id = transaction_id) <= :height THEN :height
                    ELSE NULL
                 END
             WHERE max_observed_unspent_height > :height"
        ),
        named_params![":height": u32::from(height)],
    )?;
    Ok(())
}

/// Rewinds the wallet to `height`, discarding everything above it.
pub(crate) fn truncate_to(
    conn: &rusqlite::Transaction<'_>,
    height: BlockHeight,
) -> Result<(), TreeError> {
    let h = u32::from(height);
    // Captured before anything is deleted: it bounds the range that has to be
    // scanned again.
    let previous_tip = block_height_extrema(conn)?.map(|(_, hi)| hi);

    // The trees first: they are the part that cannot be rebuilt from the rest.
    for pool in PoolId::ALL {
        let mut store = tree(WalletShardStore::new(conn, pool));
        store
            .truncate_to_checkpoint(&height)
            .map_err(TreeError::Tree)?;
    }

    // Spends are kept. A transaction that a rewind un-mined has not been
    // cancelled — it is unmined, which is where every transaction starts, and
    // it may well be mined again a block later. Releasing the notes it spends
    // is expiry's job, and expiry needs proof the transaction is gone. Deleting
    // the spend here would hand those notes back for a second spend on nothing
    // more than a one-block reorg.

    // Received notes on a retained transaction are kept, because they carry
    // memos an enhancement recovered and scanning cannot produce again. What
    // does not survive is their place in the tree: a rescan may put them
    // somewhere else, so the position and its stability are cleared.
    conn.execute(
        &format!(
            "UPDATE {CACHE_SCHEMA}.received_notes
             SET commitment_tree_position = NULL, witness_stabilized = 0
             WHERE transaction_id IN ({IRREPLACEABLE})"
        ),
        named_params![":height": h],
    )
    .map_err(Error::Query)?;

    // Everything on a reproducible transaction goes, along with the row itself
    // below. A rescan of the winning chain rebuilds it exactly if it is there.
    conn.execute(
        &format!(
            "DELETE FROM {CACHE_SCHEMA}.received_note_spends
             WHERE transaction_id IN ({REPRODUCIBLE})"
        ),
        named_params![":height": h],
    )
    .map_err(Error::Query)?;

    for table in ["received_notes", "transparent_received_outputs"] {
        conn.execute(
            &format!(
                "DELETE FROM {CACHE_SCHEMA}.{table}
                 WHERE transaction_id IN ({REPRODUCIBLE})"
            ),
            named_params![":height": h],
        )
        .map_err(Error::Query)?;
    }

    // Enhancement candidates are the exception: each one names a tree position
    // whose occupant the wallet was about to ask about privately. Above the
    // rewind that position may now hold somebody else's note, and spending a
    // private request on it would be both wasted and revealing.
    conn.execute(
        &format!(
            "DELETE FROM {CACHE_SCHEMA}.enhance_candidates
             WHERE transaction_id IN (
                SELECT id FROM {CACHE_SCHEMA}.transactions WHERE mined_height > :height
             )"
        ),
        named_params![":height": h],
    )
    .map_err(Error::Query)?;

    // And the requests that named those positions, on the same predicate. A
    // claim that outlived its material would be a request for a position the
    // wallet no longer has anything to check the answer against — which is
    // exactly the state the identity recheck exists to make impossible. Barred
    // rows are not exempt here: a bar is about a transaction, and no request
    // for a stale position should survive whatever its subject's routing says.
    conn.execute(
        &format!(
            "DELETE FROM {CACHE_SCHEMA}.retrieval_queue
             WHERE kind = :action
               AND subject_txid IN (
                SELECT txid FROM {CACHE_SCHEMA}.transactions WHERE mined_height > :height
             )"
        ),
        named_params![
            ":height": h,
            ":action": zakura_wallet_core::retrieval::LocatorKind::Action.code(),
        ],
    )
    .map_err(Error::Query)?;

    clamp_unspent_observation(conn, height)?;

    conn.execute(
        &format!("DELETE FROM {CACHE_SCHEMA}.nullifier_map WHERE block_height > :height"),
        named_params![":height": h],
    )
    .map_err(Error::Query)?;

    // Transactions are un-mined, not deleted. A rewind says the wallet was
    // wrong about *where* a transaction is, not that it never existed, and the
    // row holds things no rescan can reproduce: a fee, the height it was built
    // for, an outgoing recipient recovered under an outgoing viewing key.
    //
    // Clearing `confirmed_unmined_at_height` alongside is what makes a status
    // request reactivate on its own: the drain skips a mined transaction, so
    // un-mining one puts it back in the queue with nothing re-queued by hand.
    conn.execute(
        &format!(
            "UPDATE {CACHE_SCHEMA}.transactions
             SET block_height = NULL,
                 mined_height = NULL,
                 tx_index = NULL,
                 confirmed_unmined_at_height = NULL
             WHERE id IN ({IRREPLACEABLE})"
        ),
        named_params![":height": h],
    )
    .map_err(Error::Query)?;

    conn.execute(
        &format!(
            // A barred row is the exception. What it records is that the
            // transaction's identifier has already had to be disclosed, and a
            // rewind does not take a disclosure back — dropping the row would
            // let the next scan try to serve it privately again.
            "DELETE FROM {CACHE_SCHEMA}.retrieval_queue
             WHERE fallback_barred = 0
               AND subject_txid IN (
                SELECT txid FROM {CACHE_SCHEMA}.transactions WHERE id IN ({REPRODUCIBLE})
             )"
        ),
        named_params![":height": h],
    )
    .map_err(Error::Query)?;

    conn.execute(
        &format!("DELETE FROM {CACHE_SCHEMA}.transactions WHERE id IN ({REPRODUCIBLE})"),
        named_params![":height": h],
    )
    .map_err(Error::Query)?;

    conn.execute(
        &format!("DELETE FROM {CACHE_SCHEMA}.blocks WHERE height > :height"),
        named_params![":height": h],
    )
    .map_err(Error::Query)?;

    // A shard whose end height is above the rewind point no longer ends where
    // it says: the block that completed it has just been discarded. Left in
    // place it would name a height that does not exist, and both consumers —
    // stabilisation and range widening — would treat the shard as settled on
    // the strength of a block the wallet no longer has.
    //
    // Shards whose roots came from the server are not affected, because a
    // server-supplied root describes a shard completed far below any depth the
    // wallet rewinds to.
    conn.execute(
        &format!(
            "UPDATE {CACHE_SCHEMA}.tree_shards SET subtree_end_height = NULL
             WHERE subtree_end_height > :height"
        ),
        named_params![":height": h],
    )
    .map_err(Error::Query)?;

    // Trim the queue back to the retained range, then put the discarded range
    // back at `Verify`. Deleting it outright would leave a hole the queue never
    // revisits: nothing above the rewind point would be scanned again until the
    // tip moved far enough for `update_chain_tip` to notice, and in the
    // meantime the wallet would quietly be missing blocks.
    conn.execute(
        &format!("DELETE FROM {CACHE_SCHEMA}.scan_queue WHERE block_range_start > :height"),
        named_params![":height": h],
    )
    .map_err(Error::Query)?;
    conn.execute(
        &format!(
            "UPDATE {CACHE_SCHEMA}.scan_queue SET block_range_end = :end
             WHERE block_range_end > :end"
        ),
        named_params![":end": h + 1],
    )
    .map_err(Error::Query)?;
    conn.execute(
        &format!(
            "DELETE FROM {CACHE_SCHEMA}.scan_queue
             WHERE block_range_start >= block_range_end"
        ),
        [],
    )
    .map_err(Error::Query)?;

    // The private transparent ledger's own state follows the same cut, in
    // the same transaction: its coverage rested on blocks that are now gone,
    // and a coverage row that outlived its block would mean a range nothing
    // re-reads.
    crate::transparent::rollback_above(conn, height, "rewind").map_err(TreeError::Store)?;

    if let Some(previous_tip) = previous_tip.filter(|t| *t > height) {
        let requeue = (height + 1)..(previous_tip + 1);
        scan_queue::replace_queue_entries(
            conn,
            &requeue,
            std::iter::once(ScanRange::from_parts(requeue.clone(), ScanPriority::Verify)),
            // The discarded range was `Scanned`; only a forced replacement can
            // lower it back to work that must be redone.
            true,
        )
        .map_err(TreeError::Store)?;
    }

    Ok(())
}

/// Stores the enhance candidates a re-detection of one block produced, and
/// nothing else.
///
/// Descending recovery meets a send before the note that funded it, so at scan
/// time `funding_accounts` is empty and `collect_enhance_candidates` records
/// nothing — for exactly the transactions private enhancement exists to serve.
/// The fields it would have recorded cannot be reconstructed later without the
/// raw transaction, which is what private enhancement is avoiding fetching, so
/// the only way back is to re-read the block once the funding is known.
///
/// Only candidates are applied. The block's commitments are already in the
/// tree, its transactions are already stored, and its range is already marked
/// scanned; re-applying any of that would insert at positions already occupied
/// and would have to teach the scan queue to re-scan a range it has completed.
///
/// The block is checked against the wallet's own record of that height before
/// anything is written. Comparing a claimed hash does not authenticate compact
/// contents — the block has to come from the same trusted source scanning uses
/// — but it does stop a block for the wrong height, or for a height the wallet
/// has since rewound past, being folded in.
pub(crate) fn put_rediscovered_candidates(
    conn: &rusqlite::Transaction<'_>,
    height: BlockHeight,
    hash: &BlockHash,
    block: &zakura_wallet_core::DetectedBlock,
) -> Result<usize, Error> {
    if block.height != height {
        return Err(Error::Corrupt(
            "a rediscovered block is not the height it was asked for".into(),
        ));
    }

    let stored = block_anchor(conn, height)?.ok_or_else(|| {
        Error::Corrupt("a rediscovered block is not one the wallet has scanned".into())
    })?;
    if &stored.hash != hash || stored.hash != block.hash {
        return Err(Error::Corrupt(
            "a rediscovered block does not match the one the wallet scanned".into(),
        ));
    }

    let mut stored_count = 0;
    for tx in &block.transactions {
        if tx.enhance_candidates.is_empty() {
            continue;
        }
        // Only for transactions the wallet already holds. A re-detection can
        // surface a transaction the wallet has no other reason to keep, and
        // storing it here would put a stranger's transaction into the wallet on
        // the strength of a block fetched for another purpose.
        let Some(tx_ref) = existing_tx_ref(conn, tx.txid)? else {
            continue;
        };
        for candidate in &tx.enhance_candidates {
            put_enhance_candidate(conn, tx_ref, candidate)?;
            crate::retrieval::queue_about(
                conn,
                Locator::Action {
                    pool: PoolId::Ironwood,
                    position: candidate.position,
                },
                Some(tx.txid),
                None,
            )?;
            stored_count += 1;
        }
    }
    Ok(stored_count)
}

/// The row for a transaction the wallet already stores, if it stores one.
fn existing_tx_ref(conn: &rusqlite::Transaction<'_>, txid: TxId) -> Result<Option<i64>, Error> {
    Ok(conn
        .prepare_cached(&format!(
            "SELECT id FROM {CACHE_SCHEMA}.transactions WHERE txid = :txid"
        ))?
        .query_row(named_params![":txid": txid.as_ref()], |row| row.get(0))
        .optional()?)
}

/// Returns the chain state as of the end of `height`, if that block is stored.
///
/// This is what anchors the next range above it. It comes from the wallet's own
/// record rather than the source wherever possible, because the trees were
/// built from exactly these values.
pub(crate) fn block_anchor(
    conn: &rusqlite::Connection,
    height: BlockHeight,
) -> Result<Option<BlockAnchor>, Error> {
    conn.query_row(
        &format!(
            "SELECT hash, orchard_tree_size, ironwood_tree_size
             FROM {CACHE_SCHEMA}.blocks WHERE height = :height"
        ),
        named_params![":height": u32::from(height)],
        |row| {
            let hash: Vec<u8> = row.get(0)?;
            Ok((hash, row.get::<_, u32>(1)?, row.get::<_, u32>(2)?))
        },
    )
    .optional()?
    .map(|(hash, orchard, ironwood)| {
        Ok(BlockAnchor {
            height,
            hash: BlockHash::from_slice(&hash).ok_or_else(|| {
                Error::Serialization(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "a stored block hash was not 32 bytes",
                ))
            })?,
            tree_sizes: TreeSizes { orchard, ironwood },
        })
    })
    .transpose()
}

/// Checks a batch's anchors against the blocks the wallet already holds.
///
/// The batch's commitments are inserted at the absolute position
/// `start_anchor` names, so that number decides where every note in the batch
/// lives in the tree. Under ascending recovery it comes from the wallet's own
/// record and is trivially right. Under descending recovery a range usually
/// continues from nothing scanned, so it comes from the source instead — and
/// the scanner's end-of-block check cannot catch a wrong one, because it
/// compares the batch against block metadata from that same source. A source
/// that is wrong about both is self-consistent.
///
/// So this checks the two seams where local data can contradict the source:
///
/// - the block *at* `start_anchor.height`, if scanned, must be the block the
///   anchor names and must have left the trees the size the anchor claims; and
/// - the block *above* `end_anchor.height`, if scanned, must have started from
///   the size the batch ends at — its recorded size less its own actions.
///
/// The second is what covers descending recovery: batches descend into a
/// region whose upper neighbour is already stored, which is exactly where a
/// misplacement would otherwise go unnoticed.
fn check_anchors(conn: &rusqlite::Transaction<'_>, batch: &DetectedBatch) -> Result<(), Error> {
    if let Some(stored) = block_anchor(conn, batch.start_anchor.height)? {
        if stored.hash != batch.start_anchor.hash {
            return Err(Error::AnchorHashMismatch {
                at_height: batch.start_anchor.height,
            });
        }
        for pool in PoolId::ALL {
            let (stored, claimed) = (
                stored.tree_sizes.get(pool),
                batch.start_anchor.tree_sizes.get(pool),
            );
            if stored != claimed {
                return Err(Error::AnchorMismatch {
                    pool,
                    at_height: batch.start_anchor.height,
                    stored,
                    claimed,
                });
            }
        }
    }

    let above = batch.end_anchor.height + 1;
    let Some(sizes) = block_start_sizes(conn, above)? else {
        return Ok(());
    };
    for pool in PoolId::ALL {
        let (stored, claimed) = (sizes.get(pool), batch.end_anchor.tree_sizes.get(pool));
        if stored != claimed {
            return Err(Error::AnchorMismatch {
                pool,
                at_height: batch.end_anchor.height,
                stored,
                claimed,
            });
        }
    }
    Ok(())
}

/// Returns the tree sizes the block at `height` *started* from, if it is
/// stored: its recorded end sizes less the actions it contributed itself.
fn block_start_sizes(
    conn: &rusqlite::Connection,
    height: BlockHeight,
) -> Result<Option<TreeSizes>, Error> {
    conn.query_row(
        &format!(
            "SELECT orchard_tree_size - orchard_action_count,
                    ironwood_tree_size - ironwood_action_count
             FROM {CACHE_SCHEMA}.blocks WHERE height = :height"
        ),
        named_params![":height": u32::from(height)],
        |row| {
            Ok(TreeSizes {
                orchard: row.get(0)?,
                ironwood: row.get(1)?,
            })
        },
    )
    .optional()
    .map_err(Error::Query)
}

/// Returns the wallet's unspent nullifiers, for the scanner to match spends
/// against.
///
/// A note with a spend recorded against it is excluded: the scanner has no use
/// for a nullifier that has already been seen on chain, and carrying it would
/// grow the snapshot without bound.
pub(crate) fn unspent_nullifiers(conn: &rusqlite::Connection) -> Result<NullifierSnapshot, Error> {
    nullifier_snapshot(conn, false)
}

/// Every nullifier the wallet holds a note for, spent or not.
///
/// Detection must never see this: a note already spent is not available to be
/// spent again, and treating it as though it were would find phantom spends.
///
/// Rediscovery must see exactly this. Its whole purpose is to re-read a block
/// whose spend the wallet has *since* recognised, and by then the note it
/// spends is marked spent — so a snapshot of unspent notes would find no
/// funding, conclude the transaction was a stranger's, and hand back an empty
/// candidate list that looks just like a correct answer. That is the failure
/// `docs/zakura_pir_enhance.md` warns about: an ordinary rescan cannot be
/// allowed to silently discharge this obligation because the scanner loads only
/// unspent nullifiers.
pub(crate) fn all_nullifiers(conn: &rusqlite::Connection) -> Result<NullifierSnapshot, Error> {
    nullifier_snapshot(conn, true)
}

fn nullifier_snapshot(
    conn: &rusqlite::Connection,
    include_spent: bool,
) -> Result<NullifierSnapshot, Error> {
    let held = crate::status::held_by_live_spend();
    let spent_filter = if include_spent {
        String::new()
    } else {
        format!("AND id NOT IN ({held})")
    };
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT pool, nf, account_id FROM {CACHE_SCHEMA}.received_notes
         WHERE nf IS NOT NULL
           {spent_filter}"
    ))?;
    let mut rows = stmt.query([])?;

    let mut entries = Vec::new();
    while let Some(row) = rows.next()? {
        let pool = PoolId::from_code(row.get::<_, u8>(0)?).ok_or_else(|| {
            Error::Serialization(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "a stored note names a pool this build does not support",
            ))
        })?;
        let bytes: Vec<u8> = row.get(1)?;
        let nf = <[u8; 32]>::try_from(&bytes[..])
            .ok()
            .and_then(|b| Option::from(orchard::note::Nullifier::from_bytes(&b)))
            .ok_or_else(|| {
                Error::Serialization(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "a stored nullifier is not a valid field element",
                ))
            })?;
        entries.push((pool, nf, AccountId(row.get::<_, u32>(2)?)));
    }

    Ok(NullifierSnapshot::new(entries))
}

/// Returns how many of a pool's commitments the wallet has scanned, and how
/// many the chain holds.
///
/// Coverage rather than blocks, because the work remaining is proportional to
/// commitments: the empty stretches of the chain scan orders of magnitude
/// faster than the busy ones, so a block-count bar moves in lurches and lies
/// about the time left.
///
/// What the wallet covers is the sum of the actions in the blocks it actually
/// scanned — not the span between the lowest and highest tree size it saw,
/// which would count every commitment in the gaps it has not reached.
pub(crate) fn commitment_coverage(
    conn: &rusqlite::Connection,
    pool: PoolId,
) -> Result<(u64, u64), Error> {
    let (size, count) = match pool {
        PoolId::Orchard => ("orchard_tree_size", "orchard_action_count"),
        PoolId::Ironwood => ("ironwood_tree_size", "ironwood_action_count"),
    };

    let (covered, total): (Option<i64>, Option<u32>) = conn.query_row(
        &format!("SELECT SUM({count}), MAX({size}) FROM {CACHE_SCHEMA}.blocks"),
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;

    Ok((covered.unwrap_or(0) as u64, u64::from(total.unwrap_or(0))))
}

/// A commitment tree root the server supplied for a shard the wallet has not
/// scanned.
///
/// Backfill uses these to make notes near the tip witnessable before the whole
/// history below them has been downloaded: a witness needs the roots of every
/// other shard, and downloading a root is cheaper than scanning the shard by
/// four orders of magnitude.
#[derive(Debug, Clone, Copy)]
pub struct SubtreeRoot {
    /// The height at which the shard's last commitment was mined.
    ///
    /// This is what lets a found note's scan range be widened to cover its
    /// shard before that shard has been reached.
    pub end_height: BlockHeight,
    /// The shard's root hash.
    pub root: orchard::tree::MerkleHashOrchard,
}

/// Records server-supplied subtree roots for `pool`, starting at `start_index`.
pub(crate) fn put_subtree_roots(
    conn: &rusqlite::Transaction<'_>,
    pool: PoolId,
    start_index: u64,
    roots: &[SubtreeRoot],
) -> Result<(), TreeError> {
    if roots.is_empty() {
        return Ok(());
    }

    {
        let mut store = tree(WalletShardStore::new(conn, pool));
        for (offset, root) in roots.iter().enumerate() {
            // Inserting at the shard's own root address puts the hash in the
            // *cap*, which is what makes the shards either side of it
            // reachable without their contents. `ShardTree::insert` maintains
            // the cap itself, so this does not need the level-shifting the fork
            // does by hand.
            let address = Address::from_parts(
                Level::from(crate::tree::SHARD_HEIGHT),
                start_index + offset as u64,
            );
            store.insert(address, root.root).map_err(TreeError::Tree)?;
        }
    }

    // The cap insertion writes no shard row, so the rows are written here. An
    // unscanned shard is stored as a single ephemeral leaf holding its root
    // hash: `shardtree` cannot annotate an empty tree, so a leaf is how a shard
    // whose contents are unknown is represented at all.
    let mut stmt = conn.prepare_cached(&format!(
        "INSERT INTO {CACHE_SCHEMA}.tree_shards
            (pool, shard_index, subtree_end_height, root_hash, shard_data)
         VALUES (:pool, :index, :height, :root, :data)
         ON CONFLICT (pool, shard_index) DO UPDATE SET
            subtree_end_height = MAX(COALESCE(subtree_end_height, 0), :height),
            root_hash = :root"
    ))?;

    for (offset, root) in roots.iter().enumerate() {
        let mut root_hash = Vec::new();
        crate::hash::HashSer::write(&root.root, &mut root_hash).map_err(Error::Serialization)?;

        let mut shard_data = Vec::new();
        crate::hash::write_shard(
            &mut shard_data,
            &shardtree::Tree::leaf((root.root, shardtree::RetentionFlags::EPHEMERAL)),
        )?;

        stmt.execute(named_params![
            ":pool": pool.code(),
            ":index": start_index + offset as u64,
            ":height": u32::from(root.end_height),
            ":root": root_hash,
            ":data": shard_data,
        ])?;
    }

    Ok(())
}

/// Returns the index of the first shard the wallet has no root for.
///
/// Backfill asks the server for roots from here on, rather than refetching
/// what it already holds.
pub(crate) fn next_subtree_index(conn: &rusqlite::Connection, pool: PoolId) -> Result<u64, Error> {
    conn.query_row(
        &format!(
            "SELECT COALESCE(MAX(shard_index) + 1, 0) FROM {CACHE_SCHEMA}.tree_shards
             WHERE pool = :pool AND root_hash IS NOT NULL"
        ),
        named_params![":pool": pool.code()],
        |row| row.get(0),
    )
    .map_err(Error::Query)
}

/// A note the wallet holds, as stored.
///
/// The note itself is reconstructed from its parts rather than kept whole,
/// because that is what the database can hold: a note is a recipient, a value,
/// and two field elements.
#[derive(Debug, Clone)]
pub struct StoredNote {
    /// The pool the note belongs to.
    pub pool: PoolId,
    /// The account that holds it.
    pub account: AccountId,
    /// Which scope it arrived on.
    pub scope: KeyScope,
    /// Its position in the pool's commitment tree.
    pub position: Position,
    /// The note's value in zatoshis.
    pub value: u64,
    /// The diversifier of the address it was paid to.
    pub diversifier: [u8; 11],
    /// The rho value binding it to the action that created it.
    pub rho: [u8; 32],
    /// The note's random seed.
    pub rseed: [u8; 32],
    /// Which note plaintext version it used.
    pub note_version: u8,
}

/// Returns the notes an account could spend.
///
/// A note qualifies when it has a position, has no spend recorded against it,
/// and its witness is stable — that last condition being the one that matters,
/// because a note whose containing shard is not fully scanned and buried has no
/// witness a reorg cannot invalidate, and spending it would produce a proof
/// against an anchor the chain may abandon.
pub(crate) fn spendable_notes(
    conn: &rusqlite::Connection,
    account: AccountId,
    require_stable: bool,
) -> Result<Vec<StoredNote>, Error> {
    let held = crate::status::held_by_live_spend();
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT pool, key_scope, commitment_tree_position, value,
                diversifier, rho, rseed, note_version
         FROM {CACHE_SCHEMA}.received_notes
         WHERE account_id = :account
           AND commitment_tree_position IS NOT NULL
           AND (:any_stability OR witness_stabilized = 1)
           AND id NOT IN ({held})
         ORDER BY value DESC"
    ))?;

    let malformed = |what: &str| {
        Error::Serialization(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("a stored note has {what}"),
        ))
    };

    let mut rows = stmt.query(named_params![
        ":account": account.0,
        ":any_stability": !require_stable,
    ])?;
    let mut notes = Vec::new();
    while let Some(row) = rows.next()? {
        let pool = PoolId::from_code(row.get::<_, u8>(0)?)
            .ok_or_else(|| malformed("a pool this build does not support"))?;
        let scope = KeyScope::from_code(row.get::<_, u8>(1)?)
            .ok_or_else(|| malformed("a key scope this build does not recognise"))?;
        notes.push(StoredNote {
            pool,
            account,
            scope,
            position: Position::from(row.get::<_, u64>(2)?),
            value: row.get::<_, i64>(3)? as u64,
            diversifier: <[u8; 11]>::try_from(&row.get::<_, Vec<u8>>(4)?[..])
                .map_err(|_| malformed("a diversifier of the wrong length"))?,
            rho: <[u8; 32]>::try_from(&row.get::<_, Vec<u8>>(5)?[..])
                .map_err(|_| malformed("a rho of the wrong length"))?,
            rseed: <[u8; 32]>::try_from(&row.get::<_, Vec<u8>>(6)?[..])
                .map_err(|_| malformed("an rseed of the wrong length"))?,
            note_version: row.get::<_, u8>(7)?,
        });
    }
    Ok(notes)
}

/// Returns the lowest and highest scanned block heights.
pub(crate) fn block_height_extrema(
    conn: &rusqlite::Connection,
) -> Result<Option<(BlockHeight, BlockHeight)>, Error> {
    conn.query_row(
        &format!("SELECT MIN(height), MAX(height) FROM {CACHE_SCHEMA}.blocks"),
        [],
        |row| {
            Ok(row
                .get::<_, Option<u32>>(0)?
                .zip(row.get::<_, Option<u32>>(1)?)
                .map(|(lo, hi)| (BlockHeight::from(lo), BlockHeight::from(hi))))
        },
    )
    .map_err(Error::Query)
}

/// Marks the ZIP 318 anchor-grid boundaries this batch covered as retained.
///
/// Retention is what keeps a boundary checkpoint alive past [`PRUNING_DEPTH`].
/// A crossing proves against the tree state at a boundary and is built long
/// afterwards, so a boundary pruned on the ordinary depth rule takes every
/// crossing that would have anchored there with it — and the wallet cannot get
/// it back, because the tree state at a passed height is not refetchable once
/// the shard has moved on.
///
/// Both pools are retained at the same heights. A crossing anchors both bundles
/// at one height, so a boundary only one pool kept is a boundary neither can
/// use.
fn retain_grid_boundaries(
    conn: &rusqlite::Transaction<'_>,
    batch: &DetectedBatch,
    chain_tip: BlockHeight,
) -> Result<(), TreeError> {
    let interval = u32::from(ANCHOR_GRID.block_count());

    // Retention is bounded, not perpetual. A crossing's canonical expiry sits
    // at most `ANCHOR_RETENTION_DEPTH` above the height it targets, so a
    // boundary older than that cannot back a transfer that would still be valid
    // by the time it was sent. Retaining every boundary ever crossed would add a
    // row per interval per pool for the whole history — and, worse, would stop
    // the tree pruning the marks beneath them, so the cost is in the shards
    // rather than in the handful of checkpoint rows.
    let horizon = u32::from(chain_tip).saturating_sub(zakura_wallet_core::ANCHOR_RETENTION_DEPTH);

    let boundaries: Vec<BlockHeight> = batch
        .blocks
        .iter()
        .map(|block| block.height)
        .filter(|height| u32::from(*height) % interval == 0)
        .filter(|height| u32::from(*height) >= horizon)
        .collect();

    for pool in PoolId::ALL {
        let mut store = WalletShardStore::new(conn, pool);
        for height in &boundaries {
            store
                .add_retained_checkpoint(*height)
                .map_err(TreeError::Store)?;
        }
    }

    // Release boundaries that have fallen out of the window, so ordinary
    // pruning can reclaim them.
    conn.execute(
        &format!(
            "UPDATE {CACHE_SCHEMA}.tree_checkpoints SET retained_for = NULL
             WHERE retained_for IS NOT NULL AND checkpoint_id < :horizon"
        ),
        named_params![":horizon": horizon],
    )
    .map_err(Error::Query)?;

    // Nothing is deleted here. A checkpoint row with a NULL position is not a
    // spent retention placeholder — it is a checkpoint taken when the tree was
    // empty, which every block below a pool's first commitment has. Releasing
    // retention is all that is wanted; pruning the checkpoint itself is the
    // tree's job, and it knows which of the two it is looking at.

    Ok(())
}

/// Records the block height at which each pool's shards *complete*.
///
/// A shard's end height is the height of the block that appended its final
/// commitment — the one at position `(shard + 1) << SHARD_HEIGHT - 1`. Nothing
/// weaker will do, because of what the value is used for: `mark_stabilized_notes`
/// treats a buried end height as "this shard is settled, its notes are
/// witnessable", and `scan_queue::extend_range` treats it as "this shard is
/// covered, the range need not be widened past it". Both are statements about a
/// *complete* shard.
///
/// Recording the last block that merely *touched* a shard would satisfy neither.
/// A shard holds 2^16 leaves and is filled across many thousands of blocks, so a
/// partly-filled shard's "end" is an arbitrary point in the middle of it, and
/// treating that as settled marks notes spendable whose shard still has
/// unscanned leaves — the silently-unspendable note the design calls out as a
/// correctness requirement rather than a scheduling one.
///
/// The other way a shard's end height becomes known is
/// [`put_subtree_roots`], where the server describes a shard it has already
/// completed. That path is authoritative and unaffected by this one.
fn update_shard_end_heights(
    conn: &rusqlite::Transaction<'_>,
    batch: &DetectedBatch,
) -> Result<(), Error> {
    let mut ends: BTreeMap<(PoolId, u64), BlockHeight> = BTreeMap::new();
    let shard_leaves = 1u64 << crate::tree::SHARD_HEIGHT;

    for pool in PoolId::ALL {
        for block in &batch.blocks {
            let added = u64::from(block.commitments(pool).commitments.len() as u32);
            if added == 0 {
                continue;
            }
            let end = u64::from(block.tree_sizes.get(pool));
            let start = end - added;

            // Every shard boundary this block's commitments crossed. A block
            // can fill more than one shard only if it carried 2^16 actions,
            // which consensus does not permit, but the loop costs nothing and
            // does not depend on that.
            let first = start / shard_leaves;
            let last = (end - 1) / shard_leaves;
            for shard in first..=last {
                // The shard is complete only if its final position — the leaf
                // one below the next shard's first — is among the commitments
                // this block appended.
                let boundary = (shard + 1) * shard_leaves;
                if boundary <= end {
                    ends.insert((pool, shard), block.height);
                }
            }
        }
    }

    let mut stmt = conn.prepare_cached(&format!(
        "UPDATE {CACHE_SCHEMA}.tree_shards SET subtree_end_height = :height
         WHERE pool = :pool AND shard_index = :index
           AND (subtree_end_height IS NULL OR subtree_end_height < :height)"
    ))?;
    for ((pool, shard), height) in ends {
        stmt.execute(named_params![
            ":pool": pool.code(),
            ":index": shard,
            ":height": u32::from(height),
        ])?;
    }
    Ok(())
}

/// The stored code for a note plaintext version.
///
/// This is the version's lead byte, which is how the protocol identifies it, so
/// the stored value stays meaningful even read outside this crate.
pub(crate) fn note_version_code(version: orchard::note::NoteVersion) -> u8 {
    match version {
        orchard::note::NoteVersion::V2 => 0x02,
        orchard::note::NoteVersion::V3 => 0x03,
    }
}
