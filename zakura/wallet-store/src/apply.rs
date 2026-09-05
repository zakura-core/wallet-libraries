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
use zakura_wallet_core::{
    AccountId, BlockAnchor, BlockHash, DetectedBatch, DetectedBlock, KeyScope, NullifierSnapshot,
    pool::{PoolId, TreeSizes},
};
use zakura_wallet_core::scanning::{ScanPriority, ScanRange};
use zcash_protocol::{
    TxId,
    consensus::{BlockHeight, Parameters},
};

use shardtree::store::{Checkpoint, ShardStore, TreeState};

use crate::{
    error::{Error, TreeError},
    schema::CACHE_SCHEMA,
    scan_queue,
    tree::{PRUNING_DEPTH, WalletShardStore, tree},
};

/// The request that recovers a transaction's memos and outgoing data.
///
/// Stored as a small integer rather than in an enum table because the set is
/// fixed by the protocol. The mined-ness query joins it when transaction status
/// tracking lands.
pub(crate) const QUERY_ENHANCEMENT: u8 = 0;

/// Applies `batch` and marks its range scanned, in one transaction.
pub(crate) fn put_batch<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    birthday: Option<BlockHeight>,
    batch: &DetectedBatch,
) -> Result<(), TreeError> {
    if batch.blocks.is_empty() {
        return Ok(());
    }

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

            for output in &tx.transparent_received {
                put_transparent_output(conn, tx_ref, output)?;
            }

            for outpoint in &tx.transparent_spends {
                mark_transparent_spent(conn, tx_ref, outpoint)?;
            }

            for candidate in &tx.enhance_candidates {
                put_enhance_candidate(conn, tx_ref, candidate)?;
            }

            // Anything the wallet touched needs its full transaction fetched,
            // to recover memos and outgoing data the compact form omits. This
            // is the request private enhancement later intercepts.
            queue_request(conn, tx.txid, QUERY_ENHANCEMENT)?;
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

    let range = batch.blocks[0].height..(batch.end_anchor.height + 1);
    scan_queue::scan_complete(conn, params, birthday, range, &note_positions)?;
    mark_stabilized_notes(conn, batch.end_anchor.height)?;

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
            block_height = :height, tx_index = :index, mined_height = :height"
    ))?
    .execute(named_params![
        ":txid": txid.as_ref(),
        ":height": u32::from(block.height),
        ":index": index,
    ])?;

    tx_ref(conn, txid)
}

fn tx_ref(conn: &rusqlite::Transaction<'_>, txid: TxId) -> Result<i64, Error> {
    conn.query_row(
        &format!("SELECT id FROM {CACHE_SCHEMA}.transactions WHERE txid = :txid"),
        named_params![":txid": txid.as_ref()],
        |row| row.get(0),
    )
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
        .query_row(
            &format!(
                "SELECT txid, block_height, tx_index FROM {CACHE_SCHEMA}.nullifier_map
                 WHERE pool = :pool AND nf = :nf"
            ),
            named_params![":pool": pool.code(), ":nf": &nf.to_bytes()[..]],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;

    let Some((txid, height, tx_index)) = spend else {
        return Ok(());
    };

    // The spending transaction may have had no wallet activity visible at scan
    // time, so it may need a row of its own before the spend can reference it.
    conn.execute(
        &format!(
            "INSERT INTO {CACHE_SCHEMA}.transactions (txid, block_height, tx_index, mined_height)
             VALUES (:txid, :height, :index, :height)
             ON CONFLICT (txid) DO NOTHING"
        ),
        named_params![":txid": &txid, ":height": height, ":index": tx_index],
    )?;

    conn.execute(
        &format!(
            "INSERT OR IGNORE INTO {CACHE_SCHEMA}.received_note_spends
                (received_note_id, transaction_id)
             SELECT n.id, t.id
             FROM {CACHE_SCHEMA}.received_notes n, {CACHE_SCHEMA}.transactions t
             WHERE n.pool = :pool AND n.nf = :nf AND t.txid = :txid"
        ),
        named_params![":pool": pool.code(), ":nf": &nf.to_bytes()[..], ":txid": &txid],
    )?;

    Ok(())
}

fn put_transparent_output(
    conn: &rusqlite::Transaction<'_>,
    tx_ref: i64,
    output: &zakura_wallet_core::DetectedTransparentOutput,
) -> Result<(), Error> {
    let script = output.txout.script_pubkey().0.0.clone();
    conn.prepare_cached(&format!(
        "INSERT INTO {CACHE_SCHEMA}.transparent_received_outputs
            (transaction_id, output_index, account_id, address, script, value)
         VALUES (:tx, :index, :account, :address, :script, :value)
         ON CONFLICT (transaction_id, output_index) DO UPDATE SET value = :value"
    ))?
    .execute(named_params![
        ":tx": tx_ref,
        ":index": output.output_index,
        ":account": output.account.0,
        ":address": hex(&script),
        ":script": script,
        ":value": output.txout.value().into_u64() as i64,
    ])?;
    Ok(())
}

fn mark_transparent_spent(
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

    // Recorded whether or not the output was found, so a spend seen before its
    // output can be reconciled when the output arrives.
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
         ON CONFLICT (commitment_tree_position) DO UPDATE SET
            transaction_id = :tx, action_index = :action"
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

fn queue_request(
    conn: &rusqlite::Transaction<'_>,
    txid: TxId,
    query_type: u8,
) -> Result<(), Error> {
    conn.prepare_cached(&format!(
        "INSERT OR IGNORE INTO {CACHE_SCHEMA}.tx_requests (txid, query_type)
         VALUES (:txid, :query_type)"
    ))?
    .execute(named_params![":txid": txid.as_ref(), ":query_type": query_type])?;
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

    // Spends recorded by transactions that no longer exist must go, or the
    // notes they spent would stay unspendable after the rewind.
    conn.execute(
        &format!(
            "DELETE FROM {CACHE_SCHEMA}.received_note_spends
             WHERE transaction_id IN (
                SELECT id FROM {CACHE_SCHEMA}.transactions WHERE mined_height > :height
             )"
        ),
        named_params![":height": h],
    )
    .map_err(Error::Query)?;

    for table in [
        "received_notes",
        "transparent_received_outputs",
        "enhance_candidates",
    ] {
        conn.execute(
            &format!(
                "DELETE FROM {CACHE_SCHEMA}.{table}
                 WHERE transaction_id IN (
                    SELECT id FROM {CACHE_SCHEMA}.transactions WHERE mined_height > :height
                 )"
            ),
            named_params![":height": h],
        )
        .map_err(Error::Query)?;
    }

    conn.execute(
        &format!("DELETE FROM {CACHE_SCHEMA}.nullifier_map WHERE block_height > :height"),
        named_params![":height": h],
    )
    .map_err(Error::Query)?;

    conn.execute(
        &format!("DELETE FROM {CACHE_SCHEMA}.transactions WHERE mined_height > :height"),
        named_params![":height": h],
    )
    .map_err(Error::Query)?;

    conn.execute(
        &format!("DELETE FROM {CACHE_SCHEMA}.blocks WHERE height > :height"),
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

/// Returns the wallet's unspent nullifiers, for the scanner to match spends
/// against.
///
/// A note with a spend recorded against it is excluded: the scanner has no use
/// for a nullifier that has already been seen on chain, and carrying it would
/// grow the snapshot without bound.
pub(crate) fn unspent_nullifiers(
    conn: &rusqlite::Connection,
    epoch: u64,
) -> Result<NullifierSnapshot, Error> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT pool, nf, account_id FROM {CACHE_SCHEMA}.received_notes
         WHERE nf IS NOT NULL
           AND id NOT IN (SELECT received_note_id FROM {CACHE_SCHEMA}.received_note_spends)"
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

    Ok(NullifierSnapshot::new(epoch, entries))
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

    Ok((
        covered.unwrap_or(0) as u64,
        u64::from(total.unwrap_or(0)),
    ))
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
pub(crate) fn next_subtree_index(
    conn: &rusqlite::Connection,
    pool: PoolId,
) -> Result<u64, Error> {
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
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT pool, key_scope, commitment_tree_position, value,
                diversifier, rho, rseed, note_version
         FROM {CACHE_SCHEMA}.received_notes
         WHERE account_id = :account
           AND commitment_tree_position IS NOT NULL
           AND (:any_stability OR witness_stabilized = 1)
           AND id NOT IN (SELECT received_note_id FROM {CACHE_SCHEMA}.received_note_spends)
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

/// Records the block height at which each pool's shards end.
///
/// The scan queue needs this to know how far a shard extends, and it comes from
/// the blocks that were scanned rather than from the tree itself.
fn update_shard_end_heights(
    conn: &rusqlite::Transaction<'_>,
    batch: &DetectedBatch,
) -> Result<(), Error> {
    let mut ends: BTreeMap<(PoolId, u64), BlockHeight> = BTreeMap::new();

    for pool in PoolId::ALL {
        for block in &batch.blocks {
            // A shard ends at the block containing its last *commitment*. A
            // block that added none to this pool leaves the boundary where it
            // was, however far above it sits — extending it would make a note
            // look buried when its shard is still open.
            let added = block.commitments(pool).commitments.len() as u32;
            if added == 0 {
                continue;
            }
            let size = match pool {
                PoolId::Orchard => block.tree_sizes.orchard,
                PoolId::Ironwood => block.tree_sizes.ironwood,
            };
            // The shard containing the block's last commitment.
            let shard = u64::from(size - 1) >> crate::tree::SHARD_HEIGHT;
            ends.insert((pool, shard), block.height);
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
fn note_version_code(version: orchard::note::NoteVersion) -> u8 {
    match version {
        orchard::note::NoteVersion::V2 => 0x02,
        orchard::note::NoteVersion::V3 => 0x03,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

