//! The spend journal: every Ironwood nullifier of every transaction the block scan
//! recognizes.
//!
//! A spend of a one-time-key note always carries an output to the spending account's
//! internal address (see `zcash_client_backend::fees::orchard::InputView::is_one_time`),
//! so the scan recognizes it. For a block covered for an account, meaning stored by a
//! scan that used that account's keys, the journal therefore holds every nullifier
//! that could spend one of the account's one-time notes. See
//! `wallet::one_time_rewind::truncate` for rewinds.

use std::{collections::HashMap, ops::Range};

use orchard::note::Nullifier;
use rusqlite::{Connection, named_params, params};
use zcash_client_backend::data_api::{ScannedBlock, scanning::ScanPriority};
use zcash_primitives::transaction::TxId;
use zcash_protocol::{
    ShieldedPool,
    consensus::{BlockHeight, TxIndex},
};

use crate::{AccountUuid, error::SqliteClientError, wallet, wallet::scanning::priority_code};

/// One recognized transaction, taken from a scanned block before storage consumes it.
pub(crate) struct Entry {
    height: BlockHeight,
    tx_index: u16,
    txid: [u8; 32],
    nullifiers: Vec<[u8; 32]>,
}

/// An unlinked Ironwood nullifier in the batch matching an already-stored unspent note.
struct UnlinkedSpend {
    height: BlockHeight,
    tx_index: TxIndex,
    txid: TxId,
    nf: Nullifier,
}

/// What a batch of scanned blocks adds to the journal: its recognized transactions, the ranges
/// it covers for each account, and any spends of concurrently admitted Ironwood notes.
pub(crate) struct Batch {
    entries: Vec<Entry>,
    coverage: Vec<(AccountUuid, Range<BlockHeight>)>,
    unlinked_spends: Vec<UnlinkedSpend>,
    rescan_range: Option<Range<BlockHeight>>,
    suffix_rescan: Option<Range<BlockHeight>>,
}

/// Collects journal entries, coverage, and any unlinked spends of notes admitted after the scan
/// loaded `Nullifiers::unspent`. Runs inside `put_blocks`'s write transaction before batch rows
/// are inserted.
pub(crate) fn collect(
    conn: &Connection,
    blocks: &[ScannedBlock<AccountUuid>],
) -> Result<Batch, SqliteClientError> {
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
    let (unlinked_spends, rescan_range) = collect_unlinked_spends(conn, blocks)?;
    let suffix_rescan = collect_rescan_discovered_note_suffix(conn, blocks)?;
    Ok(Batch {
        entries,
        coverage,
        unlinked_spends,
        rescan_range,
        suffix_rescan,
    })
}

/// If `blocks` is a rescan of previously stored blocks that discovered a new Ironwood note while
/// later blocks are already stored, returns `(batch_end + 1)..(stored_tip + 1)` so any already-
/// scanned suffix is rescanned linearly with the new note's nullifier tracked (even after
/// `nullifier_map` pruning).
fn collect_rescan_discovered_note_suffix(
    conn: &Connection,
    blocks: &[ScannedBlock<AccountUuid>],
) -> Result<Option<Range<BlockHeight>>, SqliteClientError> {
    let (Some(batch_start), Some(batch_end)) = (
        blocks.iter().map(ScannedBlock::height).min(),
        blocks.iter().map(ScannedBlock::height).max(),
    ) else {
        return Ok(None);
    };
    let mut output_nfs = blocks
        .iter()
        .flat_map(|b| b.transactions().iter())
        .flat_map(|tx| tx.ironwood_outputs().iter())
        .filter_map(|out| out.nf())
        .peekable();
    if output_nfs.peek().is_none() {
        return Ok(None);
    }
    let Some(stored_tip) = conn
        .query_row("SELECT MAX(height) FROM blocks", [], |r| {
            r.get::<_, Option<u32>>(0)
        })?
        .map(BlockHeight::from)
    else {
        return Ok(None);
    };
    if stored_tip <= batch_end {
        return Ok(None);
    }
    let is_rescan: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM blocks WHERE height >= ?1 AND height <= ?2)",
        params![u32::from(batch_start), u32::from(batch_end)],
        |r| r.get(0),
    )?;
    if !is_rescan {
        return Ok(None);
    }
    let mut known =
        conn.prepare_cached("SELECT EXISTS(SELECT 1 FROM ironwood_received_notes WHERE nf = ?1)")?;
    for nf in output_nfs {
        let already_known: bool = known.query_row([nf.to_bytes()], |r| r.get(0))?;
        if !already_known {
            return Ok(Some((batch_end + 1)..(stored_tip + 1)));
        }
    }
    Ok(None)
}

/// Intersects `blocks`' unlinked Ironwood nullifier maps with currently unspent stored notes.
/// Because `nullifier_map` omits nullifiers matched during the scan, hits are notes admitted
/// concurrently after `Nullifiers::unspent`.
fn collect_unlinked_spends(
    conn: &Connection,
    blocks: &[ScannedBlock<AccountUuid>],
) -> Result<(Vec<UnlinkedSpend>, Option<Range<BlockHeight>>), SqliteClientError> {
    let Some(batch_end) = blocks.iter().map(ScannedBlock::height).max() else {
        return Ok((vec![], None));
    };
    if !blocks.iter().any(|b| {
        b.ironwood()
            .nullifier_map()
            .iter()
            .any(|(_, _, nfs)| !nfs.is_empty())
    }) {
        return Ok((vec![], None));
    }
    let mut stmt = conn.prepare_cached(
        "SELECT a.uuid, rn.nf FROM ironwood_received_notes rn
         JOIN accounts a ON a.id = rn.account_id
         WHERE rn.nf IS NOT NULL AND NOT EXISTS (
             SELECT 1 FROM ironwood_received_note_spends s
             JOIN transactions t ON t.id_tx = s.transaction_id
             WHERE s.ironwood_received_note_id = rn.id AND t.mined_height IS NOT NULL)",
    )?;
    let mut unspent: HashMap<[u8; 32], Vec<AccountUuid>> = HashMap::new();
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        unspent
            .entry(row.get(1)?)
            .or_default()
            .push(AccountUuid(row.get(0)?));
    }
    if unspent.is_empty() {
        return Ok((vec![], None));
    }
    let mut hits = vec![];
    let mut earliest_uncovered: Option<BlockHeight> = None;
    for block in blocks {
        for (tx_index, txid, nfs) in block.ironwood().nullifier_map() {
            for nf in nfs {
                if let Some(accounts) = unspent.get(&nf.to_bytes()) {
                    hits.push(UnlinkedSpend {
                        height: block.height(),
                        tx_index: *tx_index,
                        txid: *txid,
                        nf: *nf,
                    });
                    let tx_recognized = block.transactions().iter().any(|t| t.txid() == *txid);
                    if !tx_recognized
                        || accounts
                            .iter()
                            .any(|a| !block.scanned_accounts().contains(a))
                    {
                        earliest_uncovered = Some(
                            earliest_uncovered.map_or(block.height(), |m| m.min(block.height())),
                        );
                    }
                }
            }
        }
    }
    Ok((hits, earliest_uncovered.map(|start| start..(batch_end + 1))))
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
    for hit in batch.unlinked_spends {
        let tx_ref =
            wallet::put_tx_meta_by_id(conn, tpir_session, hit.txid, hit.tx_index, hit.height)?;
        let inserted = wallet::orchard::mark_ironwood_note_spent(conn, tx_ref, &hit.nf)?;
        wallet::ironwood_hooks::put_received_note_spend(
            conn,
            tpir_session,
            ShieldedPool::Ironwood,
            tx_ref,
            usize::from(inserted),
        )?;
    }
    if let Some(range) = batch.rescan_range {
        super::queue_rescan(conn, range)?;
    }
    if let Some(suffix) = batch.suffix_rescan {
        let start = u32::from(suffix.start);
        let end = u32::from(suffix.end);
        let scanned_stretches: Vec<(u32, u32)> = conn
            .prepare_cached(
                "SELECT block_range_start, block_range_end FROM scan_queue
                 WHERE priority = ?3 AND block_range_start < ?2 AND block_range_end > ?1
                 ORDER BY block_range_start",
            )?
            .query_map(
                params![start, end, priority_code(&ScanPriority::Scanned)],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?
            .collect::<Result<_, _>>()?;
        for (s, e) in scanned_stretches {
            super::queue_rescan(
                conn,
                BlockHeight::from(s.max(start))..BlockHeight::from(e.min(end)),
            )?;
        }
    }
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
        let inserted = crate::wallet::orchard::mark_ironwood_note_spent(conn, tx_ref, &nf)?;
        crate::wallet::ironwood_hooks::put_received_note_spend(
            conn,
            tpir_session,
            zcash_protocol::ShieldedPool::Ironwood,
            tx_ref,
            usize::from(inserted),
        )?;
    }
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
