//! The persistent scan queue.
//!
//! The queue is a gapless, disjoint sequence of height ranges, each with a
//! priority. It is the wallet's entire memory of what remains to be scanned:
//! there is no separate cursor or progress counter, which is what makes sync
//! resumable from any point without a recovery step. Cancelling is dropping the
//! engine; resuming is reading this table.
//!
//! Merging is delegated to
//! [`SpanningTree`](zakura_wallet_core::scanning::spanning_tree::SpanningTree),
//! which decides which priority survives where two ranges meet. Ported from
//! `zcash_client_sqlite::wallet::scanning`.

use std::{
    cmp::{max, min},
    collections::BTreeSet,
    ops::Range,
};

use incrementalmerkletree::{Address, Level, Position};
use rusqlite::{OptionalExtension, named_params};
use zakura_wallet_core::{
    pool::{PoolId, ShieldedPool},
    scanning::{ScanPriority, ScanRange, spanning_tree::SpanningTree},
};
use zcash_protocol::consensus::{BlockHeight, Parameters};

use crate::{error::Error, schema::CACHE_SCHEMA, tree::SHARD_HEIGHT};

/// How many blocks above the scanned tip are re-checked before trusting them.
///
/// Roughly twelve minutes of chain: long enough that a user who opened their
/// wallet to receive a payment, or spent their own funds, will have their
/// transaction re-examined before anything downstream depends on it.
pub const VERIFY_LOOKAHEAD: u32 = 10;

/// The stored code for a priority.
///
/// These are gapped by ten so a level can be inserted between two existing ones
/// without renumbering a deployed database.
fn priority_code(priority: ScanPriority) -> i64 {
    match priority {
        ScanPriority::Ignored => 0,
        ScanPriority::Scanned => 10,
        ScanPriority::Historic => 20,
        ScanPriority::OpenAdjacent => 30,
        ScanPriority::FoundNote => 40,
        ScanPriority::ChainTip => 50,
        ScanPriority::Verify => 60,
    }
}

fn parse_priority_code(code: i64) -> Option<ScanPriority> {
    match code {
        0 => Some(ScanPriority::Ignored),
        10 => Some(ScanPriority::Scanned),
        20 => Some(ScanPriority::Historic),
        30 => Some(ScanPriority::OpenAdjacent),
        40 => Some(ScanPriority::FoundNote),
        50 => Some(ScanPriority::ChainTip),
        60 => Some(ScanPriority::Verify),
        _ => None,
    }
}

fn range_from_row(row: &rusqlite::Row<'_>) -> Result<ScanRange, Error> {
    let start = BlockHeight::from(row.get::<_, u32>(0)?);
    let end = BlockHeight::from(row.get::<_, u32>(1)?);
    let code = row.get::<_, i64>(2)?;
    let priority = parse_priority_code(code).ok_or_else(|| {
        Error::Serialization(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{code} is not a scan priority this build recognises"),
        ))
    })?;
    Ok(ScanRange::from_parts(start..end, priority))
}

/// Returns the ranges still to be scanned, most urgent first.
///
/// Ties break towards the chain tip, because a range nearer the tip is more
/// likely to contain the funds a user is waiting for.
pub(crate) fn suggest_scan_ranges(
    conn: &rusqlite::Connection,
    min_priority: ScanPriority,
) -> Result<Vec<ScanRange>, Error> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT block_range_start, block_range_end, priority
         FROM {CACHE_SCHEMA}.scan_queue
         WHERE priority >= :min_priority
         ORDER BY priority DESC, block_range_end DESC"
    ))?;
    let mut rows = stmt.query(named_params![":min_priority": priority_code(min_priority)])?;

    let mut result = Vec::new();
    while let Some(row) = rows.next()? {
        result.push(range_from_row(row)?);
    }
    Ok(result)
}

/// Inserts queue entries verbatim, skipping empty ranges.
fn insert_queue_entries<'a>(
    conn: &rusqlite::Transaction<'_>,
    entries: impl Iterator<Item = &'a ScanRange>,
) -> Result<(), Error> {
    let mut stmt = conn.prepare_cached(&format!(
        "INSERT INTO {CACHE_SCHEMA}.scan_queue (block_range_start, block_range_end, priority)
         VALUES (:start, :end, :priority)"
    ))?;
    for entry in entries {
        if !entry.is_empty() {
            stmt.execute(named_params![
                ":start": u32::from(entry.block_range().start),
                ":end": u32::from(entry.block_range().end),
                ":priority": priority_code(entry.priority()),
            ])?;
        }
    }
    Ok(())
}

/// Merges `entries` into the queue, replacing everything that overlaps or abuts
/// `query_range`.
///
/// The merge itself is the spanning tree's job; this reads the affected rows,
/// hands them and the new entries to the tree, deletes what it read, and writes
/// back what the tree produced. Doing it as read-merge-rewrite rather than as a
/// series of SQL updates is what keeps the queue gapless: the tree fills any
/// hole between two ranges with `Historic` coverage, so no region can silently
/// stop being scanned.
pub(crate) fn replace_queue_entries(
    conn: &rusqlite::Transaction<'_>,
    query_range: &Range<BlockHeight>,
    entries: impl Iterator<Item = ScanRange>,
    force_rescans: bool,
) -> Result<(), Error> {
    let (merged, replaced_ends) = {
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT block_range_start, block_range_end, priority
             FROM {CACHE_SCHEMA}.scan_queue
             -- Ranges that neither overlap nor abut the query range are left alone.
             WHERE NOT (block_range_start > :end OR :start > block_range_end)
             ORDER BY block_range_end"
        ))?;
        let mut rows = stmt.query(named_params![
            ":start": u32::from(query_range.start),
            ":end": u32::from(query_range.end),
        ])?;

        let mut merged: Option<SpanningTree> = None;
        let mut replaced_ends: Vec<u32> = Vec::new();
        while let Some(row) = rows.next()? {
            let entry = range_from_row(row)?;
            replaced_ends.push(u32::from(entry.block_range().end));
            merged = Some(match merged {
                Some(tree) => tree.insert(entry, force_rescans),
                None => SpanningTree::Leaf(entry),
            });
        }

        for entry in entries {
            merged = Some(match merged {
                Some(tree) => tree.insert(entry, force_rescans),
                None => SpanningTree::Leaf(entry),
            });
        }

        (merged, replaced_ends)
    };

    if let Some(tree) = merged {
        // `block_range_end` is unique, so it identifies the rows just read
        // without needing a rowid or a temporary table.
        let mut delete = conn.prepare_cached(&format!(
            "DELETE FROM {CACHE_SCHEMA}.scan_queue WHERE block_range_end = :end"
        ))?;
        for end in replaced_ends {
            delete.execute(named_params![":end": end])?;
        }

        insert_queue_entries(conn, tree.into_vec().iter())?;
    }

    Ok(())
}

/// Returns the highest block height at which a shard of `pool` ends.
fn tip_shard_end_height(
    conn: &rusqlite::Transaction<'_>,
    pool: PoolId,
) -> Result<Option<BlockHeight>, Error> {
    conn.query_row(
        &format!(
            "SELECT MAX(subtree_end_height) FROM {CACHE_SCHEMA}.tree_shards WHERE pool = :pool"
        ),
        named_params![":pool": pool.code()],
        |row| Ok(row.get::<_, Option<u32>>(0)?.map(BlockHeight::from)),
    )
    .map_err(Error::Query)
}

/// Returns the height at which `pool`'s shard containing `index - 1` ends.
fn shard_end(
    conn: &rusqlite::Transaction<'_>,
    pool: PoolId,
    index: u64,
) -> Result<Option<BlockHeight>, Error> {
    Ok(conn
        .query_row(
            &format!(
                "SELECT subtree_end_height FROM {CACHE_SCHEMA}.tree_shards
                 WHERE pool = :pool AND shard_index = :index"
            ),
            named_params![":pool": pool.code(), ":index": index],
            |row| Ok(row.get::<_, Option<u32>>(0)?.map(BlockHeight::from)),
        )
        .optional()?
        .flatten())
}

/// Widens `range` to cover the shards containing the given note positions.
///
/// This is not an optimisation. A note whose containing shard has not been
/// fully scanned has no witness, and is therefore silently unspendable: the
/// balance shows it, and every attempt to spend it fails. Extending the range
/// so those shards get scanned is what makes a discovered note usable.
fn extend_range(
    conn: &rusqlite::Transaction<'_>,
    range: &Range<BlockHeight>,
    required_shards: &BTreeSet<u64>,
    pool: PoolId,
    fallback_start: Option<BlockHeight>,
    birthday: Option<BlockHeight>,
) -> Result<Option<Range<BlockHeight>>, Error> {
    let Some((&min_index, &max_index)) = required_shards
        .iter()
        .min()
        .zip(required_shards.iter().max())
    else {
        // No notes of this pool were found, so nothing needs widening.
        return Ok(None);
    };

    let range_min = if min_index > 0 {
        shard_end(conn, pool, min_index - 1)?
    } else {
        fallback_start
    };
    // Never widen below the birthday: the wallet has no tree information there,
    // and scanning it would be work that can produce nothing.
    let range_min = range_min.map(|h| birthday.map_or(h, |b| max(b, h)));
    let range_max = shard_end(conn, pool, max_index)?.map(|end| end + 1);

    Ok(Some(Range {
        start: min(range.start, range_min.unwrap_or(range.start)),
        end: max(range.end, range_max.unwrap_or(range.end)),
    }))
}

/// Marks `range` scanned, widening the queue so that any notes found in it
/// become witnessable.
pub(crate) fn scan_complete<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    birthday: Option<BlockHeight>,
    range: Range<BlockHeight>,
    note_positions: &[(PoolId, Position)],
) -> Result<(), Error> {
    let mut required: [(PoolId, BTreeSet<u64>); 2] = [
        (PoolId::Orchard, BTreeSet::new()),
        (PoolId::Ironwood, BTreeSet::new()),
    ];
    for (pool, position) in note_positions {
        let shard = Address::above_position(Level::from(SHARD_HEIGHT), *position).index();
        for (id, set) in required.iter_mut() {
            if id == pool {
                set.insert(shard);
            }
        }
    }

    let mut extended: Option<Range<BlockHeight>> = None;
    for (pool, shards) in &required {
        let activation = match pool {
            PoolId::Orchard => zakura_wallet_core::Orchard::activation_height(params),
            PoolId::Ironwood => zakura_wallet_core::Ironwood::activation_height(params),
        };
        extended = extend_range(
            conn,
            extended.as_ref().unwrap_or(&range),
            shards,
            *pool,
            activation,
            birthday,
        )?
        .or(extended);
    }

    let query_range = extended.clone().unwrap_or_else(|| range.clone());
    let scanned = ScanRange::from_parts(range.clone(), ScanPriority::Scanned);

    // Empty ranges are omitted rather than inserted: an empty range acts as a
    // barrier that stops the spanning tree merging the scanned ranges on either
    // side of it, leaving the queue more fragmented every pass.
    let before = extended
        .as_ref()
        .map(|e| ScanRange::from_parts(e.start..range.start, ScanPriority::FoundNote))
        .filter(|r| !r.is_empty());
    let after = extended
        .map(|e| ScanRange::from_parts(range.end..e.end, ScanPriority::FoundNote))
        .filter(|r| !r.is_empty());

    replace_queue_entries(
        conn,
        &query_range,
        Some(scanned).into_iter().chain(before).chain(after),
        false,
    )
}

/// Reconciles the queue with a newly observed chain tip.
pub(crate) fn update_chain_tip<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    birthday: Option<BlockHeight>,
    max_scanned: Option<BlockHeight>,
    new_tip: BlockHeight,
    pruning_depth: u32,
) -> Result<(), Error> {
    // Below the first supported pool's activation there is nothing this wallet
    // could ever find, so there is nothing to queue.
    let floor = match zakura_wallet_core::Orchard::activation_height(params) {
        Some(h) if h <= new_tip => h,
        _ => return Ok(()),
    };

    // A tip below what we have already scanned means the caller has caught the
    // chain mid-reorg. Leave the queue alone: the existing ranges will either
    // fail to fetch or fail their continuity check, and the caller's rewind
    // handles it. Reacting here would mean guessing at a chain state that is
    // still changing.
    if matches!(max_scanned, Some(h) if new_tip < h) {
        return Ok(());
    }

    // `ScanRange` is end-exclusive.
    let chain_end = new_tip + 1;

    // The minimum across the pools, not the maximum. Ironwood is sparse after
    // NU6.3, so its last shard can end far below Orchard's; following the
    // higher tip would leave Ironwood's final shard incomplete and its notes
    // unwitnessable.
    //
    // A pool with no completed shard at all is *unknown*, not absent. Dropping
    // it and taking the minimum of what remains is the same mistake as taking
    // the maximum: it follows the other pool's tip and leaves this one's final
    // shard open. So an unknown pool collapses the answer to `None`, and the
    // planner falls back to a plain linear scan, which cannot strand a shard.
    let mut min_shard_tip = None;
    for pool in PoolId::ALL {
        match tip_shard_end_height(conn, pool)? {
            None => {
                min_shard_tip = None;
                break;
            }
            Some(height) => {
                min_shard_tip = Some(min_shard_tip.map_or(height, |seen| min(seen, height)));
            }
        }
    }

    // The fragment of the final shard that runs up to the tip.
    let tip_shard_entry = min_shard_tip.filter(|h| h < &chain_end).map(|h| {
        let start = birthday.filter(|b| b > &h).unwrap_or(h);
        ScanRange::from_parts(start..chain_end, ScanPriority::ChainTip)
    });

    let tip_entry = match max_scanned {
        None => match birthday {
            // No accounts yet, so nothing before the tip can matter.
            None => ScanRange::from_parts(floor..chain_end, ScanPriority::Ignored),
            Some(birthday) => ScanRange::from_parts(birthday..chain_end, ScanPriority::Historic),
        },
        Some(max_scanned) => {
            let min_unscanned = max_scanned + 1;
            if tip_shard_entry.is_none() {
                // Without shard metadata there is no tip shard to complete, so
                // this is a plain linear scan to the tip.
                ScanRange::from_parts(min_unscanned..chain_end, ScanPriority::Historic)
            } else {
                let stable_height = new_tip.saturating_sub(pruning_depth);
                if max_scanned > stable_height {
                    // Close to the tip already: just catch up. This overlaps the
                    // tip-shard range and coalesces with it.
                    ScanRange::from_parts(min_unscanned..chain_end, ScanPriority::ChainTip)
                } else {
                    // The scanned tip is old enough to be stable against *this*
                    // tip, but may not be against the tip it was scanned at, so
                    // re-verify a short window above it before trusting any
                    // `ChainTip` work. Capping at the stable height keeps the
                    // `Verify` range itself out of reorg range.
                    ScanRange::from_parts(
                        min_unscanned..min(stable_height + 1, min_unscanned + VERIFY_LOOKAHEAD),
                        ScanPriority::Verify,
                    )
                }
            }
        }
    };

    let query_range = match tip_shard_entry.as_ref() {
        Some(shard) => Range {
            start: min(shard.block_range().start, tip_entry.block_range().start),
            end: max(shard.block_range().end, tip_entry.block_range().end),
        },
        None => tip_entry.block_range().clone(),
    };

    replace_queue_entries(
        conn,
        &query_range,
        tip_shard_entry.into_iter().chain(Some(tip_entry)),
        false,
    )
}
