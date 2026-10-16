//! Temporary spend evidence for notes that a restore sweep finds after ordinary scanning.
use std::ops::Range;

use rusqlite::{Connection, OptionalExtension, params};
use zcash_client_backend::data_api::{scanning::ScanPriority, transparent_ledger::ChainPoint};
use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters};

use super::recovery;
use crate::wallet::one_time_ivk::{account_key, corrupt, queue_rescan, restore_start};
use crate::{AccountUuid, error::SqliteClientError, wallet, wallet::scanning::priority_code};

/// The most retained Ironwood nullifiers one release frees. Freeing more at once makes the
/// prune, in the release and in the next scan batch, hold the wallet's write lock for
/// seconds; later releases continue where this one stopped. Counted in nullifiers rather
/// than blocks, because Ironwood actions per block vary by an order of magnitude.
const RELEASE_NULLIFIERS: u32 = 50_000;

/// Retains `account`'s Ironwood spend evidence from its birthday, or Ironwood
/// activation if later, until [`finish_nullifier_recovery`] releases it.
pub(in crate::wallet::one_time_ivk) fn retain_spend_history<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
) -> Result<(), SqliteClientError> {
    let (id, _) = account_key(conn, params, account)?;
    conn.execute(
        "INSERT OR IGNORE INTO ironwood_one_time_spend_retention
            (account_id, nullifier_retention_height)
         SELECT id, MAX(birthday_height, ?2) FROM accounts WHERE id = ?1",
        params![
            id.0,
            params
                .activation_height(NetworkUpgrade::Nu6_3)
                .map(u32::from)
                .unwrap_or(0)
        ],
    )?;
    Ok(())
}

/// Implements `OneTimeIvkRestoreWrite::finish_one_time_nullifier_recovery`, freeing at
/// most [`RELEASE_NULLIFIERS`] nullifiers per call.
pub(crate) fn finish_nullifier_recovery<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    through: ChainPoint,
    now: i64,
) -> Result<bool, SqliteClientError> {
    release_spend_history(conn, params, account, through, now, RELEASE_NULLIFIERS)
}

/// [`finish_nullifier_recovery`], freeing at most `limit` retained nullifiers.
pub(in crate::wallet::one_time_ivk) fn release_spend_history<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    through: ChainPoint,
    now: i64,
    limit: u32,
) -> Result<bool, SqliteClientError> {
    let (id, _) = account_key(conn, params, account)?;
    let enabled: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_spend_retention WHERE account_id = ?1)",
        [id.0],
        |r| r.get(0),
    )?;
    if !enabled
        || wallet::fully_scanned_height(conn)? != Some(through.height)
        || wallet::chain_tip_height(conn)? != Some(through.height)
        || wallet::get_block_hash(conn, through.height)? != Some(through.hash)
    {
        return Ok(false);
    }
    recovery::maintain_restore_discovery(conn, params, account, now)?;
    if recovery::refund_memos_pending(conn, account)? {
        return Ok(false);
    }
    // Pending sweeps keep evidence from their earliest possible payment, and a queued
    // candidate from its height. A later sweep of a closed key whose evidence is released
    // waits for a replay instead (see `queue_spend_history`).
    let pending: Option<u32> = conn.query_row(
        "SELECT MIN(h) FROM (
            SELECT k.scan_from AS h FROM ironwood_one_time_sweeps s
                JOIN ironwood_one_time_keys k ON k.id = s.one_time_key_id
                WHERE k.account_id = ?1 AND s.done_height IS NULL
            UNION ALL SELECT p.height FROM ironwood_one_time_payment_recovery p
                JOIN ironwood_one_time_keys k ON k.id = p.one_time_key_id
                WHERE k.account_id = ?1)",
        [id.0],
        |r| r.get(0),
    )?;
    let next = pending.unwrap_or(u32::from(through.height).saturating_add(1));
    let floor: u32 = conn.query_row(
        "SELECT nullifier_retention_height FROM ironwood_one_time_spend_retention
         WHERE account_id = ?1",
        [id.0],
        |r| r.get(0),
    )?;
    // At most `limit` rows of any pool lie below the bound, which the
    // locator index answers without reading rows; below the pruning height they are all
    // Ironwood. A release always passes at least one block.
    let next = if next > floor {
        let bound: Option<u32> = conn
            .query_row(
                "SELECT block_height FROM nullifier_map WHERE block_height >= ?1
                 ORDER BY block_height LIMIT 1 OFFSET ?2",
                params![floor, limit],
                |r| r.get(0),
            )
            .optional()?;
        bound.map_or(next, |bound| next.min(bound.max(floor + 1)))
    } else {
        next
    };
    // Raising the floor ends any replay below it.
    conn.execute(
        "UPDATE ironwood_one_time_spend_retention SET nullifier_retention_height = ?2,
            replay_through = CASE WHEN ?2 > nullifier_retention_height
                THEN NULL ELSE replay_through END
         WHERE account_id = ?1",
        params![id.0, next],
    )?;
    let prune_below = through.height.saturating_sub(crate::PRUNING_DEPTH);
    wallet::prune_nullifier_map(conn, prune_below)?;
    Ok(next > u32::from(through.height))
}

/// Repairs missing spend evidence for a payment mined at `from` by rescanning the blocks
/// from there through `through` that no retained nullifier scan covers and no queued scan
/// will, which makes no nullifier query. Starting at the payment rather than the
/// account's birthday keeps the replay, and the time no note is spendable while it is
/// queued, to the blocks the spend check reads (see `payments::spend_status`).
pub(in crate::wallet::one_time_ivk) fn queue_spend_history<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    from: BlockHeight,
    through: BlockHeight,
) -> Result<(), SqliteClientError> {
    let (id, _) = account_key(conn, params, account)?;
    let from = from.max(restore_start(conn, params, id)?);
    let end = BlockHeight::from(
        u32::from(through)
            .checked_add(1)
            .ok_or_else(|| corrupt("spend recovery height overflow"))?,
    );
    if from >= end {
        return Err(corrupt("empty spend recovery interval"));
    }
    conn.execute(
        "INSERT INTO ironwood_one_time_spend_retention
            (account_id, nullifier_retention_height, replay_through)
         VALUES (?1, ?2, ?3) ON CONFLICT (account_id) DO UPDATE SET
             nullifier_retention_height =
                 MIN(nullifier_retention_height, excluded.nullifier_retention_height),
             replay_through = MAX(COALESCE(replay_through, 0), excluded.replay_through)",
        params![id.0, u32::from(from), u32::from(through)],
    )?;
    for range in unreplayed(conn, from..end)? {
        queue_rescan(conn, range)?;
    }
    Ok(())
}

/// The runs of `range` whose blocks have no Ironwood nullifier scan mark and no
/// unscanned scan queue entry, in ascending order.
fn unreplayed(
    conn: &Connection,
    range: Range<BlockHeight>,
) -> Result<Vec<Range<BlockHeight>>, SqliteClientError> {
    let (start, end) = (u32::from(range.start), u32::from(range.end));
    let mut covered: Vec<(u32, u32)> = conn
        .prepare(
            "SELECT height, height + 1 FROM ironwood_nullifier_scan_blocks
             WHERE height >= ?1 AND height < ?2
             UNION ALL
             SELECT MAX(block_range_start, ?1), MIN(block_range_end, ?2) FROM scan_queue
             WHERE priority > ?3 AND block_range_end > ?1 AND block_range_start < ?2",
        )?
        .query_map(
            params![start, end, priority_code(&ScanPriority::Scanned)],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?
        .collect::<Result<_, _>>()?;
    covered.sort_unstable();
    let mut missing = Vec::new();
    let mut next = start;
    for (from, to) in covered {
        if from > next {
            missing.push(BlockHeight::from(next)..BlockHeight::from(from));
        }
        next = next.max(to);
    }
    if next < end {
        missing.push(BlockHeight::from(next)..BlockHeight::from(end));
    }
    Ok(missing)
}
