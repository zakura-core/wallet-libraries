//! Temporary spend evidence for notes that a restore sweep finds after ordinary scanning.
use rusqlite::{Connection, params};
use zcash_client_backend::data_api::transparent_ledger::ChainPoint;
use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters};

use super::{account_key, corrupt, queue_rescan, recovery, restore_start};
use crate::{AccountUuid, error::SqliteClientError, wallet};

/// Retains `account`'s Ironwood spend evidence from its birthday, or Ironwood
/// activation if later, until [`finish_nullifier_recovery`] releases it.
pub(super) fn retain_spend_history<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
) -> Result<(), SqliteClientError> {
    let (id, _) = account_key(conn, params, account)?;
    conn.execute(
        "INSERT OR IGNORE INTO ironwood_dynamic_spend_retention
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

/// Implements `DynamicIvkWrite::finish_dynamic_nullifier_recovery` with `lookahead`
/// incoming keys.
pub(crate) fn finish_nullifier_recovery<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    through: ChainPoint,
    lookahead: u32,
    now: i64,
) -> Result<bool, SqliteClientError> {
    let (id, _) = account_key(conn, params, account)?;
    let enabled: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_dynamic_spend_retention WHERE account_id = ?1)",
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
    recovery::maintain_restore_discovery(conn, params, account, lookahead, now)?;
    if recovery::refund_memos_pending(conn, account)? {
        return Ok(false);
    }
    // Pending sweeps keep evidence from their earliest possible payment, and a queued
    // candidate from its height. Scanned keys never need it.
    let pending: Option<u32> = conn.query_row(
        "SELECT MIN(h) FROM (
            SELECT k.scan_from AS h FROM ironwood_dynamic_sweeps s
                JOIN ironwood_receiving_keys k ON k.id = s.receiving_key_id
                WHERE k.account_id = ?1 AND s.done_height IS NULL
            UNION ALL SELECT p.height FROM ironwood_dynamic_payment_recovery p
                JOIN ironwood_receiving_keys k ON k.id = p.receiving_key_id
                WHERE k.account_id = ?1)",
        [id.0],
        |r| r.get(0),
    )?;
    let next = pending.unwrap_or(u32::from(through.height).saturating_add(1));
    // Raising the floor ends any replay below it.
    conn.execute(
        "UPDATE ironwood_dynamic_spend_retention SET nullifier_retention_height = ?2,
            replay_through = CASE WHEN ?2 > nullifier_retention_height
                THEN NULL ELSE replay_through END
         WHERE account_id = ?1",
        params![id.0, next],
    )?;
    let prune_below = through.height.saturating_sub(crate::PRUNING_DEPTH);
    wallet::prune_nullifier_map(conn, prune_below)?;
    Ok(next > u32::from(through.height))
}

/// Repairs missing spend evidence by replaying the account's recovery interval, which
/// makes no nullifier query.
pub(super) fn queue_spend_history<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    through: BlockHeight,
) -> Result<(), SqliteClientError> {
    let (id, _) = account_key(conn, params, account)?;
    let start = restore_start(conn, params, id)?;
    let end = u32::from(through)
        .checked_add(1)
        .ok_or_else(|| corrupt("spend recovery height overflow"))?;
    if start >= BlockHeight::from(end) {
        return Err(corrupt("empty spend recovery interval"));
    }
    conn.execute(
        "INSERT INTO ironwood_dynamic_spend_retention (account_id, nullifier_retention_height)
         VALUES (?1, ?2) ON CONFLICT (account_id) DO UPDATE SET
             nullifier_retention_height =
                 MIN(nullifier_retention_height, excluded.nullifier_retention_height)",
        params![id.0, u32::from(start)],
    )?;
    let previous: Option<u32> = conn.query_row(
        "SELECT replay_through FROM ironwood_dynamic_spend_retention WHERE account_id = ?1",
        [id.0],
        |r| r.get(0),
    )?;
    if previous.is_some_and(|h| h >= u32::from(through)) {
        return Ok(());
    }
    let from = previous
        .map(|h| BlockHeight::from(h.saturating_add(1)))
        .unwrap_or(start)
        .max(start);
    conn.execute(
        "UPDATE ironwood_dynamic_spend_retention SET replay_through = ?2 WHERE account_id = ?1",
        params![id.0, u32::from(through)],
    )?;
    queue_rescan(conn, from..BlockHeight::from(end))
}
