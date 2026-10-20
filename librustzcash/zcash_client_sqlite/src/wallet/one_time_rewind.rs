//! Repairs private receiver obligations in every feature configuration.
use crate::{AccountUuid, error::SqliteClientError};
use rusqlite::params;
use zcash_protocol::consensus::BlockHeight;

/// Invalidates callbacks and fork-dependent progress before ordinary notes are unmined.
/// Completed unaffected addresses stay closed to automatic direct catch-up. Enrolled receive
/// indexes keep their place there even if the window shrinks (see `queue::automatic_end`),
/// so the next catch-up rechecks their invalidated history.
pub(crate) fn truncate(
    conn: &rusqlite::Transaction<'_>,
    height: BlockHeight,
) -> Result<(), SqliteClientError> {
    let floor = u32::from(height);
    conn.execute("INSERT INTO ironwood_one_time_lookups(one_time_key_id, target_height, reasons)
        SELECT k.id, COALESCE((SELECT MAX(height) FROM blocks), ?1), 1 FROM ironwood_one_time_keys k
        WHERE k.prebirthday_height > ?1 OR EXISTS(SELECT 1 FROM ironwood_received_notes n
            JOIN transactions t ON t.id_tx = n.transaction_id WHERE n.one_time_key_id = k.id AND t.mined_height > ?1)
        ON CONFLICT(one_time_key_id) DO UPDATE SET
            target_height = MAX(COALESCE(target_height, 0), excluded.target_height), reasons = reasons | 1",
        [floor])?;
    conn.execute("UPDATE ironwood_one_time_recovery SET generation = generation + 1,
        filter_height = CASE WHEN filter_height > ?1 THEN ?2 ELSE filter_height END,
        filter_hash = CASE WHEN filter_height > ?1 THEN (SELECT hash FROM blocks WHERE height = ?2) ELSE filter_hash END,
        restore_next = CASE WHEN restore_done = 0 AND restore_height > ?1 THEN X'0000000000000000' ELSE restore_next END,
        restore_gap = CASE WHEN restore_done = 0 AND restore_height > ?1 THEN 0 ELSE restore_gap END,
        manual_purpose = CASE WHEN manual_end IS NOT NULL AND manual_height > ?1 THEN 0 ELSE manual_purpose END,
        manual_next = CASE WHEN manual_end IS NOT NULL AND manual_height > ?1 THEN X'0000000000000000' ELSE manual_next END",
        params![floor, conn.query_row("SELECT MAX(height) FROM blocks WHERE height <= ?1", [floor], |r| r.get::<_, Option<u32>>(0))?])?;
    conn.execute(
        "UPDATE ironwood_one_time_lookups SET last_record = NULL, done_height = NULL,
        read_complete = 0, attempts = 0, next_attempt_at = 0
        WHERE done_height > ?1 OR target_height > ?1",
        [floor],
    )?;
    conn.execute(
        "UPDATE ironwood_one_time_keys SET prebirthday_height = NULL WHERE prebirthday_height > ?1",
        [floor],
    )?;
    conn.execute(
        "DELETE FROM ironwood_one_time_payment_recovery WHERE height > ?1",
        [floor],
    )?;
    conn.execute(
        "UPDATE ironwood_one_time_payment_recovery SET witness = NULL,
        witness_height = NULL, witness_hash = NULL, witness_size = NULL WHERE witness_height > ?1",
        [floor],
    )?;
    conn.execute(
        "DELETE FROM ironwood_spend_journal WHERE block_height > ?1",
        [floor],
    )?;
    conn.execute(
        "DELETE FROM ironwood_journal_coverage WHERE start_height > ?1",
        [floor],
    )?;
    conn.execute(
        "UPDATE ironwood_journal_coverage SET end_height = ?1 + 1 WHERE end_height > ?1 + 1",
        [floor],
    )?;
    Ok(())
}

/// Lowering a birthday rechecks known histories, including excluded payments, even while disabled.
pub(crate) fn reopen_discovery(
    conn: &rusqlite::Transaction<'_>,
    account: AccountUuid,
) -> Result<(), SqliteClientError> {
    let owner: i64 = conn.query_row(
        "SELECT id FROM accounts WHERE uuid = ?1",
        [account.0],
        |r| r.get(0),
    )?;
    conn.execute(
        "UPDATE ironwood_one_time_recovery SET generation = generation + 1,
        restore_next = X'0000000000000000', restore_gap = 0, restore_done = 0,
        restore_height = NULL, filter_height = NULL, filter_hash = NULL WHERE account_id = ?1",
        [owner],
    )?;
    conn.execute("INSERT INTO ironwood_one_time_lookups(one_time_key_id, target_height, reasons)
        SELECT id, COALESCE((SELECT MAX(height) FROM blocks), 0), 1 FROM ironwood_one_time_keys
        WHERE account_id = ?1 AND (purpose = 1 OR funding_height IS NOT NULL)
        ON CONFLICT(one_time_key_id) DO UPDATE SET target_height = MAX(COALESCE(target_height, 0), excluded.target_height),
            reasons = reasons | 1, last_record = NULL, done_height = NULL, read_complete = 0,
            attempts = 0, next_attempt_at = 0", [owner])?;
    conn.execute(
        "DELETE FROM ironwood_one_time_payment_recovery WHERE one_time_key_id IN
        (SELECT id FROM ironwood_one_time_keys WHERE account_id = ?1)",
        [owner],
    )?;
    Ok(())
}
