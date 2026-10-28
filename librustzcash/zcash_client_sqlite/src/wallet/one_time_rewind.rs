//! Repairs private receiver obligations in every feature configuration.
use crate::{AccountUuid, error::SqliteClientError};
use rusqlite::params;
use zcash_protocol::consensus::BlockHeight;

/// Advances the wallet-wide one-time work sequence in the same transaction as a new
/// recovery obligation, so an app comparing `WalletDb::one_time_new_work` with the value
/// its last round saw knows a round has work. It never goes back.
pub(crate) fn new_work(conn: &rusqlite::Connection) -> Result<(), SqliteClientError> {
    conn.execute(
        "UPDATE ironwood_one_time_work SET sequence = sequence + 1",
        [],
    )?;
    Ok(())
}

/// SQL assignments that drop a lookup's position inside a captured inventory.
pub(crate) const CURSOR_RESET: &str =
    "inventory = NULL, shard = NULL, segment = NULL, last_record = NULL";

/// Invalidates callbacks and fork-dependent progress before ordinary notes are unmined.
/// History settled above the floor is invalidated (reason bit 4, see
/// `restore::queue::INVALIDATED`), so a receiver reserved on it waits for the re-check.
/// Completed unaffected addresses stay closed to automatic direct catch-up. Enrolled receive
/// indexes keep their place there even if the window shrinks (see `queue::automatic_end`),
/// so the next catch-up rechecks their invalidated history.
pub(crate) fn truncate(
    conn: &rusqlite::Transaction<'_>,
    height: BlockHeight,
) -> Result<(), SqliteClientError> {
    let floor = u32::from(height);
    // Anything rolled back below becomes work again: displaced funding or receipts, lookup
    // progress, filter coverage, payment candidates or their witnesses, or restore and
    // manual cursors above the floor. A cursor an earlier rewind already reset keeps its
    // captured height, so only one still past its start counts.
    let rolled_back: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_keys k WHERE k.prebirthday_height > ?1
                OR k.funding_height > ?1 OR k.covered_height > ?1
                OR EXISTS(SELECT 1 FROM ironwood_received_notes n
                    JOIN transactions t ON t.id_tx = n.transaction_id
                    WHERE n.one_time_key_id = k.id AND t.mined_height > ?1))
            OR EXISTS(SELECT 1 FROM ironwood_one_time_lookups
                WHERE done_height > ?1 OR checked_height > ?1)
            OR EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery
                WHERE height > ?1 OR witness_height > ?1)
            OR EXISTS(SELECT 1 FROM ironwood_one_time_recovery WHERE filter_height > ?1
                OR (restore_done = 0 AND restore_height > ?1
                    AND (restore_next != X'0000000000000000' OR restore_gap != 0))
                OR (manual_end IS NOT NULL AND manual_height > ?1
                    AND (manual_purpose != 0 OR manual_next != X'0000000000000000')))",
        [floor],
        |r| r.get(0),
    )?;
    if rolled_back {
        new_work(conn)?;
    }
    // A refund memo above the fork is accepted again where the replacement chain mines it.
    conn.execute(
        "INSERT OR IGNORE INTO ironwood_one_time_pending_memos (note_id)
         SELECT n.id FROM ironwood_received_notes n
         JOIN transactions t ON t.id_tx = n.transaction_id
         WHERE t.mined_height > ?1 AND n.recipient_key_scope = 1
           AND n.one_time_key_id IS NULL AND substr(n.memo, 1, 5) = X'FF5A535750'",
        [floor],
    )?;
    conn.execute("INSERT INTO ironwood_one_time_lookups(one_time_key_id, target_height, reasons, start_height)
        SELECT k.id, COALESCE((SELECT MAX(height) FROM blocks), ?1), 5, ?1 + 1 FROM ironwood_one_time_keys k
        WHERE k.prebirthday_height > ?1 OR EXISTS(SELECT 1 FROM ironwood_received_notes n
            JOIN transactions t ON t.id_tx = n.transaction_id WHERE n.one_time_key_id = k.id AND t.mined_height > ?1)
        ON CONFLICT(one_time_key_id) DO UPDATE SET
            target_height = MAX(COALESCE(target_height, 0), excluded.target_height), reasons = reasons | 5,
            start_height = CASE WHEN target_height IS NULL THEN excluded.start_height
                ELSE MIN(start_height, excluded.start_height) END",
        [floor])?;
    conn.execute("UPDATE ironwood_one_time_recovery SET generation = generation + 1,
        filter_height = CASE WHEN filter_height > ?1 THEN ?2 ELSE filter_height END,
        filter_hash = CASE WHEN filter_height > ?1 THEN (SELECT hash FROM blocks WHERE height = ?2) ELSE filter_hash END,
        restore_next = CASE WHEN restore_done = 0 AND restore_height > ?1 THEN X'0000000000000000' ELSE restore_next END,
        restore_gap = CASE WHEN restore_done = 0 AND restore_height > ?1 THEN 0 ELSE restore_gap END,
        manual_purpose = CASE WHEN manual_end IS NOT NULL AND manual_height > ?1 THEN 0 ELSE manual_purpose END,
        manual_next = CASE WHEN manual_end IS NOT NULL AND manual_height > ?1 THEN X'0000000000000000' ELSE manual_next END",
        params![floor, conn.query_row("SELECT MAX(height) FROM blocks WHERE height <= ?1", [floor], |r| r.get::<_, Option<u32>>(0))?])?;
    // Coverage and cursors above the fork are void; coverage below it still holds. A request
    // that began after such coverage, including a settled one `queue_invalidated` revives,
    // needs the invalidated interval again.
    conn.execute(
        &format!(
            "UPDATE ironwood_one_time_lookups SET {CURSOR_RESET}, read_complete = 0, attempts = 0,
            next_attempt_at = 0,
            reasons = CASE WHEN done_height > ?1 OR checked_height > ?1 THEN reasons | 4
                ELSE reasons END,
            start_height = CASE WHEN start_height > ?1 + 1 THEN ?1 + 1 ELSE start_height END,
            checked_height = CASE WHEN checked_height > ?1 THEN ?1 ELSE checked_height END,
            done_from = CASE WHEN done_height > ?1 AND NOT done_from <= ?1 THEN NULL ELSE done_from END,
            done_height = CASE WHEN done_height > ?1
                THEN CASE WHEN done_from <= ?1 THEN ?1 ELSE NULL END ELSE done_height END
            WHERE done_height > ?1 OR target_height > ?1 OR checked_height > ?1
                OR start_height > ?1 + 1 OR inventory IS NOT NULL"
        ),
        [floor],
    )?;
    conn.execute(
        "UPDATE ironwood_one_time_keys SET prebirthday_height = NULL WHERE prebirthday_height > ?1",
        [floor],
    )?;
    // Filter coverage above the fork read another chain's blocks. Funding above it is no
    // longer canonical: its memo registers the funding height again where the replacement
    // chain mines it, so the refund window follows the moved funding. The key stays
    // registered, so its index is never allocated again.
    conn.execute(
        "UPDATE ironwood_one_time_keys SET covered_height = ?1 WHERE covered_height > ?1",
        [floor],
    )?;
    conn.execute(
        "UPDATE ironwood_one_time_keys SET funding_height = NULL WHERE funding_height > ?1",
        [floor],
    )?;
    // A private receipt's position came from the directory, not a rescan that would replace
    // it, so each one loses its placement until its own repair restores it (see
    // `restore::queue::UNPLACED`).
    conn.execute(
        "UPDATE ironwood_received_notes SET commitment_tree_position = NULL
        WHERE one_time_key_id IS NOT NULL AND transaction_id IN
            (SELECT id_tx FROM transactions WHERE mined_height > ?1)",
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
    // Blocks above the floor are about to go, and filters resume above it.
    queue_invalidated(conn, Some(floor))
}

/// Gives every invalidated lookup (reason bit 4, see `restore::queue::INVALIDATED`) of an
/// automatically monitored key a runnable automatic target through its account's frontier,
/// capped at `cap`, so a reservation hold never stands without work that can lift it. Every
/// site that sets the bit calls this. A manual-only key keeps the bit alone, since nothing
/// reserves it.
pub(crate) fn queue_invalidated(
    conn: &rusqlite::Connection,
    cap: Option<u32>,
) -> Result<(), SqliteClientError> {
    conn.execute(
        "UPDATE ironwood_one_time_lookups SET reasons = reasons | 1, read_complete = 0,
            -- A new request starts from the old one, continuing coverage that reached it.
            checked_height = CASE WHEN target_height IS NOT NULL THEN checked_height
                WHEN done_from IS NOT NULL AND done_from <= start_height THEN done_height
                ELSE NULL END,
            target_height = MAX(COALESCE(target_height, 0), MIN(COALESCE(?1, 4294967295),
                (SELECT MAX(COALESCE(r.filter_height, 0), COALESCE((SELECT MAX(height) FROM blocks), 0))
                 FROM ironwood_one_time_keys k
                 JOIN ironwood_one_time_recovery r ON r.account_id = k.account_id
                 WHERE k.id = ironwood_one_time_lookups.one_time_key_id)))
        WHERE reasons & 4 != 0 AND (target_height IS NULL OR reasons & 3 = 0)
          AND one_time_key_id IN (SELECT k.id FROM ironwood_one_time_keys k
              WHERE (k.purpose = 1 AND k.key_index < (SELECT r.receive_end
                  FROM ironwood_one_time_recovery r WHERE r.account_id = k.account_id))
                 OR k.funding_height IS NOT NULL)",
        [cap],
    )?;
    Ok(())
}

/// Lowering a birthday rechecks known histories, including excluded payments, even while
/// disabled. Filter coverage restarts from activation, and the account is no longer fresh.
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
        restore_height = NULL, filter_height = NULL, filter_hash = NULL, fresh = 0
        WHERE account_id = ?1",
        [owner],
    )?;
    new_work(conn)?;
    conn.execute(
        "UPDATE ironwood_one_time_keys SET covered_height = NULL WHERE account_id = ?1",
        [owner],
    )?;
    conn.execute("INSERT INTO ironwood_one_time_lookups(one_time_key_id, target_height, reasons)
        SELECT id, COALESCE((SELECT MAX(height) FROM blocks), 0), 5 FROM ironwood_one_time_keys
        WHERE account_id = ?1 AND (purpose = 1 OR funding_height IS NOT NULL)
        ON CONFLICT(one_time_key_id) DO UPDATE SET target_height = MAX(COALESCE(target_height, 0), excluded.target_height),
            reasons = reasons | 5, start_height = 0, checked_height = NULL, inventory = NULL, shard = NULL,
            segment = NULL, last_record = NULL, done_height = NULL, done_from = NULL, read_complete = 0,
            attempts = 0, next_attempt_at = 0", [owner])?;
    conn.execute(
        "DELETE FROM ironwood_one_time_payment_recovery WHERE one_time_key_id IN
        (SELECT id FROM ironwood_one_time_keys WHERE account_id = ?1)",
        [owner],
    )?;
    queue_invalidated(conn, None)
}
