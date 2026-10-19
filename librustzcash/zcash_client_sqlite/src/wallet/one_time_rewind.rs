//! One-time IVK state that a rewind repairs in every build. The tables exist in every
//! build, and an `orchard` build may reopen a wallet that a build without it rewound, so
//! the repair cannot wait for `orchard`. That includes the receiver-set bookkeeping of
//! directory coverage (see `one_time_ivk::coverage`), which the repair extends.

use rusqlite::{Connection, OptionalExtension, params};
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_protocol::consensus::BlockHeight;

use crate::{AccountUuid, error::SqliteClientError};

/// `ironwood_one_time_publications.state` until the scan stores the publication's last block.
pub(crate) const PROVISIONAL: u8 = 0;
/// `ironwood_one_time_publications.state` once that block matched.
pub(crate) const ACCEPTED: u8 = 1;
/// `ironwood_one_time_publications.state` once that block did not match.
pub(crate) const REJECTED: u8 = 2;

/// Repairs one-time IVK state for a rewind that rescans every block above `height`.
/// Open keys start at the first rescanned block at the latest, which
/// `wallet::truncate_to_height_internal` sets after this in every build. A closed key that
/// scanned reopens if the rewind leaves one of its receipts short of the confirmations
/// closing requires (see `WalletDb::close_finished_one_time_keys`), and closes again once
/// that receipt is confirmed again. A key closed without scanning, whose note a lookup
/// found, reopens from its first note above `height`, so the rescan finds the note again,
/// and closes the same way.
///
/// Discovery is repaired too, since blocks above `height` may be replaced: a publication
/// ending there is judged again, a late candidate there becomes a hint again (its block is
/// rescanned), a path anchored there is requested again, and a cursor that passed a record
/// there restarts, since the replacement chain may put a record before it. A lookup done
/// above `height`, even one that found nothing, is due again from its cursor.
///
/// Directory coverage keeps what the shared chain below `height` still supports: a
/// frontier above it moves down to it, or is dropped with every obligation if the wallet
/// holds no block there, and an obligation owes and bridges no further. A snapshot pinned
/// above it is unpinned. Every receiver-set generation and every lookup walk in flight
/// above it is fenced out. Registered keys, windows and issuance markers stay.
pub(crate) fn truncate(
    conn: &rusqlite::Transaction<'_>,
    height: BlockHeight,
) -> Result<(), SqliteClientError> {
    let confirmed_below = u32::from(height)
        .saturating_add(1)
        .saturating_sub(ConfirmationsPolicy::default().untrusted().get());
    conn.execute(
        "UPDATE ironwood_one_time_keys SET closed_at = NULL
         WHERE closed_at IS NOT NULL AND active_from IS NOT NULL AND id IN (
             SELECT n.one_time_key_id FROM ironwood_received_notes n
             JOIN transactions t ON t.id_tx = n.transaction_id
             WHERE t.mined_height > ?1)",
        [confirmed_below],
    )?;
    let note_above = "SELECT MIN(t.mined_height) FROM ironwood_received_notes n
         JOIN transactions t ON t.id_tx = n.transaction_id
         WHERE n.one_time_key_id = ironwood_one_time_keys.id AND t.mined_height > ?1";
    conn.execute(
        &format!(
            "UPDATE ironwood_one_time_keys SET closed_at = NULL, active_from = ({note_above})
             WHERE closed_at IS NOT NULL AND active_from IS NULL
               AND ({note_above}) IS NOT NULL"
        ),
        [u32::from(height)],
    )?;
    let floor = u32::from(height);
    // A publication judged either way against a block the rewind replaces is judged again,
    // so one rejected on an abandoned fork can match the fork that replaces it.
    conn.execute(
        "UPDATE ironwood_one_time_publications SET state = ?2
         WHERE state IN (?3, ?4) AND height > ?1",
        params![floor, PROVISIONAL, ACCEPTED, REJECTED],
    )?;
    conn.execute(
        "UPDATE ironwood_one_time_payment_recovery
         SET scan_hint = 1, witness = NULL, witness_height = NULL, witness_hash = NULL
         WHERE height > ?1",
        [floor],
    )?;
    conn.execute(
        "UPDATE ironwood_one_time_payment_recovery
         SET witness = NULL, witness_height = NULL, witness_hash = NULL
         WHERE witness_height > ?1",
        [floor],
    )?;
    restart_cursor(
        conn,
        "SELECT one_time_key_id FROM ironwood_one_time_lookups WHERE last_height > ?1",
        floor,
    )?;
    conn.execute(
        "UPDATE ironwood_one_time_lookups
         SET cutoff_height = MAX(COALESCE(cutoff_height, 0), done_height), done_height = NULL
         WHERE done_height > ?1",
        [floor],
    )?;
    conn.execute(
        &format!("UPDATE ironwood_one_time_lookups SET {FENCE} WHERE dispatched_cutoff > ?1"),
        [floor],
    )?;
    conn.execute(
        "UPDATE ironwood_one_time_recovery SET
             frontier_height = CASE WHEN EXISTS(SELECT 1 FROM blocks WHERE height = ?1)
                 THEN ?1 END,
             frontier_hash = (SELECT hash FROM blocks WHERE height = ?1),
             tested_generation = CASE WHEN EXISTS(SELECT 1 FROM blocks WHERE height = ?1)
                 THEN tested_generation END
         WHERE frontier_height > ?1",
        [floor],
    )?;
    conn.execute(
        "UPDATE ironwood_one_time_recovery
         SET bootstrap_height = NULL, bootstrap_hash = NULL, bootstrap_digest = NULL
         WHERE bootstrap_height > ?1",
        [floor],
    )?;
    conn.execute(
        "UPDATE ironwood_one_time_obligations
         SET cutoff_height = NULL, cutoff_hash = NULL, cutoff_digest = NULL,
             bridged_height = NULL
         WHERE cutoff_height > ?1",
        [floor],
    )?;
    conn.execute(
        "UPDATE ironwood_one_time_obligations
         SET through_height = MIN(through_height, ?1), bridged_height = MIN(bridged_height, ?1)",
        [floor],
    )?;
    conn.execute(
        "DELETE FROM ironwood_one_time_obligations
         WHERE bridged_height >= through_height OR through_height < lower_height
            OR account_id IN (SELECT account_id FROM ironwood_one_time_recovery
                WHERE frontier_height IS NULL)",
        [],
    )?;
    conn.execute(
        "UPDATE ironwood_one_time_recovery SET generation = generation + 1",
        [],
    )?;
    // The spend journal's entries and coverage above the floor may describe replaced blocks.
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

/// Reopens `account`'s discovery after a rewind lowered its birthday: the next pass checks
/// every key again, and every lookup restarts from page zero due through the target it
/// had, since outcomes outside the old range no longer hold. The account is no longer
/// treated as fresh. Its whole receiver set owes the history from the new birthday through
/// its frontier.
pub(crate) fn reopen_discovery(
    conn: &rusqlite::Transaction<'_>,
    account: AccountUuid,
) -> Result<(), SqliteClientError> {
    let id: i64 = conn.query_row(
        "SELECT id FROM accounts WHERE uuid = ?1",
        [account.0],
        |r| r.get(0),
    )?;
    let windows: Option<(u64, u64)> = conn
        .query_row(
            "SELECT refund_end, receive_end FROM ironwood_one_time_recovery
             WHERE account_id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (refund_end, receive_end) = windows.unwrap_or_default();
    for (purpose, end) in [(0, refund_end), (1, receive_end)] {
        if end > 0 {
            join_set(conn, id, Owed::Window(purpose, 0, end))?;
        }
        let outside: Vec<i64> = conn
            .prepare(
                "SELECT id FROM ironwood_one_time_keys
                 WHERE account_id = ?1 AND purpose = ?2 AND key_index >= ?3",
            )?
            .query_map(params![id, purpose, end.to_be_bytes()], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        for key in outside {
            join_set(conn, id, Owed::Key(key, purpose))?;
        }
    }
    let owner = "(SELECT id FROM accounts WHERE uuid = ?1)";
    conn.execute(
        &format!("DELETE FROM ironwood_one_time_discovery WHERE account_id = {owner}"),
        [account.0],
    )?;
    conn.execute(
        &format!("DELETE FROM ironwood_one_time_fresh_accounts WHERE account_id = {owner}"),
        [account.0],
    )?;
    let keys = format!("SELECT id FROM ironwood_one_time_keys WHERE account_id = {owner}");
    restart_cursor(conn, &keys, account.0)
}

/// SQL assignments on `ironwood_one_time_lookups` that fence out every walk dispatched
/// before (see `one_time_ivk::coverage`).
const FENCE: &str =
    "generation = generation + 1, dispatched_cutoff = NULL, dispatched_generation = NULL";

/// Restarts from page zero the lookup cursors that SQL `keys` selects, with `?1` bound to
/// `param`, fencing out their walks in flight, and makes each due again at the cutoff it
/// last finished or still has.
pub(crate) fn restart_cursor(
    conn: &Connection,
    keys: &str,
    param: impl rusqlite::ToSql,
) -> Result<(), SqliteClientError> {
    rewind_cursor(conn, keys, param, true)
}

/// [`restart_cursor`] for the walk of lookup `id` itself, which reads on from page zero.
#[cfg(feature = "orchard")]
pub(crate) fn restart_walk(conn: &Connection, id: i64) -> Result<(), SqliteClientError> {
    rewind_cursor(conn, "?1", id, false)
}

/// Restarts the cursors SQL `keys` selects (see [`restart_cursor`]), fencing their walks
/// if `fence`.
fn rewind_cursor(
    conn: &Connection,
    keys: &str,
    param: impl rusqlite::ToSql,
    fence: bool,
) -> Result<(), SqliteClientError> {
    let fence = if fence {
        format!(", {FENCE}")
    } else {
        String::new()
    };
    conn.execute(
        &format!(
            "UPDATE ironwood_one_time_lookups
             SET applied = 0, last_position = NULL, last_nullifier = NULL, last_height = NULL,
                 cutoff_height = COALESCE(cutoff_height, done_height), done_height = NULL
                 {fence}
             WHERE one_time_key_id IN ({keys})"
        ),
        [&param],
    )?;
    conn.execute(
        &format!("DELETE FROM ironwood_one_time_lookup_reads WHERE one_time_key_id IN ({keys})"),
        [&param],
    )?;
    // Reading again from page zero replaces what the earlier reads queued, so a corrected
    // answer is not refused as a conflict. Admitted notes stay.
    conn.execute(
        &format!(
            "DELETE FROM ironwood_one_time_payment_recovery WHERE one_time_key_id IN ({keys})"
        ),
        [&param],
    )?;
    Ok(())
}

/// Receivers whose history an obligation owes (see `one_time_ivk::coverage`).
#[derive(Clone, Copy)]
pub(crate) enum Owed {
    /// Registered key `.0`, of purpose code `.1`.
    Key(i64, u8),
    /// Window indices from `.1` up to `.2`, of purpose code `.0`.
    Window(u8, u64, u64),
}

/// Adds `owed` to account `owner`'s receiver set: raises the set's generation and, if the
/// frontier already passed the account's birthday, owes `owed` the history from the
/// birthday through the frontier.
pub(crate) fn join_set(
    conn: &rusqlite::Transaction<'_>,
    owner: i64,
    owed: Owed,
) -> Result<(), SqliteClientError> {
    let (purpose, key, range) = match owed {
        Owed::Key(id, purpose) => (purpose, Some(id), None),
        Owed::Window(purpose, start, end) => (purpose, None, Some((start, end))),
    };
    conn.execute(
        "INSERT INTO ironwood_one_time_recovery (account_id, generation) VALUES (?1, 1)
         ON CONFLICT (account_id) DO UPDATE SET generation = generation + 1",
        [owner],
    )?;
    conn.execute(
        "INSERT INTO ironwood_one_time_obligations
            (account_id, purpose, one_time_key_id, range_start, range_end, lower_height,
             through_height)
         SELECT r.account_id, ?2, ?3, ?4, ?5, a.birthday_height, r.frontier_height
         FROM ironwood_one_time_recovery r JOIN accounts a ON a.id = r.account_id
         WHERE r.account_id = ?1 AND r.frontier_height >= a.birthday_height",
        params![owner, purpose, key, range.map(|r| r.0), range.map(|r| r.1)],
    )?;
    Ok(())
}
