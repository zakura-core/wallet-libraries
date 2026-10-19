//! One-time IVK state that a rewind repairs in every build. The tables exist in every
//! build, and an `orchard` build may reopen a wallet that a build without it rewound, so
//! the repair cannot wait for `orchard`.

use rusqlite::{Connection, params};
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
/// there restarts, since the replacement chain may put a record before it.
pub(crate) fn truncate(
    conn: &rusqlite::Transaction<'_>,
    height: BlockHeight,
) -> Result<(), SqliteClientError> {
    let keep = u32::from(height);
    conn.execute(
        "UPDATE ironwood_block_recovery SET work_generation=work_generation+1",
        [],
    )?;
    conn.execute(
        "UPDATE ironwood_block_receivers SET next_height=MIN(next_height,MAX(?1+1,(SELECT birthday FROM ironwood_block_recovery r WHERE r.account_id=ironwood_block_receivers.account_id)))",
        [keep],
    )?;
    conn.execute("DELETE FROM ironwood_block_matches WHERE height>?1", [keep])?;
    conn.execute("DELETE FROM ironwood_key_scans WHERE height>?1", [keep])?;
    conn.execute("UPDATE ironwood_one_time_keys SET watch_closed_height=NULL,watch_closed_hash=NULL WHERE watch_closed_height>?1",[keep])?;
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
/// every key again and every paid key's history from the start, since outcomes outside the
/// old range no longer hold. The account is no longer treated as fresh.
pub(crate) fn reopen_discovery(
    conn: &rusqlite::Transaction<'_>,
    account: AccountUuid,
) -> Result<(), SqliteClientError> {
    conn.execute("UPDATE ironwood_block_recovery SET needs_prepare=1,work_generation=work_generation+1 WHERE account_id=(SELECT id FROM accounts WHERE uuid=?1)",[account.0])?;
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
    restart_cursor(conn, &keys, account.0)?;
    // Until the next pass makes them due, no lookup runs.
    conn.execute(
        &format!(
            "UPDATE ironwood_one_time_lookups SET cutoff_height = NULL, done_height = NULL
             WHERE one_time_key_id IN ({keys})"
        ),
        [account.0],
    )?;
    Ok(())
}

/// Restarts from page zero the lookup cursors that SQL `keys` selects, with `?1` bound to
/// `param`, and makes each due again at the cutoff it last finished or still has.
pub(crate) fn restart_cursor(
    conn: &Connection,
    keys: &str,
    param: impl rusqlite::ToSql,
) -> Result<(), SqliteClientError> {
    conn.execute(
        &format!(
            "UPDATE ironwood_one_time_lookups
             SET applied = 0, last_position = NULL, last_nullifier = NULL, last_height = NULL,
                 cutoff_height = COALESCE(cutoff_height, done_height), done_height = NULL
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
