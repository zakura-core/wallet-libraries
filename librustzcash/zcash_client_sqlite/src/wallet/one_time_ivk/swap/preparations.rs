//! Durable issuance preparations: the next receive or refund address, held by one row per
//! account and purpose until it is handed out, and checked by its own lookup first.
use rusqlite::{Connection, OptionalExtension, params};
use zcash_protocol::consensus::Parameters;

use crate::error::SqliteClientError;
use crate::wallet::one_time_ivk::{Purpose, purpose_code, restore::queue};

/// Makes `key` the preparation of `owner` for `purpose` and reports whether it is ready to
/// hand out: its own history was read to completion, through the wallet's scanned tip when
/// the key was prepared and through the account's latest filter coverage, with no payment
/// candidate waiting. A new key, or one whose read fell behind filter coverage, gets a
/// lookup through the wallet's scanned tip. Repeated calls keep the same row and lookup.
pub(in crate::wallet::one_time_ivk) fn prepare<P: Parameters>(
    conn: &Connection,
    params: &P,
    owner: i64,
    purpose: Purpose,
    key: i64,
) -> Result<bool, SqliteClientError> {
    let tip: u32 = conn.query_row("SELECT COALESCE(MAX(height), 0) FROM blocks", [], |r| {
        r.get(0)
    })?;
    let code = purpose_code(purpose)?;
    let kept: Option<u32> = conn
        .query_row(
            "SELECT target_height FROM ironwood_one_time_preparations
             WHERE account_id = ?1 AND purpose = ?2 AND one_time_key_id = ?3",
            params![owner, code, key],
            |r| r.get(0),
        )
        .optional()?;
    let target = match kept {
        Some(target) => target,
        None => {
            conn.execute(
                "INSERT INTO ironwood_one_time_preparations
                    (account_id, purpose, one_time_key_id, target_height) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(account_id, purpose) DO UPDATE SET
                    one_time_key_id = excluded.one_time_key_id,
                    target_height = excluded.target_height",
                params![owner, code, key, tip],
            )?;
            tip
        }
    };
    if checked(conn, params, owner, key, target)? {
        return Ok(true);
    }
    let pending: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_lookups
             WHERE one_time_key_id = ?1 AND target_height IS NOT NULL AND reasons & 3 != 0)",
        [key],
        |r| r.get(0),
    )?;
    if !pending {
        // Never read, or read before filters moved on: read it through the current tip.
        conn.execute(
            "UPDATE ironwood_one_time_preparations SET target_height = MAX(target_height, ?3)
             WHERE account_id = ?1 AND purpose = ?2",
            params![owner, code, tip],
        )?;
        queue::enqueue(conn, key, queue::activation(params), tip, queue::AUTOMATIC)?;
    }
    checked(conn, params, owner, key, target.max(tip))
}

/// Whether `key`'s own history was read to completion from activation through `target` and
/// through `owner`'s filter frontier, with no payment candidate left.
fn checked<P: Parameters>(
    conn: &Connection,
    params: &P,
    owner: i64,
    key: i64,
    target: u32,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_lookups l
             WHERE l.one_time_key_id = ?1 AND l.target_height IS NULL AND l.read_complete = 1
               AND l.done_from <= ?2 AND l.done_height >= MAX(?3, COALESCE((SELECT filter_height
                   FROM ironwood_one_time_recovery WHERE account_id = ?4), 0)))
         AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery p
             WHERE p.one_time_key_id = ?1)",
        params![key, queue::activation(params), target, owner],
        |r| r.get(0),
    )?)
}

/// The key `owner` has prepared for `purpose`, if any.
pub(in crate::wallet::one_time_ivk) fn prepared(
    conn: &Connection,
    owner: i64,
    purpose: Purpose,
) -> Result<Option<i64>, SqliteClientError> {
    Ok(conn
        .query_row(
            "SELECT one_time_key_id FROM ironwood_one_time_preparations
             WHERE account_id = ?1 AND purpose = ?2",
            params![owner, purpose_code(purpose)?],
            |r| r.get(0),
        )
        .optional()?)
}

/// Removes `owner`'s preparation for `purpose`, once handed out or when cancelled. Its key
/// stays registered.
pub(in crate::wallet::one_time_ivk) fn consume(
    conn: &Connection,
    owner: i64,
    purpose: Purpose,
) -> Result<(), SqliteClientError> {
    conn.execute(
        "DELETE FROM ironwood_one_time_preparations WHERE account_id = ?1 AND purpose = ?2",
        params![owner, purpose_code(purpose)?],
    )?;
    Ok(())
}
