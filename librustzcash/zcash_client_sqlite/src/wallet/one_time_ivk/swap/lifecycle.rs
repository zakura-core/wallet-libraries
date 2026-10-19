//! Provider observations and the rule that ends a key's trial decryption.
use rusqlite::{Connection, named_params, params};
use zakura_one_time_ivk::swap::{
    COMPLETION_LIMIT_SECS, Observation, OperationStatus, RESTORE_WATCH_SECS, ReceiptExpectation,
};
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_protocol::consensus::{BlockHeight, Parameters};

use super::{
    RESERVED,
    reservations::{STARTED, reap},
};
use crate::wallet::one_time_ivk::{RESTORED, account_key, invalid};
use crate::{
    AccountUuid, error::SqliteClientError, wallet, wallet::common::tx_unexpired_condition,
};

/// See `WalletDb::close_finished_one_time_keys`.
pub(in crate::wallet::one_time_ivk) fn close_finished<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    now: i64,
    tip: BlockHeight,
) -> Result<usize, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    if wallet::chain_tip_height(conn)? != Some(tip)
        || wallet::fully_scanned_height(conn)? != Some(tip)
    {
        return Ok(0);
    }
    reap(conn, params, account, now)?;
    let tip_time: i64 = conn.query_row(
        "SELECT time FROM blocks WHERE height = ?1",
        [u32::from(tip)],
        |r| r.get(0),
    )?;
    let now = now.min(tip_time);
    let confirmed_below = u32::from(tip)
        .saturating_add(1)
        .saturating_sub(ConfirmationsPolicy::default().untrusted().get());
    let mut stmt = conn.prepare(&format!(
        "SELECT k.id, k.registered_at, k.purpose = 1 AND {RESERVED},
            EXISTS(SELECT 1 FROM ironwood_received_notes n
                JOIN transactions t ON t.id_tx = n.transaction_id
                WHERE n.one_time_key_id = k.id
                  AND (t.mined_height > :confirmed_below
                       OR (t.mined_height IS NULL AND ({unexpired})))),
            ({RESTORED}),
            (SELECT COUNT(*) FROM ironwood_one_time_operations o
                WHERE o.one_time_key_id = k.id),
            (SELECT COUNT(*) FROM ironwood_one_time_operations o
                WHERE o.one_time_key_id = k.id AND o.expectation IN (0, 3, 4)),
            (SELECT MAX(o.deadline) FROM ironwood_one_time_operations o
                WHERE o.one_time_key_id = k.id),
            (SELECT COALESCE(SUM(COALESCE(o.expected_value, 1)), 0)
                FROM ironwood_one_time_operations o
                WHERE o.one_time_key_id = k.id AND o.expectation = 2),
            (SELECT COALESCE(SUM(n.value), 0) FROM ironwood_received_notes n
                JOIN transactions t ON t.id_tx = n.transaction_id
                WHERE n.one_time_key_id = k.id AND t.mined_height <= :confirmed_below),
            (SELECT b.time FROM ironwood_one_time_lookups l
                JOIN blocks b ON b.height = l.done_height
                WHERE l.one_time_key_id = k.id),
            {STARTED}
         FROM ironwood_one_time_keys k
         WHERE k.account_id = :account AND k.active_from IS NOT NULL AND k.closed_at IS NULL",
        unexpired = tx_unexpired_condition("t"),
    ))?;
    let bounds = named_params![
        ":account": owner.0,
        ":confirmed_below": confirmed_below,
        ":target_height": u32::from(tip + 1),
    ];
    let finished = stmt
        .query_map(bounds, |row| {
            let id: i64 = row.get(0)?;
            let registered_at: i64 = row.get(1)?;
            let reserved: bool = row.get(2)?;
            let pending_receipt: bool = row.get(3)?;
            let restored: bool = row.get(4)?;
            let operations: u32 = row.get(5)?;
            let unresolved: u32 = row.get(6)?;
            let deadline: Option<i64> = row.get(7)?;
            let expected: i64 = row.get(8)?;
            let received: i64 = row.get(9)?;
            let looked_up_at: Option<i64> = row.get(10)?;
            let started: bool = row.get(11)?;
            let limit = if restored {
                registered_at
                    .max(looked_up_at.unwrap_or(registered_at))
                    .saturating_add(RESTORE_WATCH_SECS)
            } else {
                deadline
                    .unwrap_or(registered_at)
                    .saturating_add(COMPLETION_LIMIT_SECS)
            };
            let settled = operations > 0 && unresolved == 0 && received >= expected;
            // Reclamation may never take a started reservation, so the limit alone ends
            // its scanning. It stays reserved, keeping issuance off its address.
            let finished = if reserved {
                started && now >= limit
            } else {
                settled || now >= limit
            };
            Ok((id, !pending_receipt && finished))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut closed = 0;
    for (id, finished) in finished {
        if finished {
            conn.execute(
                "UPDATE ironwood_one_time_keys SET closed_at = ?2 WHERE id = ?1",
                params![id, now],
            )?;
            closed += 1;
        }
    }
    Ok(closed)
}

/// Records `observation`, requested at `now`, on operation `id` unless a newer one is
/// stored, and merges its `funded` in either case (see `WalletDb::record_operation_status`).
/// Returns whether `observation` was current and so recorded. `expectation` stores the
/// status: 0 active, 1 final with no receipt, 2 final with a receipt, 3 final but
/// inconclusive, 4 awaiting a deposit. Between observations requested in the same second,
/// whichever arrives last cannot replace a stored receipt with a status that expects none
/// or less, or an inconclusive end with no receipt, either of which could close the key
/// before a receipt arrives.
pub(in crate::wallet::one_time_ivk) fn record(
    conn: &Connection,
    id: i64,
    observation: Observation,
    now: i64,
) -> Result<bool, SqliteClientError> {
    if now < 0 {
        return Err(invalid("invalid observation time"));
    }
    let (expectation, amount) = match observation.status {
        OperationStatus::Active => (0, None),
        OperationStatus::Terminal(ReceiptExpectation::None) => (1, None),
        OperationStatus::Terminal(ReceiptExpectation::Positive(value)) => (2, value),
        OperationStatus::Terminal(ReceiptExpectation::Unknown) => (3, None),
        OperationStatus::AwaitingDeposit => (4, None),
    };
    let amount = amount
        .map(|v| i64::try_from(u64::from(v)).ok().filter(|v| *v > 0))
        .map(|v| v.ok_or_else(|| invalid("expected receipt must be positive")))
        .transpose()?;
    conn.execute(
        "UPDATE ironwood_one_time_operations SET funded = MAX(funded, ?2) WHERE id = ?1",
        params![id, observation.funded],
    )?;
    let previous: (u8, Option<i64>) = conn.query_row(
        "SELECT expectation,expected_value FROM ironwood_one_time_operations WHERE id=?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let current = conn.execute(
        "UPDATE ironwood_one_time_operations SET
            observed_at = ?2, expectation = ?3, expected_value = ?4
         WHERE id = ?1 AND (observed_at < ?2 OR (observed_at = ?2 AND NOT (
             (expectation = 2 AND (?3 != 2 OR COALESCE(?4, 1) < COALESCE(expected_value, 1)))
             OR (expectation = 3 AND ?3 = 1))))",
        params![id, now, expectation, amount],
    )?;
    if current > 0
        && (matches!(expectation, 0 | 3 | 4)
            || (expectation == 2
                && (previous.0 != 2
                    || (amount.is_none() && previous.1.is_some())
                    || amount.unwrap_or(1) > previous.1.unwrap_or(1))))
    {
        conn.execute("UPDATE ironwood_one_time_keys SET watch_closed_height=NULL,watch_closed_hash=NULL WHERE id=(SELECT one_time_key_id FROM ironwood_one_time_operations WHERE id=?1)", [id])?;
    }
    Ok(current > 0)
}
