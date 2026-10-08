//! Provider observations and the rule that ends a key's trial decryption.
use rusqlite::{Connection, OptionalExtension, named_params, params};
use zakura_dynamic_ivk::lifecycle::{
    COMPLETION_LIMIT_SECS, Observation, OperationStatus, RESTORE_WATCH_SECS, ReceiptExpectation,
};
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_protocol::consensus::{BlockHeight, Parameters};

use super::{RESERVED, RESTORED, account_key, invalid, reservations::reap};
use crate::{
    AccountUuid, error::SqliteClientError, wallet, wallet::common::tx_unexpired_condition,
};

/// See `WalletDb::close_finished_dynamic_keys`.
pub(super) fn close_finished<P: Parameters>(
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
                WHERE n.receiving_key_id = k.id
                  AND (t.mined_height > :confirmed_below
                       OR (t.mined_height IS NULL AND ({unexpired})))),
            ({RESTORED}),
            (SELECT COUNT(*) FROM ironwood_dynamic_operations o
                WHERE o.receiving_key_id = k.id),
            (SELECT COUNT(*) FROM ironwood_dynamic_operations o
                WHERE o.receiving_key_id = k.id AND o.expectation IN (0, 3, 4)),
            (SELECT MAX(o.deadline) FROM ironwood_dynamic_operations o
                WHERE o.receiving_key_id = k.id),
            (SELECT COALESCE(SUM(COALESCE(o.expected_value, 1)), 0)
                FROM ironwood_dynamic_operations o
                WHERE o.receiving_key_id = k.id AND o.expectation = 2),
            (SELECT COALESCE(SUM(n.value), 0) FROM ironwood_received_notes n
                JOIN transactions t ON t.id_tx = n.transaction_id
                WHERE n.receiving_key_id = k.id AND t.mined_height <= :confirmed_below),
            (SELECT b.time FROM ironwood_dynamic_sweeps s
                JOIN blocks b ON b.height = s.done_height
                WHERE s.receiving_key_id = k.id)
         FROM ironwood_receiving_keys k
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
            let swept_at: Option<i64> = row.get(10)?;
            let limit = if restored {
                registered_at
                    .max(swept_at.unwrap_or(registered_at))
                    .saturating_add(RESTORE_WATCH_SECS)
            } else {
                deadline
                    .unwrap_or(registered_at)
                    .saturating_add(COMPLETION_LIMIT_SECS)
            };
            let settled = operations > 0 && unresolved == 0 && received >= expected;
            Ok((
                id,
                !reserved && !pending_receipt && (settled || now >= limit),
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut closed = 0;
    for (id, finished) in finished {
        if finished {
            conn.execute(
                "UPDATE ironwood_receiving_keys SET closed_at = ?2 WHERE id = ?1",
                params![id, now],
            )?;
            closed += 1;
        }
    }
    Ok(closed)
}

/// Records `observation`, requested at `now`, on operation `id` unless a newer one is
/// stored (see `WalletDb::record_operation_status`). `expectation` stores the status:
/// 0 active, 1 final with no receipt, 2 final with a receipt, 3 final but
/// inconclusive, 4 awaiting a deposit.
pub(super) fn record(
    conn: &Connection,
    id: i64,
    observation: Observation,
    funded: bool,
    now: i64,
) -> Result<(), SqliteClientError> {
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
        "UPDATE ironwood_dynamic_operations SET
            observed_at = ?2, expectation = ?3, expected_value = ?4,
            deadline = COALESCE(deadline, ?5), funded = MAX(funded, ?6)
         WHERE id = ?1 AND observed_at <= ?2",
        params![id, now, expectation, amount, observation.deadline, funded],
    )?;
    Ok(())
}

/// Records `observation` on key `key`'s refund operation `reference`, adding it if new.
pub(super) fn record_refund(
    conn: &Connection,
    key: i64,
    reference: &str,
    observation: Observation,
    now: i64,
) -> Result<(), SqliteClientError> {
    if reference.is_empty() {
        return Err(invalid("empty operation reference"));
    }
    let existing: Option<i64> = conn
        .query_row(
            "SELECT id FROM ironwood_dynamic_operations
             WHERE receiving_key_id = ?1 AND reference = ?2 AND request IS NULL",
            params![key, reference],
            |r| r.get(0),
        )
        .optional()?;
    let id = match existing {
        Some(id) => id,
        None => conn.query_row(
            "INSERT INTO ironwood_dynamic_operations (receiving_key_id, reference, begun_at)
             VALUES (?1, ?2, ?3) RETURNING id",
            params![key, reference, now],
            |r| r.get(0),
        )?,
    };
    record(conn, id, observation, false, now)
}
