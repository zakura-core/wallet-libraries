//! Provider observations preserve local operation ownership and receipt obligations.
use crate::{error::SqliteClientError, wallet::one_time_ivk::invalid};
use rusqlite::{Connection, params};
use zakura_one_time_ivk::swap::{Observation, OperationStatus, ReceiptExpectation};

/// Records `observation`, requested at `now`, on operation `id` unless a newer one is
/// stored, and merges its `funded` and reported receipt transactions in either case (see
/// `WalletDb::record_operation_status`).
/// Returns whether `observation` was current and so recorded. `expectation` stores the
/// status: 0 active, 1 final with no receipt, 2 final with a receipt, 3 final but
/// inconclusive, 4 awaiting a deposit. Between observations requested in the same second,
/// whichever arrives last cannot replace a stored receipt with a status that expects none
/// or less, or an inconclusive end with no receipt, either of which could discard an obligation.
pub(in crate::wallet::one_time_ivk) fn record(
    conn: &Connection,
    id: i64,
    observation: &Observation,
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
    for txid in &observation.receipts {
        conn.execute(
            "INSERT OR IGNORE INTO ironwood_one_time_operation_receipts (operation_id, txid)
             VALUES (?1, ?2)",
            params![id, txid.as_ref()],
        )?;
    }
    let current = conn.execute(
        "UPDATE ironwood_one_time_operations SET
            observed_at = ?2, expectation = ?3, expected_value = ?4
         WHERE id = ?1 AND (observed_at < ?2 OR (observed_at = ?2 AND NOT (
             (expectation = 2 AND (?3 != 2 OR COALESCE(?4, 1) < COALESCE(expected_value, 1)))
             OR (expectation = 3 AND ?3 = 1))))",
        params![id, now, expectation, amount],
    )?;
    Ok(current > 0)
}
