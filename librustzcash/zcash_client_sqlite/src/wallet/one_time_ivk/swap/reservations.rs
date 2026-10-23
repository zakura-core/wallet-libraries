//! Incoming reservations, which live on their key's row, and their quote operations.
use rusqlite::{Connection, OptionalExtension, named_params, params};
use zakura_one_time_ivk::swap::Observation;
use zcash_protocol::consensus::Parameters;

use super::{RESERVED, ReservationPolicy, lifecycle::record};
use crate::wallet::one_time_ivk::restore::queue::RECEIVE_PENDING;
use crate::wallet::one_time_ivk::{
    KeyId, OneTimeKey, Purpose, account_key, decode_index, index_after, invalid, key_by_id,
    register,
};
use crate::{AccountUuid, error::SqliteClientError, wallet};

use zcash_client_backend::data_api::one_time_ivk::restore::RECEIVE_GAP;

/// How recent a status must be to reclaim a started reservation.
const STATUS_FRESH_SECONDS: i64 = 120;

/// How long past its deadline a started quote keeps its slot without a fresh conclusive status.
const STARTED_STATUS_GRACE_SECONDS: i64 = 86_400;

/// Deposit instructions of an accepted incoming quote, as the provider issued them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiveDeposit {
    /// Provider deposit address, which also identifies the provider operation.
    pub address: String,
    /// Memo the deposit must carry, on routes that tell deposits apart by memo.
    pub memo: Option<String>,
    /// Unix time after which the provider stops accepting the deposit.
    pub deadline: i64,
}

/// How a request begun with `WalletDb::begin_receive_operation` ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperationOutcome {
    /// The provider accepted the request with these deposit instructions.
    Accepted(ReceiveDeposit),
    /// The provider definitively rejected the request. A timeout or a malformed
    /// response is not a rejection: leave the outcome unknown instead.
    Rejected,
}

/// The deadline of the latest request on incoming key `k`'s current reservation, the
/// accepted one or else the requested one, or NULL if none was begun. A reissued address
/// keeps its earlier reservations' requests, so the current one's are those above its
/// `reservation_floor`. A NULL floor counts every request on the key, so a reservation
/// made before the floor existed is never mistaken for one never quoted.
const LATEST_DEADLINE: &str = "(SELECT o.deadline FROM ironwood_one_time_operations o
    WHERE o.one_time_key_id = k.id AND o.request IS NOT NULL
      AND o.id > IFNULL(k.reservation_floor, 0)
    ORDER BY o.id DESC LIMIT 1)";

/// SQL condition on `ironwood_one_time_keys k`: one of its quotes was started.
pub(in crate::wallet::one_time_ivk) const STARTED: &str =
    "EXISTS(SELECT 1 FROM ironwood_one_time_operations o
    WHERE o.one_time_key_id = k.id AND o.id > IFNULL(k.reservation_floor, 0) AND o.started = 1)";

/// The exclusive end of the four-index window justified by payments mined on the wallet's
/// current chain. A payment counts from the block that mines it, so the next index is
/// issuable as soon as a payout lands, and a reorg that drops the payment shrinks the
/// window again.
pub(in crate::wallet::one_time_ivk) fn recovery_end(
    conn: &Connection,
    account: i64,
) -> Result<u64, SqliteClientError> {
    let tip = wallet::chain_tip_height(conn)?.map(u32::from);
    let paid: Option<Vec<u8>> = conn.query_row(
        "SELECT MAX(k.key_index) FROM ironwood_one_time_keys k
         WHERE k.account_id = :account AND k.purpose = 1 AND (k.prebirthday_height <= :tip
             OR EXISTS(SELECT 1 FROM ironwood_received_notes n
                 JOIN transactions t ON t.id_tx = n.transaction_id
                 JOIN blocks b ON b.height = t.mined_height
                 WHERE n.one_time_key_id = k.id AND t.mined_height <= :tip))",
        named_params![":account": account, ":tip": tip],
        |r| r.get(0),
    )?;
    let next = paid
        .map(|bytes| index_after(decode_index(bytes)?, 1))
        .transpose()?
        .unwrap_or(0);
    index_after(next, RECEIVE_GAP)
}

/// Releases local ownership while preserving the provider's operation history.
fn release(conn: &Connection, key: i64, now: i64) -> Result<(), SqliteClientError> {
    conn.execute(
        "UPDATE ironwood_one_time_keys SET released_at = ?2 WHERE id = ?1",
        params![key, now],
    )?;
    Ok(())
}

/// The earlier of `now` and the latest block time. A provider sets deadlines by its own
/// clock, so they are compared with this, which a fast device clock cannot move ahead.
fn deadline_clock(conn: &Connection, now: i64) -> Result<i64, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT MIN(?1, IFNULL((SELECT time FROM blocks ORDER BY height DESC LIMIT 1), ?1))",
        [now],
        |r| r.get(0),
    )?)
}

/// Releases expired reservations only when no current request can still own them.
/// A started operation needs a recent conclusive status. On an unpaid key with no pending
/// payment, which is what reissue requires, its deadline having passed
/// [`STARTED_STATUS_GRACE_SECONDS`] ago by the deadline clock also does. A paid key keeps
/// needing the status, since a reorg can make it unpaid again. Funding evidence sticks.
pub(in crate::wallet::one_time_ivk) fn reap<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    now: i64,
) -> Result<Vec<u64>, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    let deadline_now = deadline_clock(conn, now)?;
    let released = conn
        .prepare(&format!(
            "SELECT k.id, k.key_index FROM ironwood_one_time_keys k
         WHERE k.account_id = :account AND k.purpose = 1 AND {RESERVED}
           AND EXISTS(SELECT 1 FROM ironwood_one_time_operations o
               WHERE o.one_time_key_id = k.id AND o.id > IFNULL(k.reservation_floor, 0))
           AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_operations o
               WHERE o.one_time_key_id = k.id AND o.id > IFNULL(k.reservation_floor, 0)
                 AND (o.deadline > :deadline_now OR
                     (o.reference IS NOT NULL AND o.expectation = 0) OR
                     (o.funded = 1 AND o.expectation != 1 AND k.used = 0) OR
                     (o.started = 1 AND (o.deadline > :deadline_now - :grace
                         OR k.used = 1 OR {RECEIVE_PENDING}) AND NOT (
                         o.observed_at BETWEEN :now - :fresh AND :now
                         AND (o.expectation = 1 OR (o.funded = 0 AND o.expectation IN (3, 4))
                              OR (k.used = 1 AND o.expectation IN (2, 3)))))))"
        ))?
        .query_map(
            named_params![":account": owner.0, ":deadline_now": deadline_now,
        ":now": now, ":fresh": STATUS_FRESH_SECONDS, ":grace": STARTED_STATUS_GRACE_SECONDS],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    let mut indexes = Vec::with_capacity(released.len());
    for (id, index) in released {
        release(conn, id, now)?;
        indexes.push(decode_index(index)?);
    }
    Ok(indexes)
}

/// See `WalletDb::begin_receive_operation`, which chooses `request`.
pub(in crate::wallet::one_time_ivk) fn begin(
    conn: &rusqlite::Transaction<'_>,
    account: AccountUuid,
    index: u64,
    request: &str,
    deadline: i64,
    now: i64,
) -> Result<Result<(), ReservationPolicy>, SqliteClientError> {
    if request.is_empty() {
        return Err(invalid("empty operation request"));
    }
    if deadline <= now {
        return Err(invalid("operation deadline has passed"));
    }
    let (key, owner, open, latest, pending): (i64, i64, bool, Option<i64>, bool) = conn
        .query_row(
            &format!(
                "SELECT k.id, k.account_id, {RESERVED} AND k.used = 0 AND NOT {STARTED},
            {LATEST_DEADLINE}, {RECEIVE_PENDING} FROM ironwood_one_time_keys k
            JOIN accounts a ON a.id = k.account_id
            WHERE a.uuid = ?1 AND k.purpose = 1 AND k.key_index = ?2"
            ),
            params![account.0, index.to_be_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?
        .ok_or_else(|| invalid("unknown receive reservation"))?;
    let clock = deadline_clock(conn, now)?;
    if !open || latest.is_some_and(|deadline| deadline <= clock) {
        return Ok(Err(ReservationPolicy::Stale));
    }
    if pending {
        return Ok(Err(ReservationPolicy::ReceiveHistory));
    }
    if index >= recovery_end(conn, owner)? {
        return Ok(Err(ReservationPolicy::Gap));
    }
    conn.execute(
        "INSERT INTO ironwood_one_time_operations
            (one_time_key_id, request, deadline, begun_at, observed_at)
         VALUES (?1, ?2, ?3, ?4, ?4)",
        params![key, request, deadline, now],
    )?;
    Ok(Ok(()))
}

/// The ID of `account`'s operation begun as `request`.
fn operation(
    conn: &Connection,
    account: AccountUuid,
    request: &str,
) -> Result<i64, SqliteClientError> {
    conn.query_row(
        "SELECT o.id FROM ironwood_one_time_operations o
         JOIN ironwood_one_time_keys k ON k.id = o.one_time_key_id
         JOIN accounts a ON a.id = k.account_id
         WHERE a.uuid = ?1 AND o.request = ?2",
        params![account.0, request],
        |r| r.get(0),
    )
    .optional()?
    .ok_or_else(|| invalid("unknown operation request"))
}

/// See `WalletDb::finish_receive_operation`.
pub(in crate::wallet::one_time_ivk) fn finish(
    conn: &rusqlite::Transaction<'_>,
    account: AccountUuid,
    request: &str,
    outcome: &OperationOutcome,
) -> Result<(), SqliteClientError> {
    let id = operation(conn, account, request)?;
    match outcome {
        OperationOutcome::Accepted(deposit) => {
            if deposit.address.is_empty() {
                return Err(invalid("empty deposit address"));
            }
            // The provider's clock sets this deadline, so it is checked against the earlier
            // of the request time and the latest block time, which a fast device clock
            // cannot move ahead (closing measures from the deadline the same way).
            let expired: bool = conn.query_row(
                "SELECT ?2 <= MIN(begun_at,
                    IFNULL((SELECT time FROM blocks ORDER BY height DESC LIMIT 1), begun_at))
                 FROM ironwood_one_time_operations WHERE id = ?1",
                params![id, deposit.deadline],
                |r| r.get(0),
            )?;
            if expired {
                return Err(invalid("accepted deadline has passed"));
            }
            // Statuses find operations by address and memo alone.
            let bound: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_operations o
                     JOIN ironwood_one_time_keys k ON k.id = o.one_time_key_id
                     JOIN accounts a ON a.id = k.account_id
                     WHERE a.uuid = ?1 AND o.id != ?2 AND o.reference = ?3 AND o.memo IS ?4)",
                params![account.0, id, deposit.address, deposit.memo],
                |r| r.get(0),
            )?;
            if bound {
                return Err(invalid("deposit instructions belong to another operation"));
            }
            let changed = conn.execute(
                "UPDATE ironwood_one_time_operations
                 SET expectation = CASE WHEN reference IS NULL AND expectation = 0 AND funded = 0
                         THEN 4 ELSE expectation END,
                     reference = ?2, memo = ?3, deadline = MIN(deadline, ?4)
                 WHERE id = ?1 AND rejected = 0
                     AND (reference IS NULL OR (reference = ?2 AND memo IS ?3))",
                params![id, deposit.address, deposit.memo, deposit.deadline],
            )?;
            if changed != 1 {
                return Err(invalid("operation outcome changed"));
            }
        }
        OperationOutcome::Rejected => {
            let changed = conn.execute(
                "UPDATE ironwood_one_time_operations SET rejected = 1
                 WHERE id = ?1 AND reference IS NULL",
                [id],
            )?;
            if changed != 1 {
                return Err(invalid("operation outcome changed"));
            }
        }
    }
    Ok(())
}

/// See `WalletDb::start_receive_operation`.
pub(in crate::wallet::one_time_ivk) fn start(
    conn: &rusqlite::Transaction<'_>,
    account: AccountUuid,
    request: &str,
    now: i64,
) -> Result<Result<ReceiveDeposit, ReservationPolicy>, SqliteClientError> {
    let id = operation(conn, account, request)?;
    let deposit = conn
        .query_row(
            &format!(
                "SELECT o.reference, o.memo, o.deadline, {RECEIVE_PENDING}
                 FROM ironwood_one_time_operations o
                 JOIN ironwood_one_time_keys k ON k.id = o.one_time_key_id
                 WHERE o.id = ?1 AND o.reference IS NOT NULL AND {RESERVED}
                     AND o.id > IFNULL(k.reservation_floor, 0) AND k.used = 0"
            ),
            [id],
            |r| {
                Ok((
                    ReceiveDeposit {
                        address: r.get(0)?,
                        memo: r.get(1)?,
                        deadline: r.get(2)?,
                    },
                    r.get::<_, bool>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((deposit, pending)) = deposit else {
        return Ok(Err(ReservationPolicy::Stale));
    };
    if pending {
        return Ok(Err(ReservationPolicy::ReceiveHistory));
    }
    // Instructions are shown for one request per reservation, since its receiver takes
    // one quote, and only while the provider still takes a deposit.
    let other_started: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_operations o
             JOIN ironwood_one_time_operations other
                 ON other.one_time_key_id = o.one_time_key_id
             JOIN ironwood_one_time_keys k ON k.id = o.one_time_key_id
             WHERE o.id = ?1 AND other.id != ?1 AND other.started = 1
               AND other.id > IFNULL(k.reservation_floor, 0))",
        [id],
        |r| r.get(0),
    )?;
    if other_started || deposit.deadline <= deadline_clock(conn, now)? {
        return Ok(Err(ReservationPolicy::Stale));
    }
    conn.execute(
        "UPDATE ironwood_one_time_operations SET started = 1 WHERE id = ?1",
        [id],
    )?;
    Ok(Ok(deposit))
}

/// See `WalletDb::record_operation_status`. An incoming operation is updated while its
/// reservation is open, and after release if its key was paid and it was funded.
pub(in crate::wallet::one_time_ivk) fn record_status<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    (deposit, memo): (&str, Option<&str>),
    observation: Observation,
    now: i64,
) -> Result<bool, SqliteClientError> {
    if deposit.is_empty() {
        return Err(invalid("empty deposit address"));
    }
    let operations = conn
        .prepare(&format!(
            "SELECT o.id FROM ironwood_one_time_operations o
         JOIN ironwood_one_time_keys k ON k.id = o.one_time_key_id
         JOIN accounts a ON a.id = k.account_id
         WHERE a.uuid = ?1 AND o.reference = ?2 AND o.memo IS ?3
           AND (k.purpose = 0 OR {RESERVED} OR (k.used = 1 AND (o.funded = 1 OR ?4)))"
        ))?
        .query_map(params![account.0, deposit, memo, observation.funded], |r| {
            r.get::<_, i64>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for id in &operations {
        record(conn, params, *id, &observation, now)?;
    }
    reap(conn, params, account, now)?;
    Ok(!operations.is_empty())
}

/// Resumes a live draft or reserves the lowest unpaid hole inside the mined window.
pub(in crate::wallet::one_time_ivk) fn prepare<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    now: i64,
) -> Result<Result<OneTimeKey, ReservationPolicy>, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    let end = recovery_end(conn, owner.0)?;
    let clock = deadline_clock(conn, now)?;
    let rows = conn.prepare(&format!(
        "SELECT k.id, k.key_index, k.used, {RESERVED}, {STARTED}, {LATEST_DEADLINE},
            EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery p WHERE p.one_time_key_id = k.id),
            {RECEIVE_PENDING}
         FROM ironwood_one_time_keys k
         WHERE k.account_id = ?1 AND k.purpose = 1 AND k.key_index < ?2 ORDER BY k.key_index"
    ))?.query_map(params![owner.0, end.to_be_bytes()], |r| Ok((
        r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?, r.get::<_, bool>(2)?,
        r.get::<_, bool>(3)?, r.get::<_, bool>(4)?, r.get::<_, Option<i64>>(5)?, r.get::<_, bool>(6)?,
        r.get::<_, bool>(7)?
    )))?.collect::<Result<Vec<_>, _>>()?;
    let mut next = 0;
    for (id, index, paid, reserved, started, deadline, candidate, pending) in rows {
        let index = decode_index(index)?;
        if index > next {
            break;
        }
        if !paid && !candidate {
            if !reserved {
                break;
            }
            if !started && deadline.is_none_or(|deadline| deadline > clock) {
                // A positive hint since it was reserved may mean another device paid it.
                if pending {
                    return Ok(Err(ReservationPolicy::ReceiveHistory));
                }
                return key_by_id(conn, params, account, id).map(Ok);
            }
        }
        next = index_after(index, 1)?;
    }
    if next >= end {
        return Ok(Err(ReservationPolicy::Limit));
    }
    let (id, key) = register(conn, params, account, KeyId::new(Purpose::Receive, next))?;
    // A restored seed may have paid this address before the wallet knew it, so it is
    // handed out only after its own history was read to completion with nothing pending.
    let checked: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_lookups l
             WHERE l.one_time_key_id = ?1 AND l.target_height IS NULL AND l.read_complete = 1
               AND l.done_height IS NOT NULL)
         AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery p
             WHERE p.one_time_key_id = ?1)",
        [id],
        |r| r.get(0),
    )?;
    if !checked {
        return Ok(Err(ReservationPolicy::ReceiveHistory));
    }
    conn.execute(
        "UPDATE ironwood_one_time_keys SET reserved_at = ?2, released_at = NULL,
            reservation_floor = IFNULL((SELECT MAX(id) FROM ironwood_one_time_operations
                WHERE one_time_key_id = ?1), 0) WHERE id = ?1",
        params![id, now],
    )?;
    Ok(Ok(key))
}
