//! Incoming reservations, which live on their key's row, and their quote operations.
use rusqlite::{Connection, OptionalExtension, named_params, params};
use zakura_dynamic_ivk::lifecycle::{
    Observation,
    OperationStatus::Terminal,
    ReceiptExpectation::{Positive, Unknown},
};
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_protocol::consensus::{BlockHeight, Parameters};

use super::{
    DynamicKey, KeyId, Purpose, RESERVED, ReservationPolicy, account_key, activate, corrupt,
    decode_index, invalid, key_by_id, lifecycle::record, next_index, register,
};
use crate::{AccountUuid, error::SqliteClientError, wallet};

/// Incoming seed recovery searches at least this many consecutive empty indices, and
/// issuance stays within this many indices of the highest paid or seen one.
pub const RECEIVE_GAP_LIMIT: u64 = 30;
/// [`RECEIVE_GAP_LIMIT`] as a lookahead key count.
pub(crate) const RECEIVE_LOOKAHEAD: u32 = RECEIVE_GAP_LIMIT as u32;
/// Grace after the last deposit deadline before an unpaid reservation can be reclaimed,
/// for a late status report and clock differences.
pub const RECEIVE_RECLAIM_SECONDS: i64 = 2 * 60 * 60;
/// How recent a status must be to reclaim a started reservation.
const STATUS_FRESH_SECONDS: i64 = 120;
/// Margin for clock differences between this device and a provider's feed when deciding
/// whether a [`ProviderSeen`] read covers a quote.
pub const SEEN_SLACK_SECONDS: i64 = 60 * 60;

/// A swap provider's seen set, as a receiver directory publishes it: every receiver the
/// provider was given between `since` and `until`.
///
/// An incoming address counts as seen, and is never issued again, if the set holds it,
/// if the provider accepted a quote for it (an accepted quote is always in the set), or
/// if a quote for it that was not rejected falls outside the set's read, widened by
/// [`SEEN_SLACK_SECONDS`]. Without a set, every quote that was not rejected counts. A
/// seen address moves the recovery gap like a paid one, since a restore walks past the
/// addresses the set holds. The set's answers are kept, so a later set that lacks an
/// address cannot make it issuable again.
pub struct ProviderSeen<'a> {
    /// When the provider's feed started, in Unix seconds. Receivers the provider was
    /// given earlier are missing.
    pub since: i64,
    /// When the feed's last complete read of the provider began, in Unix seconds.
    /// Receivers the provider was given later are missing.
    pub until: i64,
    /// Which of the given receivers the set holds, in order.
    pub contains: &'a dyn Fn(&[[u8; 43]]) -> Vec<bool>,
}

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

/// The quote times `seen` covers, as `SEEN`'s bounds; without a set, none.
fn coverage(seen: Option<&ProviderSeen<'_>>) -> (i64, i64) {
    seen.map_or((i64::MAX, i64::MIN), |s| {
        (s.since, s.until.saturating_sub(SEEN_SLACK_SECONDS))
    })
}

/// Whether incoming key `k` counts as seen (see [`ProviderSeen`]), with a quote covered
/// when begun between `:since` and `:covered`.
const SEEN: &str = "(k.provider_seen = 1
    OR EXISTS(SELECT 1 FROM ironwood_dynamic_operations o
        WHERE o.receiving_key_id = k.id AND o.request IS NOT NULL
          AND (o.reference IS NOT NULL OR o.begun_at < :since OR o.begun_at > :covered)))";

/// SQL condition on `ironwood_receiving_keys k`: one of its quotes was started.
const STARTED: &str = "EXISTS(SELECT 1 FROM ironwood_dynamic_operations o
    WHERE o.receiving_key_id = k.id AND o.started = 1)";

/// Whether key `key` is open and scanned through the tip without a payment or candidate.
fn scanned_empty(conn: &Connection, key: i64) -> Result<bool, SqliteClientError> {
    let empty: bool = conn.query_row(
        "SELECT active_from IS NOT NULL AND closed_at IS NULL AND used = 0
            AND NOT EXISTS(SELECT 1 FROM ironwood_dynamic_payment_recovery
                WHERE receiving_key_id = ?1)
         FROM ironwood_receiving_keys WHERE id = ?1",
        [key],
        |r| r.get(0),
    )?;
    let tip = wallet::chain_tip_height(conn)?;
    Ok(empty && tip.is_some() && wallet::fully_scanned_height(conn)? == tip)
}

/// The first incoming index seed recovery may not reach: [`RECEIVE_GAP_LIMIT`] past the
/// highest seen index or paid one, whose receipt has the untrusted confirmations so a
/// reorg cannot lower the bound below keys already issued.
fn recovery_end(
    conn: &Connection,
    account: i64,
    coverage: (i64, i64),
) -> Result<u64, SqliteClientError> {
    let confirmed_below = wallet::chain_tip_height(conn)?.map(|tip| {
        u32::from(tip)
            .saturating_add(1)
            .saturating_sub(ConfirmationsPolicy::default().untrusted().get())
    });
    let paid: Option<Vec<u8>> = conn.query_row(
        &format!(
            "SELECT MAX(k.key_index) FROM ironwood_receiving_keys k
             WHERE k.account_id = :account AND k.purpose = 1 AND (k.paid_before_birthday = 1
                 OR {SEEN}
                 OR EXISTS(SELECT 1 FROM ironwood_received_notes n
                     JOIN transactions t ON t.id_tx = n.transaction_id
                     JOIN blocks b ON b.height = t.mined_height
                     WHERE n.receiving_key_id = k.id AND t.mined_height <= :confirmed_below))"
        ),
        named_params![
            ":account": account,
            ":confirmed_below": confirmed_below,
            ":since": coverage.0,
            ":covered": coverage.1,
        ],
        |r| r.get(0),
    )?;
    paid.map(|bytes| decode_index(bytes).and_then(next_index))
        .transpose()?
        .unwrap_or(0)
        .checked_add(RECEIVE_GAP_LIMIT)
        .ok_or(SqliteClientError::DynamicIvkIndexExhausted)
}

/// Releases key `key`'s reservation. Its operations still in progress, only expired
/// unfunded ones by then, expect no receipt.
fn release(conn: &Connection, key: i64, now: i64) -> Result<(), SqliteClientError> {
    conn.execute(
        "UPDATE ironwood_receiving_keys SET released_at = ?2 WHERE id = ?1",
        params![key, now],
    )?;
    conn.execute(
        "UPDATE ironwood_dynamic_operations
         SET expectation = 1, expected_value = NULL, observed_at = MAX(observed_at, ?2)
         WHERE receiving_key_id = ?1 AND request IS NOT NULL AND expectation IN (0, 4)",
        params![key, now],
    )?;
    Ok(())
}

/// Releases key `key`'s reservation and stops scanning it.
fn abandon(conn: &Connection, key: i64, now: i64) -> Result<(), SqliteClientError> {
    release(conn, key, now)?;
    conn.execute(
        "UPDATE ironwood_receiving_keys SET closed_at = ?2 WHERE id = ?1 AND closed_at IS NULL",
        params![key, now],
    )?;
    Ok(())
}

/// Whether unpaid reserved key `key` can be reclaimed at `now`: every quote is past its
/// deadline and the cooldown, and if the reservation was started, each accepted quote
/// has a fresh conclusive status (a refund, once funded). A status from the future is
/// not fresh.
fn reusable(conn: &Connection, key: i64, now: i64) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        &format!(
            "SELECT {RESERVED} AND k.reserved_at <= :now - :reclaim AND k.used = 0
                AND NOT EXISTS(SELECT 1 FROM ironwood_dynamic_operations o
                    WHERE o.receiving_key_id = k.id AND o.request IS NOT NULL AND (
                        o.deadline IS NULL OR o.deadline > :now - :reclaim
                        OR ({STARTED} AND o.reference IS NOT NULL AND NOT (
                            o.observed_at BETWEEN :now - :fresh AND :now
                            AND (o.expectation = 1
                                OR (o.expectation IN (3, 4) AND o.funded = 0))))))
             FROM ironwood_receiving_keys k WHERE k.id = :key"
        ),
        named_params![
            ":key": key,
            ":now": now,
            ":reclaim": RECEIVE_RECLAIM_SECONDS,
            ":fresh": STATUS_FRESH_SECONDS,
        ],
        |r| r.get(0),
    )?)
}

/// Releases `account`'s settled paid reservations and reclaims abandoned unpaid ones
/// scanned empty (see [`reusable`]), whose keys stop scanning. Returns the reclaimed
/// incoming indices.
pub(super) fn reap<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    now: i64,
) -> Result<Vec<u64>, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    // A paid reservation keeps its key's used marker. Its unfunded quote edits finish
    // after the cooldown and a fresh status, and unknown outcomes after the cooldown.
    let paid = conn
        .prepare(&format!(
            "SELECT k.id FROM ironwood_receiving_keys k
             WHERE k.account_id = :account AND k.used = 1 AND {RESERVED}
               AND NOT EXISTS(SELECT 1 FROM ironwood_dynamic_operations o
                 WHERE o.receiving_key_id = k.id AND o.request IS NOT NULL AND (
                   (o.reference IS NULL AND (o.deadline IS NULL OR o.deadline > :now - :reclaim))
                   OR (o.reference IS NOT NULL AND (o.observed_at > :now OR NOT (
                     o.expectation IN (1, 2, 3)
                     OR (o.expectation = 4 AND o.funded = 0
                       AND o.deadline <= :now - :reclaim
                       AND o.observed_at >= :now - :fresh))))))"
        ))?
        .query_map(
            named_params![
                ":account": owner.0,
                ":now": now,
                ":reclaim": RECEIVE_RECLAIM_SECONDS,
                ":fresh": STATUS_FRESH_SECONDS,
            ],
            |r| r.get::<_, i64>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    for key in paid {
        release(conn, key, now)?;
    }
    let open = conn
        .prepare(&format!(
            "SELECT k.id, k.key_index FROM ironwood_receiving_keys k
             WHERE k.account_id = ?1 AND {RESERVED} ORDER BY k.key_index"
        ))?
        .query_map([owner.0], |r| Ok((r.get::<_, i64>(0)?, r.get(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    let mut reclaimed = Vec::new();
    for (key, index) in open {
        if reusable(conn, key, now)? && scanned_empty(conn, key)? {
            abandon(conn, key, now)?;
            reclaimed.push(decode_index(index)?);
        }
    }
    Ok(reclaimed)
}

/// See `WalletDb::begin_receive_operation`, which chooses `request`.
pub(super) fn begin(
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
    let (key, owner, open): (i64, i64, bool) = conn
        .query_row(
            &format!(
                "SELECT k.id, k.account_id, {RESERVED} AND k.used = 0 AND NOT {STARTED}
                 FROM ironwood_receiving_keys k JOIN accounts a ON a.id = k.account_id
                 WHERE a.uuid = ?1 AND k.purpose = 1 AND k.key_index = ?2"
            ),
            params![account.0, index.to_be_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?
        .ok_or_else(|| invalid("unknown receive reservation"))?;
    if !open {
        return Ok(Err(ReservationPolicy::Stale));
    }
    // Without a seen set every quote counts, which only raises the bound.
    if index >= recovery_end(conn, owner, coverage(None))? {
        return Ok(Err(ReservationPolicy::Gap));
    }
    if !scanned_empty(conn, key)? {
        return Ok(Err(ReservationPolicy::Coverage));
    }
    // The provider has the address from here on, so issuance avoids it.
    conn.execute(
        "INSERT INTO ironwood_dynamic_operations
            (receiving_key_id, request, deadline, begun_at, observed_at)
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
        "SELECT o.id FROM ironwood_dynamic_operations o
         JOIN ironwood_receiving_keys k ON k.id = o.receiving_key_id
         JOIN accounts a ON a.id = k.account_id
         WHERE a.uuid = ?1 AND o.request = ?2",
        params![account.0, request],
        |r| r.get(0),
    )
    .optional()?
    .ok_or_else(|| invalid("unknown operation request"))
}

/// See `WalletDb::finish_receive_operation`.
pub(super) fn finish(
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
            let changed = conn.execute(
                "UPDATE ironwood_dynamic_operations
                 SET reference = ?2, memo = ?3, deadline = MIN(deadline, ?4)
                 WHERE id = ?1 AND (reference IS NULL OR reference = ?2)",
                params![id, deposit.address, deposit.memo, deposit.deadline],
            )?;
            if changed != 1 {
                return Err(invalid("operation deposit address changed"));
            }
        }
        // A provider that rejected every request never saw the address.
        OperationOutcome::Rejected => {
            conn.execute(
                "DELETE FROM ironwood_dynamic_operations WHERE id = ?1 AND reference IS NULL",
                [id],
            )?;
        }
    }
    Ok(())
}

/// See `WalletDb::start_receive_operation`.
pub(super) fn start(
    conn: &rusqlite::Transaction<'_>,
    account: AccountUuid,
    request: &str,
) -> Result<Result<ReceiveDeposit, ReservationPolicy>, SqliteClientError> {
    let id = operation(conn, account, request)?;
    let deposit = conn
        .query_row(
            &format!(
                "SELECT o.reference, o.memo, o.deadline FROM ironwood_dynamic_operations o
                 JOIN ironwood_receiving_keys k ON k.id = o.receiving_key_id
                 WHERE o.id = ?1 AND o.reference IS NOT NULL AND o.deadline IS NOT NULL
                   AND {RESERVED}"
            ),
            [id],
            |r| {
                Ok(ReceiveDeposit {
                    address: r.get(0)?,
                    memo: r.get(1)?,
                    deadline: r.get(2)?,
                })
            },
        )
        .optional()?;
    let Some(deposit) = deposit else {
        return Ok(Err(ReservationPolicy::Stale));
    };
    conn.execute(
        "UPDATE ironwood_dynamic_operations SET started = 1 WHERE id = ?1",
        [id],
    )?;
    Ok(Ok(deposit))
}

/// See `WalletDb::record_operation_status`. An incoming operation is updated only while
/// its reservation is open.
pub(super) fn record_status<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    (deposit, memo): (&str, Option<&str>),
    observation: Observation,
    funded: bool,
    now: i64,
) -> Result<bool, SqliteClientError> {
    if deposit.is_empty() {
        return Err(invalid("empty deposit address"));
    }
    let operations = conn
        .prepare(&format!(
            "SELECT o.id, k.id, k.purpose = 0 AND k.active_from IS NULL, k.scan_from
             FROM ironwood_dynamic_operations o
             JOIN ironwood_receiving_keys k ON k.id = o.receiving_key_id
             JOIN accounts a ON a.id = k.account_id
             WHERE a.uuid = ?1 AND o.reference = ?2 AND o.memo IS ?3
               AND (k.purpose = 0 OR {RESERVED})"
        ))?
        .query_map(params![account.0, deposit, memo], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?
        .collect::<Result<Vec<(i64, i64, bool, u32)>, _>>()?;
    let refund_owed = matches!(observation.status, Terminal(Positive(_) | Unknown));
    for &(id, key, unstarted_refund, scan_from) in &operations {
        if unstarted_refund && refund_owed {
            // A refund key whose restore sweep is pending starts when the sweep finishes.
            activate(conn, key, BlockHeight::from(scan_from))?;
        }
        record(conn, id, observation, funded, now)?;
    }
    reap(conn, params, account, now)?;
    Ok(!operations.is_empty())
}

/// See `WalletDb::prepare_receive_reservation`: resumes the draft, or reserves the lowest
/// index never quoted, or else the lowest abandoned one, scanning it from `scan_from`.
pub(super) fn prepare<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    now: i64,
    scan_from: BlockHeight,
    seen: Option<&ProviderSeen<'_>>,
) -> Result<Result<DynamicKey, ReservationPolicy>, SqliteClientError> {
    let (a, _) = account_key(conn, params, account)?;
    let sweeping: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_dynamic_sweeps s
        JOIN ironwood_receiving_keys k ON k.id = s.receiving_key_id
        WHERE k.account_id = ?1 AND k.purpose = 1 AND s.done_height IS NULL)",
        [a.0],
        |r| r.get(0),
    )?;
    if sweeping {
        return Ok(Err(ReservationPolicy::Gap));
    }
    if let Some(seen) = seen {
        record_seen(conn, a.0, seen)?;
    }
    let coverage = coverage(seen);
    let end = recovery_end(conn, a.0, coverage)?;
    // A received address is permanently excluded, even if later spent or rewound.
    let draft: Option<(i64, Vec<u8>, bool)> = conn
        .query_row(
            &format!(
                "SELECT k.id, k.key_index, {SEEN} FROM ironwood_receiving_keys k
                 WHERE k.account_id = :account AND {RESERVED} AND k.used = 0 AND NOT {STARTED}
                 ORDER BY k.reserved_at, k.id LIMIT 1"
            ),
            named_params![":account": a.0, ":since": coverage.0, ":covered": coverage.1],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    match draft {
        Some((key, index, false)) => {
            if decode_index(index)? >= end {
                return Ok(Err(ReservationPolicy::Gap));
            }
            return key_by_id(conn, params, account, key).map(Ok);
        }
        // The provider has the draft's address from an earlier review, so the next swap
        // gets another. Its funding instructions were never shown, so nothing can pay it
        // and its key stops scanning.
        Some((key, _, true)) => abandon(conn, key, now)?,
        None => {}
    }
    // An address the provider was given without seeing it, such as a request that never
    // reached it, is reissued only when the gap rule leaves no fresh one.
    let mut abandoned = None;
    let mut fresh = None;
    for index in 0..end {
        let (blocked, quoted): (bool, bool) = conn
            .query_row(
                &format!(
                    "SELECT k.used = 1 OR {SEEN} OR {RESERVED}
                          OR EXISTS(SELECT 1 FROM ironwood_dynamic_payment_recovery p
                            WHERE p.receiving_key_id = k.id),
                        EXISTS(SELECT 1 FROM ironwood_dynamic_operations o
                            WHERE o.receiving_key_id = k.id AND o.request IS NOT NULL)
                     FROM ironwood_receiving_keys k
                     WHERE k.account_id = :account AND k.purpose = 1 AND k.key_index = :index"
                ),
                named_params![
                    ":account": a.0,
                    ":index": index.to_be_bytes(),
                    ":since": coverage.0,
                    ":covered": coverage.1,
                ],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .unwrap_or_default();
        if blocked {
            continue;
        }
        if !quoted {
            fresh = Some(index);
            break;
        }
        abandoned.get_or_insert(index);
    }
    let Some(index) = fresh.or(abandoned) else {
        return Ok(Err(ReservationPolicy::Limit));
    };
    let (key, registered) = register(
        conn,
        params,
        account,
        KeyId::new(Purpose::Receive, index),
        scan_from,
        true,
        super::Discovery::Scan,
        now,
    )?;
    conn.execute(
        "UPDATE ironwood_receiving_keys SET reserved_at = ?2, released_at = NULL WHERE id = ?1",
        params![key, now],
    )?;
    Ok(Ok(registered))
}

/// Records which of `account`'s quoted incoming keys `seen` holds.
fn record_seen(
    conn: &Connection,
    account: i64,
    seen: &ProviderSeen<'_>,
) -> Result<(), SqliteClientError> {
    let mut stmt = conn.prepare(
        "SELECT k.id, k.receiver FROM ironwood_receiving_keys k
         WHERE k.account_id = ?1 AND k.purpose = 1 AND k.provider_seen = 0
           AND EXISTS(SELECT 1 FROM ironwood_dynamic_operations o
               WHERE o.receiving_key_id = k.id AND o.request IS NOT NULL)",
    )?;
    let keys = stmt
        .query_map([account], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let receivers = keys
        .iter()
        .map(|(_, receiver)| {
            <[u8; 43]>::try_from(receiver.as_slice()).map_err(|_| corrupt("invalid receiver"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let hits = (seen.contains)(&receivers);
    if hits.len() != keys.len() {
        return Err(invalid(
            "seen set answered for the wrong number of receivers",
        ));
    }
    for ((id, _), hit) in keys.iter().zip(hits) {
        if hit {
            conn.execute(
                "UPDATE ironwood_receiving_keys SET provider_seen = 1 WHERE id = ?1",
                [id],
            )?;
        }
    }
    Ok(())
}
