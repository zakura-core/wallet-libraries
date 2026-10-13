//! Incoming reservations, which live on their key's row, and their quote operations.
use orchard::keys::Scope;
use rusqlite::{Connection, OptionalExtension, named_params, params};
use zakura_one_time_ivk::swap::{
    Observation,
    OperationStatus::Terminal,
    ReceiptExpectation::{Positive, Unknown},
};
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_protocol::consensus::{BlockHeight, Parameters};

use super::{RESERVED, ReservationPolicy, lifecycle::record};
use crate::wallet::one_time_ivk::{
    Discovery, KeyId, OneTimeKey, Purpose, account_key, activate, corrupt, decode_index,
    index_after, invalid, key_by_id, register, restore_start,
};
use crate::{AccountUuid, error::SqliteClientError, wallet};

/// Incoming seed recovery searches at least this many consecutive empty indices, and
/// issuance stays within this many indices of the highest paid or seen one.
pub const RECEIVE_GAP_LIMIT: u64 = 30;
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
/// if the provider accepted a quote for it (an accepted quote is always in the set) or
/// rejected one (the request still gave it the address), or if a quote for it falls
/// outside the set's read, widened by [`SEEN_SLACK_SECONDS`]. Without a set, every quote
/// counts. An
/// address the set holds or with an accepted quote moves the recovery gap like a paid
/// one, since a restore walks past the addresses the set holds; one only assumed seen
/// does not. The set's answers are kept, so a later set that lacks an address cannot make
/// it issuable again.
///
/// A refund address the set holds is never issued either, which covers one an unfunded
/// quote used, since no funding memo recovers it. An address another device of the same
/// seed quoted is known only through the set, so one quoted within the feed's read lag
/// before a restore can still be issued again.
///
/// An app can fill it from a receiver directory's `Seen`, which
/// `zakura_pir_receiver::fetch_seen` downloads.
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

impl ProviderSeen<'_> {
    /// Whether the set holds `receiver`. An answer for any number of receivers but one is
    /// refused, so a malformed answer cannot make a seen address issuable.
    pub(in crate::wallet::one_time_ivk) fn holds(
        &self,
        receiver: &orchard::Address,
    ) -> Result<bool, SqliteClientError> {
        match (self.contains)(&[receiver.to_raw_address_bytes()])[..] {
            [hit] => Ok(hit),
            _ => Err(wrong_answer_count()),
        }
    }
}

/// The error for a seen set that answered for the wrong number of receivers.
fn wrong_answer_count() -> SqliteClientError {
    invalid("seen set answered for the wrong number of receivers")
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

/// The local quote times `seen` covers, as `SEEN`'s bounds; without a set, none.
fn coverage(seen: Option<&ProviderSeen<'_>>) -> (i64, i64) {
    seen.map_or((i64::MAX, i64::MIN), |s| {
        (
            s.since.saturating_add(SEEN_SLACK_SECONDS),
            s.until.saturating_sub(SEEN_SLACK_SECONDS),
        )
    })
}

/// Whether incoming key `k` counts as seen (see [`ProviderSeen`]), with a quote covered
/// when begun between `:since` and `:covered`.
const SEEN: &str = "(k.provider_seen = 1
    OR EXISTS(SELECT 1 FROM ironwood_one_time_operations o
        WHERE o.one_time_key_id = k.id AND o.request IS NOT NULL
          AND (o.reference IS NOT NULL OR o.rejected = 1
            OR o.begun_at < :since OR o.begun_at > :covered)))";

/// SQL condition on `ironwood_one_time_keys k`: one of its quotes was started.
pub(in crate::wallet::one_time_ivk) const STARTED: &str =
    "EXISTS(SELECT 1 FROM ironwood_one_time_operations o
    WHERE o.one_time_key_id = k.id AND o.started = 1)";

/// Whether key `key` is open and scanned through the tip without a payment or candidate.
fn scanned_empty(conn: &Connection, key: i64) -> Result<bool, SqliteClientError> {
    let empty: bool = conn.query_row(
        "SELECT active_from IS NOT NULL AND closed_at IS NULL AND used = 0
            AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery
                WHERE one_time_key_id = ?1)
         FROM ironwood_one_time_keys WHERE id = ?1",
        [key],
        |r| r.get(0),
    )?;
    let tip = wallet::chain_tip_height(conn)?;
    Ok(empty && tip.is_some() && wallet::fully_scanned_height(conn)? == tip)
}

/// The first incoming index seed recovery may not reach: [`RECEIVE_GAP_LIMIT`] past the
/// highest index a restore walks past, one the provider saw (in a seen set, or by
/// accepting a quote) or paid with a receipt that has the untrusted confirmations, so a
/// reorg cannot lower the bound below keys already issued. A quote only assumed seen
/// (see [`ProviderSeen`]) is not reissued, but does not move the bound.
fn recovery_end(conn: &Connection, account: i64) -> Result<u64, SqliteClientError> {
    let confirmed_below = wallet::chain_tip_height(conn)?.map(|tip| {
        u32::from(tip)
            .saturating_add(1)
            .saturating_sub(ConfirmationsPolicy::default().untrusted().get())
    });
    let paid: Option<Vec<u8>> = conn.query_row(
        "SELECT MAX(k.key_index) FROM ironwood_one_time_keys k
         WHERE k.account_id = :account AND k.purpose = 1 AND (k.paid_before_birthday = 1
             OR k.provider_seen = 1
             OR EXISTS(SELECT 1 FROM ironwood_one_time_operations o
                 WHERE o.one_time_key_id = k.id AND o.reference IS NOT NULL)
             OR EXISTS(SELECT 1 FROM ironwood_received_notes n
                 JOIN transactions t ON t.id_tx = n.transaction_id
                 JOIN blocks b ON b.height = t.mined_height
                 WHERE n.one_time_key_id = k.id AND t.mined_height <= :confirmed_below))",
        named_params![":account": account, ":confirmed_below": confirmed_below],
        |r| r.get(0),
    )?;
    let next = paid
        .map(|bytes| index_after(decode_index(bytes)?, 1))
        .transpose()?
        .unwrap_or(0);
    index_after(next, RECEIVE_GAP_LIMIT)
}

/// Releases key `key`'s reservation. Its operations still in progress, only expired
/// unfunded ones by then, expect no receipt.
fn release(conn: &Connection, key: i64, now: i64) -> Result<(), SqliteClientError> {
    conn.execute(
        "UPDATE ironwood_one_time_keys SET released_at = ?2 WHERE id = ?1",
        params![key, now],
    )?;
    conn.execute(
        "UPDATE ironwood_one_time_operations
         SET expectation = 1, expected_value = NULL, observed_at = MAX(observed_at, ?2)
         WHERE one_time_key_id = ?1 AND request IS NOT NULL AND expectation IN (0, 4)",
        params![key, now],
    )?;
    Ok(())
}

/// Releases key `key`'s reservation and stops scanning it.
fn abandon(conn: &Connection, key: i64, now: i64) -> Result<(), SqliteClientError> {
    release(conn, key, now)?;
    conn.execute(
        "UPDATE ironwood_one_time_keys SET closed_at = ?2 WHERE id = ?1 AND closed_at IS NULL",
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
                AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_operations o
                    WHERE o.one_time_key_id = k.id AND o.request IS NOT NULL AND (
                        o.deadline > :now - :reclaim
                        OR ({STARTED} AND o.reference IS NOT NULL AND NOT (
                            o.observed_at BETWEEN :now - :fresh AND :now
                            AND (o.expectation = 1
                                OR (o.expectation IN (3, 4) AND o.funded = 0))))))
             FROM ironwood_one_time_keys k WHERE k.id = :key"
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
pub(in crate::wallet::one_time_ivk) fn reap<P: Parameters>(
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
            "SELECT k.id FROM ironwood_one_time_keys k
             WHERE k.account_id = :account AND k.used = 1 AND {RESERVED}
               AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_operations o
                 WHERE o.one_time_key_id = k.id AND o.request IS NOT NULL AND (
                   (o.reference IS NULL AND o.deadline > :now - :reclaim)
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
            "SELECT k.id, k.key_index FROM ironwood_one_time_keys k
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
    let (key, owner, open): (i64, i64, bool) = conn
        .query_row(
            &format!(
                "SELECT k.id, k.account_id, {RESERVED} AND k.used = 0 AND NOT {STARTED}
                 FROM ironwood_one_time_keys k JOIN accounts a ON a.id = k.account_id
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
    if index >= recovery_end(conn, owner)? {
        return Ok(Err(ReservationPolicy::Gap));
    }
    if !scanned_empty(conn, key)? {
        return Ok(Err(ReservationPolicy::Coverage));
    }
    // The provider has the address from here on, so issuance avoids it.
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
                 SET reference = ?2, memo = ?3, deadline = MIN(deadline, ?4)
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
) -> Result<Result<ReceiveDeposit, ReservationPolicy>, SqliteClientError> {
    let id = operation(conn, account, request)?;
    let deposit = conn
        .query_row(
            &format!(
                "SELECT o.reference, o.memo, o.deadline FROM ironwood_one_time_operations o
                 JOIN ironwood_one_time_keys k ON k.id = o.one_time_key_id
                 WHERE o.id = ?1 AND o.reference IS NOT NULL AND {RESERVED}"
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
            "SELECT o.id, k.id,
                k.purpose = 0 AND k.active_from IS NULL AND k.closed_at IS NULL, k.scan_from
             FROM ironwood_one_time_operations o
             JOIN ironwood_one_time_keys k ON k.id = o.one_time_key_id
             JOIN accounts a ON a.id = k.account_id
             WHERE a.uuid = ?1 AND o.reference = ?2 AND o.memo IS ?3
               AND (k.purpose = 0 OR {RESERVED} OR (k.used = 1 AND (o.funded = 1 OR ?4)))"
        ))?
        .query_map(params![account.0, deposit, memo, observation.funded], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?
        .collect::<Result<Vec<(i64, i64, bool, u32)>, _>>()?;
    let refund_owed = matches!(observation.status, Terminal(Positive(_) | Unknown));
    for &(id, key, unstarted_refund, scan_from) in &operations {
        if record(conn, id, observation, now)? && unstarted_refund && refund_owed {
            // A refund key whose restore sweep is pending starts when the sweep finishes
            // (see `restore::sweep::finish`).
            activate(conn, key, BlockHeight::from(scan_from))?;
        }
    }
    reap(conn, params, account, now)?;
    Ok(!operations.is_empty())
}

/// See `WalletDb::prepare_receive_reservation`: resumes the draft, or reserves the lowest
/// index never quoted, or else the lowest abandoned one, scanning it from `scan_from`.
pub(in crate::wallet::one_time_ivk) fn prepare<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    now: i64,
    scan_from: BlockHeight,
    seen: Option<&ProviderSeen<'_>>,
) -> Result<Result<OneTimeKey, ReservationPolicy>, SqliteClientError> {
    let (a, parent) = account_key(conn, params, account)?;
    let sweeping: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_sweeps s
        JOIN ironwood_one_time_keys k ON k.id = s.one_time_key_id
        WHERE k.account_id = ?1 AND k.purpose = 1 AND s.done_height IS NULL)",
        [a.0],
        |r| r.get(0),
    )?;
    if sweeping {
        return Ok(Err(ReservationPolicy::Gap));
    }
    let coverage = coverage(seen);
    let end = recovery_end(conn, a.0)?;
    // A received address is permanently excluded, even if later spent or rewound.
    let draft: Option<(i64, Vec<u8>, bool)> = conn
        .query_row(
            &format!(
                "SELECT k.id, k.key_index, {SEEN} FROM ironwood_one_time_keys k
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
        let row: Option<(bool, bool)> = conn
            .query_row(
                &format!(
                    "SELECT k.used = 1 OR {SEEN} OR {RESERVED}
                          OR EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery p
                            WHERE p.one_time_key_id = k.id),
                        EXISTS(SELECT 1 FROM ironwood_one_time_operations o
                            WHERE o.one_time_key_id = k.id AND o.request IS NOT NULL)
                     FROM ironwood_one_time_keys k
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
            .optional()?;
        // `record_seen` checked every registered key, so check an unregistered one here. A
        // hit is registered for a restore sweep, since its quote may have been paid.
        let Some((blocked, quoted)) = row else {
            let key_id = KeyId::new(Purpose::Receive, index);
            let receiver = key_id.derive(&parent)?.address_at(0u32, Scope::External);
            if seen.map(|s| s.holds(&receiver)).transpose()? == Some(true) {
                let from = restore_start(conn, params, a)?;
                let (id, _) = register(
                    conn,
                    params,
                    account,
                    key_id,
                    from,
                    false,
                    Discovery::Sweep,
                    now,
                )?;
                record_provider_seen(conn, id)?;
                continue;
            }
            fresh = Some(index);
            break;
        };
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
        Discovery::Scan,
        now,
    )?;
    conn.execute(
        "UPDATE ironwood_one_time_keys SET reserved_at = ?2, released_at = NULL WHERE id = ?1",
        params![key, now],
    )?;
    Ok(Ok(registered))
}

/// Records which of `account`'s unseen incoming keys `seen` holds.
pub(in crate::wallet::one_time_ivk) fn record_seen(
    conn: &Connection,
    account: i64,
    seen: &ProviderSeen<'_>,
) -> Result<(), SqliteClientError> {
    let mut stmt = conn.prepare(
        "SELECT k.id, k.receiver FROM ironwood_one_time_keys k
         WHERE k.account_id = ?1 AND k.purpose = 1 AND k.provider_seen = 0",
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
        return Err(wrong_answer_count());
    }
    for ((id, _), hit) in keys.iter().zip(hits) {
        if hit {
            record_provider_seen(conn, *id)?;
        }
    }
    Ok(())
}

/// Records that a swap provider was given key `id`'s receiver. The key is never issued
/// again; an incoming one, like a paid one, extends the restore walk and the gap (see
/// [`recovery_end`]). Nothing clears this.
pub(in crate::wallet::one_time_ivk) fn record_provider_seen(
    conn: &Connection,
    id: i64,
) -> Result<(), SqliteClientError> {
    conn.execute(
        "UPDATE ironwood_one_time_keys
         SET provider_seen = 1, advances_allocation = 1 WHERE id = ?1",
        [id],
    )?;
    Ok(())
}
