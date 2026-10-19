//! Incoming reservations, which live on their key's row, and their quote operations, and
//! the issuance rules both purposes share.
use orchard::keys::Scope;
use rusqlite::{Connection, OptionalExtension, named_params, params};
use zakura_one_time_ivk::swap::{Observation, provider_read_is_current};
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_protocol::consensus::{BlockHeight, Parameters};

use super::{CURRENT, RESERVED, ReservationPolicy, lifecycle::record};
use crate::wallet::one_time_ivk::{
    Discovery, KeyId, OneTimeKey, Purpose, account_key, authenticate_key, block_issuance,
    block_recovery, block_recovery::advanced, corrupt, decode_index, index_after, invalid,
    key_by_id, purpose_code, register, restore_start,
};
use crate::{AccountUuid, error::SqliteClientError, wallet};

/// Seed recovery searches at least this many consecutive empty indices of each purpose,
/// and issuance stays within this many indices of the highest one with evidence (see the
/// [issuance rules](super#issuance)).
pub const RECEIVE_GAP_LIMIT: u64 = 30;
/// Grace after the last deposit deadline before an unpaid reservation can be reclaimed,
/// for a late status report and clock differences.
pub const RECEIVE_RECLAIM_SECONDS: i64 = 2 * 60 * 60;
/// How recent a status must be to reclaim a started reservation.
const STATUS_FRESH_SECONDS: i64 = 120;

/// A swap provider's seen set, as a receiver directory publishes it: every receiver the
/// provider was given up to `until`, in a set that only grows.
///
/// An address of either purpose that the set holds and this wallet never exposed was
/// given to the provider by another device of the seed, so it is never issued here. That
/// is known only through the set, so issuing an address, or quoting a reservation for
/// the first time, needs a fresh set: one whose `until` is within
/// [`zakura_one_time_ivk::swap::provider_read_is_current`]'s bounds of the caller's
/// clock. One quoted elsewhere after that read can still be issued again. Every address
/// the set holds moves the issuance bound, since a restore walks past them (see the
/// [issuance rules](super#issuance)). The set's answers are kept, so a later set that
/// lacks an address cannot undo them.
///
/// An app can fill it from a receiver directory's `Seen`, which
/// `zakura_pir_receiver::fetch_seen` downloads.
pub struct ProviderSeen<'a> {
    /// Earliest provider history included by the validated capture.
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
        receiver: &[u8; 43],
    ) -> Result<bool, SqliteClientError> {
        match (self.contains)(&[*receiver])[..] {
            [hit] => Ok(hit),
            _ => Err(wrong_answer_count()),
        }
    }
}

/// `seen` if its read is current at `now`, the caller's wall clock (see
/// [`provider_read_is_current`]), or else [`ReservationPolicy::SeenUnavailable`].
pub(in crate::wallet::one_time_ivk) fn fresh_seen<'a, 's>(
    seen: Option<&'a ProviderSeen<'s>>,
    now: i64,
) -> Result<&'a ProviderSeen<'s>, ReservationPolicy> {
    seen.filter(|s| provider_read_is_current(s.until, now))
        .ok_or(ReservationPolicy::SeenUnavailable)
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

/// Whether incoming key `k`'s address is known to the provider whatever later sets say: a
/// set held it, or the provider accepted or rejected a quote for it.
const GIVEN: &str = "(k.provider_seen = 1
    OR EXISTS(SELECT 1 FROM ironwood_one_time_operations o
        WHERE o.one_time_key_id = k.id AND o.request IS NOT NULL
          AND (o.reference IS NOT NULL OR o.rejected = 1)))";

/// The deadline of the latest request on key `k`'s current reservation, the accepted one
/// or else the requested one, or NULL if none was begun. A reissued key keeps its earlier
/// reservations' requests, so the current one's are those above its `reservation_floor`.
/// A NULL floor counts every request on the key, so a reservation made before the floor
/// existed is never mistaken for one never quoted.
pub(in crate::wallet::one_time_ivk) const LATEST_DEADLINE: &str =
    "(SELECT o.deadline FROM ironwood_one_time_operations o
    WHERE o.one_time_key_id = k.id AND o.request IS NOT NULL
      AND o.id > IFNULL(k.reservation_floor, 0)
    ORDER BY o.id DESC LIMIT 1)";

/// SQL condition on `ironwood_one_time_keys k`: one of its quotes was started.
pub(in crate::wallet::one_time_ivk) const STARTED: &str =
    "EXISTS(SELECT 1 FROM ironwood_one_time_operations o
    WHERE o.one_time_key_id = k.id AND o.started = 1)";

/// Reuse requires current historical filters and no known payment or pending candidate.
pub(in crate::wallet::one_time_ivk) fn scanned_empty(
    conn: &Connection,
    key: i64,
) -> Result<bool, SqliteClientError> {
    let tip = wallet::chain_tip_height(conn)?.map(u32::from);
    Ok(conn.query_row("SELECT k.used=0 AND r.enabled=1 AND r.needs_prepare=0 AND r.archive IS NOT NULL
        AND v.next_height>?2
        AND NOT EXISTS(SELECT 1 FROM ironwood_block_matches m WHERE m.account_id=k.account_id AND m.purpose=k.purpose AND m.key_index=k.key_index)
        AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery p WHERE p.one_time_key_id=k.id)
        FROM ironwood_one_time_keys k JOIN ironwood_block_recovery r ON r.account_id=k.account_id
        JOIN ironwood_block_receivers v ON v.account_id=k.account_id AND v.purpose=k.purpose AND v.key_index=k.key_index WHERE k.id=?1",
        params![key,tip], |r|r.get::<_,Option<bool>>(0))?.unwrap_or(false))
}

/// The issuance bound of `account`'s keys of purpose code `purpose`, the first index
/// issuance may not reach (see the [issuance rules](super#issuance)): [`RECEIVE_GAP_LIMIT`]
/// past the highest index a restore walks past, one the provider saw (in a seen set, or by
/// accepting a quote) or paid with a receipt that has the untrusted confirmations, so a
/// reorg cannot lower the bound below keys already issued.
pub(in crate::wallet::one_time_ivk) fn issuance_end(
    conn: &Connection,
    account: i64,
    purpose: u8,
) -> Result<u64, SqliteClientError> {
    let confirmed_below = wallet::chain_tip_height(conn)?.map(|tip| {
        u32::from(tip)
            .saturating_add(1)
            .saturating_sub(ConfirmationsPolicy::default().untrusted().get())
    });
    let paid: Option<Vec<u8>> = conn.query_row(
        "SELECT MAX(k.key_index) FROM ironwood_one_time_keys k
         WHERE k.account_id = :account AND k.purpose = :purpose AND (k.paid_before_birthday = 1
             OR k.provider_seen = 1
             OR EXISTS(SELECT 1 FROM ironwood_one_time_operations o
                 WHERE o.one_time_key_id = k.id AND o.reference IS NOT NULL)
             OR EXISTS(SELECT 1 FROM ironwood_received_notes n
                 JOIN transactions t ON t.id_tx = n.transaction_id
                 JOIN blocks b ON b.height = t.mined_height
                 WHERE n.one_time_key_id = k.id AND t.mined_height <= :confirmed_below))",
        named_params![
            ":account": account,
            ":purpose": purpose,
            ":confirmed_below": confirmed_below
        ],
        |r| r.get(0),
    )?;
    let next = paid
        .map(|bytes| index_after(decode_index(bytes)?, 1))
        .transpose()?
        .unwrap_or(0);
    index_after(next, RECEIVE_GAP_LIMIT)
}

/// Releases incoming key `key`'s reservation, which retires its requests (see
/// [`CURRENT`]). Its operations still in progress, only expired unfunded ones by then,
/// expect no receipt.
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

/// Retires a never-quoted reservation whose receiver appeared in provider history.
/// Its payment discovery remains a filter obligation, without inventing a local watch.
fn retire(conn: &rusqlite::Transaction<'_>, key: i64, now: i64) -> Result<(), SqliteClientError> {
    record_provider_seen(conn, key)?;
    release(conn, key, now)
}

/// Checks reservation `key` of purpose code `purpose`, with `receiver`, before its first
/// request: refused without a `seen` set fresh at `now`. If the provider has an address
/// this wallet never exposed, another device gave it out, so an incoming reservation is
/// retired (see [`retire`]) and a refund key recorded seen, and neither is issued again.
/// Returns whether it can still be quoted.
pub(in crate::wallet::one_time_ivk) fn check_unquoted(
    conn: &rusqlite::Transaction<'_>,
    (key, purpose): (i64, u8),
    receiver: &[u8; 43],
    provider_seen: bool,
    seen: Option<&ProviderSeen<'_>>,
    now: i64,
) -> Result<Result<bool, ReservationPolicy>, SqliteClientError> {
    let exposed = exposed(conn, key)?;
    if !provider_seen || exposed {
        let seen = match fresh_seen(seen, now) {
            Ok(seen) => seen,
            Err(policy) => return Ok(Err(policy)),
        };
        if exposed || !seen.holds(receiver)? {
            return Ok(Ok(true));
        }
    }
    if purpose == 1 {
        retire(conn, key, now)?;
    } else {
        record_provider_seen(conn, key)?;
    }
    Ok(Ok(false))
}

/// Whether a request of this wallet's ever exposed key `key`'s address.
fn exposed(conn: &Connection, key: i64) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_operations
             WHERE one_time_key_id = ?1 AND request IS NOT NULL)",
        [key],
        |r| r.get(0),
    )?)
}

/// Whether operation `id` is a request of its key's open reservation (see [`CURRENT`]).
pub(in crate::wallet::one_time_ivk) fn current(
    conn: &Connection,
    id: i64,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        &format!(
            "SELECT {CURRENT} FROM ironwood_one_time_operations o
             JOIN ironwood_one_time_keys k ON k.id = o.one_time_key_id WHERE o.id = ?1"
        ),
        [id],
        |r| r.get(0),
    )?)
}

/// A stored receiver's bytes.
pub(in crate::wallet::one_time_ivk) fn receiver_bytes(
    receiver: &[u8],
) -> Result<[u8; 43], SqliteClientError> {
    <[u8; 43]>::try_from(receiver).map_err(|_| corrupt("invalid receiver"))
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

/// The earlier of `now` and the latest block time. A provider sets deadlines by its own
/// clock, so they are compared with this, which a fast device clock cannot move ahead.
fn deadline_clock(conn: &Connection, now: i64) -> Result<i64, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT MIN(?1, IFNULL((SELECT time FROM blocks ORDER BY height DESC LIMIT 1), ?1))",
        [now],
        |r| r.get(0),
    )?)
}

/// Whether unpaid reserved key `key` can be reclaimed at `now`: every quote is past its
/// deadline at `deadline_now` (see [`deadline_clock`]) and the cooldown, and if the
/// reservation was started, each accepted quote has a fresh conclusive status (a refund,
/// once funded). A status from the future is not fresh.
fn reusable(
    conn: &Connection,
    key: i64,
    now: i64,
    deadline_now: i64,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        &format!(
            "SELECT {RESERVED} AND k.reserved_at <= :now - :reclaim AND k.used = 0
                AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_operations o
                    WHERE o.one_time_key_id = k.id AND o.request IS NOT NULL AND (
                        o.deadline > :deadline_now - :reclaim
                        OR ({STARTED} AND o.reference IS NOT NULL AND NOT (
                            o.observed_at BETWEEN :now - :fresh AND :now
                            AND (o.expectation = 1
                                OR (o.expectation IN (3, 4) AND o.funded = 0))))))
             FROM ironwood_one_time_keys k WHERE k.id = :key"
        ),
        named_params![
            ":key": key,
            ":now": now,
            ":deadline_now": deadline_now,
            ":reclaim": RECEIVE_RECLAIM_SECONDS,
            ":fresh": STATUS_FRESH_SECONDS,
        ],
        |r| r.get(0),
    )?)
}

/// Releases `account`'s settled paid reservations and reclaims abandoned unpaid ones
/// scanned empty (see [`reusable`]), whose keys stop scanning. One never quoted whose
/// address the provider has is retired instead (see [`retire`]). Returns the reclaimed
/// incoming indices.
pub(in crate::wallet::one_time_ivk) fn reap<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    now: i64,
) -> Result<Vec<u64>, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    let deadline_now = deadline_clock(conn, now)?;
    // A paid reservation keeps its key's used marker. Its unfunded quote edits finish
    // after the cooldown and a fresh status, and unknown outcomes after the cooldown.
    let paid = conn
        .prepare(&format!(
            "SELECT k.id FROM ironwood_one_time_keys k
             WHERE k.account_id = :account AND k.purpose = 1 AND k.used = 1 AND {RESERVED}
               AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_operations o
                 WHERE o.one_time_key_id = k.id AND o.request IS NOT NULL AND (
                   (o.reference IS NULL AND o.deadline > :deadline_now - :reclaim)
                   OR (o.reference IS NOT NULL AND (o.observed_at > :now OR NOT (
                     o.expectation IN (1, 2, 3)
                     OR (o.expectation = 4 AND o.funded = 0
                       AND o.deadline <= :deadline_now - :reclaim
                       AND o.observed_at >= :now - :fresh))))))"
        ))?
        .query_map(
            named_params![
                ":account": owner.0,
                ":now": now,
                ":deadline_now": deadline_now,
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
            "SELECT k.id, k.key_index, k.provider_seen = 1 AND {LATEST_DEADLINE} IS NULL
             FROM ironwood_one_time_keys k
             WHERE k.account_id = ?1 AND k.purpose = 1 AND {RESERVED} ORDER BY k.key_index"
        ))?
        .query_map([owner.0], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<Result<Vec<(i64, Vec<u8>, bool)>, _>>()?;
    let mut reclaimed = Vec::new();
    for (key, index, held) in open {
        if reusable(conn, key, now, deadline_now)? && scanned_empty(conn, key)? {
            if held {
                retire(conn, key, now)?;
            } else {
                abandon(conn, key, now)?;
                reclaimed.push(decode_index(index)?);
            }
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
    seen: Option<&ProviderSeen<'_>>,
) -> Result<Result<(), ReservationPolicy>, SqliteClientError> {
    if !super::enabled(conn, account)? {
        return Ok(Err(ReservationPolicy::Gap));
    }
    if request.is_empty() {
        return Err(invalid("empty operation request"));
    }
    if now < 0 || deadline <= now {
        return Err(invalid("operation deadline has passed"));
    }
    let (key, owner, open, provider_seen, receiver, latest): (
        i64,
        i64,
        bool,
        bool,
        Vec<u8>,
        Option<i64>,
    ) = conn
        .query_row(
            &format!(
                "SELECT k.id, k.account_id, {RESERVED} AND k.used = 0 AND NOT {STARTED},
                    k.provider_seen, k.receiver, {LATEST_DEADLINE}
                 FROM ironwood_one_time_keys k JOIN accounts a ON a.id = k.account_id
                 WHERE a.uuid = ?1 AND k.purpose = 1 AND k.key_index = ?2"
            ),
            params![account.0, index.to_be_bytes()],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| invalid("unknown receive reservation"))?;
    if !open {
        return Ok(Err(ReservationPolicy::Stale));
    }
    match latest {
        // The attempt expired, so the next one prepares another address.
        Some(latest) if latest <= deadline_clock(conn, now)? => {
            return Ok(Err(ReservationPolicy::Stale));
        }
        Some(_) => {}
        None => {
            let receiver = receiver_bytes(&receiver)?;
            match check_unquoted(conn, (key, 1), &receiver, provider_seen, seen, now)? {
                Ok(true) => {}
                Ok(false) => return Ok(Err(ReservationPolicy::Stale)),
                Err(policy) => return Ok(Err(policy)),
            }
        }
    }
    if index >= issuance_end(conn, owner, 1)? {
        return Ok(Err(ReservationPolicy::Gap));
    }
    if !scanned_empty(conn, key)? {
        return Ok(Err(ReservationPolicy::Coverage));
    }
    // The address is exposed from here on, so reissuing it waits for the request to end.
    conn.execute(
        "INSERT INTO ironwood_one_time_operations
            (one_time_key_id, request, deadline, begun_at, observed_at,local_watch_deadline)
         VALUES (?1, ?2, ?3, ?4, ?4,?3)",
        params![key, request, deadline, now],
    )?;
    conn.execute("UPDATE ironwood_one_time_keys SET watch_closed_height=NULL,watch_closed_hash=NULL WHERE id=?1",[key])?;
    Ok(Ok(()))
}

/// The ID of `account`'s operation begun as `request`.
pub(in crate::wallet::one_time_ivk) fn operation(
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
) -> Result<Result<(), ReservationPolicy>, SqliteClientError> {
    let id = operation(conn, account, request)?;
    if !current(conn, id)? {
        return Ok(Err(ReservationPolicy::Stale));
    }
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
                 SET reference = ?2, memo = ?3, deadline = MIN(deadline, ?4),
                     local_watch_deadline=CASE WHEN local_watch_deadline IS NOT NULL AND local_watch_accepted=0 THEN ?4 ELSE local_watch_deadline END,
                     local_watch_accepted=CASE WHEN local_watch_deadline IS NOT NULL THEN 1 ELSE local_watch_accepted END
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
    Ok(Ok(()))
}

/// See `WalletDb::start_receive_operation`.
pub(in crate::wallet::one_time_ivk) fn start(
    conn: &rusqlite::Transaction<'_>,
    account: AccountUuid,
    request: &str,
    now: i64,
) -> Result<Result<ReceiveDeposit, ReservationPolicy>, SqliteClientError> {
    if !super::enabled(conn, account)? {
        return Ok(Err(ReservationPolicy::Gap));
    }
    let id = operation(conn, account, request)?;
    let deposit = conn
        .query_row(
            &format!(
                "SELECT o.one_time_key_id, o.reference, o.memo, o.deadline
                 FROM ironwood_one_time_operations o
                 JOIN ironwood_one_time_keys k ON k.id = o.one_time_key_id
                 WHERE o.id = ?1 AND o.reference IS NOT NULL AND {CURRENT}"
            ),
            [id],
            |r| {
                let deposit = ReceiveDeposit {
                    address: r.get(1)?,
                    memo: r.get(2)?,
                    deadline: r.get(3)?,
                };
                Ok((r.get::<_, i64>(0)?, deposit))
            },
        )
        .optional()?;
    let Some((key, deposit)) = deposit else {
        return Ok(Err(ReservationPolicy::Stale));
    };
    // Instructions are shown for one request per reservation, since its receiver takes
    // one quote, and only while the provider still takes a deposit.
    let other_started: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_operations o
             JOIN ironwood_one_time_operations other
                 ON other.one_time_key_id = o.one_time_key_id
             WHERE o.id = ?1 AND other.id != ?1 AND other.started = 1)",
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
    // Shown for funding, so the address is never issued again.
    block_issuance(conn, key)?;
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
    for &id in &operations {
        record(conn, id, observation, now)?;
    }
    reap(conn, params, account, now)?;
    Ok(!operations.is_empty())
}

/// See `WalletDb::prepare_receive_reservation`: resumes the draft, or reserves the index
/// [`next_index`] chooses, scanning it from `scan_from`. `seen`, if given, must already be
/// recorded (see [`record_seen`]).
pub(in crate::wallet::one_time_ivk) fn prepare<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    now: i64,
    scan_from: BlockHeight,
    seen: Option<&ProviderSeen<'_>>,
) -> Result<Result<OneTimeKey, ReservationPolicy>, SqliteClientError> {
    let (a, _) = account_key(conn, params, account)?;
    // Until the windows were checked against a seen set, another device may have given
    // out any index.
    if !block_recovery::seen_ready(conn, a.0)? {
        return Ok(Err(ReservationPolicy::Gap));
    }
    let end = issuance_end(conn, a.0, 1)?;
    let deadline_now = deadline_clock(conn, now)?;
    // Open reservations not started, paid or awaiting a payment, oldest first. A received
    // address is permanently excluded, even if later spent or rewound.
    let drafts = conn
        .prepare(&format!(
            "SELECT k.id, k.key_index, k.receiver, k.provider_seen, {LATEST_DEADLINE}, {GIVEN}
             FROM ironwood_one_time_keys k
             WHERE k.account_id = ?1 AND k.purpose = 1 AND {RESERVED} AND k.used = 0
               AND NOT {STARTED}
               AND NOT EXISTS(SELECT 1 FROM ironwood_block_matches m WHERE m.account_id=k.account_id AND m.purpose=k.purpose AND m.key_index=k.key_index)
               AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery p
                   WHERE p.one_time_key_id = k.id)
             ORDER BY k.reserved_at, k.id"
        ))?
        .query_map([a.0], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, bool>(3)?,
                r.get::<_, Option<i64>>(4)?,
                r.get::<_, bool>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (key, index, receiver, provider_seen, latest, given) in drafts {
        let resume = match latest {
            None => {
                let receiver = receiver_bytes(&receiver)?;
                match check_unquoted(conn, (key, 1), &receiver, provider_seen, seen, now)? {
                    Ok(usable) => usable,
                    Err(policy) => return Ok(Err(policy)),
                }
            }
            // The attempt is live, so its next quote keeps the address.
            Some(deadline) if deadline > deadline_now => true,
            // The provider has the expired draft's address, so the next attempt gets
            // another. Its funding instructions were never shown, so nothing can pay it
            // and its key stops scanning.
            Some(_) if given => {
                abandon(conn, key, now)?;
                false
            }
            // Only unknown outcomes: it stays reserved until reaped (see [`reusable`]).
            Some(_) => false,
        };
        if resume {
            if decode_index(index)? >= end {
                return Ok(Err(ReservationPolicy::Gap));
            }
            return key_by_id(conn, params, account, key).map(Ok);
        }
    }
    let seen = match fresh_seen(seen, now) {
        Ok(seen) => seen,
        Err(policy) => return Ok(Err(policy)),
    };
    let index = match next_index(conn, params, account, Purpose::Receive, seen, now)? {
        Ok(index) => index,
        Err(policy) => return Ok(Err(policy)),
    };
    let key = KeyId::new(Purpose::Receive, index);
    reserve_index(conn, params, account, key, scan_from, Discovery::Scan, now).map(Ok)
}

/// The index the [issuance rules](super#issuance) give `account`'s next reservation of
/// `purpose`, below [`issuance_end`]: the lowest fresh one, else the lowest abandoned one,
/// preferring one `seen` does not hold, else [`ReservationPolicy::Limit`]. An open incoming reservation is never chosen here
/// (see [`prepare`] for drafts), while a refund reservation never exposed counts as fresh.
///
/// No key is registered at a fresh index past the others, so `seen`, which must be fresh
/// and already recorded (see [`record_seen`]), is checked for it. One the set holds is
/// registered for filter history and recorded seen. That moves
/// the bound, so if nothing fresh is left this returns [`ReservationPolicy::Gap`] and the
/// next call sees the wider bound.
pub(in crate::wallet::one_time_ivk) fn next_index<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    purpose: Purpose,
    seen: &ProviderSeen<'_>,
    now: i64,
) -> Result<Result<u64, ReservationPolicy>, SqliteClientError> {
    let (a, parent) = account_key(conn, params, account)?;
    let code = purpose_code(purpose)?;
    let end = issuance_end(conn, a.0, code)?;
    let deadline_now = deadline_clock(conn, now)?;
    // Abandoned indices the provider's set lacks, then those it holds, whose quotes were
    // more likely accepted, so reusing them is more likely to link two quotes.
    let mut abandoned = [None, None];
    let mut fresh = None;
    let mut widened = false;
    let mut uncovered = false;
    for index in 0..end {
        if conn.query_row("SELECT EXISTS(SELECT 1 FROM ironwood_block_matches WHERE account_id=?1 AND purpose=?2 AND key_index=?3)",params![a.0,code,index.to_be_bytes()],|r|r.get::<_,bool>(0))? {continue;}

        let row: Option<(bool, bool, Option<i64>, bool, bool)> = conn
            .query_row(
                &format!(
                    "SELECT k.issuance_blocked = 1 OR k.used = 1
                          OR EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery p
                            WHERE p.one_time_key_id = k.id),
                        {RESERVED}, {LATEST_DEADLINE},
                        EXISTS(SELECT 1 FROM ironwood_one_time_operations o
                            WHERE o.one_time_key_id = k.id AND o.request IS NOT NULL),
                        k.provider_seen
                     FROM ironwood_one_time_keys k
                     WHERE k.account_id = ?1 AND k.purpose = ?2 AND k.key_index = ?3"
                ),
                params![a.0, code, index.to_be_bytes()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;
        // `record_seen` checked every registered key, so check an unregistered one here.
        let Some((blocked, reserved, latest, exposed, held)) = row else {
            let key_id = KeyId::new(purpose, index);
            let receiver = key_id.derive(&parent)?.address_at(0u32, Scope::External);
            if seen.holds(&receiver.to_raw_address_bytes())? {
                let from = restore_start(conn, params, a)?;
                let (id, _) = register(
                    conn,
                    params,
                    account,
                    key_id,
                    from,
                    false,
                    Discovery::Filter,
                    now,
                )?;
                record_provider_seen(conn, id)?;
                widened = true;
                continue;
            }
            fresh = Some(index);
            break;
        };
        if blocked {
            continue;
        }
        // A refund reservation's one request holds its key until the request's deadline.
        let in_use = match purpose {
            Purpose::Receive => reserved,
            _ => reserved && latest.is_some_and(|deadline| deadline > deadline_now),
        };
        if in_use {
            continue;
        }
        let draft = reserved && latest.is_none();
        if draft || !exposed {
            fresh = Some(index);
            break;
        }
        if !scanned_empty(conn, key_ref(conn, account, KeyId::new(purpose, index))?)? {
            uncovered = true;
            continue;
        }
        abandoned[usize::from(held)].get_or_insert(index);
    }
    if fresh.is_none() && widened {
        return Ok(Err(ReservationPolicy::Gap));
    }
    Ok(fresh.or(abandoned[0]).or(abandoned[1]).ok_or(if uncovered {
        ReservationPolicy::Coverage
    } else {
        ReservationPolicy::Limit
    }))
}

/// Reserves `key_id`, which [`next_index`] chose, as this wallet's, registering it with
/// `discovery` from `scan_from`. A new reservation starts above every request on the key,
/// which retires a reissued key's earlier requests (see [`CURRENT`]).
pub(in crate::wallet::one_time_ivk) fn reserve_index<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    key_id: KeyId,
    scan_from: BlockHeight,
    discovery: Discovery,
    now: i64,
) -> Result<OneTimeKey, SqliteClientError> {
    let (key, registered) = register(
        conn, params, account, key_id, scan_from, true, discovery, now,
    )?;
    authenticate_key(conn, key)?;
    conn.execute(
        "UPDATE ironwood_one_time_keys
         SET reserved_at = ?2, released_at = NULL, reservation_floor = IFNULL(
             (SELECT MAX(id) FROM ironwood_one_time_operations WHERE one_time_key_id = ?1), 0)
         WHERE id = ?1",
        params![key, now],
    )?;
    Ok(registered)
}

/// Records which of `account`'s unseen keys of purpose code `purpose` `seen` holds (see
/// [`record_provider_seen`]). A hit on an unauthenticated key outside the receiver window,
/// such as one a forged funding memo names, only blocks its issuance: it is sparse, so a
/// false match must not move the bound or the window to it.
pub(in crate::wallet::one_time_ivk) fn record_seen(
    conn: &rusqlite::Transaction<'_>,
    account: i64,
    purpose: u8,
    seen: &ProviderSeen<'_>,
) -> Result<(), SqliteClientError> {
    let end = block_recovery::window_end(conn, account, purpose)?;
    let mut stmt = conn.prepare(
        "SELECT k.id, k.receiver, k.authenticated = 0 AND ?3 IS NOT NULL AND k.key_index >= ?3
         FROM ironwood_one_time_keys k
         WHERE k.account_id = ?1 AND k.purpose = ?2 AND k.provider_seen = 0",
    )?;
    let keys = stmt
        .query_map(params![account, purpose, end.map(u64::to_be_bytes)], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, bool>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let receivers = keys
        .iter()
        .map(|(_, receiver, _)| receiver_bytes(receiver))
        .collect::<Result<Vec<_>, _>>()?;
    let hits = (seen.contains)(&receivers);
    if hits.len() != keys.len() {
        return Err(wrong_answer_count());
    }
    for (&(id, _, sparse), hit) in keys.iter().zip(hits) {
        match (hit, sparse) {
            (true, true) => block_issuance(conn, id)?,
            (true, false) => record_provider_seen(conn, id)?,
            (false, _) => {}
        }
    }
    Ok(())
}

/// Records that a swap provider was given key `id`'s receiver, which moves the issuance
/// bound (see [`issuance_end`]), extends the restore walk and widens its receiver window.
/// Unless a request of this wallet's exposed it, another device did, so it is never
/// issued again. Nothing clears this.
pub(in crate::wallet::one_time_ivk) fn record_provider_seen(
    conn: &rusqlite::Transaction<'_>,
    id: i64,
) -> Result<(), SqliteClientError> {
    conn.execute(
        "UPDATE ironwood_one_time_keys
         SET provider_seen = 1, advances_allocation = 1,
             issuance_blocked = issuance_blocked OR NOT EXISTS(
                 SELECT 1 FROM ironwood_one_time_operations o
                 WHERE o.one_time_key_id = ?1 AND o.request IS NOT NULL)
         WHERE id = ?1",
        [id],
    )?;
    advanced(conn, id)
}
