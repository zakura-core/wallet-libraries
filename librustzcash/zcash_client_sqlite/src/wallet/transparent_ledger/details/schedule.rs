//! Listing due and parked lookups, and scheduling retries after a failed one.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension as _, named_params};
use zcash_client_backend::data_api::transparent_ledger::{
    TRANSPARENT_DISPLAY_MAP_RECHECK, TransparentDetailOutcome, TransparentDetailParked,
    TransparentDetailReasons, TransparentDetailRequest, TransparentDetailWork,
    TransparentLedgerMode,
};
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;

use crate::{error::SqliteClientError, wallet::TxQueryType};

use super::super::{durable_policy, resolve_mode, with_read_snapshot};
use super::codes::{
    ABSENT, CONTRADICTION, NOT_COVERED, NOT_YET_PUBLISHED, PROTOCOL, UNAVAILABLE, UNSUPPORTED,
};
use super::sql::{REARMED, eligible, parked};

pub(super) const MINUTE: u64 = 60;
pub(super) const HOUR: u64 = 60 * MINUTE;
pub(super) const DAY: u64 = 24 * HOUR;

/// How long a parked row waits for a changed display map before it is due anyway.
pub(crate) const PARKED_BACKSTOP: Duration = Duration::from_secs(7 * DAY);

pub(super) fn unix(now: SystemTime) -> i64 {
    now.duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

pub(super) fn i64_secs(d: Duration) -> i64 {
    i64::try_from(d.as_secs()).unwrap_or(i64::MAX)
}

/// The due lookups; see `TransparentDetailRead::transparent_detail_work`. The caller supplies
/// the read snapshot.
pub(crate) fn work(
    conn: &Connection,
    configured: Option<TransparentLedgerMode>,
    now: SystemTime,
    limit: usize,
    map_sha256: Option<[u8; 32]>,
) -> Result<TransparentDetailWork, SqliteClientError> {
    let mode = resolve_mode(conn, configured)?;
    let policy_generation = durable_policy(conn)?.map_or(0, |p| p.generation);
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT t.txid, t.mined_height, w.reasons
         FROM transparent_detail_work w
         JOIN transactions t ON t.id_tx = w.transaction_id
         WHERE {eligible}
           AND ({REARMED} OR (w.next_attempt_at <= :now AND NOT ({parked})))
         ORDER BY (w.attempts = 0 OR {REARMED}) DESC, t.mined_height DESC, t.txid
         LIMIT :limit",
        eligible = eligible(),
        parked = parked(),
    ))?;
    let rows = stmt.query_map(
        named_params![
            ":now": unix(now),
            ":map": map_sha256.as_ref().map(|m| &m[..]),
            ":backstop": i64_secs(PARKED_BACKSTOP),
            ":public": mode.retains_public_authority(),
            ":enhancement": TxQueryType::Enhancement.code(),
            ":limit": i64::try_from(limit).unwrap_or(i64::MAX),
        ],
        |row| {
            Ok(TransparentDetailRequest {
                txid: TxId::from_bytes(row.get(0)?),
                mined_height: BlockHeight::from_u32(row.get(1)?),
                reasons: TransparentDetailReasons::from_bits(row.get(2)?),
            })
        },
    )?;
    Ok(TransparentDetailWork {
        mode,
        policy_generation,
        requests: rows.collect::<Result<_, _>>()?,
    })
}

pub(super) fn system_time(unix: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(u64::try_from(unix).unwrap_or(0))
}

/// The lookups parked under the caller's map; see
/// `TransparentDetailRead::transparent_detail_parked`.
pub(crate) fn parked_work(
    conn: &Connection,
    configured: Option<TransparentLedgerMode>,
    now: SystemTime,
    map_sha256: Option<[u8; 32]>,
    map_checked_at: Option<SystemTime>,
) -> Result<TransparentDetailParked, SqliteClientError> {
    let mode = resolve_mode(conn, configured)?;
    // The longest-parked row's map hash, with the count of all parked rows and their newest
    // attempt.
    let parked = conn
        .query_row(
            &format!(
                "SELECT COUNT(*) OVER (), MAX(w.attempted_at) OVER (), w.last_map_sha256
                 FROM transparent_detail_work w
                 JOIN transactions t ON t.id_tx = w.transaction_id
                 WHERE {eligible} AND NOT {REARMED}
                   AND w.next_attempt_at <= :now AND {parked}
                 ORDER BY w.attempted_at, w.transaction_id
                 LIMIT 1",
                eligible = eligible(),
                parked = parked(),
            ),
            named_params![
                ":now": unix(now),
                ":map": map_sha256.as_ref().map(|m| &m[..]),
                ":backstop": i64_secs(PARKED_BACKSTOP),
                ":public": mode.retains_public_authority(),
                ":enhancement": TxQueryType::Enhancement.code(),
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<[u8; 32]>>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((count, newest_attempt, oldest)) = parked else {
        return Ok(TransparentDetailParked::default());
    };
    // A refresh is worth trying once the map may have changed since the caller last checked it
    // or a parked lookup last used it.
    let checked = newest_attempt
        .unwrap_or(0)
        .max(map_checked_at.map_or(0, unix));
    Ok(TransparentDetailParked {
        count: u64::try_from(count).unwrap_or(0),
        oldest_map_sha256: oldest,
        refresh_at: Some(system_time(checked) + TRANSPARENT_DISPLAY_MAP_RECHECK),
    })
}

/// A deterministic jitter fraction in `[0, 1)` for this row and attempt.
pub(super) fn jitter(txid: &TxId, attempts: u32) -> f64 {
    // SplitMix64 over the txid prefix and attempt count; spreads retries of many rows apart
    // without a random source.
    let mut x = u64::from_le_bytes(txid.as_ref()[..8].try_into().expect("8 bytes"))
        ^ u64::from(attempts).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    (x >> 11) as f64 / (1u64 << 53) as f64
}

/// Exponential backoff from `base`, doubling per attempt, plus up to 25% jitter, capped at `cap`.
pub(super) fn exponential(base: u64, cap: u64, attempts: u32, txid: &TxId) -> u64 {
    let doubled = base.saturating_mul(1u64 << attempts.saturating_sub(1).min(32));
    let delay = doubled.min(cap);
    (delay + (delay as f64 * 0.25 * jitter(txid, attempts)) as u64).min(cap)
}

/// The delay before the next attempt after `outcome`, as the `attempts`th consecutive failure.
pub(crate) fn backoff(outcome: TransparentDetailOutcome, attempts: u32, txid: &TxId) -> Duration {
    let secs = match outcome {
        TransparentDetailOutcome::Unavailable { retry_after } => {
            // Honour the server's advice beyond the cap, up to a day.
            let advised = retry_after.map_or(0, |d| d.as_secs()).min(DAY);
            exponential(30, HOUR, attempts, txid).max(advised)
        }
        TransparentDetailOutcome::Protocol => exponential(30, HOUR, attempts, txid),
        TransparentDetailOutcome::NotYetPublished => {
            exponential(MINUTE, 5 * MINUTE, attempts, txid)
        }
        TransparentDetailOutcome::Absent => exponential(HOUR, DAY, attempts, txid),
        TransparentDetailOutcome::NotCovered
        | TransparentDetailOutcome::Unsupported
        | TransparentDetailOutcome::Contradiction => {
            DAY + (DAY as f64 * 0.25 * jitter(txid, attempts)) as u64
        }
    };
    Duration::from_secs(secs)
}

pub(super) fn outcome_code(outcome: TransparentDetailOutcome) -> i64 {
    match outcome {
        TransparentDetailOutcome::Unavailable { .. } => UNAVAILABLE,
        TransparentDetailOutcome::Absent => ABSENT,
        TransparentDetailOutcome::NotCovered => NOT_COVERED,
        TransparentDetailOutcome::Unsupported => UNSUPPORTED,
        TransparentDetailOutcome::Protocol => PROTOCOL,
        TransparentDetailOutcome::Contradiction => CONTRADICTION,
        TransparentDetailOutcome::NotYetPublished => NOT_YET_PUBLISHED,
    }
}

/// Outcomes sharing a backoff schedule. A change of class starts a fresh backoff, so that
/// minutes-apart `NotYetPublished` retries do not lengthen a later `Unavailable` or `Absent`
/// backoff.
pub(super) fn outcome_class(code: i64) -> i64 {
    match code {
        UNAVAILABLE | PROTOCOL => UNAVAILABLE,
        NOT_COVERED | UNSUPPORTED | CONTRADICTION => NOT_COVERED,
        other => other,
    }
}

pub(super) fn record_outcome(
    conn: &Connection,
    txid: &TxId,
    looked_up_height: BlockHeight,
    outcome: TransparentDetailOutcome,
    map_sha256: Option<[u8; 32]>,
    now: SystemTime,
) -> Result<(), SqliteClientError> {
    let row = conn
        .query_row(
            "SELECT w.transaction_id, w.attempts, w.attempted_height, t.mined_height,
                    w.last_outcome
             FROM transparent_detail_work w JOIN transactions t ON t.id_tx = w.transaction_id
             WHERE t.txid = :txid",
            named_params![":txid": txid.as_ref()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, Option<u32>>(2)?,
                    row.get::<_, Option<u32>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((tx, attempts, attempted_height, mined_height, last_outcome)) = row else {
        return Ok(());
    };
    // A late result must not park or back off work for a different placement. This check
    // and the update run in the caller's snapshot transaction.
    if mined_height != Some(u32::from(looked_up_height)) {
        return Ok(());
    }
    // A changed placement, or another class of outcome, starts a fresh backoff.
    let code = outcome_code(outcome);
    let attempts = if attempted_height.is_some()
        && attempted_height == mined_height
        && last_outcome.map(outcome_class) == Some(outcome_class(code))
    {
        attempts.saturating_add(1)
    } else {
        1
    };
    let delay = i64_secs(backoff(outcome, attempts, txid));
    conn.execute(
        "UPDATE transparent_detail_work
         SET attempts = :attempts, next_attempt_at = :next, attempted_at = :now,
             attempted_height = :height, last_outcome = :outcome, last_map_sha256 = :map
         WHERE transaction_id = :tx",
        named_params![
            ":tx": tx,
            ":attempts": attempts,
            ":now": unix(now),
            ":next": unix(now).saturating_add(delay),
            ":height": mined_height,
            ":outcome": code,
            ":map": map_sha256.as_ref().map(|m| &m[..]),
        ],
    )?;
    Ok(())
}

/// Records a failed lookup; see `TransparentDetailWrite::defer_transparent_detail`.
pub(crate) fn defer(
    conn: &Connection,
    configured: Option<TransparentLedgerMode>,
    txid: TxId,
    looked_up_height: BlockHeight,
    outcome: TransparentDetailOutcome,
    map_sha256: Option<[u8; 32]>,
    now: SystemTime,
) -> Result<(), SqliteClientError> {
    resolve_mode(conn, configured)?;
    with_read_snapshot(conn, |conn| {
        record_outcome(conn, &txid, looked_up_height, outcome, map_sha256, now)
    })
}
