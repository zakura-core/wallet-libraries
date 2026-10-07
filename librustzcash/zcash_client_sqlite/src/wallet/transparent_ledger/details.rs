//! Transparent txid enhancement: durable work, validated display facts and the detail view.
//!
//! Work rows (`transparent_detail_work`) are written where the wallet records a transaction of
//! ours without its raw bytes: ledger projection and the Enhance PIR route-2 marker. Storing raw
//! bytes deletes them. Display facts (`transparent_tx_display*`) are display only: no balance,
//! spendability or history query reads them. See `docs/transparent-txid-enhancement.md`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension as _, named_params};
use transparent::{address::Script, bundle::TxOut};
use zcash_client_backend::data_api::transparent_ledger::{
    TRANSPARENT_DISPLAY_MAP_RECHECK, TransactionMetadata, TransparentDetailOutcome,
    TransparentDetailParked, TransparentDetailReasons, TransparentDetailRequest,
    TransparentDetailWork, TransparentDisplayContradiction, TransparentDisplayDetails,
    TransparentDisplayFacts, TransparentDisplayOutput, TransparentDisplayProvenance,
    TransparentDisplaySource, TransparentDisplayStore, TransparentDisplayView,
    TransparentDisplayViewOutput, TransparentLedgerMode, WholeTransactionFee,
};
use zcash_primitives::transaction::TxId;
use zcash_protocol::{
    consensus::{self, BlockHeight},
    value::Zatoshis,
};

use crate::{AccountUuid, TxRef, error::SqliteClientError, wallet::TxQueryType};

use super::{
    check_transparent_policy_generation, durable_policy, output_observation_condition,
    resolve_mode, with_read_snapshot,
};

const UNAVAILABLE: i64 = 0;
const ABSENT: i64 = 1;
const NOT_COVERED: i64 = 2;
const UNSUPPORTED: i64 = 3;
const PROTOCOL: i64 = 4;
const CONTRADICTION: i64 = 5;
const NOT_YET_PUBLISHED: i64 = 6;

const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;

/// How long a parked row waits for a changed display map before it is due anyway.
pub(crate) const PARKED_BACKSTOP: Duration = Duration::from_secs(7 * DAY);

/// Whether the wallet still records an effect of transaction `t`: an owned output or a spend
/// of one that financial queries count (a withdrawn ledger-only receive does not), a spend link,
/// or a route-2 marker.
fn related() -> String {
    format!(
        "(
            EXISTS (SELECT 1 FROM transparent_received_outputs o
                    WHERE o.transaction_id = t.id_tx AND ({}))
            OR EXISTS (SELECT 1 FROM transparent_received_output_spends s
                       JOIN transparent_received_outputs so
                           ON so.id = s.transparent_received_output_id
                       WHERE s.transaction_id = t.id_tx AND ({}))
            OR EXISTS (SELECT 1 FROM transparent_spend_map m
                       WHERE m.spending_transaction_id = t.id_tx)
            OR EXISTS (SELECT 1 FROM ironwood_enhance_routing r
                       WHERE r.transaction_id = t.id_tx AND r.route = 2)
        )",
        output_observation_condition("o"),
        output_observation_condition("so"),
    )
}

/// Rows of `transparent_detail_work w` the listing returns for transaction `t` once it is mined,
/// before timing: without raw bytes, still related, and not owned by public payload work.
///
/// Under public authority (`:public`), payload retrieval already fetches transactions queued
/// in `tx_retrieval_queue`, and a privately protected Ironwood transaction (route 0) must not
/// be fetched publicly.
fn listable() -> String {
    format!(
        "t.raw IS NULL AND {}
         AND NOT (:public AND (
             EXISTS (SELECT 1 FROM tx_retrieval_queue q
                     WHERE q.txid = t.txid AND q.query_type = :enhancement)
             OR EXISTS (SELECT 1 FROM ironwood_enhance_routing p
                        WHERE p.transaction_id = t.id_tx AND p.route = 0)
         ))",
        related()
    )
}

/// Rows the listing may return now, before timing: [`listable`] and mined.
fn eligible() -> String {
    format!("t.mined_height IS NOT NULL AND {}", listable())
}

/// The mined height changed since the last attempt: due at once, with a fresh backoff.
const REARMED: &str = "(w.attempted_height IS NOT NULL AND w.attempted_height != t.mined_height)";

/// Parked under caller map `:map`: `NotCovered` and `Contradiction` until the map differs from
/// the one that produced them, `Unsupported` until any map is seen; never past the backstop.
///
/// Only without public authority (`:public`): a map is the private source's, and a public
/// lookup answers with the raw transaction whatever the publication covers, so under public
/// authority these rows are due at their ordinary retry.
fn parked() -> String {
    format!(
        "NOT :public
         AND ((w.last_outcome IN ({NOT_COVERED}, {CONTRADICTION})
           AND (:map IS NULL OR w.last_map_sha256 IS :map))
          OR (w.last_outcome = {UNSUPPORTED} AND :map IS NULL))
         AND IFNULL(w.attempted_at, 0) + :backstop > :now"
    )
}

fn unix(now: SystemTime) -> i64 {
    now.duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Queues work with `reasons` for the transactions `filter` selects from `transactions t`,
/// OR-ed into an existing row, while they are mined, have no raw bytes and no stored display
/// facts. A parent transaction (known only by txid, height unknown) is never queued.
///
/// Stored facts are first checked against what the wallet now holds: facts that were valid when
/// stored can contradict a receive or spend projected later (a withdrawn receive reported
/// again, say). Contradicted facts are deleted, so the transaction is looked up again.
fn enqueue(
    conn: &Connection,
    filter: &str,
    params: &[(&str, &dyn rusqlite::ToSql)],
    reasons: TransparentDetailReasons,
) -> Result<(), SqliteClientError> {
    revalidate(conn, filter, params)?;
    let bits = reasons.bits();
    let mut all = params.to_vec();
    all.push((":reasons", &bits));
    conn.prepare_cached(&format!(
        "INSERT INTO transparent_detail_work (transaction_id, reasons)
         SELECT t.id_tx, :reasons FROM transactions t
         WHERE {filter} AND t.raw IS NULL AND t.mined_height IS NOT NULL
           AND NOT EXISTS (SELECT 1 FROM transparent_tx_display d
                           WHERE d.transaction_id = t.id_tx)
         ON CONFLICT (transaction_id) DO UPDATE SET reasons = reasons | excluded.reasons"
    ))?
    .execute(&all[..])?;
    Ok(())
}

/// Deletes the stored display facts of the transactions `filter` selects that contradict the
/// wallet; see [`enqueue`].
fn revalidate(
    conn: &Connection,
    filter: &str,
    params: &[(&str, &dyn rusqlite::ToSql)],
) -> Result<(), SqliteClientError> {
    let stored: Vec<(i64, Option<u32>, Option<u64>)> = conn
        .prepare_cached(&format!(
            "SELECT t.id_tx, t.tx_index, t.fee FROM transactions t
             JOIN transparent_tx_display d ON d.transaction_id = t.id_tx
             WHERE {filter}"
        ))?
        .query_map(params, |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<_, _>>()?;
    for (tx, tx_index, fee) in stored {
        let Some(facts) = stored_facts(conn, tx)? else {
            continue;
        };
        if validate(conn, tx, tx_index, fee, &facts)?.is_some() {
            conn.execute(
                "DELETE FROM transparent_tx_display WHERE transaction_id = :tx",
                named_params![":tx": tx],
            )?;
        }
    }
    Ok(())
}

/// Queues work for `txid` with `reasons`; see [`enqueue`].
#[cfg_attr(
    not(any(feature = "transparent-inputs", feature = "orchard")),
    allow(dead_code)
)]
pub(crate) fn enqueue_txid(
    conn: &Connection,
    txid: &TxId,
    reasons: TransparentDetailReasons,
) -> Result<(), SqliteClientError> {
    enqueue(
        conn,
        "t.txid = :txid",
        named_params![":txid": txid.as_ref()],
        reasons,
    )
}

/// Like [`enqueue_txid`], by the wallet's transaction id.
#[cfg_attr(
    not(any(feature = "transparent-inputs", feature = "orchard")),
    allow(dead_code)
)]
pub(crate) fn enqueue_tx(
    conn: &Connection,
    tx_ref: TxRef,
    reasons: TransparentDetailReasons,
) -> Result<(), SqliteClientError> {
    enqueue(
        conn,
        "t.id_tx = :tx",
        named_params![":tx": tx_ref.0],
        reasons,
    )
}

const ROUTE_TWO: &str = "EXISTS (SELECT 1 FROM ironwood_enhance_routing r
                                 WHERE r.transaction_id = t.id_tx AND r.route = 2)";

/// Queues mixed-transaction work for every unresolved route-2 transaction; see [`enqueue`].
pub(crate) fn enqueue_route_two(conn: &Connection) -> Result<(), SqliteClientError> {
    enqueue(conn, ROUTE_TWO, &[], TransparentDetailReasons::MIXED)
}

/// Queues mixed-transaction work for `txid` as it is mined, when it is a route-2 transaction.
///
/// A route-2 marker written while the transaction was unmined (rewound, or seen unmined) could
/// not queue it, since work requires a mined height.
pub(crate) fn enqueue_mined_route_two(
    conn: &Connection,
    txid: &TxId,
) -> Result<(), SqliteClientError> {
    enqueue(
        conn,
        &format!("t.txid = :txid AND {ROUTE_TWO}"),
        named_params![":txid": txid.as_ref()],
        TransparentDetailReasons::MIXED,
    )
}

/// Removes work and display facts once raw bytes are stored: the raw transaction supersedes them.
pub(crate) fn clear(conn: &Connection, tx_ref: TxRef) -> Result<(), SqliteClientError> {
    conn.prepare_cached("DELETE FROM transparent_detail_work WHERE transaction_id = :tx")?
        .execute(named_params![":tx": tx_ref.0])?;
    conn.prepare_cached("DELETE FROM transparent_tx_display WHERE transaction_id = :tx")?
        .execute(named_params![":tx": tx_ref.0])?;
    Ok(())
}

fn i64_secs(d: Duration) -> i64 {
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

fn system_time(unix: i64) -> SystemTime {
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
fn jitter(txid: &TxId, attempts: u32) -> f64 {
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
fn exponential(base: u64, cap: u64, attempts: u32, txid: &TxId) -> u64 {
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

fn outcome_code(outcome: TransparentDetailOutcome) -> i64 {
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
fn outcome_class(code: i64) -> i64 {
    match code {
        UNAVAILABLE | PROTOCOL => UNAVAILABLE,
        NOT_COVERED | UNSUPPORTED | CONTRADICTION => NOT_COVERED,
        other => other,
    }
}

fn record_outcome(
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

fn fee_columns(fee: WholeTransactionFee) -> (i64, Option<i64>) {
    match fee {
        WholeTransactionFee::Exact(value) => (0, Some(value.into_u64() as i64)),
        WholeTransactionFee::Unknown => (1, None),
        WholeTransactionFee::NotApplicable => (2, None),
    }
}

fn fee_from_columns(
    state: i64,
    fee: Option<u64>,
) -> Result<WholeTransactionFee, SqliteClientError> {
    match (state, fee) {
        (0, Some(fee)) => Ok(WholeTransactionFee::Exact(
            Zatoshis::from_u64(fee).map_err(|_| {
                SqliteClientError::CorruptedData("display fee exceeds MAX_MONEY".into())
            })?,
        )),
        (1, None) => Ok(WholeTransactionFee::Unknown),
        (2, None) => Ok(WholeTransactionFee::NotApplicable),
        _ => Err(SqliteClientError::CorruptedData(
            "invalid display fee state".into(),
        )),
    }
}

/// Checks `facts` against everything the wallet holds about transaction `tx`.
fn validate(
    conn: &Connection,
    tx: i64,
    tx_index: Option<u32>,
    stored_fee: Option<u64>,
    facts: &TransparentDisplayFacts,
) -> Result<Option<TransparentDisplayContradiction>, SqliteClientError> {
    use TransparentDisplayContradiction as C;
    let txid = facts.txid.as_ref();
    let metadata = facts.metadata;

    // Coinbase: the metadata must suit the flag, and agree with the known position and with
    // recovered receive events.
    let event_coinbase: Vec<bool> = conn
        .prepare_cached("SELECT DISTINCT coinbase FROM tpir_receive_events WHERE txid = :txid")?
        .query_map(named_params![":txid": txid], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    if !metadata.is_valid_for(facts.coinbase)
        || tx_index.is_some_and(|i| (i == 0) != facts.coinbase)
        || event_coinbase.iter().any(|c| *c != facts.coinbase)
    {
        return Ok(Some(C::Coinbase));
    }

    // A coinbase transaction spends nothing: no known spend may name it.
    let known_spends = known_spent_outpoints(conn, tx, txid)?;
    if facts.coinbase && known_spends > 0 {
        return Ok(Some(C::Coinbase));
    }

    // Every owned output financial queries count, and every recovered receive, must be present
    // at its index with the same value and script.
    let owned: Vec<(u32, u64, Vec<u8>)> = conn
        .prepare_cached(&format!(
            "SELECT output_index, value_zat, script FROM transparent_received_outputs o
             WHERE transaction_id = :tx AND ({})
             UNION
             SELECT output_index, value_zat, script FROM tpir_receive_events WHERE txid = :txid
             ORDER BY 1",
            output_observation_condition("o"),
        ))?
        .query_map(named_params![":tx": tx, ":txid": txid], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?
        .collect::<Result<_, _>>()?;
    for (index, value, script) in owned {
        match facts.outputs.get(index as usize) {
            None => return Ok(Some(C::OutputIndexOutOfRange { index })),
            Some(o) if o.value.into_u64() != value || o.script != script => {
                return Ok(Some(C::OwnedOutput { index }));
            }
            Some(_) => {}
        }
    }

    // Recovered metadata must be equal.
    let (fee_state, fee_zat) = fee_columns(metadata.fee);
    let metadata_conflict: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM tpir_transaction_metadata WHERE txid = :txid
         AND (fee_state != :fee_state OR fee_zat IS NOT :fee OR input_count != :inputs
              OR shielded != :shielded))",
        named_params![
            ":txid": txid,
            ":fee_state": fee_state,
            ":fee": fee_zat,
            ":inputs": metadata.transparent_input_count,
            ":shielded": metadata.has_shielded_components,
        ],
        |row| row.get(0),
    )?;
    if metadata_conflict {
        return Ok(Some(C::Metadata));
    }

    // The stored fee must be equal; an unknown published fee asserts nothing.
    if let Some(stored) = stored_fee {
        match metadata.fee {
            WholeTransactionFee::Exact(fee) if fee.into_u64() != stored => {
                return Ok(Some(C::Fee));
            }
            WholeTransactionFee::NotApplicable => return Ok(Some(C::Fee)),
            _ => {}
        }
    }

    // A known shielded component, or a route-2 marker, requires the shielded bit.
    if !metadata.has_shielded_components {
        let shielded: bool = conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM sapling_received_notes WHERE transaction_id = :tx)
                 OR EXISTS (SELECT 1 FROM orchard_received_notes WHERE transaction_id = :tx)
                 OR EXISTS (SELECT 1 FROM ironwood_received_notes WHERE transaction_id = :tx)
                 OR EXISTS (SELECT 1 FROM sapling_received_note_spends WHERE transaction_id = :tx)
                 OR EXISTS (SELECT 1 FROM orchard_received_note_spends WHERE transaction_id = :tx)
                 OR EXISTS (SELECT 1 FROM ironwood_received_note_spends WHERE transaction_id = :tx)
                 OR EXISTS (SELECT 1 FROM sent_notes WHERE transaction_id = :tx AND output_pool != 0)
                 OR EXISTS (SELECT 1 FROM ironwood_enhance_routing
                            WHERE transaction_id = :tx AND route = 2)",
            named_params![":tx": tx],
            |row| row.get(0),
        )?;
        if shielded {
            return Ok(Some(C::Shielded));
        }
    }

    // Known spends must name an input below the transparent input count.
    let beyond: Option<u32> = conn
        .query_row(
            "SELECT MIN(input_index) FROM tpir_spend_events
             WHERE spending_txid = :txid AND input_index >= :inputs",
            named_params![":txid": txid, ":inputs": metadata.transparent_input_count],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    if let Some(index) = beyond {
        return Ok(Some(C::InputIndex { index }));
    }
    // Public spend links carry no input index, but each names a distinct input.
    if known_spends > metadata.transparent_input_count {
        return Ok(Some(C::InputCount {
            known: known_spends,
        }));
    }
    Ok(None)
}

/// The number of distinct outpoints the wallet knows transaction `tx` (`txid`) spends: recovered
/// spend events, public spend links, and the spend map.
fn known_spent_outpoints(
    conn: &Connection,
    tx: i64,
    txid: &[u8],
) -> Result<u32, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM (
             SELECT prevout_txid, prevout_output_index FROM tpir_spend_events
             WHERE spending_txid = :txid
             UNION
             SELECT prevout_txid, prevout_output_index FROM transparent_spend_map
             WHERE spending_transaction_id = :tx
             UNION
             SELECT ot.txid, o.output_index FROM transparent_received_output_spends s
             JOIN transparent_received_outputs o ON o.id = s.transparent_received_output_id
             JOIN transactions ot ON ot.id_tx = o.transaction_id
             WHERE s.transaction_id = :tx
         )",
        named_params![":tx": tx, ":txid": txid],
        |row| row.get(0),
    )?)
}

/// Validates and stores display facts; see `TransparentDetailWrite::store_transparent_display`.
pub(crate) fn store(
    conn: &Connection,
    configured: Option<TransparentLedgerMode>,
    facts: TransparentDisplayFacts,
    expected_generation: u64,
    now: SystemTime,
) -> Result<TransparentDisplayStore, SqliteClientError> {
    resolve_mode(conn, configured)?;
    with_read_snapshot(conn, |conn| {
        check_transparent_policy_generation(conn, expected_generation)?;
        let row = conn
            .query_row(
                "SELECT id_tx, raw IS NOT NULL, tx_index, fee FROM transactions WHERE txid = :txid",
                named_params![":txid": facts.txid.as_ref()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, bool>(1)?,
                        row.get::<_, Option<u32>>(2)?,
                        row.get::<_, Option<u64>>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((tx, has_raw, tx_index, fee)) = row else {
            return Ok(TransparentDisplayStore::Superseded);
        };
        if has_raw {
            clear(conn, TxRef(tx))?;
            return Ok(TransparentDisplayStore::Superseded);
        }
        // Only a transaction the wallet wants details of, or still relates to, takes facts.
        let wanted: bool = conn.query_row(
            &format!(
                "SELECT EXISTS (SELECT 1 FROM transparent_detail_work WHERE transaction_id = :tx)
                     OR EXISTS (SELECT 1 FROM transactions t WHERE t.id_tx = :tx AND {})",
                related()
            ),
            named_params![":tx": tx],
            |row| row.get(0),
        )?;
        if !wanted {
            return Ok(TransparentDisplayStore::Superseded);
        }
        if let Some(kind) = validate(conn, tx, tx_index, fee, &facts)? {
            record_outcome(
                conn,
                &facts.txid,
                facts.provenance.looked_up_height,
                TransparentDetailOutcome::Contradiction,
                Some(facts.provenance.map_sha256),
                now,
            )?;
            return Ok(TransparentDisplayStore::Contradiction(kind));
        }

        let (fee_state, fee_zat) = fee_columns(facts.metadata.fee);
        let p = &facts.provenance;
        conn.execute(
            "DELETE FROM transparent_tx_display WHERE transaction_id = :tx",
            named_params![":tx": tx],
        )?;
        conn.execute(
            "INSERT INTO transparent_tx_display
             (transaction_id, coinbase, fee_state, fee_zat, input_count, shielded, shard_id,
              revision, map_sha256, looked_up_height, stored_at)
             VALUES (:tx, :coinbase, :fee_state, :fee, :inputs, :shielded, :shard, :revision,
                     :map, :height, :now)",
            named_params![
                ":tx": tx,
                ":coinbase": facts.coinbase,
                ":fee_state": fee_state,
                ":fee": fee_zat,
                ":inputs": facts.metadata.transparent_input_count,
                ":shielded": facts.metadata.has_shielded_components,
                ":shard": i64::try_from(p.shard_id).map_err(|_| {
                    SqliteClientError::CorruptedData("display shard id does not fit i64".into())
                })?,
                ":revision": p.revision,
                ":map": &p.map_sha256[..],
                ":height": u32::from(p.looked_up_height),
                ":now": unix(now),
            ],
        )?;
        let mut insert = conn.prepare_cached(
            "INSERT INTO transparent_tx_display_outputs
             (transaction_id, output_index, value_zat, script)
             VALUES (:tx, :index, :value, :script)",
        )?;
        for (index, output) in facts.outputs.iter().enumerate() {
            insert.execute(named_params![
                ":tx": tx,
                ":index": u32::try_from(index).map_err(|_| {
                    SqliteClientError::CorruptedData("display output index overflow".into())
                })?,
                ":value": output.value.into_u64() as i64,
                ":script": output.script,
            ])?;
        }
        conn.execute(
            "DELETE FROM transparent_detail_work WHERE transaction_id = :tx",
            named_params![":tx": tx],
        )?;
        Ok(TransparentDisplayStore::Stored)
    })
}

/// The display facts stored for transaction `tx`, if any.
fn stored_facts(
    conn: &Connection,
    tx: i64,
) -> Result<Option<TransparentDisplayFacts>, SqliteClientError> {
    let display = conn
        .query_row(
            "SELECT t.txid, d.coinbase, d.fee_state, d.fee_zat, d.input_count, d.shielded,
                    d.shard_id, d.revision, d.map_sha256, d.looked_up_height
             FROM transparent_tx_display d JOIN transactions t ON t.id_tx = d.transaction_id
             WHERE d.transaction_id = :tx",
            named_params![":tx": tx],
            |row| {
                Ok((
                    row.get::<_, [u8; 32]>(0)?,
                    row.get::<_, bool>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<u64>>(3)?,
                    row.get::<_, u32>(4)?,
                    row.get::<_, bool>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, u32>(7)?,
                    row.get::<_, [u8; 32]>(8)?,
                    row.get::<_, u32>(9)?,
                ))
            },
        )
        .optional()?;
    let Some((txid, coinbase, fee_state, fee, input_count, shielded, shard, revision, map, height)) =
        display
    else {
        return Ok(None);
    };
    let outputs = conn
        .prepare_cached(
            "SELECT output_index, value_zat, script FROM transparent_tx_display_outputs
             WHERE transaction_id = :tx ORDER BY output_index",
        )?
        .query_map(named_params![":tx": tx], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, u64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?
        .zip(0u32..)
        .map(|(row, expected)| {
            let (index, value, script) = row?;
            if index != expected {
                return Err(SqliteClientError::CorruptedData(
                    "display outputs are not contiguous".into(),
                ));
            }
            let value = Zatoshis::from_u64(value).map_err(|_| {
                SqliteClientError::CorruptedData("display value exceeds MAX_MONEY".into())
            })?;
            Ok(TransparentDisplayOutput { value, script })
        })
        .collect::<Result<_, SqliteClientError>>()?;
    Ok(Some(TransparentDisplayFacts {
        txid: TxId::from_bytes(txid),
        coinbase,
        metadata: TransactionMetadata {
            fee: fee_from_columns(fee_state, fee)?,
            transparent_input_count: input_count,
            has_shielded_components: shielded,
        },
        outputs,
        provenance: TransparentDisplayProvenance {
            shard_id: u64::try_from(shard).map_err(|_| {
                SqliteClientError::CorruptedData("negative display shard id".into())
            })?,
            revision,
            map_sha256: map,
            looked_up_height: BlockHeight::from_u32(height),
        },
    }))
}

fn view_output(
    index: u32,
    value: Zatoshis,
    script: Vec<u8>,
    owned: bool,
) -> TransparentDisplayViewOutput {
    let address =
        TxOut::new(value, Script(zcash_script::script::Code(script.clone()))).recipient_address();
    TransparentDisplayViewOutput {
        index,
        value,
        script,
        address,
        owned,
    }
}

/// The detail view; see `TransparentDetailRead::transparent_display_view`.
pub(crate) fn view<P: consensus::Parameters>(
    conn: &Connection,
    params: &P,
    configured: Option<TransparentLedgerMode>,
    account: AccountUuid,
    txid: TxId,
) -> Result<Option<TransparentDisplayView>, SqliteClientError> {
    let mode = resolve_mode(conn, configured)?;
    let row = conn
        .query_row(
            "SELECT id_tx, raw IS NOT NULL, fee FROM transactions WHERE txid = :txid",
            named_params![":txid": txid.as_ref()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, bool>(1)?,
                    row.get::<_, Option<u64>>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((tx, has_raw, stored_fee)) = row else {
        return Ok(None);
    };
    let owned: Vec<u32> = conn
        .prepare_cached(&format!(
            "SELECT o.output_index FROM transparent_received_outputs o
             JOIN accounts a ON a.id = o.account_id
             WHERE o.transaction_id = :tx AND a.uuid = :account AND ({})",
            output_observation_condition("o"),
        ))?
        .query_map(named_params![":tx": tx, ":account": account.0], |row| {
            row.get(0)
        })?
        .collect::<Result<_, _>>()?;

    if has_raw {
        let Some((_, transaction)) = crate::wallet::get_transaction(conn, params, txid)? else {
            return Ok(None);
        };
        let bundle = transaction.transparent_bundle();
        let coinbase = bundle.is_some_and(|b| b.is_coinbase());
        let outputs = bundle
            .map(|b| {
                b.vout
                    .iter()
                    .enumerate()
                    .map(|(i, o)| {
                        let index = i as u32;
                        view_output(
                            index,
                            o.value(),
                            o.script_pubkey().0.0.clone(),
                            owned.contains(&index),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let fee = if coinbase {
            WholeTransactionFee::NotApplicable
        } else {
            stored_fee
                .and_then(|f| Zatoshis::from_u64(f).ok())
                .map_or(WholeTransactionFee::Unknown, WholeTransactionFee::Exact)
        };
        return Ok(Some(TransparentDisplayView::Available(
            TransparentDisplayDetails {
                outputs,
                coinbase,
                fee,
                input_count: if coinbase {
                    0
                } else {
                    bundle.map_or(0, |b| b.vin.len() as u32)
                },
                shielded: transaction.sprout_bundle().is_some()
                    || transaction.sapling_bundle().is_some()
                    || transaction.orchard_bundle().is_some()
                    || transaction.ironwood_bundle().is_some(),
                source: TransparentDisplaySource::RawTransaction,
            },
        )));
    }

    if let Some(facts) = stored_facts(conn, tx)? {
        return Ok(Some(TransparentDisplayView::Available(
            TransparentDisplayDetails {
                outputs: facts
                    .outputs
                    .into_iter()
                    .zip(0u32..)
                    .map(|(o, index)| view_output(index, o.value, o.script, owned.contains(&index)))
                    .collect(),
                coinbase: facts.coinbase,
                fee: facts.metadata.fee,
                input_count: facts.metadata.transparent_input_count,
                shielded: facts.metadata.has_shielded_components,
                source: TransparentDisplaySource::Display(facts.provenance),
            },
        )));
    }

    // Work counts only while the listing would return it, now or once the transaction is mined
    // again; otherwise the view is what it would be without work.
    let work: Option<Option<i64>> = conn
        .query_row(
            &format!(
                "SELECT w.last_outcome FROM transparent_detail_work w
                 JOIN transactions t ON t.id_tx = w.transaction_id
                 WHERE w.transaction_id = :tx AND {}",
                listable()
            ),
            named_params![
                ":tx": tx,
                ":public": mode.retains_public_authority(),
                ":enhancement": TxQueryType::Enhancement.code(),
            ],
            |row| row.get(0),
        )
        .optional()?;
    Ok(Some(match work {
        Some(None | Some(NOT_YET_PUBLISHED)) => TransparentDisplayView::Pending,
        Some(Some(NOT_COVERED)) => TransparentDisplayView::NotCovered,
        Some(Some(_)) => TransparentDisplayView::Unavailable,
        // Payload retrieval fetches the raw transaction only under public authority.
        None if !mode.retains_public_authority() => TransparentDisplayView::Unavailable,
        None => {
            let payload_owned: bool = conn.query_row(
                "SELECT EXISTS (SELECT 1 FROM tx_retrieval_queue
                                WHERE txid = :txid AND query_type = :enhancement)",
                named_params![
                    ":txid": txid.as_ref(),
                    ":enhancement": TxQueryType::Enhancement.code(),
                ],
                |row| row.get(0),
            )?;
            if payload_owned {
                TransparentDisplayView::Pending
            } else {
                TransparentDisplayView::Unavailable
            }
        }
    }))
}
