//! Transparent txid enhancement: durable work, validated display facts and the detail view.
//!
//! Work rows (`transparent_detail_work`) are written where the wallet records a transaction of
//! ours without its raw bytes: ledger projection and the Enhance PIR route-2 marker. Storing raw
//! bytes deletes them. Display facts (`transparent_tx_display*`) are display only: no balance,
//! spendability or history query reads them. See `docs/transparent-txid-enhancement.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension as _, named_params};
use transparent::address::TransparentAddress;
use zcash_client_backend::data_api::transparent_ledger::{
    TRANSPARENT_DISPLAY_MAP_RECHECK, TransparentDetailOutcome, TransparentDetailParked,
    TransparentDetailReasons, TransparentDetailRequest, TransparentDetailWork,
    TransparentDisplayAddress, TransparentDisplayContradiction, TransparentDisplayDetails,
    TransparentDisplayFacts, TransparentDisplayOmission, TransparentDisplayOutput,
    TransparentDisplayProvenance, TransparentDisplaySender, TransparentDisplaySource,
    TransparentDisplayStore, TransparentDisplayView, TransparentDisplayViewOutput,
    TransparentDisplayViewSender, TransparentLedgerMode, WholeTransactionFee,
    transparent_display_address,
};
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::{
    consensus::{self, BlockHeight},
    value::{ZatBalance, Zatoshis},
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

/// Address kind codes of `transparent_tx_display.sender_kind` and
/// `transparent_tx_display_outputs.address_kind`, as the display publisher encodes them.
const KIND_ABSENT: i64 = 0;
const KIND_P2PKH: i64 = 1;
const KIND_P2SH: i64 = 2;
const KIND_NON_STANDARD: i64 = 3;

fn address_columns(address: Option<TransparentAddress>) -> (i64, Option<[u8; 20]>) {
    match address {
        Some(TransparentAddress::PublicKeyHash(hash)) => (KIND_P2PKH, Some(hash)),
        Some(TransparentAddress::ScriptHash(hash)) => (KIND_P2SH, Some(hash)),
        None => (KIND_NON_STANDARD, None),
    }
}

fn sender_columns(sender: TransparentDisplaySender) -> (i64, Option<[u8; 20]>) {
    match sender {
        TransparentDisplaySender::Absent => (KIND_ABSENT, None),
        TransparentDisplaySender::Address(address) => address_columns(Some(address)),
        TransparentDisplaySender::NonStandard => address_columns(None),
    }
}

fn sender_from_columns(
    kind: i64,
    hash: Option<[u8; 20]>,
) -> Result<TransparentDisplaySender, SqliteClientError> {
    match (kind, hash) {
        (KIND_ABSENT, None) => Ok(TransparentDisplaySender::Absent),
        (KIND_P2PKH, Some(hash)) => Ok(TransparentDisplaySender::Address(
            TransparentAddress::PublicKeyHash(hash),
        )),
        (KIND_P2SH, Some(hash)) => Ok(TransparentDisplaySender::Address(
            TransparentAddress::ScriptHash(hash),
        )),
        (KIND_NON_STANDARD, None) => Ok(TransparentDisplaySender::NonStandard),
        _ => Err(SqliteClientError::CorruptedData(
            "invalid display address kind".into(),
        )),
    }
}

/// What the wallet knows about one outpoint a transaction spends.
#[derive(Default)]
struct KnownInput {
    /// The spending input's index, when a recovered spend names it.
    input_index: Option<u32>,
    /// The script of the spent output, when known.
    script: Option<Vec<u8>>,
    /// The value of the spent output, when known.
    value: Option<u64>,
}

/// Every distinct outpoint the wallet knows transaction `tx` (`txid`) spends, by outpoint:
/// recovered spends (with input index and script, and value once the output is recovered),
/// spend links to owned outputs (script and value only while financial queries count
/// the output), and public spend links from the spend map (the outpoint only).
/// These records can reject a contradiction even when they no longer establish ownership.
fn known_inputs(
    conn: &Connection,
    tx: i64,
    txid: &[u8],
) -> Result<BTreeMap<([u8; 32], u32), KnownInput>, SqliteClientError> {
    let counted = output_observation_condition("o");
    let mut inputs: BTreeMap<([u8; 32], u32), KnownInput> = BTreeMap::new();
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT e.prevout_txid, e.prevout_output_index, e.input_index, e.prevout_script,
                (SELECT re.value_zat FROM tpir_receive_events re
                 WHERE re.txid = e.prevout_txid AND re.output_index = e.prevout_output_index)
         FROM tpir_spend_events e
         WHERE e.spending_txid = :txid
         UNION ALL
         SELECT ot.txid, o.output_index, NULL,
                CASE WHEN ({counted}) THEN o.script END,
                CASE WHEN ({counted}) THEN o.value_zat END
         FROM transparent_received_output_spends s
         JOIN transparent_received_outputs o ON o.id = s.transparent_received_output_id
         JOIN transactions ot ON ot.id_tx = o.transaction_id
         WHERE s.transaction_id = :tx
         UNION ALL
         SELECT m.prevout_txid, m.prevout_output_index, NULL, NULL, NULL
         FROM transparent_spend_map m
         WHERE m.spending_transaction_id = :tx"
    ))?;
    let mut rows = stmt.query(named_params![":tx": tx, ":txid": txid])?;
    while let Some(row) = rows.next()? {
        let outpoint = (row.get::<_, [u8; 32]>(0)?, row.get::<_, u32>(1)?);
        let known = inputs.entry(outpoint).or_default();
        known.input_index = known.input_index.or(row.get(2)?);
        if known.script.is_none() {
            known.script = row.get(3)?;
        }
        known.value = known.value.or(row.get(4)?);
    }
    Ok(inputs)
}

/// Spent outpoints whose ownership the account can affirm now, with their spent scripts.
/// Private evidence must be active, qualified, non-quarantined and at the transaction's
/// accepted height. Independently recorded public or local spends retain their semantics;
/// ledger projection alone cannot bypass the private evidence checks.
fn owned_inputs(
    conn: &Connection,
    tx: i64,
    txid: &[u8],
    account: Option<i64>,
) -> Result<BTreeMap<([u8; 32], u32), Vec<u8>>, SqliteClientError> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT e.prevout_txid, e.prevout_output_index, e.prevout_script
         FROM tpir_spend_events e
         JOIN tpir_active_accounts a ON a.account_id = e.account_id
         JOIN transactions t ON t.txid = e.spending_txid AND t.mined_height = e.mined_height
         WHERE e.spending_txid = :txid AND e.account_id = :account
         AND NOT EXISTS (SELECT 1 FROM tpir_quarantined_accounts qa
                         WHERE qa.account_id = e.account_id)
         AND EXISTS (
             SELECT 1 FROM tpir_spend_observations so
             JOIN tpir_qualified_revisions q ON q.revision_id = so.revision_id
             JOIN tpir_revisions r ON r.id = so.revision_id
             WHERE so.spend_id = e.id
             AND NOT EXISTS (SELECT 1 FROM tpir_quarantined_sources qs
                             WHERE qs.source = r.source)
         )
         UNION
         SELECT ot.txid, o.output_index, o.script
         FROM transparent_received_output_spends s
         JOIN transparent_received_outputs o ON o.id = s.transparent_received_output_id
         JOIN transactions ot ON ot.id_tx = o.transaction_id
         WHERE s.transaction_id = :tx AND o.account_id = :account AND ({})
         AND EXISTS (
             SELECT 1 FROM tpir_spend_origins origin
             WHERE origin.spending_transaction_id = s.transaction_id
             AND origin.prevout_txid = ot.txid AND origin.prevout_output_index = o.output_index
             AND origin.origin IN (0, 1)
         )",
        output_observation_condition("o"),
    ))?;
    Ok(stmt
        .query_map(
            named_params![":tx": tx, ":txid": txid, ":account": account],
            |row| Ok(((row.get(0)?, row.get(1)?), row.get(2)?)),
        )?
        .collect::<Result<_, _>>()?)
}

/// The address the first address-shaped input spends, when the wallet knows the index and
/// spent script of every input up to it: `Some(None)` when it knows all `count` inputs and
/// none is address-shaped, `None` when an input before the first address-shaped one is unknown.
fn known_first_address(
    inputs: &BTreeMap<([u8; 32], u32), KnownInput>,
    count: u32,
) -> Option<Option<TransparentAddress>> {
    let by_index: BTreeMap<u32, Option<&[u8]>> = inputs
        .values()
        .filter_map(|i| i.input_index.map(|index| (index, i.script.as_deref())))
        .collect();
    for index in 0..count {
        let script = (*by_index.get(&index)?)?;
        if let Some(address) = transparent_display_address(script) {
            return Some(Some(address));
        }
    }
    Some(None)
}

/// Checks the sender and `multiple_source_scripts` against the spent scripts the wallet knows.
///
/// When it knows the script of every input, the flag must say whether they differ. When it
/// knows every input in order up to the first address-shaped one, the sender must be that
/// one's address; knowing every script but not every index, the sender must be one of them.
/// Otherwise it can only require the flag when it already knows two distinct scripts, and,
/// when the flag is clear, the sender to be the one script every input spends.
fn sender_contradiction(
    facts: &TransparentDisplayFacts,
    inputs: &BTreeMap<([u8; 32], u32), KnownInput>,
) -> Option<TransparentDisplayContradiction> {
    use TransparentDisplayContradiction as C;
    let scripts: BTreeSet<&[u8]> = inputs
        .values()
        .filter_map(|i| i.script.as_deref())
        .collect();
    let all_known =
        inputs.len() == facts.input_count as usize && inputs.values().all(|i| i.script.is_some());
    if (scripts.len() > 1 && !facts.multiple_source_scripts)
        || (all_known && facts.multiple_source_scripts != (scripts.len() > 1))
    {
        return Some(C::SourceScripts);
    }

    let addressed: BTreeSet<TransparentAddress> = scripts
        .iter()
        .filter_map(|s| transparent_display_address(s))
        .collect();
    let consistent = match (facts.sender, known_first_address(inputs, facts.input_count)) {
        // Without inputs the wallet knows no spend (`InputCount`).
        (TransparentDisplaySender::Absent, _) => true,
        (TransparentDisplaySender::NonStandard, _) => addressed.is_empty(),
        (TransparentDisplaySender::Address(sender), Some(first)) => first == Some(sender),
        (TransparentDisplaySender::Address(sender), None) if all_known => {
            addressed.contains(&sender)
        }
        // Every input spends the one script the wallet may know.
        (TransparentDisplaySender::Address(sender), None) if !facts.multiple_source_scripts => {
            scripts
                .first()
                .is_none_or(|s| transparent_display_address(s) == Some(sender))
        }
        (TransparentDisplaySender::Address(_), None) => true,
    };
    (!consistent).then_some(C::Sender)
}

/// Checks the transparent value balance when the wallet knows the value of every input.
///
/// The shielded pools' net contribution is the fee plus the outputs minus the inputs. With
/// only the first two outputs given, the fee and those outputs bound it from below.
fn funding_contradiction(
    facts: &TransparentDisplayFacts,
    inputs: &BTreeMap<([u8; 32], u32), KnownInput>,
) -> Option<TransparentDisplayContradiction> {
    if facts.input_count == 0 || inputs.len() != facts.input_count as usize {
        return None;
    }
    let spent: u128 = inputs
        .values()
        .map(|i| i.value.map(u128::from))
        .sum::<Option<u128>>()?;
    let paid = u128::from(facts.fee.into_u64())
        + facts
            .outputs
            .iter()
            .map(|o| u128::from(o.value.into_u64()))
            .sum::<u128>();
    let contradicted = if paid > spent {
        // The shielded pools paid part of it (or, without shielded components, it is
        // unbalanced: mixed funding requires them).
        !facts.shielded_and_transparent_funding
    } else if !facts.more_than_two_outputs() {
        // Every output is given: the shielded pools contributed nothing, and a transaction
        // without shielded components balances exactly.
        facts.shielded_and_transparent_funding || (!facts.shielded_components && paid != spent)
    } else {
        false
    };
    contradicted.then_some(TransparentDisplayContradiction::Funding)
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
    let inputs = known_inputs(conn, tx, txid)?;
    let known_spends = u32::try_from(inputs.len()).unwrap_or(u32::MAX);

    // Coinbase: the flag must agree with the known position and with recovered receive events.
    // A coinbase transaction spends nothing, so no known spend may name it, and pays no fee.
    let event_coinbase: Vec<bool> = conn
        .prepare_cached("SELECT DISTINCT coinbase FROM tpir_receive_events WHERE txid = :txid")?
        .query_map(named_params![":txid": txid], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    if tx_index.is_some_and(|i| (i == 0) != facts.coinbase)
        || event_coinbase.iter().any(|c| *c != facts.coinbase)
        || (facts.coinbase
            && (facts.fee != Zatoshis::ZERO || facts.input_count != 0 || known_spends > 0))
    {
        return Ok(Some(C::Coinbase));
    }
    if !facts.is_well_formed() {
        return Ok(Some(C::Malformed));
    }

    // Every owned output financial queries count, and every recovered receive, must be below
    // the output count; at index 0 or 1 it must match the given output by value and by
    // script (P2PKH and P2SH by address; any other script faces a slot without one).
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
        if index >= facts.output_count {
            return Ok(Some(C::OutputIndexOutOfRange { index }));
        }
        if let Some(given) = facts.outputs.get(index as usize)
            && (given.value.into_u64() != value
                || given.address != transparent_display_address(&script))
        {
            return Ok(Some(C::OwnedOutput { index }));
        }
    }

    // Recovered metadata must agree. An unknown recovered fee asserts nothing.
    let metadata_conflict: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM tpir_transaction_metadata WHERE txid = :txid
         AND (input_count != :inputs OR shielded != :shielded
              OR (fee_state = 2) != :coinbase
              OR (fee_state = 0 AND fee_zat != :fee)))",
        named_params![
            ":txid": txid,
            ":inputs": facts.input_count,
            ":shielded": facts.shielded_components,
            ":coinbase": facts.coinbase,
            ":fee": facts.fee.into_u64() as i64,
        ],
        |row| row.get(0),
    )?;
    if metadata_conflict {
        return Ok(Some(C::Metadata));
    }

    // The stored fee must be equal; a coinbase transaction has none.
    if let Some(stored) = stored_fee
        && (facts.coinbase || facts.fee.into_u64() != stored)
    {
        return Ok(Some(C::Fee));
    }

    // A known shielded component, or a route-2 marker, requires the shielded bit.
    if !facts.shielded_components {
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
            named_params![":txid": txid, ":inputs": facts.input_count],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    if let Some(index) = beyond {
        return Ok(Some(C::InputIndex { index }));
    }
    // Public spend links carry no input index, but each names a distinct input.
    if known_spends > facts.input_count {
        return Ok(Some(C::InputCount {
            known: known_spends,
        }));
    }

    Ok(sender_contradiction(facts, &inputs).or_else(|| funding_contradiction(facts, &inputs)))
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

        let p = &facts.provenance;
        let (sender_kind, sender_hash) = sender_columns(facts.sender);
        conn.execute(
            "DELETE FROM transparent_tx_display WHERE transaction_id = :tx",
            named_params![":tx": tx],
        )?;
        conn.execute(
            "INSERT INTO transparent_tx_display
             (transaction_id, coinbase, fee_zat, input_count, output_count, shielded,
              sender_kind, sender_hash, multiple_source_scripts,
              shielded_and_transparent_funding, shard_id, revision, map_sha256,
              looked_up_height, stored_at)
             VALUES (:tx, :coinbase, :fee, :inputs, :outputs, :shielded, :sender_kind,
                     :sender_hash, :multiple, :mixed, :shard, :revision, :map, :height, :now)",
            named_params![
                ":tx": tx,
                ":coinbase": facts.coinbase,
                ":fee": facts.fee.into_u64() as i64,
                ":inputs": facts.input_count,
                ":outputs": facts.output_count,
                ":shielded": facts.shielded_components,
                ":sender_kind": sender_kind,
                ":sender_hash": sender_hash.as_ref().map(|h| &h[..]),
                ":multiple": facts.multiple_source_scripts,
                ":mixed": facts.shielded_and_transparent_funding,
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
             (transaction_id, output_index, value_zat, address_kind, address_hash)
             VALUES (:tx, :index, :value, :kind, :hash)",
        )?;
        for (output, index) in facts.outputs.iter().zip(0u32..) {
            let (kind, hash) = address_columns(output.address);
            insert.execute(named_params![
                ":tx": tx,
                ":index": index,
                ":value": output.value.into_u64() as i64,
                ":kind": kind,
                ":hash": hash.as_ref().map(|h| &h[..]),
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
    let corrupt = |what: &str| SqliteClientError::CorruptedData(format!("display {what}"));
    let display = conn
        .query_row(
            "SELECT t.txid, d.coinbase, d.fee_zat, d.input_count, d.output_count, d.shielded,
                    d.sender_kind, d.sender_hash, d.multiple_source_scripts,
                    d.shielded_and_transparent_funding, d.shard_id, d.revision, d.map_sha256,
                    d.looked_up_height
             FROM transparent_tx_display d JOIN transactions t ON t.id_tx = d.transaction_id
             WHERE d.transaction_id = :tx",
            named_params![":tx": tx],
            |row| {
                Ok((
                    (
                        row.get::<_, [u8; 32]>(0)?,
                        row.get::<_, bool>(1)?,
                        row.get::<_, u64>(2)?,
                        row.get::<_, u32>(3)?,
                        row.get::<_, u32>(4)?,
                        row.get::<_, bool>(5)?,
                    ),
                    (
                        row.get::<_, i64>(6)?,
                        row.get::<_, Option<[u8; 20]>>(7)?,
                        row.get::<_, bool>(8)?,
                        row.get::<_, bool>(9)?,
                    ),
                    (
                        row.get::<_, i64>(10)?,
                        row.get::<_, u32>(11)?,
                        row.get::<_, [u8; 32]>(12)?,
                        row.get::<_, u32>(13)?,
                    ),
                ))
            },
        )
        .optional()?;
    let Some((
        (txid, coinbase, fee, input_count, output_count, shielded),
        (sender_kind, sender_hash, multiple_source_scripts, mixed),
        (shard, revision, map, height),
    )) = display
    else {
        return Ok(None);
    };
    let outputs = conn
        .prepare_cached(
            "SELECT output_index, value_zat, address_kind, address_hash
             FROM transparent_tx_display_outputs
             WHERE transaction_id = :tx ORDER BY output_index",
        )?
        .query_map(named_params![":tx": tx], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, u64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<[u8; 20]>>(3)?,
            ))
        })?
        .zip(0u32..)
        .map(|(row, expected)| {
            let (index, value, kind, hash) = row?;
            if index != expected {
                return Err(corrupt("outputs are not contiguous"));
            }
            let address = match sender_from_columns(kind, hash)? {
                TransparentDisplaySender::Address(address) => Some(address),
                TransparentDisplaySender::NonStandard => None,
                TransparentDisplaySender::Absent => return Err(corrupt("output without a kind")),
            };
            let value =
                Zatoshis::from_u64(value).map_err(|_| corrupt("value exceeds MAX_MONEY"))?;
            Ok(TransparentDisplayOutput { value, address })
        })
        .collect::<Result<Vec<_>, SqliteClientError>>()?;
    let facts = TransparentDisplayFacts {
        txid: TxId::from_bytes(txid),
        coinbase,
        fee: Zatoshis::from_u64(fee).map_err(|_| corrupt("fee exceeds MAX_MONEY"))?,
        input_count,
        output_count,
        shielded_components: shielded,
        sender: sender_from_columns(sender_kind, sender_hash)?,
        outputs,
        multiple_source_scripts,
        shielded_and_transparent_funding: mixed,
        provenance: TransparentDisplayProvenance {
            shard_id: u64::try_from(shard).map_err(|_| corrupt("shard id is negative"))?,
            revision,
            map_sha256: map,
            looked_up_height: BlockHeight::from_u32(height),
        },
    };
    if !facts.is_well_formed() {
        return Err(corrupt("facts are malformed"));
    }
    Ok(Some(facts))
}

/// The pushes of a push-only script, or `None` when it is malformed or not push-only. A small
/// number opcode (`OP_1NEGATE`, `OP_1` to `OP_16`) pushes its opcode byte.
fn pushes(script: &[u8]) -> Option<Vec<&[u8]>> {
    let mut out = Vec::new();
    let mut rest = script;
    while let Some((&op, tail)) = rest.split_first() {
        let (len, tail) = match op {
            0x00..=0x4b => (usize::from(op), tail),
            0x4c => (usize::from(*tail.first()?), &tail[1..]),
            0x4d => (
                usize::from(u16::from_le_bytes(tail.get(..2)?.try_into().ok()?)),
                &tail[2..],
            ),
            0x4e => (
                usize::try_from(u32::from_le_bytes(tail.get(..4)?.try_into().ok()?)).ok()?,
                &tail[4..],
            ),
            0x4f | 0x51..=0x60 => {
                out.push(&rest[..1]);
                rest = tail;
                continue;
            }
            _ => return None,
        };
        out.push(tail.get(..len)?);
        rest = &tail[len..];
    }
    Some(out)
}

/// The last opcode of a well-formed script: every push is within the script.
fn last_opcode(script: &[u8]) -> Option<u8> {
    let mut last = None;
    let mut rest = script;
    while let Some((&op, tail)) = rest.split_first() {
        let skip = match op {
            0x01..=0x4b => usize::from(op),
            0x4c => 1 + usize::from(*tail.first()?),
            0x4d => 2 + usize::from(u16::from_le_bytes(tail.get(..2)?.try_into().ok()?)),
            0x4e => {
                4 + usize::try_from(u32::from_le_bytes(tail.get(..4)?.try_into().ok()?)).ok()?
            }
            _ => 0,
        };
        rest = tail.get(skip..)?;
        last = Some(op);
    }
    last
}

/// The address an input spends, read from its unlocking script alone, without the spent output.
///
/// A P2PKH spend is a signature and then a 33-byte compressed or 65-byte uncompressed public
/// key; its address is the key's HASH160. A P2SH spend pushes its redeem script last, after at
/// least one other push; the redeem script must be well formed and end in a signature check
/// (`OP_CHECKSIG`, `OP_CHECKMULTISIG` or their `VERIFY` forms), which tells it apart from a
/// signature. Anything else has no address here.
///
/// Without the spent output this is a reading, not a proof: a P2SH redeem script shaped like
/// a public key reads as P2PKH, and a non-standard locking script can accept any key. So a
/// raw transaction's sender is never taken as the account's own on this alone.
fn spent_address(script_sig: &[u8]) -> Option<TransparentAddress> {
    let pushes = pushes(script_sig)?;
    let is_signature = |sig: &[u8]| (9..=73).contains(&sig.len()) && sig[0] == 0x30;
    let is_key = |key: &[u8]| {
        (key.len() == 33 && matches!(key[0], 0x02 | 0x03)) || (key.len() == 65 && key[0] == 0x04)
    };
    match pushes.as_slice() {
        [sig, key] if is_signature(sig) && is_key(key) => Some(TransparentAddress::PublicKeyHash(
            transparent::util::hash160::hash(key),
        )),
        [_, .., redeem] if matches!(last_opcode(redeem), Some(0xac..=0xaf)) => Some(
            TransparentAddress::ScriptHash(transparent::util::hash160::hash(redeem)),
        ),
        _ => None,
    }
}

/// The net value the shielded pools contribute to the transparent side: the sum of the shielded
/// value balances, which equals the fee plus the transparent outputs minus the transparent
/// inputs. `None` when it overflows.
fn shielded_contribution(transaction: &Transaction) -> Option<i64> {
    let zero = ZatBalance::zero();
    let total = [
        transaction
            .sprout_bundle()
            .map_or(Some(zero), |b| b.value_balance())?,
        transaction
            .sapling_bundle()
            .map_or(zero, |b| *b.value_balance()),
        transaction
            .orchard_bundle()
            .map_or(zero, |b| *b.value_balance()),
        transaction
            .ironwood_bundle()
            .map_or(zero, |b| *b.value_balance()),
    ]
    .iter()
    .sum::<Option<ZatBalance>>()?;
    Some(i64::from(total))
}

/// The omissions of a view, in their fixed order.
///
/// Several source scripts are this account's own send when it funded every input; when it
/// funded some, the rest came from inputs it does not own (shared funding). With one source
/// script, an account funding any input owns the script every input spends, so neither applies.
fn omissions(
    sender: &TransparentDisplayViewSender,
    multiple_source_scripts: bool,
    owned_inputs: u32,
    input_count: u32,
    mixed_funding: bool,
    outputs: &[TransparentDisplayViewOutput],
    more_than_two_outputs: bool,
) -> Vec<TransparentDisplayOmission> {
    use TransparentDisplayOmission as O;
    let mut omissions = Vec::new();
    if *sender == TransparentDisplayViewSender::NonStandard {
        omissions.push(O::NonStandardSender);
    }
    if multiple_source_scripts {
        if owned_inputs == 0 {
            omissions.push(O::MultipleSourceScripts);
        } else if owned_inputs < input_count {
            omissions.push(O::SharedFunding);
        }
    }
    if mixed_funding {
        omissions.push(O::ShieldedAndTransparentFunding);
    }
    omissions.extend(
        outputs
            .iter()
            .filter(|o| o.address.is_none())
            .map(|o| O::NonStandardOutput { index: o.index }),
    );
    if more_than_two_outputs {
        omissions.push(O::MoreThanTwoOutputs);
    }
    omissions
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
    let account_id: Option<i64> = conn
        .query_row(
            "SELECT id FROM accounts WHERE uuid = :account",
            named_params![":account": account.0],
            |row| row.get(0),
        )
        .optional()?;
    let owned_outputs: Vec<u32> = conn
        .prepare_cached(&format!(
            "SELECT o.output_index FROM transparent_received_outputs o
             WHERE o.transaction_id = :tx AND o.account_id IS :account AND ({})",
            output_observation_condition("o"),
        ))?
        .query_map(named_params![":tx": tx, ":account": account_id], |row| {
            row.get(0)
        })?
        .collect::<Result<_, _>>()?;
    let transaction = if has_raw {
        let Some((_, transaction)) = crate::wallet::get_transaction(conn, params, txid)? else {
            return Ok(None);
        };
        Some(transaction)
    } else {
        None
    };
    let mut owned_inputs = owned_inputs(conn, tx, txid.as_ref(), account_id)?;
    // A recorded link cannot attribute a raw sender unless the transaction actually spends
    // that outpoint. Unlocking scripts can reveal a previously used public key on their own.
    if let Some(transaction) = &transaction {
        owned_inputs.retain(|(hash, index), _| {
            transaction.transparent_bundle().is_some_and(|bundle| {
                bundle
                    .vin
                    .iter()
                    .any(|input| input.prevout().hash() == hash && input.prevout().n() == *index)
            })
        });
    }
    let address = |address: TransparentAddress| TransparentDisplayAddress {
        address,
        encoded: zcash_keys::encoding::encode_transparent_address_p(params, &address),
    };
    // A sender is the account's own when the account is known to have spent an output paying
    // it here or, for a sender the publisher asserts from the spent outputs, when it is one of
    // the account's addresses. An unlocking script alone can show any public key that has ever
    // signed, so in a raw transaction only a known spend makes the sender the account's.
    let sender_of = |found: TransparentAddress, asserted: bool| -> Result<_, SqliteClientError> {
        let found = address(found);
        let owned = owned_inputs
            .values()
            .any(|script| transparent_display_address(script) == Some(found.address))
            || asserted
                && conn.query_row(
                    "SELECT EXISTS (SELECT 1 FROM addresses
                            WHERE account_id IS :account
                            AND cached_transparent_receiver_address = :address)",
                    named_params![":account": account_id, ":address": found.encoded],
                    |row| row.get(0),
                )?;
        Ok(TransparentDisplayViewSender::Address {
            address: found,
            owned,
        })
    };
    let view_output = |index: u32, value: Zatoshis, found: Option<TransparentAddress>| {
        TransparentDisplayViewOutput {
            index,
            value,
            address: found.map(address),
            owned: owned_outputs.contains(&index),
        }
    };
    let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);

    if let Some(transaction) = transaction {
        let bundle = transaction.transparent_bundle();
        let coinbase = bundle.is_some_and(|b| b.is_coinbase());
        let vin = match bundle {
            Some(b) if !coinbase => &b.vin[..],
            _ => &[],
        };
        // The address each input spends, as far as its unlocking script shows it.
        let spent: Vec<Option<TransparentAddress>> = vin
            .iter()
            .map(|i| spent_address(&i.script_sig().0.0))
            .collect();
        let sender = if coinbase {
            TransparentDisplayViewSender::Coinbase
        } else if vin.is_empty() {
            TransparentDisplayViewSender::Shielded
        } else {
            match spent.iter().flatten().next() {
                Some(found) => sender_of(*found, false)?,
                None => TransparentDisplayViewSender::NonStandard,
            }
        };
        let outputs: Vec<_> = bundle
            .map(|b| {
                b.vout
                    .iter()
                    .zip(0u32..)
                    .map(|(o, index)| {
                        view_output(
                            index,
                            o.value(),
                            transparent_display_address(&o.script_pubkey().0.0),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let owned = count(
            vin.iter()
                .filter(|i| owned_inputs.contains_key(&(*i.prevout().hash(), i.prevout().n())))
                .count(),
        );
        let input_count = count(vin.len());
        let omissions = omissions(
            &sender,
            spent.windows(2).any(|w| w[0] != w[1]),
            owned,
            input_count,
            !vin.is_empty() && shielded_contribution(&transaction).is_some_and(|c| c > 0),
            &outputs,
            false,
        );
        let fee = if coinbase {
            WholeTransactionFee::NotApplicable
        } else {
            stored_fee
                .and_then(|f| Zatoshis::from_u64(f).ok())
                .map_or(WholeTransactionFee::Unknown, WholeTransactionFee::Exact)
        };
        return Ok(Some(TransparentDisplayView::Available(
            TransparentDisplayDetails {
                coinbase,
                fee,
                input_count,
                output_count: count(outputs.len()),
                shielded: transaction.sprout_bundle().is_some()
                    || transaction.sapling_bundle().is_some()
                    || transaction.orchard_bundle().is_some()
                    || transaction.ironwood_bundle().is_some(),
                sender,
                outputs,
                omissions,
                source: TransparentDisplaySource::RawTransaction,
            },
        )));
    }

    if let Some(facts) = stored_facts(conn, tx)? {
        let sender = match facts.sender {
            TransparentDisplaySender::Absent if facts.coinbase => {
                TransparentDisplayViewSender::Coinbase
            }
            TransparentDisplaySender::Absent => TransparentDisplayViewSender::Shielded,
            TransparentDisplaySender::Address(found) => sender_of(found, true)?,
            TransparentDisplaySender::NonStandard => TransparentDisplayViewSender::NonStandard,
        };
        let outputs: Vec<_> = facts
            .outputs
            .iter()
            .zip(0u32..)
            .map(|(o, index)| view_output(index, o.value, o.address))
            .collect();
        let omissions = omissions(
            &sender,
            facts.multiple_source_scripts,
            count(owned_inputs.len()),
            facts.input_count,
            facts.shielded_and_transparent_funding,
            &outputs,
            facts.more_than_two_outputs(),
        );
        return Ok(Some(TransparentDisplayView::Available(
            TransparentDisplayDetails {
                coinbase: facts.coinbase,
                fee: facts.metadata().fee,
                input_count: facts.input_count,
                output_count: facts.output_count,
                shielded: facts.shielded_components,
                sender,
                outputs,
                omissions,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn push(data: &[u8]) -> Vec<u8> {
        assert!(data.len() <= 75);
        [&[data.len() as u8][..], data].concat()
    }

    fn signature() -> Vec<u8> {
        let mut sig = vec![0x30; 71];
        sig[70] = 0x01;
        sig
    }

    #[test]
    fn spent_address_from_unlocking_scripts() {
        use transparent::util::hash160::hash;
        let key = [&[0x02][..], &[7; 32]].concat();
        let p2pkh = [push(&signature()), push(&key)].concat();
        assert_eq!(
            spent_address(&p2pkh),
            Some(TransparentAddress::PublicKeyHash(hash(&key)))
        );
        let uncompressed = [&[0x04][..], &[7; 64]].concat();
        assert_eq!(
            spent_address(&[push(&signature()), push(&uncompressed)].concat()),
            Some(TransparentAddress::PublicKeyHash(hash(&uncompressed)))
        );
        // 2-of-2 multisig P2SH: OP_0, two signatures, the redeem script.
        let redeem = [
            &[0x52][..],
            &push(&key),
            &push(&[&[0x03][..], &[8; 32]].concat()),
            &[0x52, 0xae],
        ]
        .concat();
        let p2sh = [
            &[0x00][..],
            &push(&signature()),
            &push(&signature()),
            &[0x4c, redeem.len() as u8],
            &redeem,
        ]
        .concat();
        assert_eq!(
            spent_address(&p2sh),
            Some(TransparentAddress::ScriptHash(hash(&redeem)))
        );
        // A lone signature (P2PK), a non-push opcode, a truncated push, an empty script, and a
        // last push that does not end in a signature check have no address.
        for none in [
            push(&signature()),
            [push(&signature()), vec![0xac]].concat(),
            vec![0x05, 0x01],
            vec![],
            [push(&signature()), push(&[0x51, 0x87])].concat(),
            [push(&signature()), push(&[0x02; 20])].concat(),
        ] {
            assert_eq!(spent_address(&none), None, "{none:x?}");
        }
    }
}
