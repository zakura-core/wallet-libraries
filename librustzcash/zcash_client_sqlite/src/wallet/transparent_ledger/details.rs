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
    TransparentDetailOutcome, TransparentDetailReasons, TransparentDetailRequest,
    TransparentDisplayContradiction, TransparentDisplayDetails, TransparentDisplayFacts,
    TransparentDisplayProvenance, TransparentDisplaySource, TransparentDisplayStore,
    TransparentDisplayView, TransparentDisplayViewOutput, TransparentLedgerMode,
    WholeTransactionFee,
};
use zcash_primitives::transaction::TxId;
use zcash_protocol::{
    consensus::{self, BlockHeight},
    value::Zatoshis,
};

use crate::{AccountUuid, TxRef, error::SqliteClientError, wallet::TxQueryType};

use super::{check_transparent_policy_generation, resolve_mode, with_read_snapshot};

const UNAVAILABLE: i64 = 0;
const ABSENT: i64 = 1;
const NOT_COVERED: i64 = 2;
const UNSUPPORTED: i64 = 3;
const PROTOCOL: i64 = 4;
const CONTRADICTION: i64 = 5;

/// Outcomes that hold a row until the caller's display map changes.
const HELD_OUTCOMES: &str = "(2, 3, 5)";

const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;

/// Whether the wallet still records an effect of transaction `t`: an owned output, a spend of
/// one, or a route-2 marker.
const RELATED: &str = "(
    EXISTS (SELECT 1 FROM transparent_received_outputs o WHERE o.transaction_id = t.id_tx)
    OR EXISTS (SELECT 1 FROM transparent_received_output_spends s
               WHERE s.transaction_id = t.id_tx)
    OR EXISTS (SELECT 1 FROM transparent_spend_map m WHERE m.spending_transaction_id = t.id_tx)
    OR EXISTS (SELECT 1 FROM ironwood_enhance_routing r
               WHERE r.transaction_id = t.id_tx AND r.route = 2)
)";

fn unix(now: SystemTime) -> i64 {
    now.duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Queues work for `txid` with `reasons`, OR-ed into an existing row, while it has no raw bytes.
#[cfg_attr(
    not(any(feature = "transparent-inputs", feature = "orchard")),
    allow(dead_code)
)]
pub(crate) fn enqueue_txid(
    conn: &Connection,
    txid: &TxId,
    reasons: TransparentDetailReasons,
) -> Result<(), SqliteClientError> {
    conn.prepare_cached(
        "INSERT INTO transparent_detail_work (transaction_id, reasons)
         SELECT id_tx, :reasons FROM transactions WHERE txid = :txid AND raw IS NULL
         ON CONFLICT (transaction_id) DO UPDATE SET reasons = reasons | excluded.reasons",
    )?
    .execute(named_params![":txid": txid.as_ref(), ":reasons": reasons.bits()])?;
    Ok(())
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
    conn.prepare_cached(
        "INSERT INTO transparent_detail_work (transaction_id, reasons)
         SELECT id_tx, :reasons FROM transactions WHERE id_tx = :tx AND raw IS NULL
         ON CONFLICT (transaction_id) DO UPDATE SET reasons = reasons | excluded.reasons",
    )?
    .execute(named_params![":tx": tx_ref.0, ":reasons": reasons.bits()])?;
    Ok(())
}

/// Queues mixed-transaction work for every unresolved route-2 transaction.
pub(crate) fn enqueue_route_two(conn: &Connection) -> Result<(), SqliteClientError> {
    conn.execute(
        "INSERT INTO transparent_detail_work (transaction_id, reasons)
         SELECT r.transaction_id, :mixed FROM ironwood_enhance_routing r
         JOIN transactions t ON t.id_tx = r.transaction_id
         WHERE r.route = 2 AND t.raw IS NULL
         ON CONFLICT (transaction_id) DO UPDATE SET reasons = reasons | excluded.reasons",
        named_params![":mixed": TransparentDetailReasons::MIXED.bits()],
    )?;
    Ok(())
}

/// Removes work and display facts once raw bytes are stored: the raw transaction supersedes them.
pub(crate) fn clear(conn: &Connection, tx_ref: TxRef) -> Result<(), SqliteClientError> {
    conn.prepare_cached("DELETE FROM transparent_detail_work WHERE transaction_id = :tx")?
        .execute(named_params![":tx": tx_ref.0])?;
    conn.prepare_cached("DELETE FROM transparent_tx_display WHERE transaction_id = :tx")?
        .execute(named_params![":tx": tx_ref.0])?;
    Ok(())
}

/// The due lookups; see `TransparentDetailRead::transparent_detail_work`.
pub(crate) fn work(
    conn: &Connection,
    configured: Option<TransparentLedgerMode>,
    now: SystemTime,
    limit: usize,
    map_sha256: Option<[u8; 32]>,
) -> Result<Vec<TransparentDetailRequest>, SqliteClientError> {
    let mode = resolve_mode(conn, configured)?;
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT t.txid, t.mined_height, w.reasons
         FROM transparent_detail_work w
         JOIN transactions t ON t.id_tx = w.transaction_id
         WHERE t.mined_height IS NOT NULL AND t.raw IS NULL AND {RELATED}
           AND (
               (w.attempted_height IS NOT NULL AND w.attempted_height != t.mined_height)
               OR (w.next_attempt_at <= :now
                   AND NOT (IFNULL(w.last_outcome, -1) IN {HELD_OUTCOMES}
                            AND (:map IS NULL OR w.last_map_sha256 IS :map)))
           )
           AND NOT (:public AND EXISTS (
               SELECT 1 FROM tx_retrieval_queue q
               WHERE q.txid = t.txid AND q.query_type = :enhancement))
         ORDER BY (w.attempts = 0
                   OR (w.attempted_height IS NOT NULL AND w.attempted_height != t.mined_height))
                  DESC,
                  t.mined_height DESC, t.txid
         LIMIT :limit"
    ))?;
    let rows = stmt.query_map(
        named_params![
            ":now": unix(now),
            ":map": map_sha256.as_ref().map(|m| &m[..]),
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
    Ok(rows.collect::<Result<_, _>>()?)
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
            let advised = retry_after.map_or(0, |d| d.as_secs());
            exponential(30, HOUR, attempts, txid).max(advised).min(HOUR)
        }
        TransparentDetailOutcome::Protocol => exponential(30, HOUR, attempts, txid),
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
    }
}

fn record_outcome(
    conn: &Connection,
    txid: &TxId,
    outcome: TransparentDetailOutcome,
    map_sha256: Option<[u8; 32]>,
    now: SystemTime,
) -> Result<(), SqliteClientError> {
    let row = conn
        .query_row(
            "SELECT w.transaction_id, w.attempts, w.attempted_height, t.mined_height
             FROM transparent_detail_work w JOIN transactions t ON t.id_tx = w.transaction_id
             WHERE t.txid = :txid",
            named_params![":txid": txid.as_ref()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, Option<u32>>(2)?,
                    row.get::<_, Option<u32>>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((tx, attempts, attempted_height, mined_height)) = row else {
        return Ok(());
    };
    // A changed placement starts a fresh backoff.
    let attempts = if attempted_height.is_some() && attempted_height == mined_height {
        attempts.saturating_add(1)
    } else {
        1
    };
    let delay = i64::try_from(backoff(outcome, attempts, txid).as_secs()).unwrap_or(i64::MAX);
    conn.execute(
        "UPDATE transparent_detail_work
         SET attempts = :attempts, next_attempt_at = :next, attempted_height = :height,
             last_outcome = :outcome, last_map_sha256 = :map
         WHERE transaction_id = :tx",
        named_params![
            ":tx": tx,
            ":attempts": attempts,
            ":next": unix(now).saturating_add(delay),
            ":height": mined_height,
            ":outcome": outcome_code(outcome),
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
    outcome: TransparentDetailOutcome,
    map_sha256: Option<[u8; 32]>,
    now: SystemTime,
) -> Result<(), SqliteClientError> {
    resolve_mode(conn, configured)?;
    with_read_snapshot(conn, |conn| {
        record_outcome(conn, &txid, outcome, map_sha256, now)
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

    // Every owned output must be present at its index with the same value and script.
    let owned: Vec<(u32, u64, Vec<u8>)> = conn
        .prepare_cached(
            "SELECT output_index, value_zat, script FROM transparent_received_outputs
             WHERE transaction_id = :tx
             UNION
             SELECT output_index, value_zat, script FROM tpir_receive_events WHERE txid = :txid
             ORDER BY 1",
        )?
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
    Ok(None)
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
        if let Some(kind) = validate(conn, tx, tx_index, fee, &facts)? {
            record_outcome(
                conn,
                &facts.txid,
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
    resolve_mode(conn, configured)?;
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
        .prepare_cached(
            "SELECT o.output_index FROM transparent_received_outputs o
             JOIN accounts a ON a.id = o.account_id
             WHERE o.transaction_id = :tx AND a.uuid = :account",
        )?
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

    let display = conn
        .query_row(
            "SELECT coinbase, fee_state, fee_zat, input_count, shielded, shard_id, revision,
                    map_sha256, looked_up_height
             FROM transparent_tx_display WHERE transaction_id = :tx",
            named_params![":tx": tx],
            |row| {
                Ok((
                    row.get::<_, bool>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<u64>>(2)?,
                    row.get::<_, u32>(3)?,
                    row.get::<_, bool>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, u32>(6)?,
                    row.get::<_, [u8; 32]>(7)?,
                    row.get::<_, u32>(8)?,
                ))
            },
        )
        .optional()?;
    if let Some((coinbase, fee_state, fee, input_count, shielded, shard, revision, map, height)) =
        display
    {
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
            .map(|row| {
                let (index, value, script) = row?;
                let value = Zatoshis::from_u64(value).map_err(|_| {
                    SqliteClientError::CorruptedData("display value exceeds MAX_MONEY".into())
                })?;
                Ok(view_output(index, value, script, owned.contains(&index)))
            })
            .collect::<Result<_, SqliteClientError>>()?;
        return Ok(Some(TransparentDisplayView::Available(
            TransparentDisplayDetails {
                outputs,
                coinbase,
                fee: fee_from_columns(fee_state, fee)?,
                input_count,
                shielded,
                source: TransparentDisplaySource::Display(TransparentDisplayProvenance {
                    shard_id: u64::try_from(shard).map_err(|_| {
                        SqliteClientError::CorruptedData("negative display shard id".into())
                    })?,
                    revision,
                    map_sha256: map,
                    looked_up_height: BlockHeight::from_u32(height),
                }),
            },
        )));
    }

    let work: Option<Option<i64>> = conn
        .query_row(
            "SELECT last_outcome FROM transparent_detail_work WHERE transaction_id = :tx",
            named_params![":tx": tx],
            |row| row.get(0),
        )
        .optional()?;
    Ok(Some(match work {
        Some(None) => TransparentDisplayView::Pending,
        Some(Some(NOT_COVERED)) => TransparentDisplayView::NotCovered,
        Some(Some(_)) => TransparentDisplayView::Unavailable,
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
