//! History completeness, derived from the facts the wallet holds.
//!
//! Nothing here is stored. Completeness follows from the transaction row, the account's recorded
//! outputs and spends, the scan queue, the account's ledger coverage, and queued follow-on work,
//! so a rewind, promotion, account change, or later enhancement changes the result as soon as it
//! changes those facts.

#[cfg(test)]
mod tests;

use std::rc::Rc;

use rusqlite::{OptionalExtension as _, named_params, types::Value};
use zcash_client_backend::data_api::transparent_ledger::{
    AccountMovement, AggregatePayment, DetailCompleteness, EffectCompleteness, FeeState,
    HistoryClassification, MetadataProvenance, PoolEffect, TransactionFunding,
    TransactionHistoryDetails, TransactionMetadata, TransactionMetadataEvidence,
    TransparentLedgerMode, WholeTransactionFee,
};
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::{
    PoolType, ShieldedPool,
    consensus::{self, BlockHeight, BranchId},
    value::Zatoshis,
};

use crate::{
    AccountUuid,
    error::SqliteClientError,
    wallet::{
        chain_tip_height,
        common::table_constants,
        encoding::{parse_pool_code, pool_code},
        fully_scanned_height,
    },
};

use super::{policy::pending_details, resolve_mode};

#[cfg(feature = "transparent-inputs")]
use {
    super::recovery::account_ledger,
    zcash_client_backend::data_api::transparent_ledger::AccountLifecycle,
    zcash_keys::keys::transparent::gap_limits::GapLimits,
};

/// The pools this build supports, in the order history entries report them.
fn supported_pools() -> Vec<PoolType> {
    vec![
        #[cfg(feature = "transparent-inputs")]
        PoolType::Transparent,
        PoolType::SAPLING,
        #[cfg(feature = "orchard")]
        PoolType::ORCHARD,
        #[cfg(feature = "orchard")]
        PoolType::IRONWOOD,
    ]
}

/// What the account's transparent evidence can establish, independent of any one transaction.
#[cfg_attr(not(feature = "transparent-inputs"), allow(dead_code))]
enum TransparentDiscovery {
    /// Public discovery holds authority.
    Public,
    /// Private authority applies. An active, unquarantined account's ledger covers every watched
    /// address through `covered_through`; otherwise nothing is covered.
    Private {
        covered_through: Option<BlockHeight>,
    },
}

#[cfg(feature = "transparent-inputs")]
fn transparent_discovery<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    gap_limits: &GapLimits,
    mode: TransparentLedgerMode,
    account: AccountUuid,
) -> Result<TransparentDiscovery, SqliteClientError> {
    if mode.retains_public_authority() {
        return Ok(TransparentDiscovery::Public);
    }
    let ledger = account_ledger(conn, params, gap_limits, account)?;
    let covered_through = (ledger.lifecycle == AccountLifecycle::Active && !ledger.quarantined)
        .then_some(ledger.status.covered_through)
        .flatten();
    Ok(TransparentDiscovery::Private { covered_through })
}

/// Current qualified facts, kept separate from independently stored local-send records.
fn metadata_evidence(
    conn: &rusqlite::Connection,
    account: i64,
    txid: &TxId,
) -> Result<Option<TransactionMetadataEvidence>, SqliteClientError> {
    let mut stmt = conn.prepare_cached("SELECT m.fee_state, m.fee_zat, m.input_count, m.shielded,
        r.source, r.revision, r.lineage
        FROM tpir_transaction_metadata m
        JOIN tpir_revisions r ON r.id = m.revision_id
        JOIN tpir_qualified_revisions q ON q.revision_id = r.id
        JOIN tpir_active_accounts a ON a.account_id = m.account_id
        WHERE m.account_id = :account AND m.txid = :txid
        AND NOT EXISTS (SELECT 1 FROM tpir_quarantined_sources s WHERE s.source = r.source)
        AND NOT EXISTS (SELECT 1 FROM tpir_quarantined_accounts a WHERE a.account_id = m.account_id)
        AND (EXISTS (SELECT 1 FROM tpir_receive_events e JOIN tpir_receive_observations o ON o.receive_id = e.id
            WHERE e.account_id = m.account_id AND e.txid = m.txid AND e.mined_height = m.mined_height
            AND o.revision_id = m.revision_id)
        OR EXISTS (SELECT 1 FROM tpir_spend_events e JOIN tpir_spend_observations o ON o.spend_id = e.id
            WHERE e.account_id = m.account_id AND e.spending_txid = m.txid AND e.mined_height = m.mined_height
            AND o.revision_id = m.revision_id)) ORDER BY r.source, r.lineage")?;
    let mut rows = stmt.query(named_params![":account": account, ":txid": txid.as_ref()])?;
    let mut evidence: Option<TransactionMetadataEvidence> = None;
    while let Some(row) = rows.next()? {
        let fee = match row.get::<_, i64>(0)? {
            0 => WholeTransactionFee::Exact(zatoshis(row.get(1)?)?),
            1 => WholeTransactionFee::Unknown,
            2 => WholeTransactionFee::NotApplicable,
            _ => {
                return Err(SqliteClientError::CorruptedData(
                    "invalid transaction fee state".into(),
                ));
            }
        };
        let metadata = TransactionMetadata {
            fee,
            transparent_input_count: row.get(2)?,
            has_shielded_components: row.get(3)?,
        };
        let provenance = MetadataProvenance {
            source: row.get(4)?,
            revision: row.get(5)?,
            lineage: row.get(6)?,
        };
        if let Some(existing) = &mut evidence {
            if existing.metadata != metadata {
                return Err(SqliteClientError::CorruptedData(
                    "conflicting transaction metadata".into(),
                ));
            }
            existing.provenance.push(provenance);
        } else {
            evidence = Some(TransactionMetadataEvidence {
                metadata,
                provenance: vec![provenance],
            });
        }
    }
    Ok(evidence)
}

fn published_owned_inputs(
    conn: &rusqlite::Connection,
    account: i64,
    txid: &TxId,
) -> Result<u32, SqliteClientError> {
    Ok(conn.query_row("SELECT COUNT(DISTINCT s.input_index) FROM tpir_spend_events s
        WHERE s.account_id = :account AND s.spending_txid = :txid AND s.mined_height IS NOT NULL
        AND EXISTS (SELECT 1 FROM tpir_spend_observations o JOIN tpir_qualified_revisions q ON q.revision_id = o.revision_id
            JOIN tpir_revisions r ON r.id = o.revision_id WHERE o.spend_id = s.id
            AND NOT EXISTS (SELECT 1 FROM tpir_quarantined_sources qs WHERE qs.source = r.source))",
        named_params![":account": account, ":txid": txid.as_ref()], |row| row.get(0))?)
}

/// The `transactions` row facts a history entry depends on.
struct TransactionFacts {
    id: i64,
    mined_height: Option<BlockHeight>,
    has_full_data: bool,
    fee: Option<Zatoshis>,
    /// The wallet constructed and stored the transaction, recording every input it spent and
    /// every output it created, with recipients and memos. Deleting the funding account deletes
    /// those outputs, and with them this evidence.
    constructed: bool,
    /// The wallet created the transaction, whether or not it stored the construction details. An
    /// outbox records only this evidence; its details live outside the wallet database.
    created_locally: bool,
    /// Enhancement found pools beyond Ironwood (transparent data, by the service's flags or the
    /// compact scan) and the full transaction is not stored: its fee, if known, comes from
    /// private metadata and also covers inputs and outputs that are not the account's.
    mixed_without_full_data: bool,
    /// Display-only service assertion; NULL means it has not been recovered.
    has_transparent_outputs: Option<bool>,
}

fn transaction_facts(
    conn: &rusqlite::Connection,
    txid: &TxId,
) -> Result<Option<TransactionFacts>, SqliteClientError> {
    conn.query_row(
        "SELECT id_tx, mined_height, raw IS NOT NULL, fee,
                created IS NOT NULL
                    AND EXISTS (SELECT 1 FROM sent_notes s WHERE s.transaction_id = id_tx),
                created IS NOT NULL OR target_height IS NOT NULL,
                raw IS NULL AND EXISTS (
                    SELECT 1 FROM ironwood_enhance_routing r
                    WHERE r.transaction_id = id_tx AND r.route IN (1, 2)
                ),
                (SELECT has_transparent_outputs FROM ironwood_enhance_routing r
                 WHERE r.transaction_id = id_tx)
         FROM transactions WHERE txid = :txid",
        named_params![":txid": txid.as_ref()],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<u32>>(1)?,
                row.get::<_, bool>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, bool>(4)?,
                row.get::<_, bool>(5)?,
                row.get::<_, bool>(6)?,
                row.get::<_, Option<bool>>(7)?,
            ))
        },
    )
    .optional()?
    .map(
        |(id, mined_height, has_full_data, fee, constructed, created_locally, mixed, outputs)| {
            Ok(TransactionFacts {
                id,
                mined_height: mined_height.map(BlockHeight::from_u32),
                has_full_data,
                fee: fee.map(zatoshis).transpose()?,
                constructed,
                created_locally,
                mixed_without_full_data: mixed,
                has_transparent_outputs: outputs,
            })
        },
    )
    .transpose()
}

fn zatoshis(value: i64) -> Result<Zatoshis, SqliteClientError> {
    Zatoshis::from_nonnegative_i64(value)
        .map_err(|_| SqliteClientError::CorruptedData(format!("invalid value {value}")))
}

/// The account's recorded received and spent amounts per pool in the transaction. Empty when the
/// account has no recorded output or spend in it.
fn known_amounts(
    conn: &rusqlite::Connection,
    account_id: i64,
    transaction_id: i64,
) -> Result<Vec<(PoolType, Zatoshis, Zatoshis)>, SqliteClientError> {
    let mut stmt = conn.prepare_cached(
        "SELECT pool, SUM(received), SUM(spent) FROM (
             SELECT ro.pool, ro.value AS received, 0 AS spent
             FROM v_received_outputs ro
             WHERE ro.account_id = :account_id AND ro.transaction_id = :transaction_id
             UNION ALL
             SELECT ro.pool, 0, ro.value
             FROM v_received_outputs ro
             JOIN v_received_output_spends ros
                  ON ros.pool = ro.pool AND ros.received_output_id = ro.id_within_pool_table
             WHERE ro.account_id = :account_id AND ros.transaction_id = :transaction_id
         )
         GROUP BY pool",
    )?;
    let mut rows = stmt.query(named_params![
        ":account_id": account_id,
        ":transaction_id": transaction_id,
    ])?;
    let mut amounts = vec![];
    while let Some(row) = rows.next()? {
        amounts.push((
            parse_pool_code(row.get(0)?)?,
            zatoshis(row.get(1)?)?,
            zatoshis(row.get(2)?)?,
        ));
    }
    Ok(amounts)
}

/// Payload ingestion links only notes whose nullifiers are already known. Later compact scanning
/// can discover a funding note without linking its unmined spender, since the reverse nullifier
/// map contains mined transactions only. A scanned chain tip therefore does not suffice: every
/// currently known owned nullifier in the payload must also have its spend link.
fn has_unlinked_shielded_spend(
    conn: &rusqlite::Connection,
    account_id: i64,
    transaction_id: i64,
    tx: &Transaction,
    pool: ShieldedPool,
) -> Result<bool, SqliteClientError> {
    let nullifiers: Vec<Value> = match pool {
        ShieldedPool::Sapling => tx
            .sapling_bundle()
            .iter()
            .flat_map(|bundle| bundle.shielded_spends())
            .map(|spend| Value::Blob(spend.nullifier().0.to_vec()))
            .collect(),
        #[cfg(feature = "orchard")]
        ShieldedPool::Orchard | ShieldedPool::Ironwood => {
            let bundle = match pool {
                ShieldedPool::Orchard => tx.orchard_bundle(),
                _ => tx.ironwood_bundle(),
            };
            bundle
                .iter()
                .flat_map(|bundle| bundle.actions().iter())
                .map(|action| Value::Blob(action.nullifier().to_bytes().to_vec()))
                .collect()
        }
        #[cfg(not(feature = "orchard"))]
        _ => {
            return Err(SqliteClientError::UnsupportedPoolType(PoolType::Shielded(
                pool,
            )));
        }
    };
    let prefix = table_constants::<SqliteClientError>(pool)?.table_prefix;
    Ok(conn.query_row(
        &format!(
            "SELECT EXISTS (
                 SELECT 1 FROM {prefix}_received_notes n
                 WHERE n.account_id = :account_id AND n.nf IN rarray(:nullifiers)
                 AND NOT EXISTS (
                     SELECT 1 FROM {prefix}_received_note_spends s
                     WHERE s.{prefix}_received_note_id = n.id
                     AND s.transaction_id = :transaction_id
                 )
             )"
        ),
        named_params![
            ":account_id": account_id,
            ":transaction_id": transaction_id,
            ":nullifiers": Rc::new(nullifiers),
        ],
        |row| row.get(0),
    )?)
}

/// Whether a shielded output the account received or sent in the transaction lacks its memo.
/// Compact scanning does not retrieve memos. For an owned sent output, a recovered received
/// memo satisfies the requirement only for the same account, transaction, pool, and output index.
/// A known empty memo is recovered; SQL NULL is unknown. Other received memos remain independent.
fn has_unretrieved_memo(
    conn: &rusqlite::Connection,
    account_id: i64,
    transaction_id: i64,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM v_received_outputs
             WHERE account_id = :account_id AND transaction_id = :transaction_id
             AND pool != 0 AND memo IS NULL
         ) OR EXISTS (
             SELECT 1 FROM sent_notes s
             WHERE s.from_account_id = :account_id AND s.transaction_id = :transaction_id
             AND s.output_pool != 0 AND s.memo IS NULL
             AND NOT EXISTS (
                 SELECT 1 FROM v_received_outputs ro
                 WHERE ro.account_id = s.from_account_id
                 AND ro.transaction_id = s.transaction_id
                 AND ro.pool = s.output_pool AND ro.output_index = s.output_index
                 AND ro.memo IS NOT NULL
             )
         )",
        named_params![":account_id": account_id, ":transaction_id": transaction_id],
        |row| row.get(0),
    )?)
}

/// The value of the recorded outputs the account sent in the transaction to anyone but itself.
fn sent_elsewhere(
    conn: &rusqlite::Connection,
    account_id: i64,
    transaction_id: i64,
) -> Result<u64, SqliteClientError> {
    let value: i64 = conn.query_row(
        "SELECT COALESCE(SUM(s.value), 0) FROM sent_notes s
         WHERE s.from_account_id = :account_id AND s.transaction_id = :transaction_id
         AND NOT EXISTS (
             SELECT 1 FROM v_received_outputs ro
             WHERE ro.account_id = :account_id AND ro.transaction_id = s.transaction_id
             AND ro.pool = s.output_pool AND ro.output_index = s.output_index
         )",
        named_params![":account_id": account_id, ":transaction_id": transaction_id],
        |row| row.get(0),
    )?;
    Ok(zatoshis(value)?.into_u64())
}

/// Whether the transaction has an output in `pool` that the wallet created for an external
/// address without recording its receipt. Local construction defers the receipt of a shielded
/// payment to one of the wallet's own external addresses until scanning or enhancement finds it,
/// so any such output may be an owned receipt not yet recorded.
fn has_unrecorded_sent_output(
    conn: &rusqlite::Connection,
    transaction_id: i64,
    pool: PoolType,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM sent_notes s
             WHERE s.transaction_id = :transaction_id AND s.output_pool = :pool
             AND s.to_account_id IS NULL
             AND NOT EXISTS (
                 SELECT 1 FROM v_received_outputs ro
                 WHERE ro.transaction_id = s.transaction_id
                 AND ro.pool = s.output_pool AND ro.output_index = s.output_index
             )
         )",
        named_params![":transaction_id": transaction_id, ":pool": pool_code(pool)],
        |row| row.get(0),
    )?)
}

/// Whether a parent of one of the transaction's unresolved transparent inputs is queued for
/// retrieval. Until it arrives, the input may spend one of the account's outputs. A transaction
/// whose funding attribution awaits re-derivation is likewise pending: an input it spends was
/// found after it was stored.
#[cfg(feature = "transparent-inputs")]
fn has_pending_parent(
    conn: &rusqlite::Connection,
    transaction_id: i64,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM tx_retrieval_queue q
             WHERE q.query_type = 1 AND q.dependent_transaction_id IS NOT NULL
             AND (
                 q.dependent_transaction_id = :transaction_id
                 OR q.txid IN (
                     SELECT m.prevout_txid FROM transparent_spend_map m
                     WHERE m.spending_transaction_id = :transaction_id
                 )
             )
         ) OR EXISTS (
             SELECT 1 FROM tx_attribution_queue WHERE transaction_id = :transaction_id
         )",
        named_params![":transaction_id": transaction_id],
        |row| row.get(0),
    )?)
}

/// Whether an active account's ledger records a spend in `txid`. Such a spend makes the account a
/// party to the transaction even before the output it consumes is recovered. A candidate ledger
/// is isolated from history.
#[cfg(feature = "transparent-inputs")]
fn has_active_ledger_spend(
    conn: &rusqlite::Connection,
    account_id: i64,
    txid: &TxId,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM tpir_spend_events s
             JOIN tpir_active_accounts a ON a.account_id = s.account_id
             WHERE s.account_id = :account_id AND s.spending_txid = :txid
         )",
        named_params![":account_id": account_id, ":txid": txid.as_ref()],
        |row| row.get(0),
    )?)
}

/// Whether the account's ledger records a spend in `txid` whose output it has not recovered.
#[cfg(feature = "transparent-inputs")]
fn has_unresolved_spend(
    conn: &rusqlite::Connection,
    account_id: i64,
    txid: &TxId,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM tpir_spend_events s
             WHERE s.account_id = :account_id AND s.spending_txid = :txid
             AND NOT EXISTS (
                 SELECT 1 FROM tpir_receive_events r
                 WHERE r.account_id = :account_id AND r.mined_height IS NOT NULL
                 AND r.txid = s.prevout_txid AND r.output_index = s.prevout_output_index
             )
         )",
        named_params![":account_id": account_id, ":txid": txid.as_ref()],
        |row| row.get(0),
    )?)
}

/// The exact whole-transaction fee: the stored fee, or the exact fee of qualified transparent
/// metadata. Evidence that contradicts the stored fee leaves it unknown.
fn whole_fee(
    stored: Option<Zatoshis>,
    metadata: Option<&TransactionMetadataEvidence>,
) -> Option<Zatoshis> {
    match (stored, metadata.map(|e| e.metadata.fee)) {
        (Some(stored), Some(WholeTransactionFee::Exact(fee))) => (stored == fee).then_some(stored),
        (Some(_), Some(WholeTransactionFee::NotApplicable)) => None,
        (Some(stored), _) => Some(stored),
        (None, Some(WholeTransactionFee::Exact(fee))) => Some(fee),
        (None, _) => None,
    }
}

/// Whether the account recorded an output it sent in the transaction to anyone but itself, even
/// one of zero value, or another wallet account spent funds in it.
fn has_other_outgoing_evidence(
    conn: &rusqlite::Connection,
    account_id: i64,
    transaction_id: i64,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM sent_notes s
             WHERE s.from_account_id = :account_id AND s.transaction_id = :transaction_id
             AND NOT EXISTS (
                 SELECT 1 FROM v_received_outputs ro
                 WHERE ro.account_id = :account_id AND ro.transaction_id = s.transaction_id
                 AND ro.pool = s.output_pool AND ro.output_index = s.output_index
             )
         ) OR EXISTS (
             SELECT 1 FROM v_received_outputs ro
             JOIN v_received_output_spends ros
                  ON ros.pool = ro.pool AND ros.received_output_id = ro.id_within_pool_table
             WHERE ros.transaction_id = :transaction_id AND ro.account_id != :account_id
         )",
        named_params![":account_id": account_id, ":transaction_id": transaction_id],
        |row| row.get(0),
    )?)
}

/// Whether any account's ledger records a transparent spend in `txid`.
#[cfg(feature = "transparent-inputs")]
fn has_ledger_spend(conn: &rusqlite::Connection, txid: &TxId) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM tpir_spend_events WHERE spending_txid = :txid)",
        named_params![":txid": txid.as_ref()],
        |row| row.get(0),
    )?)
}

/// The Activity-only outgoing value of a mixed transaction known without its full data, for
/// which Enhance asserted transparent outputs: the value of the account's spent shielded notes,
/// less its shielded receipts and the whole fee `fee`. Outgoing shielded recovery does not run
/// for such a transaction, so no sent output records where that value went.
///
/// The inference assumes the account paid the whole fee. Each condition removes evidence that
/// another funder shared it, or that the account's funds moved in a way the balance misreads:
/// - every shielded effect is complete, so no owned spend or receipt is missing;
/// - the account spent no transparent funds, no account's ledger records a transparent spend in
///   the transaction, and qualified metadata, when present, counts no transparent input;
/// - no other wallet account spent funds in it, and the account recorded no sent output, which
///   other Activity would show;
/// - the account's net shielded debit exceeds the fee.
///
/// What remains unknown is reported as such elsewhere: an unrecovered transparent input of
/// another party, or a foreign shielded spend, could have paid part of the fee, and the outgoing
/// value may include outputs to the account's own transparent addresses or to shielded
/// recipients. The result is therefore an Activity amount, never a payment or a fee attribution.
fn inferred_outgoing(
    conn: &rusqlite::Connection,
    account_id: i64,
    transaction_id: i64,
    #[cfg_attr(not(feature = "transparent-inputs"), allow(unused_variables))] txid: &TxId,
    effects: &[PoolEffect],
    fee: Zatoshis,
    metadata: Option<&TransactionMetadataEvidence>,
) -> Result<Option<Zatoshis>, SqliteClientError> {
    if metadata.is_some_and(|e| e.metadata.transparent_input_count != 0) {
        return Ok(None);
    }
    let mut spent = Zatoshis::ZERO;
    let mut received = Zatoshis::ZERO;
    for effect in effects {
        match effect.pool {
            PoolType::Transparent if effect.spent != Zatoshis::ZERO => return Ok(None),
            PoolType::Transparent => {}
            PoolType::Shielded(_) if effect.completeness != EffectCompleteness::Complete => {
                return Ok(None);
            }
            PoolType::Shielded(_) => {
                let (Some(s), Some(r)) = (spent + effect.spent, received + effect.received) else {
                    return Ok(None);
                };
                spent = s;
                received = r;
            }
        }
    }
    #[cfg(feature = "transparent-inputs")]
    if has_ledger_spend(conn, txid)? {
        return Ok(None);
    }
    if has_other_outgoing_evidence(conn, account_id, transaction_id)? {
        return Ok(None);
    }
    Ok((spent - received)
        .and_then(|net| net - fee)
        .filter(|outgoing| *outgoing > Zatoshis::ZERO))
}

/// Whether the account's side of a mixed transaction, known without its full data, is a
/// transparent-to-shielded self-transfer whose spent value the whole-transaction fee and the
/// account's shielded receipts account for.
///
/// Each condition closes one way the account's funds could have reached someone else:
/// - every owned effect is complete (not merely settled), so the balance is not partial;
/// - qualified transparent metadata counts as many inputs as the account's published spends,
///   so every transparent input is the account's and no other party funded the transparent
///   side;
/// - that metadata's fee is exact, balances the owned effects, and agrees with the canonical
///   fee if one exists; the service's separately retained output flag says no transparent
///   outputs exist (unknown is not absence);
/// - the account spent only transparent funds and received only shielded outputs, with no
///   recorded outputs to others.
///
/// What no available evidence can exclude is another party's self-balanced shielded
/// participation: a real foreign shielded spend paying an equal foreign shielded output in an
/// action the wallet cannot decrypt. Standard builders pad bundles with dummy outputs whose
/// outgoing ciphertext is encrypted to no key and enable spends, so a dummy and a foreign action
/// look alike, and the transparent txid record, the Enhance PIR record, and the account's own
/// events are identical in both cases. Payment details derived from the full data share this
/// blind spot. The result is therefore classified as
/// [`HistoryClassification::NetReconstructed`], not `Reconstructed`: the account's net movement
/// is final, but its split between a self-transfer and the fee is not proven. The fee is not
/// attributed to the account; `FeeState` stays unknown, and the whole-transaction fee remains
/// available from the metadata.
fn is_private_shielding(
    tx: &TransactionFacts,
    effects: &[PoolEffect],
    metadata: Option<&TransactionMetadataEvidence>,
    owned_inputs: u32,
    sent_elsewhere: u64,
) -> bool {
    let Some(metadata) = metadata.map(|e| e.metadata) else {
        return false;
    };
    let WholeTransactionFee::Exact(fee) = metadata.fee else {
        return false;
    };
    // TPIR fee evidence is qualified on every read; do not copy it into transactions.fee.
    // If an independent canonical fee exists, it must agree.
    let fees_agree = tx.fee.is_none_or(|known| known == fee);
    let spent: u64 = effects.iter().map(|e| e.spent.into_u64()).sum();
    let received: u64 = effects.iter().map(|e| e.received.into_u64()).sum();
    let balanced = Some(spent) == received.checked_add(fee.into_u64());
    let shape = effects.iter().all(|e| {
        e.completeness == EffectCompleteness::Complete
            && match e.pool {
                PoolType::Transparent => e.received == Zatoshis::ZERO && e.spent > Zatoshis::ZERO,
                PoolType::Shielded(_) => e.spent == Zatoshis::ZERO,
            }
    }) && effects
        .iter()
        .any(|e| matches!(e.pool, PoolType::Shielded(_)) && e.received > Zatoshis::ZERO);
    metadata.has_shielded_components
        && owned_inputs > 0
        && owned_inputs == metadata.transparent_input_count
        && fees_agree
        && balanced
        && tx.has_transparent_outputs == Some(false)
        && shape
        && sent_elsewhere == 0
}

/// Who funded the transaction, from the account's view. A settled `transparent_effect` means an
/// input the account does not own belongs to another party rather than awaiting discovery.
/// Qualified metadata and complete owned input
/// evidence can establish funding without the raw transaction; partial coverage cannot.
fn transaction_funding(
    conn: &rusqlite::Connection,
    account_id: i64,
    tx: &TransactionFacts,
    account_spent: bool,
    transparent_effect: Option<&PoolEffect>,
    metadata: Option<&TransactionMetadataEvidence>,
    owned_inputs: u32,
) -> Result<TransactionFunding, SqliteClientError> {
    if !account_spent {
        return Ok(TransactionFunding::NotFunded);
    }
    let other_wallet_funder: bool = conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM v_received_output_spends
             WHERE transaction_id = :transaction_id AND account_id != :account_id
         )",
        named_params![":transaction_id": tx.id, ":account_id": account_id],
        |row| row.get(0),
    )?;
    if other_wallet_funder {
        return Ok(TransactionFunding::Shared);
    }
    if tx.constructed {
        return Ok(TransactionFunding::Sole);
    }
    if let Some(metadata) = metadata.filter(|_| {
        transparent_effect.is_some_and(|e| e.completeness == EffectCompleteness::Complete)
    }) {
        if owned_inputs < metadata.metadata.transparent_input_count {
            return Ok(TransactionFunding::Shared);
        }
        if owned_inputs > 0
            && owned_inputs == metadata.metadata.transparent_input_count
            && !metadata.metadata.has_shielded_components
        {
            return Ok(TransactionFunding::Sole);
        }
    }
    if !tx.has_full_data {
        return Ok(TransactionFunding::Undetermined);
    }
    let raw: Vec<u8> = conn.query_row(
        "SELECT raw FROM transactions WHERE id_tx = ?1",
        [tx.id],
        |row| row.get(0),
    )?;
    // Only the transparent inputs are inspected. The pre-v5 branch ID affects the decoded
    // transaction's identity, which is unused here.
    let inputs = Transaction::read(&raw[..], BranchId::Sprout)?
        .transparent_bundle()
        .filter(|bundle| !bundle.is_coinbase())
        .map_or(0, |bundle| bundle.vin.len());
    // No other wallet account spent in the transaction, so every linked spend is the account's.
    let owned: usize = conn.query_row(
        "SELECT COUNT(*) FROM transparent_received_output_spends WHERE transaction_id = ?1",
        [tx.id],
        |row| row.get(0),
    )?;
    Ok(if owned >= inputs {
        TransactionFunding::Sole
    } else if transparent_effect.is_some_and(|e| e.completeness.is_settled()) {
        TransactionFunding::Shared
    } else {
        TransactionFunding::Undetermined
    })
}

/// Returns `account`'s history view of each of `txids` that it has a recorded output or spend
/// in, in request order. The caller provides the read snapshot.
pub(crate) fn transaction_history_details<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    #[cfg_attr(not(feature = "transparent-inputs"), allow(unused_variables))] params: &P,
    #[cfg(feature = "transparent-inputs")] gap_limits: &GapLimits,
    configured: Option<TransparentLedgerMode>,
    account: AccountUuid,
    txids: &[TxId],
) -> Result<Vec<TransactionHistoryDetails>, SqliteClientError> {
    let mode = resolve_mode(conn, configured)?;
    // Scanning detects an account's shielded spends only through the nullifiers its full viewing
    // key derives; an account imported from an incoming viewing key never learns them.
    let (account_id, detects_shielded_spends): (i64, bool) = conn
        .query_row(
            "SELECT id, ufvk IS NOT NULL FROM accounts WHERE uuid = :uuid",
            named_params![":uuid": account.0],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or(SqliteClientError::AccountUnknown)?;
    let fully_scanned = fully_scanned_height(conn)?;
    let tip = chain_tip_height(conn)?;
    #[cfg(feature = "transparent-inputs")]
    let transparent = transparent_discovery(conn, params, gap_limits, mode, account)?;

    let mut entries = vec![];
    for txid in txids {
        let Some(tx) = transaction_facts(conn, txid)? else {
            continue;
        };
        let known = known_amounts(conn, account_id, tx.id)?;
        // An owned spend establishes participation even before its parent supplies the value.
        let account_spent = known.iter().any(|(_, _, spent)| *spent > Zatoshis::ZERO);
        #[cfg(feature = "transparent-inputs")]
        let account_spent = account_spent || has_active_ledger_spend(conn, account_id, txid)?;
        let involved = !known.is_empty() || account_spent;
        if !involved {
            continue;
        }

        let scanned = tx
            .mined_height
            .is_some_and(|mined| fully_scanned.is_some_and(|scanned| mined <= scanned));
        let unmined_data = if !tx.constructed
            && tx.mined_height.is_none()
            && tx.has_full_data
            && detects_shielded_spends
            && fully_scanned.is_some_and(|scanned| Some(scanned) >= tip)
        {
            let raw: Vec<u8> = conn.query_row(
                "SELECT raw FROM transactions WHERE id_tx = ?1",
                [tx.id],
                |row| row.get(0),
            )?;
            // Only inspect nullifiers. The pre-v5 branch ID affects the decoded transaction's
            // identity, which is unused here, so even a zero-expiry payload can be inspected.
            Some(Transaction::read(&raw[..], BranchId::Sprout)?)
        } else {
            None
        };
        let completeness = |pool: PoolType| -> Result<EffectCompleteness, SqliteClientError> {
            if tx.constructed {
                // The wallet built and stored it, recording every input it spent and every
                // output to its own transparent or internal addresses. A shielded payment to one
                // of its external addresses is recorded only once scanning or enhancement finds
                // it.
                return Ok(match pool {
                    PoolType::Shielded(_)
                        if !scanned && has_unrecorded_sent_output(conn, tx.id, pool)? =>
                    {
                        EffectCompleteness::Incomplete
                    }
                    _ => EffectCompleteness::Complete,
                });
            }
            Ok(match pool {
                PoolType::Transparent => {
                    #[cfg(feature = "transparent-inputs")]
                    match &transparent {
                        // Public discovery is authoritative only once its own pending input
                        // work is done.
                        TransparentDiscovery::Public if has_pending_parent(conn, tx.id)? => {
                            EffectCompleteness::Incomplete
                        }
                        TransparentDiscovery::Public => EffectCompleteness::PublicDiscovery,
                        TransparentDiscovery::Private { covered_through } => {
                            match (tx.mined_height, *covered_through) {
                                (Some(mined), Some(covered))
                                    if mined <= covered
                                        && !has_unresolved_spend(conn, account_id, txid)? =>
                                {
                                    EffectCompleteness::Complete
                                }
                                _ => EffectCompleteness::Incomplete,
                            }
                        }
                    }
                    #[cfg(not(feature = "transparent-inputs"))]
                    EffectCompleteness::Incomplete
                }
                // Without a full viewing key, no amount of scanning reveals the account's spends.
                PoolType::Shielded(_) if !detects_shielded_spends => EffectCompleteness::Incomplete,
                // Scanning a block finds every owned output and every spend of an output found
                // earlier, so everything through the contiguously scanned height is known. An
                // unmined transaction's full data reveals its owned outputs, but its spends are
                // linked only to notes already found. Once scanning reaches the tip, verify that
                // notes discovered after payload ingestion have their spend links too.
                PoolType::Shielded(pool) => match (tx.mined_height, unmined_data.as_ref()) {
                    (Some(_), _) if scanned => EffectCompleteness::Complete,
                    (None, Some(data))
                        if !has_unlinked_shielded_spend(conn, account_id, tx.id, data, pool)? =>
                    {
                        EffectCompleteness::Complete
                    }
                    _ => EffectCompleteness::Incomplete,
                },
            })
        };

        let mut effects = vec![];
        for pool in supported_pools() {
            let (received, spent) = known
                .iter()
                .find(|(p, _, _)| *p == pool)
                .map_or((Zatoshis::ZERO, Zatoshis::ZERO), |(_, r, s)| (*r, *s));
            effects.push(PoolEffect {
                pool,
                received,
                spent,
                completeness: completeness(pool)?,
            });
        }
        let transaction_metadata = metadata_evidence(conn, account_id, txid)?;
        let settled = effects.iter().all(|e| e.completeness.is_settled());
        let spent: u64 = known.iter().map(|(_, _, spent)| spent.into_u64()).sum();
        let received: u64 = known
            .iter()
            .map(|(_, received, _)| received.into_u64())
            .sum();

        let owned_inputs = published_owned_inputs(conn, account_id, txid)?;
        let transparent_effect = effects.iter().find(|e| e.pool == PoolType::Transparent);
        let funding = transaction_funding(
            conn,
            account_id,
            &tx,
            account_spent,
            transparent_effect,
            transaction_metadata.as_ref(),
            owned_inputs,
        )?;

        // The account provably only received: every effect is settled and none is a spend. Creation
        // evidence without the stored construction details means the wallet likely funded the
        // transaction through spends it has not recorded.
        let received_only = settled && spent == 0 && !(tx.created_locally && !tx.constructed);
        // For a sole funder, every spent unit is accounted for by its receipts, recorded payments,
        // and the fee. Shared funding cannot allocate the whole transaction's fee to this account,
        // even when its net movement happens to equal that fee. Full data alone proves nothing:
        // outputs that cannot be decrypted are not recorded.
        let payments_accounted = match tx.fee {
            Some(fee) if settled && spent > 0 && funding == TransactionFunding::Sole => {
                let sent = sent_elsewhere(conn, account_id, tx.id)?;
                Some(spent)
                    == received
                        .checked_add(sent)
                        .and_then(|v| v.checked_add(fee.into_u64()))
            }
            _ => false,
        };
        // Without the full data of a mixed transaction, the balance above does not show that the
        // account was its only funder: a foreign transparent input could have paid the fee while
        // the account's funds paid someone else the same amount. It stands only for the one shape
        // the recovered evidence pins down, and then only as a net movement; see
        // `is_private_shielding`.
        let net_shielding = tx.mixed_without_full_data
            && is_private_shielding(
                &tx,
                &effects,
                transaction_metadata.as_ref(),
                owned_inputs,
                sent_elsewhere(conn, account_id, tx.id)?,
            );
        let payments_accounted = payments_accounted && !tx.mixed_without_full_data;
        let payment_details = if tx.constructed
            || ((received_only || payments_accounted || net_shielding)
                && !has_unretrieved_memo(conn, account_id, tx.id)?)
        {
            DetailCompleteness::Complete
        } else {
            DetailCompleteness::Incomplete
        };
        let sole_transparent_funding = transaction_metadata.as_ref().is_some_and(|e| {
            funding == TransactionFunding::Sole
                && !e.metadata.has_shielded_components
                && owned_inputs > 0
                && owned_inputs == e.metadata.transparent_input_count
        });
        let inferred_payment = transaction_metadata.as_ref().and_then(|e| {
            let WholeTransactionFee::Exact(fee) = e.metadata.fee else {
                return None;
            };
            let effect = transparent_effect?;
            if !sole_transparent_funding || effect.completeness != EffectCompleteness::Complete {
                return None;
            }
            effect
                .spent
                .into_u64()
                .checked_sub(effect.received.into_u64())?
                .checked_sub(fee.into_u64())
                .and_then(|v| Zatoshis::from_u64(v).ok())
        });
        let recorded_sent = sent_elsewhere(conn, account_id, tx.id)?;
        // Once every spent unit is accounted for, the recorded outputs sent elsewhere are all of
        // the account's payments.
        let aggregate_payment = if tx.constructed || payments_accounted {
            AggregatePayment::Exact(
                Zatoshis::from_u64(recorded_sent)
                    .map_err(|e| SqliteClientError::CorruptedData(e.to_string()))?,
            )
        } else if let Some(amount) = inferred_payment {
            AggregatePayment::Exact(amount)
        } else if recorded_sent > 0 {
            AggregatePayment::Partial(
                Zatoshis::from_u64(recorded_sent)
                    .map_err(|e| SqliteClientError::CorruptedData(e.to_string()))?,
            )
        } else {
            AggregatePayment::Unknown
        };
        // Local construction records the fee independently of recovered metadata.
        // Mixed-pool metadata cannot erase that richer local-send fact. Without full data, a
        // mixed transaction's stored fee is the whole transaction's, and never the account's.
        let fee = match tx.fee {
            Some(fee)
                if spent > 0
                    && (tx.constructed
                        || (!tx.mixed_without_full_data
                            && (transaction_metadata.is_none() || sole_transparent_funding))) =>
            {
                FeeState::Known(fee)
            }
            _ if sole_transparent_funding && inferred_payment.is_some() => {
                match transaction_metadata.as_ref().unwrap().metadata.fee {
                    WholeTransactionFee::Exact(fee) => FeeState::Known(fee),
                    _ => FeeState::Unknown,
                }
            }
            _ if received_only => FeeState::NotApplicable,
            _ => FeeState::Unknown,
        };
        let whole_fee = whole_fee(tx.fee, transaction_metadata.as_ref());
        // A database may retain owned amounts from a pool disabled in this build. The effects
        // above omit that pool, so their completeness cannot justify dropping its known amounts.
        let effects_cover_known = known.iter().all(|(pool, received, spent)| {
            (*received == Zatoshis::ZERO && *spent == Zatoshis::ZERO)
                || effects.iter().any(|effect| effect.pool == *pool)
        });
        let inferred_outgoing = match whole_fee {
            Some(fee)
                if tx.mixed_without_full_data
                    && tx.has_transparent_outputs == Some(true)
                    && !tx.created_locally
                    && tx.mined_height.is_some()
                    && effects_cover_known =>
            {
                inferred_outgoing(
                    conn,
                    account_id,
                    tx.id,
                    txid,
                    &effects,
                    fee,
                    transaction_metadata.as_ref(),
                )?
            }
            _ => None,
        };
        // A missing memo does not change what the transaction did; missing effects or payments
        // can.
        let classification = if tx.created_locally {
            HistoryClassification::LocalIntent
        } else if received_only || payments_accounted || inferred_payment.is_some() {
            HistoryClassification::Reconstructed
        } else if net_shielding {
            HistoryClassification::NetReconstructed
        } else {
            HistoryClassification::Provisional
        };

        entries.push(TransactionHistoryDetails {
            has_transparent_outputs: tx.has_transparent_outputs,
            transaction_metadata,
            whole_fee,
            aggregate_payment,
            inferred_outgoing,
            account_movement: AccountMovement {
                received,
                spent,
                complete: effects
                    .iter()
                    .all(|e| e.completeness == EffectCompleteness::Complete),
            },
            txid: *txid,
            mined_height: tx.mined_height,
            effects,
            payment_details,
            fee,
            funding,
            classification,
            pending_private_details: pending_details(conn, mode, Some(tx.id))?,
        });
    }
    Ok(entries)
}
