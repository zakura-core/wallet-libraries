//! History completeness, derived from the facts the wallet holds.
//!
//! Nothing here is stored. Completeness follows from the transaction row, the account's recorded
//! outputs and spends, the scan queue, the account's ledger coverage, and queued follow-on work,
//! so a rewind, promotion, account change, or later enhancement changes the result as soon as it
//! changes those facts.

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
}

fn transaction_facts(
    conn: &rusqlite::Connection,
    txid: &TxId,
) -> Result<Option<TransactionFacts>, SqliteClientError> {
    conn.query_row(
        "SELECT id_tx, mined_height, raw IS NOT NULL, fee,
                created IS NOT NULL
                    AND EXISTS (SELECT 1 FROM sent_notes s WHERE s.transaction_id = id_tx),
                created IS NOT NULL OR target_height IS NOT NULL
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
            ))
        },
    )
    .optional()?
    .map(
        |(id, mined_height, has_full_data, fee, constructed, created_locally)| {
            Ok(TransactionFacts {
                id,
                mined_height: mined_height.map(BlockHeight::from_u32),
                has_full_data,
                fee: fee.map(zatoshis).transpose()?,
                constructed,
                created_locally,
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
/// Compact scanning does not retrieve memos.
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
             SELECT 1 FROM sent_notes
             WHERE from_account_id = :account_id AND transaction_id = :transaction_id
             AND output_pool != 0 AND memo IS NULL
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

/// Who funded the transaction, from the account's view. `transparent_settled` says whether the
/// account's transparent evidence for it is settled, so that an input it does not own belongs to
/// another party rather than awaiting discovery.
fn transaction_funding(
    conn: &rusqlite::Connection,
    account_id: i64,
    tx: &TransactionFacts,
    account_spent: bool,
    transparent_settled: bool,
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
    } else if transparent_settled {
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
        #[cfg(feature = "transparent-inputs")]
        let involved = !known.is_empty() || has_active_ledger_spend(conn, account_id, txid)?;
        #[cfg(not(feature = "transparent-inputs"))]
        let involved = !known.is_empty();
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

        // The account provably only received: every effect is settled and none is a spend. Creation
        // evidence without the stored construction details means the wallet likely funded the
        // transaction through spends it has not recorded.
        let received_only = settled && spent == 0 && !(tx.created_locally && !tx.constructed);
        // Every unit the account spent is accounted for by what it received back, the recorded
        // outputs it sent elsewhere, and the fee, so no unknown payment of its funds remains.
        // Full data alone proves nothing: outputs that cannot be decrypted are not recorded.
        let payments_accounted = match tx.fee {
            Some(fee) if settled && spent > 0 => {
                let sent = sent_elsewhere(conn, account_id, tx.id)?;
                Some(spent)
                    == received
                        .checked_add(sent)
                        .and_then(|v| v.checked_add(fee.into_u64()))
            }
            _ => false,
        };
        let payment_details = if tx.constructed
            || ((received_only || payments_accounted)
                && !has_unretrieved_memo(conn, account_id, tx.id)?)
        {
            DetailCompleteness::Complete
        } else {
            DetailCompleteness::Incomplete
        };
        let owned_inputs = published_owned_inputs(conn, account_id, txid)?;
        let transparent_effect = effects.iter().find(|e| e.pool == PoolType::Transparent);
        let sole_transparent_funding = transaction_metadata.as_ref().is_some_and(|e| {
            !e.metadata.has_shielded_components
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
        // Mixed-pool metadata cannot erase that richer local-send fact.
        let fee = match tx.fee {
            Some(fee)
                if spent > 0
                    && (tx.constructed
                        || transaction_metadata.is_none()
                        || sole_transparent_funding) =>
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
        // A missing memo does not change what the transaction did; missing effects or payments
        // can.
        let classification = if tx.created_locally {
            HistoryClassification::LocalIntent
        } else if received_only || payments_accounted || inferred_payment.is_some() {
            HistoryClassification::Reconstructed
        } else {
            HistoryClassification::Provisional
        };

        let transparent_settled = effects
            .iter()
            .filter(|e| e.pool == PoolType::Transparent)
            .all(|e| e.completeness.is_settled());
        let funding = transaction_funding(conn, account_id, &tx, spent > 0, transparent_settled)?;

        entries.push(TransactionHistoryDetails {
            transaction_metadata,
            aggregate_payment,
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
