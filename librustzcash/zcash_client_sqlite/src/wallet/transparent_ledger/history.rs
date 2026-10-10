//! History completeness, derived from the facts the wallet holds.
//!
//! Nothing here is stored. Completeness follows from the transaction row, the account's recorded
//! outputs and spends, the scan queue, the account's ledger coverage, and queued follow-on work,
//! so a rewind, promotion, account change, or later enhancement changes the result as soon as it
//! changes those facts.

#[cfg(test)]
mod tests;

mod classify;
mod completeness;
mod evidence;

use rusqlite::{OptionalExtension as _, named_params};
use zcash_client_backend::data_api::transparent_ledger::{
    AccountMovement, AggregatePayment, DetailCompleteness, EffectCompleteness, FeeState,
    HistoryClassification, PoolEffect, TransactionHistoryDetails, TransparentLedgerMode,
    WholeTransactionFee,
};
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::{
    PoolType,
    consensus::{self, BranchId},
    value::Zatoshis,
};

use crate::{
    AccountUuid,
    error::SqliteClientError,
    wallet::{chain_tip_height, fully_scanned_height},
};

use super::{policy::pending_details, resolve_mode};

use classify::{inferred_outgoing, is_private_shielding, whole_fee};
use completeness::{
    has_unlinked_shielded_spend, has_unrecorded_sent_output, has_unretrieved_memo, supported_pools,
};
use evidence::{
    known_amounts, metadata_evidence, qualified_owned_spend_inputs, sent_elsewhere,
    transaction_facts,
};

#[cfg(feature = "transparent-inputs")]
use {
    completeness::{
        TransparentDiscovery, has_pending_parent, has_unresolved_spend, transparent_discovery,
    },
    evidence::has_active_ledger_spend,
    zcash_keys::keys::transparent::gap_limits::GapLimits,
};

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
    let discovery = transparent_discovery(conn, params, gap_limits, mode, account)?;

    let mut entries = vec![];
    for txid in txids {
        let Some(tx_facts) = transaction_facts(conn, txid)? else {
            continue;
        };
        let recorded_amounts = known_amounts(conn, account_id, tx_facts.id)?;
        #[cfg(feature = "transparent-inputs")]
        let involved =
            !recorded_amounts.is_empty() || has_active_ledger_spend(conn, account_id, txid)?;
        #[cfg(not(feature = "transparent-inputs"))]
        let involved = !recorded_amounts.is_empty();
        if !involved {
            continue;
        }

        let scanned = tx_facts
            .mined_height
            .is_some_and(|mined| fully_scanned.is_some_and(|scanned| mined <= scanned));
        let unmined_data = if !tx_facts.constructed
            && tx_facts.mined_height.is_none()
            && tx_facts.has_full_data
            && detects_shielded_spends
            && fully_scanned.is_some_and(|scanned| Some(scanned) >= tip)
        {
            let raw: Vec<u8> = conn.query_row(
                "SELECT raw FROM transactions WHERE id_tx = ?1",
                [tx_facts.id],
                |row| row.get(0),
            )?;
            // Only inspect nullifiers. The pre-v5 branch ID affects the decoded transaction's
            // identity, which is unused here, so even a zero-expiry payload can be inspected.
            Some(Transaction::read(&raw[..], BranchId::Sprout)?)
        } else {
            None
        };
        let completeness = |pool: PoolType| -> Result<EffectCompleteness, SqliteClientError> {
            if tx_facts.constructed {
                // The wallet built and stored it, recording every input it spent and every
                // output to its own transparent or internal addresses. A shielded payment to one
                // of its external addresses is recorded only once scanning or enhancement finds
                // it.
                return Ok(match pool {
                    PoolType::Shielded(_)
                        if !scanned && has_unrecorded_sent_output(conn, tx_facts.id, pool)? =>
                    {
                        EffectCompleteness::Incomplete
                    }
                    _ => EffectCompleteness::Complete,
                });
            }
            Ok(match pool {
                PoolType::Transparent => {
                    #[cfg(feature = "transparent-inputs")]
                    match &discovery {
                        // Public discovery is authoritative only once its own pending input
                        // work is done.
                        TransparentDiscovery::Public if has_pending_parent(conn, tx_facts.id)? => {
                            EffectCompleteness::Incomplete
                        }
                        TransparentDiscovery::Public => EffectCompleteness::PublicDiscovery,
                        TransparentDiscovery::Private { covered_through } => {
                            match (tx_facts.mined_height, *covered_through) {
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
                PoolType::Shielded(pool) => match (tx_facts.mined_height, unmined_data.as_ref()) {
                    (Some(_), _) if scanned => EffectCompleteness::Complete,
                    (None, Some(data))
                        if !has_unlinked_shielded_spend(
                            conn,
                            account_id,
                            tx_facts.id,
                            data,
                            pool,
                        )? =>
                    {
                        EffectCompleteness::Complete
                    }
                    _ => EffectCompleteness::Incomplete,
                },
            })
        };

        let mut effects = vec![];
        for pool in supported_pools() {
            let (received, spent) = recorded_amounts
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
        let spent: u64 = recorded_amounts
            .iter()
            .map(|(_, _, spent)| spent.into_u64())
            .sum();
        let received: u64 = recorded_amounts
            .iter()
            .map(|(_, received, _)| received.into_u64())
            .sum();

        // The account provably only received: every effect is settled and none is a spend. Creation
        // evidence without the stored construction details means the wallet likely funded the
        // transaction through spends it has not recorded.
        let received_only =
            settled && spent == 0 && !(tx_facts.created_locally && !tx_facts.constructed);
        // Every unit the account spent is accounted for by what it received back, the recorded
        // outputs it sent elsewhere, and the fee, so no unknown payment of its funds remains.
        // Full data alone proves nothing: outputs that cannot be decrypted are not recorded.
        let payments_accounted = match tx_facts.fee {
            Some(fee) if settled && spent > 0 => {
                let sent = sent_elsewhere(conn, account_id, tx_facts.id)?;
                Some(spent)
                    == received
                        .checked_add(sent)
                        .and_then(|v| v.checked_add(fee.into_u64()))
            }
            _ => false,
        };
        let owned_inputs = qualified_owned_spend_inputs(conn, account_id, txid)?;
        // Without the full data of a mixed transaction, the balance above does not show that the
        // account was its only funder: a foreign transparent input could have paid the fee while
        // the account's funds paid someone else the same amount. It stands only for the one shape
        // the recovered evidence pins down, and then only as a net movement; see
        // `is_private_shielding`.
        let net_shielding = tx_facts.mixed_without_full_data
            && is_private_shielding(
                &tx_facts,
                &effects,
                transaction_metadata.as_ref(),
                owned_inputs,
                sent_elsewhere(conn, account_id, tx_facts.id)?,
            );
        let payments_accounted = payments_accounted && !tx_facts.mixed_without_full_data;
        let payment_details = if tx_facts.constructed
            || ((received_only || payments_accounted || net_shielding)
                && !has_unretrieved_memo(conn, account_id, tx_facts.id)?)
        {
            DetailCompleteness::Complete
        } else {
            DetailCompleteness::Incomplete
        };
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
        let recorded_sent = sent_elsewhere(conn, account_id, tx_facts.id)?;
        let aggregate_payment = if tx_facts.constructed {
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
        let fee = match tx_facts.fee {
            Some(fee)
                if spent > 0
                    && (tx_facts.constructed
                        || (!tx_facts.mixed_without_full_data
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
        let whole_transaction_fee = whole_fee(tx_facts.fee, transaction_metadata.as_ref());
        // A database may retain owned amounts from a pool disabled in this build. The effects
        // above omit that pool, so their completeness cannot justify dropping its known amounts.
        let effects_cover_known = recorded_amounts.iter().all(|(pool, received, spent)| {
            (*received == Zatoshis::ZERO && *spent == Zatoshis::ZERO)
                || effects.iter().any(|effect| effect.pool == *pool)
        });
        let inferred_outgoing_value = match whole_transaction_fee {
            Some(fee)
                if tx_facts.mixed_without_full_data
                    && tx_facts.has_transparent_outputs == Some(true)
                    && !tx_facts.created_locally
                    && tx_facts.mined_height.is_some()
                    && effects_cover_known =>
            {
                inferred_outgoing(
                    conn,
                    account_id,
                    tx_facts.id,
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
        let classification = if tx_facts.created_locally {
            HistoryClassification::LocalIntent
        } else if received_only || payments_accounted || inferred_payment.is_some() {
            HistoryClassification::Reconstructed
        } else if net_shielding {
            HistoryClassification::NetReconstructed
        } else {
            HistoryClassification::Provisional
        };

        entries.push(TransactionHistoryDetails {
            has_transparent_outputs: tx_facts.has_transparent_outputs,
            transaction_metadata,
            whole_fee: whole_transaction_fee,
            aggregate_payment,
            inferred_outgoing: inferred_outgoing_value,
            account_movement: AccountMovement {
                received,
                spent,
                complete: effects
                    .iter()
                    .all(|e| e.completeness == EffectCompleteness::Complete),
            },
            txid: *txid,
            mined_height: tx_facts.mined_height,
            effects,
            payment_details,
            fee,
            classification,
            pending_private_details: pending_details(conn, mode, Some(tx_facts.id))?,
        });
    }
    Ok(entries)
}
