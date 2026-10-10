//! History completeness, derived from the facts the wallet holds.
//!
//! Nothing here is stored. Completeness follows from the transaction row, the account's recorded
//! outputs and spends, the scan queue, the account's ledger coverage, and queued follow-on work,
//! so a rewind, activation, account change, or later enhancement changes the result as soon as it
//! changes those facts.

#[cfg(test)]
mod tests;

mod activity;
mod classify;
mod completeness;
mod evidence;

use rusqlite::{OptionalExtension as _, named_params};
use zcash_client_backend::data_api::transparent_ledger::{
    AccountMovement, DetailCompleteness, EffectCompleteness, FeeState, HistoryClassification,
    TransactionHistoryDetails, TransparentLedgerMode,
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

use activity::{
    ActivityEvidence, activity, has_orchard_spend, has_shielding_shape, read_outputs, summarize,
};
use classify::{
    account_fee, aggregate_payment, classification, inferred_outgoing, inferred_payment,
    is_private_shielding, whole_fee,
};
use completeness::{EffectEvidence, has_unretrieved_memo};
use evidence::{
    known_amounts, metadata_evidence, qualified_owned_spend_inputs, sent_elsewhere,
    transaction_facts,
};

#[cfg(feature = "transparent-inputs")]
use {
    completeness::transparent_discovery, evidence::has_active_ledger_spend,
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
        // Load the transaction row and the account's recorded amounts in it.
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

        // Effects: each supported pool's recorded amounts, and how complete they are.
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
        let effect_evidence = EffectEvidence {
            conn,
            account_id,
            #[cfg(feature = "transparent-inputs")]
            txid,
            tx_facts: &tx_facts,
            scanned,
            unmined_data: unmined_data.as_ref(),
            detects_shielded_spends,
            #[cfg(feature = "transparent-inputs")]
            discovery: &discovery,
        };
        let effects = effect_evidence.pool_effects(&recorded_amounts)?;
        let transaction_metadata = metadata_evidence(conn, account_id, txid)?;
        let settled = effects.iter().all(|e| e.completeness.is_settled());
        let spent: u64 = recorded_amounts
            .iter()
            .map(|amounts| amounts.spent.into_u64())
            .sum();
        let received: u64 = recorded_amounts
            .iter()
            .map(|amounts| amounts.received.into_u64())
            .sum();

        // Payments: whether the account's recorded movements account for all it spent.
        // The account provably only received: every effect is settled and none is a spend. Creation
        // evidence without the stored construction details means the wallet likely funded the
        // transaction through spends it has not recorded.
        let received_only =
            settled && spent == 0 && !(tx_facts.created_locally && !tx_facts.constructed);
        let recorded_sent = sent_elsewhere(conn, account_id, tx_facts.id)?;
        // Every unit the account spent is accounted for by what it received back, the recorded
        // outputs it sent elsewhere, and the fee, so no unknown payment of its funds remains.
        // Full data alone proves nothing: outputs that cannot be decrypted are not recorded.
        let payments_accounted = match tx_facts.fee {
            Some(fee) if settled && spent > 0 => {
                Some(spent)
                    == received
                        .checked_add(recorded_sent)
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
                recorded_sent,
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
        let inferred_payment = inferred_payment(
            transaction_metadata.as_ref(),
            transparent_effect,
            sole_transparent_funding,
        );
        let aggregate_payment = aggregate_payment(&tx_facts, inferred_payment, recorded_sent)?;

        // Fees and the Activity-only outgoing value. A whole fee the account's share of which is
        // not established stays unattributed rather than unknown.
        let whole_transaction_fee = whole_fee(tx_facts.fee, transaction_metadata.as_ref());
        let fee = match account_fee(
            &tx_facts,
            spent,
            transaction_metadata.as_ref(),
            sole_transparent_funding,
            inferred_payment,
            received_only,
        ) {
            FeeState::Unknown if spent > 0 => whole_transaction_fee
                .map_or(FeeState::Unknown, |whole| FeeState::Unattributed { whole }),
            fee => fee,
        };
        // A database may retain owned amounts from a pool disabled in this build. The effects
        // above omit that pool, so their completeness cannot justify dropping its known amounts.
        let effects_cover_known = recorded_amounts.iter().all(|amounts| {
            (amounts.received == Zatoshis::ZERO && amounts.spent == Zatoshis::ZERO)
                || effects.iter().any(|effect| effect.pool == amounts.pool)
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
        let classification = classification(
            &tx_facts,
            received_only,
            payments_accounted,
            inferred_payment,
            net_shielding,
        );
        let account_movement = AccountMovement {
            received,
            spent,
            complete: effects
                .iter()
                .all(|e| e.completeness == EffectCompleteness::Complete),
        };

        // What the transaction shows in the account's activity list.
        let activity_evidence = ActivityEvidence {
            shielding_shape: has_shielding_shape(conn, account_id, tx_facts.id)?,
            orchard_spend: has_orchard_spend(conn, tx_facts.id)?,
            mined: tx_facts.mined_height.is_some(),
            spent,
            received,
            net: account_movement.net(),
            details_complete: payment_details == DetailCompleteness::Complete,
            provisional: classification == HistoryClassification::Provisional || !settled,
            effects_settled: settled,
            classification,
            fee,
            whole_fee: whole_transaction_fee
                .filter(|_| spent > 0)
                .map(Zatoshis::into_u64),
            inferred_payment: inferred_payment
                .filter(|_| classification == HistoryClassification::Reconstructed)
                .map(Zatoshis::into_u64),
            inferred_outgoing: inferred_outgoing_value.map(Zatoshis::into_u64),
        };
        let outputs = read_outputs(conn, account, account_id, tx_facts.id)?;
        let summary = summarize(&activity_evidence, &outputs)?;
        let activity = activity(&activity_evidence, &summary)?;
        let funding_step = summary.funding_step()?;

        entries.push(TransactionHistoryDetails {
            has_transparent_outputs: tx_facts.has_transparent_outputs,
            transaction_metadata,
            whole_fee: whole_transaction_fee,
            aggregate_payment,
            inferred_outgoing: inferred_outgoing_value,
            account_movement,
            txid: *txid,
            mined_height: tx_facts.mined_height,
            effects,
            payment_details,
            fee,
            classification,
            activity,
            funding_step,
            pending_private_details: pending_details(conn, mode, Some(tx_facts.id))?,
        });
    }
    Ok(entries)
}

/// What an account's receipt of a transaction needs beyond its history view, from the same
/// records. The caller provides the read snapshot.
pub(crate) struct ReceiptEvidence {
    /// An owned transparent output pays an address whose key scope is not one the wallet uses.
    pub(crate) unknown_transparent_scope: bool,
    /// The stored raw transaction, when there is one.
    pub(crate) raw: Option<Vec<u8>>,
}

/// Reads `account`'s [`ReceiptEvidence`] for the transaction of `entry`.
pub(crate) fn receipt_evidence(
    conn: &rusqlite::Connection,
    account: AccountUuid,
    txid: &TxId,
) -> Result<Option<ReceiptEvidence>, SqliteClientError> {
    let account_id: i64 = conn
        .query_row(
            "SELECT id FROM accounts WHERE uuid = :uuid",
            named_params![":uuid": account.0],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(SqliteClientError::AccountUnknown)?;
    let Some(tx_facts) = transaction_facts(conn, txid)? else {
        return Ok(None);
    };
    let unknown_transparent_scope = read_outputs(conn, account, account_id, tx_facts.id)?
        .iter()
        .any(|output| output.has_unknown_transparent_scope());
    let raw = conn.query_row(
        "SELECT raw FROM transactions WHERE id_tx = ?1",
        [tx_facts.id],
        |row| row.get(0),
    )?;
    Ok(Some(ReceiptEvidence {
        unknown_transparent_scope,
        raw,
    }))
}
