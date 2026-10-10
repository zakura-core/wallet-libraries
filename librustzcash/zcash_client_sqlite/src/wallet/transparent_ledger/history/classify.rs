//! Classifying a transaction's history entry: the whole fee, inferred outgoing value, and
//! the shapes the recovered evidence pins down.

use rusqlite::named_params;
use zcash_client_backend::data_api::transparent_ledger::{
    EffectCompleteness, PoolEffect, TransactionMetadataEvidence, WholeTransactionFee,
};
use zcash_primitives::transaction::TxId;
use zcash_protocol::{PoolType, value::Zatoshis};

use crate::error::SqliteClientError;

use super::evidence::TransactionFacts;

/// The exact whole-transaction fee: the stored fee, or the exact fee of qualified transparent
/// metadata. Evidence that contradicts the stored fee leaves it unknown.
pub(super) fn whole_fee(
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
pub(super) fn has_other_outgoing_evidence(
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

/// Whether current, qualified evidence from an active account records a transparent spend.
/// Candidate recovery and withdrawn or quarantined observations are not Activity evidence.
/// An unresolved parent does not erase an otherwise established funding participant.
#[cfg(feature = "transparent-inputs")]
pub(super) fn has_ledger_spend(
    conn: &rusqlite::Connection,
    txid: &TxId,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM tpir_spend_events s
             JOIN tpir_active_accounts a ON a.account_id = s.account_id
             JOIN transactions t ON t.txid = s.spending_txid AND t.mined_height = s.mined_height
             WHERE s.spending_txid = :txid
             AND NOT EXISTS (SELECT 1 FROM tpir_quarantined_accounts qa
                             WHERE qa.account_id = s.account_id)
             AND EXISTS (
                 SELECT 1 FROM tpir_spend_observations o
                 JOIN tpir_qualified_revisions q ON q.revision_id = o.revision_id
                 JOIN tpir_revisions r ON r.id = o.revision_id
                 WHERE o.spend_id = s.id
                 AND NOT EXISTS (SELECT 1 FROM tpir_quarantined_sources qs
                                 WHERE qs.source = r.source)
             )
         )",
        named_params![":txid": txid.as_ref()],
        |row| row.get(0),
    )?)
}

/// The Activity-only outgoing value of a mixed transaction known without its full data, for
/// which Enhance asserted transparent outputs: the value of the account's spent shielded notes,
/// less its shielded receipts and the whole fee `fee`. Outgoing shielded recovery does not run
/// for such a transaction, so no sent output records where that value went.
///
/// Activity assumes the account funded the transaction and paid the whole fee unless recovered
/// evidence identifies another contributor. It does not require proof that no unobserved foreign
/// contributor exists. Each condition excludes observed conflicting funding or effects:
/// - every shielded effect is complete, so no owned spend or receipt is missing;
/// - the account spent no transparent funds, no active account's qualified ledger records a spend in
///   the transaction, and qualified metadata, when present, counts no transparent input;
/// - no other wallet account spent funds in it, and the account recorded no sent output, which
///   other Activity would show;
/// - the account's net shielded debit exceeds the fee.
///
/// What remains unknown is reported as such elsewhere: an unrecovered transparent input of
/// another party, or a foreign shielded spend, could have paid part of the fee, and the outgoing
/// value may include outputs to the account's own transparent addresses or to shielded
/// recipients. The result is therefore an Activity amount, never a payment or a fee attribution.
pub(super) fn inferred_outgoing(
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
pub(super) fn is_private_shielding(
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
