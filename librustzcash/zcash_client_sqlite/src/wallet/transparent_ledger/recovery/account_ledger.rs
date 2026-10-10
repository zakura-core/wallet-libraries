//! An account's ledger state as authority reads it: lifecycle, quarantine and recovery status,
//! and the blockers that keep it from private authority or promotion.

use super::diagnostics::RecoveryStatus;
use super::*;

/// One account's ledger state at the local target, from one read.
#[cfg(feature = "transparent-inputs")]
pub(crate) struct AccountLedger {
    pub(crate) account_ref: AccountRef,
    pub(crate) lifecycle: AccountLifecycle,
    pub(crate) quarantined: bool,
    pub(crate) status: RecoveryStatus,
}

#[cfg(feature = "transparent-inputs")]
impl AccountLedger {
    /// Whether the account holds private authority for a transaction targeting the block after
    /// `tip`: it is active and not quarantined, and its ledger is complete through a local
    /// target that is the chain tip.
    pub(crate) fn authorizes_after(&self, tip: BlockHeight) -> bool {
        self.lifecycle == AccountLifecycle::Active
            && !self.quarantined
            && self.status.blockers.is_empty()
            && self
                .status
                .target
                .is_some_and(|target| target.height == tip)
    }
}

/// Reads `account`'s ledger state. The caller provides the read snapshot.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn account_ledger<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    gap_limits: &GapLimits,
    account: AccountUuid,
) -> Result<AccountLedger, SqliteClientError> {
    let watch =
        Watch::load(conn, params, gap_limits, account)?.ok_or(SqliteClientError::AccountUnknown)?;
    let account_ref = watch.account.internal_id();
    Ok(AccountLedger {
        account_ref,
        lifecycle: lifecycle(conn, account_ref)?,
        quarantined: account_quarantined(conn, account_ref)?,
        status: recovery_status(conn, gap_limits, &watch)?,
    })
}

/// Why `ledger`'s account lacks private authority after `tip`, or cannot be promoted.
///
/// Qualification and legacy agreement are promotion conditions, reported only for a candidate;
/// an active account satisfied them when promoted, and its later commits require qualification.
/// Legacy agreement is judged only against a complete candidate ledger.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn ledger_blockers(
    conn: &rusqlite::Connection,
    ledger: &AccountLedger,
    tip: Option<BlockHeight>,
) -> Result<Vec<RecoveryBlocker>, SqliteClientError> {
    let mut blockers = vec![];
    let candidate = ledger.lifecycle == AccountLifecycle::Candidate;
    if candidate {
        blockers.push(RecoveryBlocker::NotActivated);
    }
    if ledger.quarantined {
        blockers.push(RecoveryBlocker::Quarantined);
    }
    blockers.extend(
        ledger
            .status
            .blockers
            .iter()
            .map(|b| RecoveryBlocker::Recovery(*b)),
    );
    if let (Some(target), Some(tip)) = (ledger.status.target, tip)
        && target.height < tip
    {
        blockers.push(RecoveryBlocker::ChainBehindTip);
    }
    if candidate {
        if has_unqualified_revisions(conn, ledger.account_ref)? {
            blockers.push(RecoveryBlocker::UnqualifiedRevision);
        }
        if let Some(target) = ledger
            .status
            .target
            .filter(|_| ledger.status.blockers.is_empty())
            && has_legacy_discrepancy(conn, ledger.account_ref, target.height)?
        {
            blockers.push(RecoveryBlocker::LegacyDiscrepancy);
        }
    }
    Ok(blockers)
}

/// Whether a revision that supplied `account_ref`'s supported coverage or observed events is
/// not qualified.
#[cfg(feature = "transparent-inputs")]
fn has_unqualified_revisions(
    conn: &rusqlite::Connection,
    account_ref: AccountRef,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS (
             SELECT revision_id FROM tpir_coverage
             WHERE account_id = :account_id AND supported = 1
             UNION
             SELECT o.revision_id FROM tpir_receive_observations o
             JOIN tpir_receive_events e ON e.id = o.receive_id
             WHERE e.account_id = :account_id
             UNION
             SELECT o.revision_id FROM tpir_spend_observations o
             JOIN tpir_spend_events e ON e.id = o.spend_id
             WHERE e.account_id = :account_id
             EXCEPT
             SELECT revision_id FROM tpir_qualified_revisions
         )",
        named_params![":account_id": account_ref.0],
        |row| row.get(0),
    )?)
}

/// Whether legacy public evidence of `account_ref` disagrees with its complete candidate
/// ledger at `target`.
///
/// A discrepancy is an output the wallet holds, from any origin, whose candidate receive has
/// other content, account, or placement; an output the wallet holds, from any origin, mined at
/// or below `target` with no placed candidate receive, including one whose receive a rewind
/// unplaced; or a legacy spend mined at or below `target` that no placed candidate spend by the
/// same transaction confirms. Candidate-only events are explained: legacy history was
/// incomplete.
#[cfg(feature = "transparent-inputs")]
fn has_legacy_discrepancy(
    conn: &rusqlite::Connection,
    account_ref: AccountRef,
    target: BlockHeight,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        &format!(
            "SELECT EXISTS (
             SELECT 1 FROM transparent_received_outputs o
             JOIN transactions t ON t.id_tx = o.transaction_id
             JOIN tpir_receive_events r
                 ON r.txid = t.txid AND r.output_index = o.output_index
             WHERE o.account_id = :account_id
             AND (
                 r.account_id != o.account_id OR r.script != o.script
                 OR r.value_zat != o.value_zat
                 OR (r.mined_height IS NOT NULL AND t.mined_height IS NOT NULL
                     AND r.mined_height != t.mined_height)
             )
         ) OR EXISTS (
             SELECT 1 FROM transparent_received_outputs o
             JOIN transactions t ON t.id_tx = o.transaction_id
             WHERE o.account_id = :account_id AND t.mined_height <= :target
             AND (({}) OR EXISTS (
                 SELECT 1 FROM tpir_receive_events r
                 WHERE r.txid = t.txid AND r.output_index = o.output_index
             )) -- a withdrawn ledger-only row is retained state, not legacy evidence
             AND NOT EXISTS (
                 SELECT 1 FROM tpir_receive_events r
                 WHERE r.txid = t.txid AND r.output_index = o.output_index
                 AND r.mined_height IS NOT NULL
             )
         ) OR EXISTS (
             SELECT 1 FROM transparent_received_output_spends s
             JOIN transparent_received_outputs o ON o.id = s.transparent_received_output_id
             JOIN transactions prevout_tx ON prevout_tx.id_tx = o.transaction_id
             JOIN transactions spending_tx ON spending_tx.id_tx = s.transaction_id
             WHERE o.account_id = :account_id AND spending_tx.mined_height <= :target
             AND EXISTS (
                 SELECT 1 FROM tpir_spend_origins so
                 WHERE so.spending_transaction_id = s.transaction_id
                 AND so.prevout_txid = prevout_tx.txid
                 AND so.prevout_output_index = o.output_index
                 AND so.origin = 0
             )
             AND NOT EXISTS (
                 SELECT 1 FROM tpir_spend_events e
                 WHERE e.spending_txid = spending_tx.txid
                 AND e.prevout_txid = prevout_tx.txid
                 AND e.prevout_output_index = o.output_index
                 AND e.mined_height IS NOT NULL
             )
         )",
            super::super::output_observation_condition("o")
        ),
        named_params![":account_id": account_ref.0, ":target": u32::from(target)],
        |row| row.get(0),
    )?)
}
