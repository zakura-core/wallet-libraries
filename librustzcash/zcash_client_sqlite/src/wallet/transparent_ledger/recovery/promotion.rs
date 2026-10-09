//! Promotion of an account's complete candidate ledger to private authority.

use super::*;

/// Promotes `account` to private authority, atomically; see
/// `TransparentLedgerWrite::promote_transparent_account`.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn promote<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    gap_limits: &GapLimits,
    configured: Option<TransparentLedgerMode>,
    account: AccountUuid,
) -> Result<(), SqliteClientError> {
    atomically(conn, |conn| {
        if !grants_private_authority(conn, configured)? {
            return Err(SqliteClientError::TransparentRecoveryNotEnabled);
        }
        let watch = Watch::load(conn, params, gap_limits, account)?
            .ok_or(SqliteClientError::AccountUnknown)?;
        let account_ref = watch.account.internal_id();
        let ledger = AccountLedger {
            account_ref,
            lifecycle: lifecycle(conn, account_ref)?,
            quarantined: account_quarantined(conn, account_ref)?,
            status: recovery_status(conn, gap_limits, &watch)?,
        };
        if ledger.lifecycle == AccountLifecycle::Active {
            return Ok(());
        }
        let tip = chain_tip_height(conn)?;
        let blockers: Vec<_> = ledger_blockers(conn, &ledger, tip)?
            .into_iter()
            .filter(|b| *b != RecoveryBlocker::NotActivated)
            .collect();
        if !blockers.is_empty() {
            return Err(SqliteClientError::TransparentPromotionBlocked(blockers));
        }

        // Skipped receiver origins survive materialization independently of ownership.
        ownership::materialize_watch(conn, params, &watch)?;
        conn.execute(
            "DELETE FROM tpir_candidate_windows WHERE account_id = :account_id",
            named_params![":account_id": account_ref.0],
        )?;

        // Defense in depth: the addresses just written must not have changed what the account
        // is required to cover. Refuse and roll back rather than activate incomplete recovery.
        let generated = Watch::load(conn, params, gap_limits, account)?
            .ok_or(SqliteClientError::AccountUnknown)?;
        let status = recovery_status(conn, gap_limits, &generated)?;
        if !status.blockers.is_empty() {
            return Err(SqliteClientError::TransparentPromotionBlocked(
                status
                    .blockers
                    .into_iter()
                    .map(RecoveryBlocker::Recovery)
                    .collect(),
            ));
        }
        for receive in placed_receives(conn, account_ref)? {
            projection::project_receive(conn, params, gap_limits, account, &receive)?;
        }
        for spend in placed_spends(conn, account_ref)? {
            projection::project_spend(conn, params, gap_limits, &spend)?;
        }

        conn.execute(
            "INSERT INTO tpir_active_accounts (account_id) VALUES (:account_id)",
            named_params![":account_id": account_ref.0],
        )?;
        super::super::require_reader_version(conn, super::super::ACTIVATION_READER_VERSION)
    })
}
