//! Activate an account's recovered transparent ledger: check readiness, project
//! recovered events into wallet financial state, and record activation atomically.

use super::*;

/// Activates `account` to private authority, atomically; see
/// `TransparentLedgerWrite::activate_transparent_ledger`.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn activate_recovered_ledger<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    session: &SessionState,
    params: &P,
    gap_limits: &GapLimits,
    configured: Option<TransparentLedgerMode>,
    account: AccountUuid,
) -> Result<(), SqliteClientError> {
    let session = session.transaction();
    atomically(conn, |conn| {
        if !grants_private_authority(conn, configured)? {
            return Err(SqliteClientError::TransparentRecoveryNotEnabled);
        }
        let recovery_addresses = AccountRecoveryAddresses::load(conn, params, gap_limits, account)?
            .ok_or(SqliteClientError::AccountUnknown)?;
        let ledger = AccountLedger::from_recovery_addresses(conn, gap_limits, &recovery_addresses)?;
        let account_ref = ledger.account_ref;
        if ledger.lifecycle == AccountLifecycle::Active {
            return Ok(());
        }
        let tip = chain_tip_height(conn)?;
        let blockers: Vec<_> = ledger_blockers(conn, &ledger, tip)?
            .into_iter()
            .filter(|b| *b != RecoveryBlocker::NotActivated)
            .collect();
        if !blockers.is_empty() {
            return Err(SqliteClientError::TransparentActivationBlocked(blockers));
        }

        // Skipped receiver origins survive materialization independently of ownership.
        ownership::materialize_recovery_addresses(conn, params, &recovery_addresses)?;
        conn.execute(
            "DELETE FROM tpir_candidate_windows WHERE account_id = :account_id",
            named_params![":account_id": account_ref.0],
        )?;

        // Defense in depth: the addresses just written must not have changed what the account
        // is required to cover. Refuse and roll back rather than activate incomplete recovery.
        let generated = AccountRecoveryAddresses::load(conn, params, gap_limits, account)?
            .ok_or(SqliteClientError::AccountUnknown)?;
        let status = recovery_status(conn, gap_limits, &generated)?;
        if !status.blockers.is_empty() {
            return Err(SqliteClientError::TransparentActivationBlocked(
                status
                    .blockers
                    .into_iter()
                    .map(RecoveryBlocker::Recovery)
                    .collect(),
            ));
        }
        for receive in placed_receives(conn, account_ref)? {
            projection::project_receive(conn, &session, params, gap_limits, account, &receive)?;
        }
        for spend in placed_spends(conn, account_ref)? {
            projection::project_spend(conn, &session, params, gap_limits, &spend)?;
        }

        conn.execute(
            "INSERT INTO tpir_active_accounts (account_id) VALUES (:account_id)",
            named_params![":account_id": account_ref.0],
        )?;
        super::super::require_reader_version(conn, super::super::ACTIVATION_READER_VERSION)
    })?;
    session.commit();
    Ok(())
}
