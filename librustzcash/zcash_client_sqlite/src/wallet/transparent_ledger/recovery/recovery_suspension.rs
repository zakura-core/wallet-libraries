//! Stop accepting a source's recovery results and using affected accounts'
//! recovered ledgers after contradictory evidence is detected. Suspension is
//! durable: saved facts remain, while unfinished retrieval pages are removed.

use super::*;

/// Whether recovery from `source` is suspended after an integrity rejection.
#[cfg(feature = "transparent-inputs")]
pub(super) fn source_recovery_is_suspended(
    conn: &rusqlite::Connection,
    source: &[u8],
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM tpir_quarantined_sources WHERE source = :source)",
        named_params![":source": source],
        |row| row.get(0),
    )?)
}

/// Whether the account's recovered ledger is suspended after an integrity rejection.
#[cfg(feature = "transparent-inputs")]
pub(super) fn account_recovery_is_suspended(
    conn: &rusqlite::Connection,
    account_ref: AccountRef,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM tpir_quarantined_accounts WHERE account_id = :account_id
         )",
        named_params![":account_id": account_ref.0],
        |row| row.get(0),
    )?)
}

/// Suspends recovery from `source` and for every affected account after contradictory
/// evidence is detected. This includes `account_ref` and accounts holding coverage,
/// pages, or observed events from the source. Saved facts remain; unfinished pages are removed.
///
/// The caller must hold the transaction that records the integrity rejection. Suspension
/// prevents new recovery commits and private spending authority until explicitly resolved.
#[cfg(feature = "transparent-inputs")]
pub(super) fn suspend_recovery(
    conn: &rusqlite::Connection,
    source: &[u8],
    account_ref: AccountRef,
) -> Result<(), SqliteClientError> {
    conn.execute(
        "INSERT OR IGNORE INTO tpir_quarantined_sources (source) VALUES (:source)",
        named_params![":source": source],
    )?;
    conn.execute(
        "INSERT OR IGNORE INTO tpir_quarantined_accounts (account_id)
         SELECT :account_id
         UNION SELECT account_id FROM tpir_coverage
             WHERE revision_id IN (SELECT id FROM tpir_revisions WHERE source = :source)
         UNION SELECT account_id FROM tpir_pending_pages
             WHERE revision_id IN (SELECT id FROM tpir_revisions WHERE source = :source)
         UNION SELECT e.account_id FROM tpir_receive_events e
             JOIN tpir_receive_observations o ON o.receive_id = e.id
             WHERE o.revision_id IN (SELECT id FROM tpir_revisions WHERE source = :source)
         UNION SELECT e.account_id FROM tpir_spend_events e
             JOIN tpir_spend_observations o ON o.spend_id = e.id
             WHERE o.revision_id IN (SELECT id FROM tpir_revisions WHERE source = :source)",
        named_params![":account_id": account_ref.0, ":source": source],
    )?;
    conn.execute(
        "DELETE FROM tpir_pending_pages
         WHERE account_id IN (SELECT account_id FROM tpir_quarantined_accounts)",
        [],
    )?;
    super::super::require_reader_version(conn, super::super::ACTIVATION_READER_VERSION)
}
