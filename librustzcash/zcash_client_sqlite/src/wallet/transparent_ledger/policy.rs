//! Durable transparent-policy transitions and generation checks.
//!
//! The stored policy is what dispatch trusts. A mode change increments
//! `policy_generation` in the same SQLite transaction; same-mode reapplication does not.

use rusqlite::named_params;
use zcash_client_backend::data_api::transparent_ledger::{
    AppliedTransparentPolicy, PrivateTransparentDetail, TransparentLedgerMode,
};
use zcash_primitives::transaction::TxId;

use crate::error::SqliteClientError;

use super::{durable_policy, mode_code, resolve_mode};

/// Reads the durable policy, including its generation. The handle must already be configured,
/// and a stored `PrivateRequired` policy is never weakened by a weaker handle.
pub(crate) fn applied_transparent_policy(
    conn: &rusqlite::Connection,
    configured: Option<TransparentLedgerMode>,
) -> Result<AppliedTransparentPolicy, SqliteClientError> {
    // Reject unconfigured handles before reading, matching other ledger APIs.
    let _ = resolve_mode(conn, configured)?;
    read_applied_policy(conn)?
        .ok_or_else(|| SqliteClientError::CorruptedData("tpir_meta policy row is missing".into()))
}

/// Confirms that the durable generation still equals `expected`.
pub(crate) fn check_transparent_policy_generation(
    conn: &rusqlite::Connection,
    expected: u64,
) -> Result<(), SqliteClientError> {
    let applied = read_applied_policy(conn)?.ok_or_else(|| {
        SqliteClientError::CorruptedData("tpir_meta policy row is missing".into())
    })?;
    if applied.generation != expected {
        return Err(SqliteClientError::StaleTransparentPolicy {
            expected,
            applied: applied.generation,
        });
    }
    Ok(())
}

/// Durably applies `mode`. A mode change increments the generation; same-mode reapplication
/// does not.
pub(crate) fn apply_transparent_policy(
    conn: &rusqlite::Connection,
    configured: Option<TransparentLedgerMode>,
    mode: TransparentLedgerMode,
) -> Result<AppliedTransparentPolicy, SqliteClientError> {
    // The handle must already be configured; the write does not invent a mode for empty wallets.
    let _ = configured.ok_or(SqliteClientError::TransparentLedgerModeNotConfigured)?;
    let write =
        |conn: &rusqlite::Connection| -> Result<AppliedTransparentPolicy, SqliteClientError> {
            // Re-read under the write lock so a concurrent transition cannot be overwritten.
            let current = read_applied_policy(conn)?.ok_or_else(|| {
                SqliteClientError::CorruptedData("tpir_meta policy row is missing".into())
            })?;
            if current.mode == mode {
                return Ok(current);
            }
            let generation = current.generation.checked_add(1).ok_or_else(|| {
                SqliteClientError::CorruptedData("policy_generation overflow".into())
            })?;
            let updated = conn.execute(
            "UPDATE tpir_meta
             SET applied_mode = :mode,
                 policy_generation = :generation
             WHERE id = 0",
            rusqlite::named_params![
                ":mode": mode_code(mode),
                ":generation": i64::try_from(generation).map_err(|_| {
                    SqliteClientError::CorruptedData("policy_generation does not fit i64".into())
                })?,
            ],
        )?;
            if updated != 1 {
                return Err(SqliteClientError::CorruptedData(
                    "tpir_meta policy row is missing".into(),
                ));
            }
            // Candidate pages were opened under the previous policy.
            super::clear_pending_pages(conn)?;
            if current.mode == TransparentLedgerMode::PrivateRequired {
                // Private authority exists only under PrivateRequired. Returning to it requires
                // promoting each account again, which revalidates its whole ledger.
                conn.execute("DELETE FROM tpir_active_accounts", [])?;
            }
            // Keep still-required retrieval obligations on the new generation. Leaving the old
            // stamp would hide them from public dispatch after a transition back to Public.
            // Under PrivateRequired, matching generation does not restore public follow-on:
            // authority is absent.
            let generation_i64 = i64::try_from(generation).map_err(|_| {
                SqliteClientError::CorruptedData("policy_generation does not fit i64".into())
            })?;
            conn.execute(
                "UPDATE tx_retrieval_queue SET policy_generation = :generation",
                rusqlite::named_params![":generation": generation_i64],
            )?;
            if mode == TransparentLedgerMode::PrivateRequired {
                // Unresolved public LWD markers become sticky private-details rows so pending
                // private recovery can observe them after the transition.
                conn.execute(
                    "UPDATE ironwood_enhance_routing
                 SET route = 2
                 WHERE route = 1
                   AND EXISTS (
                       SELECT 1 FROM transactions t
                       WHERE t.id_tx = ironwood_enhance_routing.transaction_id
                         AND t.raw IS NULL
                   )",
                    [],
                )?;
                // Their transparent details are now txid enhancement work.
                super::details::enqueue_route_two(conn)?;
                // Their received memos remain privately recoverable.
                #[cfg(feature = "orchard")]
                crate::wallet::enhance_pir::queue_unsupported_memos(conn, None)?;
            } else if mode.retains_public_authority() {
                // Sticky route 2 was assigned while public enhancement was forbidden. With
                // public authority restored, unresolved mixed rows become ordinary LWD work
                // (route 1). Route codes match enhance_pir::{LWD_REQUIRED, PRIVATE_DETAILS_UNSUPPORTED}.
                conn.execute(
                    "UPDATE ironwood_enhance_routing
                 SET route = 1
                 WHERE route = 2
                   AND EXISTS (
                       SELECT 1 FROM transactions t
                       WHERE t.id_tx = ironwood_enhance_routing.transaction_id
                         AND t.raw IS NULL
                   )",
                    [],
                )?;
                // LWD retrieval supersedes received memo and shape-only private work.
                conn.execute(
                    "DELETE FROM ironwood_enhance_metadata_queue WHERE transaction_id IN (
                         SELECT transaction_id FROM ironwood_enhance_routing WHERE route = 1)",
                    [],
                )?;
                conn.execute(
                    "DELETE FROM ironwood_memo_retrieval_queue
                 WHERE received_note_id IN (
                     SELECT rn.id FROM ironwood_received_notes rn
                     JOIN ironwood_enhance_routing r ON r.transaction_id = rn.transaction_id
                     WHERE r.route = 1
                 )",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO tx_retrieval_queue (txid, query_type, policy_generation)
                 SELECT t.txid, 1, :generation
                 FROM ironwood_enhance_routing r
                 JOIN transactions t ON t.id_tx = r.transaction_id
                 WHERE r.route = 1 AND t.raw IS NULL
                 ON CONFLICT (txid, query_type) DO NOTHING",
                    rusqlite::named_params![":generation": generation_i64],
                )?;
            }
            Ok(AppliedTransparentPolicy { mode, generation })
        };

    if conn.is_autocommit() {
        let tx = conn.unchecked_transaction()?;
        let applied = write(&tx)?;
        tx.commit()?;
        Ok(applied)
    } else {
        write(conn)
    }
}

/// Transparent follow-on details withheld from public dispatch under a policy that does not
/// retain public authority.
pub(crate) fn pending_private_transparent_details(
    conn: &rusqlite::Connection,
    configured: Option<TransparentLedgerMode>,
) -> Result<Vec<PrivateTransparentDetail>, SqliteClientError> {
    pending_details(conn, resolve_mode(conn, configured)?, None)
}

/// The details withheld under `mode`, restricted to those of the transaction with internal id
/// `transaction` when one is given: a parent retrieval for one of its inputs, or its own
/// mixed-transaction marker. A queued parent records only its latest dependent, so the parents of
/// a transaction's unresolved inputs are found through the spend map as well.
pub(super) fn pending_details(
    conn: &rusqlite::Connection,
    mode: TransparentLedgerMode,
    transaction: Option<i64>,
) -> Result<Vec<PrivateTransparentDetail>, SqliteClientError> {
    if mode.retains_public_authority() {
        // Public authority dispatches matching-generation work; nothing is withheld as private.
        return Ok(vec![]);
    }

    let mut details = Vec::new();
    let mut parents = conn.prepare_cached(
        "SELECT q.txid FROM tx_retrieval_queue q
         WHERE q.query_type = 1
           AND q.dependent_transaction_id IS NOT NULL
           AND (
               :transaction IS NULL
               OR q.dependent_transaction_id = :transaction
               OR q.txid IN (
                   SELECT m.prevout_txid FROM transparent_spend_map m
                   WHERE m.spending_transaction_id = :transaction
               )
           )
         ORDER BY q.txid",
    )?;
    for txid in parents.query_map(named_params![":transaction": transaction], |row| {
        row.get::<_, [u8; 32]>(0)
    })? {
        details.push(PrivateTransparentDetail::ParentTransaction {
            txid: TxId::from_bytes(txid?),
        });
    }

    // Unresolved mixed/LWD follow-on: sticky route 2, plus route 1 when privacy is required
    // only by the current handle and no durable transition has rewritten the route.
    let mut mixed = conn.prepare_cached(
        "SELECT t.txid FROM ironwood_enhance_routing r
         JOIN transactions t ON t.id_tx = r.transaction_id
         WHERE r.route IN (1, 2) AND t.raw IS NULL
           AND (:transaction IS NULL OR r.transaction_id = :transaction)
         ORDER BY t.txid",
    )?;
    for txid in mixed.query_map(named_params![":transaction": transaction], |row| {
        row.get::<_, [u8; 32]>(0)
    })? {
        details.push(PrivateTransparentDetail::MixedTransaction {
            txid: TxId::from_bytes(txid?),
        });
    }
    Ok(details)
}

/// Reads the durable policy without requiring a configured handle. Used by commit checks that
/// already hold a captured generation from the start of their SQLite transaction.
pub(crate) fn read_applied_policy(
    conn: &rusqlite::Connection,
) -> Result<Option<AppliedTransparentPolicy>, SqliteClientError> {
    Ok(durable_policy(conn)?.map(Into::into))
}

/// Captures the current generation for a commit path, failing closed when the ledger schema
/// is present but the policy row is missing.
pub(crate) fn capture_policy_generation(
    conn: &rusqlite::Connection,
) -> Result<u64, SqliteClientError> {
    Ok(read_applied_policy(conn)?
        .ok_or_else(|| SqliteClientError::CorruptedData("tpir_meta policy row is missing".into()))?
        .generation)
}

/// Like [`check_transparent_policy_generation`], for internal commit paths that do not need a
/// configured handle beyond the generation already captured.
pub(crate) fn ensure_policy_generation(
    conn: &rusqlite::Connection,
    expected: u64,
) -> Result<(), SqliteClientError> {
    check_transparent_policy_generation(conn, expected)
}

/// Returns whether the resolved mode retains public transparent authority.
///
/// When `configured` is present, the handle mode is resolved against the durable policy.
/// When absent (lower-level scan hooks), the durable policy alone decides; a wallet that
/// predates the ledger schema is treated as retaining public authority.
pub(crate) fn retains_public_authority(
    conn: &rusqlite::Connection,
    configured: Option<TransparentLedgerMode>,
) -> Result<bool, SqliteClientError> {
    match configured {
        Some(_) => Ok(resolve_mode(conn, configured)?.retains_public_authority()),
        None => Ok(read_applied_policy(conn)?
            .map(|p| p.mode.retains_public_authority())
            .unwrap_or(true)),
    }
}
