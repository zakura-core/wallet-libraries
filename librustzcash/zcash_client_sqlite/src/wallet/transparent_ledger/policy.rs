//! Durable transparent-policy transitions and generation checks.
//!
//! The stored policy is what dispatch trusts. A mode change increments
//! `policy_generation` in the same SQLite transaction; same-mode reapplication does not.

use rusqlite::{OptionalExtension as _, named_params};
use zcash_client_backend::data_api::transparent_ledger::{
    AppliedTransparentPolicy, PrivateTransparentDetail, TransparentLedgerMode,
};
use zcash_primitives::transaction::TxId;

use crate::{error::SqliteClientError, wallet::init::migrations::TRANSPARENT_LEDGER_SCHEMA_ID};

use super::{
    reader_version::TPIR_READER_VERSION, session::SessionState, transactions::in_transaction,
};

/// Decodes `tpir_meta.applied_mode`. Code 1 belonged to the removed shadow mode and is refused.
fn mode_from_code(code: i64) -> Result<TransparentLedgerMode, SqliteClientError> {
    match code {
        0 => Ok(TransparentLedgerMode::Public),
        2 => Ok(TransparentLedgerMode::PrivateRequired),
        other => Err(SqliteClientError::CorruptedData(format!(
            "unknown transparent ledger mode code {other}"
        ))),
    }
}

/// The persisted `tpir_meta.applied_mode` code of `mode`.
fn mode_code(mode: TransparentLedgerMode) -> i64 {
    match mode {
        TransparentLedgerMode::Public => 0,
        TransparentLedgerMode::PrivateRequired => 2,
    }
}

/// The error for a wallet whose ledger schema exists without its `tpir_meta` policy row.
fn missing_policy_row() -> SqliteClientError {
    SqliteClientError::CorruptedData("tpir_meta policy row is missing".into())
}

/// Reads the durable policy. A wallet that predates the ledger schema has none, and so cannot
/// hold a stricter policy than any handle.
///
/// Fails when the wallet requires a newer reader than this build
/// ([`TransparentLedgerIncompatible`](SqliteClientError::TransparentLedgerIncompatible)), or
/// when the policy table or its row is missing after the ledger migration. Callers that only
/// need that refusal call it as a guard: a build that cannot interpret the ledger state must
/// not write or rewind it.
pub(crate) fn durable_policy(
    conn: &rusqlite::Connection,
) -> Result<Option<AppliedTransparentPolicy>, SqliteClientError> {
    let has_meta: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'tpir_meta')",
        [],
        |row| row.get(0),
    )?;
    if !has_meta {
        // Only a wallet that never ran the ledger migration may lack the policy table. Once
        // the migration is recorded, a missing table is damage and must not read as public.
        let migrated: bool = conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM schemer_migrations WHERE id = ?1)",
            [TRANSPARENT_LEDGER_SCHEMA_ID.as_bytes().to_vec()],
            |row| row.get(0),
        )?;
        return if migrated {
            Err(SqliteClientError::CorruptedData(
                "tpir_meta is missing after the transparent ledger migration".into(),
            ))
        } else {
            Ok(None)
        };
    }
    let (mode, generation, min_reader_version) = conn
        .query_row(
            "SELECT applied_mode, policy_generation, min_reader_version FROM tpir_meta WHERE id = 0",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?
        // Once the table exists, a missing singleton is damage, not the absence of a policy.
        .ok_or_else(missing_policy_row)?;
    if min_reader_version > TPIR_READER_VERSION {
        return Err(SqliteClientError::TransparentLedgerIncompatible {
            required: min_reader_version,
        });
    }
    Ok(Some(AppliedTransparentPolicy {
        mode: mode_from_code(mode)?,
        generation: u64::try_from(generation).map_err(|_| {
            SqliteClientError::CorruptedData("negative policy_generation in tpir_meta".into())
        })?,
    }))
}

/// The mode a configured handle operates under, given the durable policy: a durably applied
/// `PrivateRequired` is never weakened by the handle's configuration.
fn effective_mode(
    configured: TransparentLedgerMode,
    durable: Option<AppliedTransparentPolicy>,
) -> TransparentLedgerMode {
    match durable {
        Some(AppliedTransparentPolicy {
            mode: TransparentLedgerMode::PrivateRequired,
            ..
        }) => TransparentLedgerMode::PrivateRequired,
        _ => configured,
    }
}

/// Resolves the mode a handle operates under for transparent ledger APIs, which require
/// explicit configuration even for an empty wallet.
///
/// The durable policy is read on every call, so a `PrivateRequired` policy another connection
/// applied after this handle was configured takes effect at the handle's next read. The
/// resolution neither changes the stored policy nor the handle's configuration: once the
/// policy is explicitly lowered, the handle again operates under its configured mode. A
/// missing, corrupt, or newer-than-this-build policy fails closed.
pub(crate) fn resolve_mode(
    conn: &rusqlite::Connection,
    configured: Option<TransparentLedgerMode>,
) -> Result<TransparentLedgerMode, SqliteClientError> {
    let mode = configured.ok_or(SqliteClientError::TransparentLedgerModeNotConfigured)?;
    Ok(effective_mode(mode, durable_policy(conn)?))
}

/// Reads the durable policy, including its generation. The handle must already be configured,
/// and a stored `PrivateRequired` policy is never weakened by a weaker handle.
pub(crate) fn applied_transparent_policy(
    conn: &rusqlite::Connection,
    configured: Option<TransparentLedgerMode>,
) -> Result<AppliedTransparentPolicy, SqliteClientError> {
    // Reject unconfigured handles before reading, matching other ledger APIs.
    let _ = resolve_mode(conn, configured)?;
    required_policy(conn)
}

/// Confirms that the durable generation still equals `expected`.
pub(crate) fn check_transparent_policy_generation(
    conn: &rusqlite::Connection,
    expected: u64,
) -> Result<(), SqliteClientError> {
    let applied = required_policy(conn)?;
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
    session: &SessionState,
    configured: Option<TransparentLedgerMode>,
    mode: TransparentLedgerMode,
) -> Result<AppliedTransparentPolicy, SqliteClientError> {
    // The handle must already be configured; the write does not invent a mode for empty wallets.
    let _ = configured.ok_or(SqliteClientError::TransparentLedgerModeNotConfigured)?;
    let session = session.transaction();
    let applied = in_transaction(conn, |conn| transition_policy(conn, &session, mode))?;
    session.commit();
    Ok(applied)
}

/// Writes `mode` as the durable policy within the caller's transaction, and moves the wallet's
/// pending work onto it: candidate pages are cleared, leaving `PrivateRequired` demotes every
/// active account, retrieval obligations move to the new generation, and unresolved mixed
/// transactions are rerouted for the new mode. Same-mode reapplication writes nothing.
fn transition_policy(
    conn: &rusqlite::Connection,
    session: &SessionState,
    mode: TransparentLedgerMode,
) -> Result<AppliedTransparentPolicy, SqliteClientError> {
    // Re-read under the write lock so a concurrent transition cannot be overwritten.
    let current = required_policy(conn)?;
    if current.mode == mode {
        return Ok(current);
    }
    let generation = current
        .generation
        .checked_add(1)
        .ok_or_else(|| SqliteClientError::CorruptedData("policy_generation overflow".into()))?;
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
        return Err(missing_policy_row());
    }
    // Candidate pages were opened under the previous policy.
    super::clear_pending_pages(conn)?;
    if current.mode == TransparentLedgerMode::PrivateRequired {
        // Private authority exists only under PrivateRequired. Returning to it requires
        // activating each account again, which revalidates its whole ledger.
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
        super::details::enqueue_route_two(conn, session)?;
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

/// Reads the durable policy without requiring a configured handle, failing closed when the
/// wallet has none: a wallet with the ledger schema must hold its policy row. Used by commit
/// checks that already hold a captured generation from the start of their SQLite transaction.
fn required_policy(
    conn: &rusqlite::Connection,
) -> Result<AppliedTransparentPolicy, SqliteClientError> {
    durable_policy(conn)?.ok_or_else(missing_policy_row)
}

/// Captures the current generation for a commit path, failing closed when the ledger schema
/// is present but the policy row is missing.
pub(crate) fn capture_policy_generation(
    conn: &rusqlite::Connection,
) -> Result<u64, SqliteClientError> {
    Ok(required_policy(conn)?.generation)
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
        None => Ok(durable_policy(conn)?
            .map(|p| p.mode.retains_public_authority())
            .unwrap_or(true)),
    }
}
