//! Explicit handover to the published rc5/rc7 public wallet writers.
use std::borrow::BorrowMut;

use rand_core::Rng;
use rusqlite::{Connection, TransactionBehavior};
use schemerz::MigratorError;
use uuid::Uuid;
use zcash_protocol::consensus;

use super::{WalletMigrationError, WalletMigrator, migrations};
use crate::{WalletDb, util::Clock};

/// Prepares an exclusively owned, public wallet database for a legacy rc5/rc7 writer.
///
/// Stop every wallet worker and take a consistent backup before calling this function. Close all
/// current-build handles after success, then hand the file to the older application. This restores
/// `transactions.zip318_kind` and its view column with `0` (unclassified) for existing rows; it does
/// not restore the removed pool-migration engine or its classifications. Applied migration IDs,
/// balances, reservations, transaction bytes and local creation evidence are preserved.
///
/// A changed policy generation, a private policy, or any recovery/activation state refuses the
/// handover. This cannot authorize a rollback of a private wallet. The current library's ledger
/// APIs refuse the prepared database until [`WalletMigrator`] runs again. On returning to this
/// build, initialization atomically reconciles older writers' output/spend provenance and removes
/// the compatibility columns. That reconciliation grants no private coverage or authority.
///
/// The database is first initialized seedlessly, so historical wallets needing a seed must be
/// migrated by their caller before preparation. Calling this again on a prepared wallet is safe.
pub fn prepare_legacy_rollback<C, P, CL, R>(
    wdb: &mut WalletDb<C, P, CL, R>,
) -> Result<(), MigratorError<Uuid, WalletMigrationError>>
where
    C: BorrowMut<Connection>,
    P: consensus::Parameters + 'static,
    CL: Clock + Clone + 'static,
    R: Rng + Clone + 'static,
{
    WalletMigrator::new().init_or_migrate(wdb)?;
    prepare(wdb.conn.borrow_mut()).map_err(MigratorError::Adapter)
}

fn prepare(conn: &mut Connection) -> Result<(), WalletMigrationError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_public_baseline(&tx)?;
    if !column_restored(&tx)? {
        let view = view_sql(&tx)?;
        let column = "transactions.trust_status";
        if view.matches(column).count() != 1 {
            return Err(WalletMigrationError::CorruptedData(
                "unexpected history view for legacy rollback".into(),
            ));
        }
        let updated = view.replacen(
            column,
            "transactions.trust_status, transactions.zip318_kind",
            1,
        );
        tx.execute_batch(
            "ALTER TABLE transactions ADD COLUMN zip318_kind INTEGER NOT NULL DEFAULT 0;
                          DROP VIEW v_transactions;",
        )?;
        tx.execute_batch(&updated)?;
    }
    tx.commit()?;
    Ok(())
}

pub(in crate::wallet) fn column_restored(conn: &Connection) -> Result<bool, rusqlite::Error> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('transactions') WHERE name = 'zip318_kind')",
        [],
        |r| r.get(0),
    )
}

fn is_prepared(conn: &Connection) -> Result<bool, rusqlite::Error> {
    let dropped: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'schemer_migrations')",
        [],
        |r| r.get(0),
    )?;
    if !dropped {
        return Ok(false);
    }
    let dropped: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM schemer_migrations WHERE id = ?1)",
        [migrations::DROP_ZIP318_POOL_MIGRATION_ID
            .as_bytes()
            .to_vec()],
        |r| r.get(0),
    )?;
    Ok(dropped && column_restored(conn)?)
}

fn require_public_baseline(conn: &Connection) -> Result<(), WalletMigrationError> {
    let eligible: bool = conn.query_row(
        "SELECT applied_mode = 0 AND policy_generation = 0 AND min_reader_version = 1
         FROM tpir_meta WHERE id = 0",
        [],
        |r| r.get(0),
    )?;
    if !eligible {
        return Err(WalletMigrationError::LegacyRollbackNotSupported);
    }
    for table in [
        "tpir_candidate_windows",
        "tpir_revisions",
        "tpir_receive_events",
        "tpir_receive_observations",
        "tpir_spend_events",
        "tpir_spend_observations",
        "tpir_coverage",
        "tpir_pending_pages",
        "tpir_pending_page_scripts",
        "tpir_active_accounts",
        "tpir_qualified_revisions",
        "tpir_quarantined_sources",
        "tpir_quarantined_accounts",
    ] {
        if conn.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {table})"), [], |r| {
            r.get::<_, bool>(0)
        })? {
            return Err(WalletMigrationError::LegacyRollbackNotSupported);
        }
    }
    // Prepared wallets from preceding builds resume before newer additive migrations run.
    // Absence is valid only if the corresponding migration has not been recorded yet.
    for (table, migration) in [
        (
            "tpir_transaction_metadata",
            migrations::TRANSPARENT_ACTIVITY_METADATA_ID,
        ),
        (
            "tpir_shared_derivations",
            migrations::TRANSPARENT_SHARED_DERIVATIONS_ID,
        ),
    ] {
        let installed: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
            [table],
            |r| r.get(0),
        )?;
        if installed {
            if conn.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {table})"), [], |r| {
                r.get::<_, bool>(0)
            })? {
                return Err(WalletMigrationError::LegacyRollbackNotSupported);
            }
        } else if conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM schemer_migrations WHERE id = ?1)",
            [migration.as_bytes().to_vec()],
            |r| r.get::<_, bool>(0),
        )? {
            return Err(WalletMigrationError::CorruptedData(format!(
                "missing {table} after migration"
            )));
        }
    }
    let private_evidence: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM tpir_output_origins WHERE origin IN (2, 3))
             OR EXISTS(SELECT 1 FROM tpir_spend_origins WHERE origin IN (2, 3))
             OR EXISTS(SELECT 1 FROM ironwood_enhance_routing WHERE route = 2)",
        [],
        |r| r.get(0),
    )?;
    if private_evidence {
        return Err(WalletMigrationError::LegacyRollbackNotSupported);
    }
    Ok(())
}

fn view_sql(conn: &Connection) -> Result<String, rusqlite::Error> {
    conn.query_row(
        "SELECT sql FROM sqlite_master WHERE type = 'view' AND name = 'v_transactions'",
        [],
        |r| r.get(0),
    )
}

/// Re-enter the current schema only after every applied migration and the network were checked.
pub(super) fn resume_current(conn: &mut Connection) -> Result<(), WalletMigrationError> {
    if !is_prepared(conn)? {
        return Ok(());
    }
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_public_baseline(&tx)?;
    let updated = migrations::remove_zip318_column(&view_sql(&tx)?).ok_or_else(|| {
        WalletMigrationError::CorruptedData("unexpected legacy rollback history view".into())
    })?;
    // Older writers do not maintain origins. Reconcile all of their public records, including
    // writes to rows that existed before handover; local construction remains local evidence.
    tx.execute_batch(
        "INSERT OR IGNORE INTO tpir_output_origins(output_id, origin)
             SELECT id, 0 FROM transparent_received_outputs;
         INSERT OR IGNORE INTO tpir_output_origins(output_id, origin)
             SELECT o.id, 1 FROM transparent_received_outputs o
             JOIN transactions t ON t.id_tx = o.transaction_id
             WHERE t.created IS NOT NULL OR t.target_height IS NOT NULL;
         INSERT OR IGNORE INTO tpir_spend_origins(spending_transaction_id, prevout_txid, prevout_output_index, origin)
             SELECT s.transaction_id, t.txid, o.output_index, 0
             FROM transparent_received_output_spends s
             JOIN transparent_received_outputs o ON o.id = s.transparent_received_output_id
             JOIN transactions t ON t.id_tx = o.transaction_id
             UNION ALL SELECT spending_transaction_id, prevout_txid, prevout_output_index, 0
             FROM transparent_spend_map;
         INSERT OR IGNORE INTO tpir_spend_origins(spending_transaction_id, prevout_txid, prevout_output_index, origin)
             SELECT o.spending_transaction_id, o.prevout_txid, o.prevout_output_index, 1
             FROM tpir_spend_origins o JOIN transactions t ON t.id_tx = o.spending_transaction_id
             WHERE o.origin = 0 AND (t.created IS NOT NULL OR t.target_height IS NOT NULL);
         DROP VIEW v_transactions;",
    )?;
    // Restore the normal view before DROP COLUMN so application views over its retained columns
    // continue to resolve while SQLite validates the schema.
    tx.execute_batch(&updated)?;
    tx.execute_batch("ALTER TABLE transactions DROP COLUMN zip318_kind")?;
    // Older writers attribute sent outputs under their own rules. Re-derive the transactions they
    // may have stored once the queue exists; a wallet prepared before it existed has every
    // affected transaction queued when the migration that creates it runs.
    let queue_exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'tx_attribution_queue')",
        [],
        |r| r.get(0),
    )?;
    if queue_exists {
        tx.execute(migrations::QUEUE_AFFECTED_TRANSACTIONS, [])?;
    }
    // Older writers' rewinds do not request status for the transactions they un-mine. A wallet
    // prepared before re-confirmation provenance existed gets it from the migrations that follow.
    let reconfirmation: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('tx_retrieval_queue')
                       WHERE name = 'reconfirm_mined')",
        [],
        |r| r.get(0),
    )?;
    if reconfirmation {
        crate::wallet::queue_status_for_unobservable_transactions(&tx, None)?;
    }
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests;
