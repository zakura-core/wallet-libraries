//! Drops the schema of the ZIP 318 pool-migration engine.
//!
//! This fork does not carry the Orchard -> Ironwood pool-migration engine. The migrations that
//! created its schema stay registered, because they are published and later migrations depend on
//! them; this migration removes the `orchard_ironwood_migration*` tables and their indexes, which
//! nothing reads or writes, so that a fresh wallet and an upgraded one converge on the same schema.
//! Published zakura-client-sqlite 0.1.0-rc5 and 0.1.0-rc7 reference those tables only through
//! `ON DELETE CASCADE` from `accounts`, which is inert once they are gone.
//!
//! The `zip318_kind` column of `transactions` and `v_transactions` is kept. Published rc5 and rc7
//! write it every time they store a decrypted transaction, so dropping it would break a wallet
//! reopened by a build that uses them. This build never reads it. Upgrades from
//! published schemas retain the column and view field without reconstructing either.
//! Retaining the field does not qualify writes by older builds after a private-ledger upgrade.

use std::collections::HashSet;

use crate::migration::SqliteMigration as RusqliteMigration;
use uuid::Uuid;

use super::status_inclusion_evidence;
use crate::wallet::init::WalletMigrationError;

/// Drops the pool-migration tables.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x772a0632_3d0e_4dff_b1f8_c64863eefaaa);

// `status_inclusion_evidence` transitively depends on every migration that created the dropped
// schema, and on `ironwood_enhance`, the last migration to rebuild `v_transactions`.
const DEPENDENCIES: &[Uuid] = &[status_inclusion_evidence::MIGRATION_ID];

pub(super) struct Migration;

impl crate::migration::Migration for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Drops the ZIP 318 pool-migration tables."
    }
}

/// Fails, naming them, if views or triggers outside this library's schema still depend on the
/// tables this migration removes.
///
/// SQLite drops a table that a view or trigger names without complaint, leaving the dependent
/// object to fail on first use with an error that does not say why. An application view over the
/// pool-migration tables, or one left by a build this fork never shipped, is refused here instead.
fn reject_dependents(transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
    let mut dependents = vec![];
    let views: Vec<String> = transaction
        .prepare("SELECT name FROM sqlite_master WHERE type = 'view'")?
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    for view in views {
        let query = format!("SELECT * FROM \"{}\" LIMIT 0", view.replace('"', "\"\""));
        if transaction.prepare(&query).is_err() {
            dependents.push(view);
        }
    }
    dependents.extend(
        transaction
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'trigger'
                 AND instr(lower(sql), 'orchard_ironwood_migration') > 0",
            )?
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?,
    );
    if dependents.is_empty() {
        Ok(())
    } else {
        Err(WalletMigrationError::CorruptedData(format!(
            "views or triggers depend on the ZIP 318 tables this upgrade removes: {}",
            dependents.join(", ")
        )))
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // Children before parents, so no foreign key is left dangling while the batch runs.
        transaction.execute_batch(
            "DROP INDEX IF EXISTS idx_orchard_ironwood_migration_tx_due;
             DROP INDEX IF EXISTS idx_orchard_ironwood_migrations_account;
             DROP TABLE IF EXISTS orchard_ironwood_migration_spend_nullifiers;
             DROP TABLE IF EXISTS orchard_ironwood_migration_transaction_deps;
             DROP TABLE IF EXISTS orchard_ironwood_migration_transactions;
             DROP TABLE IF EXISTS orchard_ironwood_migration_prep_direct_funding;
             DROP TABLE IF EXISTS orchard_ironwood_migration_prep_outputs;
             DROP TABLE IF EXISTS orchard_ironwood_migration_prep_inputs;
             DROP TABLE IF EXISTS orchard_ironwood_migration_crossing_values;
             DROP TABLE IF EXISTS orchard_ironwood_migrations;",
        )?;
        reject_dependents(transaction)
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::{Connection, named_params};
    use secrecy::Secret;
    use tempfile::NamedTempFile;
    use zcash_protocol::consensus::Network;

    use crate::{
        WalletDb,
        testing::db::{test_clock, test_rng},
        wallet::init::{WalletMigrator, migrations::tests::test_migrate},
    };

    use super::{DEPENDENCIES, MIGRATION_ID};

    #[test]
    fn migrate() {
        test_migrate(&[MIGRATION_ID]);
    }

    fn table_exists(conn: &Connection, name: &str) -> bool {
        conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE name = :name)",
            named_params![":name": name],
            |row| row.get(0),
        )
        .unwrap()
    }

    fn has_column(conn: &Connection, relation: &str, column: &str) -> bool {
        conn.query_row(
            "SELECT EXISTS (
                SELECT 1 FROM pragma_table_info(:relation) WHERE name = :column
             )",
            named_params![":relation": relation, ":column": column],
            |row| row.get(0),
        )
        .unwrap()
    }

    /// A wallet that has pool-migration rows loses them, and keeps its transactions with their
    /// ZIP 318 classification, which published rc5/rc7 builds still write and read.
    #[test]
    fn drops_populated_schema_and_keeps_transactions() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(
            data_file.path(),
            Network::TestNetwork,
            test_clock(),
            test_rng(),
        )
        .unwrap();
        let seed = [0xab; 32];
        WalletMigrator::new()
            .with_seed(Secret::new(seed.to_vec()))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, DEPENDENCIES)
            .unwrap();

        let conn = &db_data.conn;
        // The pool-migration row names no real account; this test is about the schema.
        conn.execute_batch(
            "PRAGMA foreign_keys = OFF;
             INSERT INTO transactions (id_tx, txid, min_observed_height, zip318_kind)
             VALUES (1, X'01', 0, 3);
             INSERT INTO orchard_ironwood_migrations (
                 id, account_id, status, note_split_fee_buffer, note_split_change,
                 note_split_prep_fees, note_split_total_input, note_split_total_migratable
             )
             VALUES (1, 1, 'planned', 100, NULL, 200, 300, 400);
             PRAGMA foreign_keys = ON;",
        )
        .unwrap();
        assert!(has_column(conn, "v_transactions", "zip318_kind"));

        WalletMigrator::new()
            .with_seed(Secret::new(seed.to_vec()))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
            .unwrap();

        let conn = &db_data.conn;
        for table in [
            "orchard_ironwood_migrations",
            "orchard_ironwood_migration_crossing_values",
            "orchard_ironwood_migration_prep_inputs",
            "orchard_ironwood_migration_prep_outputs",
            "orchard_ironwood_migration_prep_direct_funding",
            "orchard_ironwood_migration_transactions",
            "orchard_ironwood_migration_transaction_deps",
            "orchard_ironwood_migration_spend_nullifiers",
            "idx_orchard_ironwood_migration_tx_due",
            "idx_orchard_ironwood_migrations_account",
        ] {
            assert!(!table_exists(conn, table), "{table} was not dropped");
        }
        assert!(has_column(conn, "transactions", "zip318_kind"));
        assert!(has_column(conn, "v_transactions", "zip318_kind"));
        assert!(has_column(conn, "v_transactions", "pool_crossing_value"));

        let (txid, kind): (Vec<u8>, i64) = conn
            .query_row(
                "SELECT txid, zip318_kind FROM transactions WHERE id_tx = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((txid, kind), (vec![1], 3));
    }

    /// A view that depends on the removed tables is named, and the wallet is left exactly as it
    /// was, instead of failing on first use with an anonymous error. Views over the retained
    /// `zip318_kind` column keep working.
    #[test]
    fn dependent_views_are_named_and_the_upgrade_rolls_back() {
        use crate::wallet::init::WalletMigrationError;
        use std::error::Error as _;

        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(
            data_file.path(),
            Network::TestNetwork,
            test_clock(),
            test_rng(),
        )
        .unwrap();
        let seed = [0xab; 32];
        WalletMigrator::new()
            .with_seed(Secret::new(seed.to_vec()))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, DEPENDENCIES)
            .unwrap();
        db_data
            .conn
            .execute_batch(
                "CREATE VIEW ext_app_history AS SELECT txid FROM v_transactions;
                 CREATE VIEW ext_zip318_history AS SELECT zip318_kind FROM v_transactions;
                 CREATE VIEW ext_app_migrations AS SELECT * FROM orchard_ironwood_migrations;",
            )
            .unwrap();

        let result = WalletMigrator::new()
            .with_seed(Secret::new(seed.to_vec()))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID]);
        assert!(
            matches!(
                result.as_ref().err().and_then(|error| error.source()).and_then(|source| source.downcast_ref()),
                Some(WalletMigrationError::CorruptedData(reason))
                    if !reason.contains("ext_app_history") && !reason.contains("ext_zip318_history") && reason.contains("ext_app_migrations")
            ),
            "{result:?}"
        );
        assert!(table_exists(&db_data.conn, "orchard_ironwood_migrations"));

        db_data
            .conn
            .execute_batch("DROP VIEW ext_app_migrations;")
            .unwrap();
        WalletMigrator::new()
            .with_seed(Secret::new(seed.to_vec()))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
            .unwrap();
        assert!(!table_exists(&db_data.conn, "orchard_ironwood_migrations"));
        for view in ["ext_app_history", "ext_zip318_history"] {
            db_data
                .conn
                .prepare(&format!("SELECT * FROM {view}"))
                .unwrap();
        }
    }
    /// SQLite identifiers are case-insensitive; every casing of a dependent trigger must
    /// refuse the migration before its removed tables and journal entry are committed.
    #[test]
    fn dependent_triggers_are_named_and_the_upgrade_rolls_back() {
        use crate::wallet::init::WalletMigrationError;
        use std::error::Error as _;

        for table in ["ORCHARD_IRONWOOD_MIGRATIONS", "Orchard_Ironwood_Migrations"] {
            let file = NamedTempFile::new().unwrap();
            let mut db =
                WalletDb::for_path(file.path(), Network::TestNetwork, test_clock(), test_rng())
                    .unwrap();
            let seed = [0xab; 32];
            WalletMigrator::new()
                .with_seed(Secret::new(seed.to_vec()))
                .ignore_seed_relevance()
                .init_or_migrate_to(&mut db, DEPENDENCIES)
                .unwrap();
            db.conn
                .execute_batch(&format!(
                    "CREATE TRIGGER ext_pool_trigger AFTER UPDATE ON accounts
                 BEGIN DELETE FROM {table} WHERE account_id = NEW.id; END;"
                ))
                .unwrap();
            let result = WalletMigrator::new()
                .with_seed(Secret::new(seed.to_vec()))
                .ignore_seed_relevance()
                .init_or_migrate_to(&mut db, &[MIGRATION_ID]);
            assert!(
                matches!(
                    result.as_ref().err().and_then(|error| error.source()).and_then(|source| source.downcast_ref()),
                    Some(WalletMigrationError::CorruptedData(reason)) if reason.contains("ext_pool_trigger")
                ),
                "{result:?}"
            );
            assert!(table_exists(&db.conn, "orchard_ironwood_migrations"));
            let applied: bool = db
                .conn
                .query_row(
                    "SELECT EXISTS (SELECT 1 FROM schemer_migrations WHERE id = ?1)",
                    [MIGRATION_ID.as_bytes().to_vec()],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(!applied);
            db.conn
                .execute_batch("DROP TRIGGER ext_pool_trigger")
                .unwrap();
            WalletMigrator::new()
                .with_seed(Secret::new(seed.to_vec()))
                .ignore_seed_relevance()
                .init_or_migrate_to(&mut db, &[MIGRATION_ID])
                .unwrap();
            assert!(!table_exists(&db.conn, "orchard_ironwood_migrations"));
        }
    }
}
