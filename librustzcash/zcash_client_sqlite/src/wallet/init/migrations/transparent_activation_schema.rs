//! Adds the activation tables of the transparent ledger.
//!
//! Seedless and additive: it creates empty `tpir_*` tables for the account lifecycle, revision
//! qualification, and integrity recovery suspension. Every account starts as a candidate, no revision is
//! qualified, and nothing is suspended, so the upgrade grants no private authority.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::transparent_recovery_schema;
use crate::wallet::init::WalletMigrationError;

/// Creates the activation tables.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x88cad111_4914_4382_a78f_d85bb3507c5c);

const DEPENDENCIES: &[Uuid] = &[transparent_recovery_schema::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds the transparent ledger activation tables."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(
            r#"
            CREATE TABLE tpir_active_accounts (
                account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE
            );
            CREATE TABLE tpir_qualified_revisions (
                revision_id INTEGER PRIMARY KEY REFERENCES tpir_revisions(id)
            );
            CREATE TABLE tpir_quarantined_sources (
                source BLOB PRIMARY KEY
            );
            CREATE TABLE tpir_quarantined_accounts (
                account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE
            );
            "#,
        )?;
        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use tempfile::NamedTempFile;
    use zcash_protocol::consensus::Network;

    use super::{DEPENDENCIES, MIGRATION_ID};
    use crate::{
        WalletDb,
        testing::db::{test_clock, test_rng},
        wallet::init::{WalletMigrator, migrations::tests::test_migrate},
    };

    const ACTIVATION_TABLES: &[&str] = &[
        "tpir_active_accounts",
        "tpir_qualified_revisions",
        "tpir_quarantined_sources",
        "tpir_quarantined_accounts",
    ];

    #[test]
    fn migrate() {
        test_migrate(&[MIGRATION_ID]);
    }

    #[test]
    fn seedless_upgrade_creates_only_empty_activation_tables() {
        let file = NamedTempFile::new().unwrap();
        let mut db =
            WalletDb::for_path(file.path(), Network::TestNetwork, test_clock(), test_rng())
                .unwrap();
        WalletMigrator::new()
            .init_or_migrate_to(&mut db, DEPENDENCIES)
            .unwrap();
        let tables = |db: &WalletDb<rusqlite::Connection, _, _, _>| -> BTreeSet<String> {
            db.conn
                .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        let before = tables(&db);

        // No seed: imported-only and hardware-first wallets must upgrade.
        WalletMigrator::new()
            .init_or_migrate_to(&mut db, &[MIGRATION_ID])
            .unwrap();

        let added: BTreeSet<String> = tables(&db).difference(&before).cloned().collect();
        assert_eq!(
            added,
            ACTIVATION_TABLES.iter().map(|t| t.to_string()).collect()
        );
        for table in ACTIVATION_TABLES {
            let rows: i64 = db
                .conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(rows, 0, "{table} must start empty");
        }
    }
}
