//! Adds a per-position count of rejected Enhance PIR records, so a record that keeps failing
//! verification is suspended instead of being queried again at every drain.
use super::transparent_txid_enhancement;
use crate::wallet::init::WalletMigrationError;
use schemerz_rusqlite::RusqliteMigration;
use std::collections::HashSet;
use uuid::Uuid;

/// Additive: one new table, initially empty.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x7f7e0bed_c9f8_4db9_9836_fac7374474a3);
pub(super) struct Migration;
impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }
    fn dependencies(&self) -> HashSet<Uuid> {
        [transparent_txid_enhancement::MIGRATION_ID]
            .into_iter()
            .collect()
    }
    fn description(&self) -> &'static str {
        "Adds a rejection count per Ironwood Enhance PIR position."
    }
}
impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;
    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(
            "CREATE TABLE ironwood_enhance_rejections (
                commitment_tree_position INTEGER PRIMARY KEY,
                rejections INTEGER NOT NULL CHECK (rejections > 0)
            );",
        )?;
        Ok(())
    }
    fn down(&self, _conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        WalletDb,
        testing::db::{test_clock, test_rng},
        wallet::init::WalletMigrator,
    };
    use secrecy::Secret;
    use tempfile::NamedTempFile;
    use zcash_protocol::consensus::Network;

    #[test]
    fn migrate() {
        super::super::tests::test_migrate(&[super::MIGRATION_ID]);
    }

    #[test]
    fn adds_an_empty_count_table_to_an_existing_wallet() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(
            data_file.path(),
            Network::TestNetwork,
            test_clock(),
            test_rng(),
        )
        .unwrap();
        let migrate = |db_data: &mut WalletDb<_, _, _, _>, to| {
            WalletMigrator::new()
                .with_seed(Secret::new(vec![0xab; 32]))
                .ignore_seed_relevance()
                .init_or_migrate_to(db_data, &[to])
                .unwrap();
        };
        migrate(
            &mut db_data,
            super::super::transparent_txid_enhancement::MIGRATION_ID,
        );
        let exists = |conn: &rusqlite::Connection| -> bool {
            conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master
                 WHERE type = 'table' AND name = 'ironwood_enhance_rejections')",
                [],
                |row| row.get(0),
            )
            .unwrap()
        };
        assert!(!exists(&db_data.conn));
        migrate(&mut db_data, super::MIGRATION_ID);
        assert!(exists(&db_data.conn));
        let count: i64 = db_data
            .conn
            .query_row(
                "SELECT COUNT(*) FROM ironwood_enhance_rejections",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
        assert!(
            db_data
                .conn
                .execute("INSERT INTO ironwood_enhance_rejections VALUES (0, 0)", [])
                .is_err()
        );
        db_data
            .conn
            .execute("INSERT INTO ironwood_enhance_rejections VALUES (0, 1)", [])
            .unwrap();
    }
}
