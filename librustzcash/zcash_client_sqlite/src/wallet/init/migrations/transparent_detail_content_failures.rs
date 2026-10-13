//! Counts the content failures of transparent txid enhancement work, so that a lookup whose
//! private replies keep failing on content stops after the third one.
//!
//! Additive: existing work rows start with no content failures and keep their schedule.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::transparent_txid_enhancement;
use crate::wallet::init::WalletMigrationError;

/// Adds `transparent_detail_work.content_failures`.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0xe5339f96_a98a_4047_8274_28efdb9107ce);

const DEPENDENCIES: &[Uuid] = &[transparent_txid_enhancement::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Counts content failures of transparent txid enhancement work."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(
            "ALTER TABLE transparent_detail_work ADD COLUMN content_failures INTEGER NOT NULL
                DEFAULT 0 CHECK (content_failures >= 0);",
        )?;
        Ok(())
    }

    fn down(&self, _conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
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

    /// Work queued before the migration keeps its schedule and has no content failures.
    #[test]
    fn existing_work_has_no_content_failures() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(
            data_file.path(),
            Network::TestNetwork,
            test_clock(),
            test_rng(),
        )
        .unwrap();
        let migrator = || {
            WalletMigrator::new()
                .with_seed(Secret::new([0xab; 32].to_vec()))
                .ignore_seed_relevance()
        };
        migrator()
            .init_or_migrate_to(&mut db_data, DEPENDENCIES)
            .unwrap();
        db_data
            .conn
            .execute_batch(
                "INSERT INTO transactions (id_tx, txid, min_observed_height) VALUES (1, X'01', 0);
                 INSERT INTO transparent_detail_work
                     (transaction_id, reasons, attempts, next_attempt_at, last_outcome)
                 VALUES (1, 1, 2, 77, 1);",
            )
            .unwrap();

        migrator()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
            .unwrap();
        let row: (u32, i64, u32) = db_data
            .conn
            .query_row(
                "SELECT attempts, next_attempt_at, content_failures FROM transparent_detail_work",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(row, (2, 77, 0));
    }
}
