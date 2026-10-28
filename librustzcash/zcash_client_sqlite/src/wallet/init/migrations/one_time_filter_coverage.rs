//! Tracks one-time filter coverage per span and per key.
//!
//! The old frontier had no per-key record, so it is discarded: coverage restarts from
//! Ironwood activation. Completed lookups, keys, notes and ordinary wallet data stay.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::one_time_pir;
use crate::wallet::init::WalletMigrationError;

/// Adds per-key filter coverage and the account's fresh and complete-check flags.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x88723a02_f965_461a_8e06_634dbb2b2974);

const DEPENDENCIES: &[Uuid] = &[one_time_pir::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    /// This migration's identifier.
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    /// Runs after the PIR recovery queue exists.
    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    /// Describes the stored-state change for migration diagnostics.
    fn description(&self) -> &'static str {
        "Track one-time filter coverage per span and per key."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    /// Adds the coverage columns and discards the old filter frontiers.
    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(
            "UPDATE ironwood_one_time_recovery SET filter_height = NULL, filter_hash = NULL;
             ALTER TABLE ironwood_one_time_recovery DROP COLUMN skipped_height;
             ALTER TABLE ironwood_one_time_recovery ADD COLUMN fresh INTEGER NOT NULL
                DEFAULT 1 CHECK (fresh IN (0, 1));
             ALTER TABLE ironwood_one_time_recovery ADD COLUMN pir_coverage INTEGER NOT NULL
                DEFAULT 0 CHECK (pir_coverage IN (0, 1));
             -- An existing account may have paid keys, so it is not counted as fresh.
             UPDATE ironwood_one_time_recovery SET fresh = 0;
             ALTER TABLE ironwood_one_time_keys ADD COLUMN covered_height INTEGER
                CHECK (covered_height BETWEEN 0 AND 4294967295);",
        )?;
        Ok(())
    }

    /// The discarded frontiers cannot be restored.
    fn down(&self, _: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use secrecy::Secret;
    use tempfile::NamedTempFile;
    use zcash_keys::keys::UnifiedSpendingKey;
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

    /// A wallet at the previous schema keeps its keys, lookups and restore progress, loses
    /// its old filter frontier, and reads as not fresh.
    #[test]
    fn upgrade_discards_old_frontiers_only() {
        let network = Network::TestNetwork;
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data =
            WalletDb::for_path(data_file.path(), network, test_clock(), test_rng()).unwrap();
        let migrator = || {
            WalletMigrator::new()
                .with_seed(Secret::new([0xab; 32].to_vec()))
                .ignore_seed_relevance()
        };
        migrator()
            .init_or_migrate_to(&mut db_data, DEPENDENCIES)
            .unwrap();
        let ufvk = UnifiedSpendingKey::from_seed(&network, &[0xab; 32], zip32::AccountId::ZERO)
            .unwrap()
            .to_unified_full_viewing_key();
        db_data
            .conn
            .execute(
                "INSERT INTO accounts (id, uuid, account_kind, ufvk, uivk, birthday_height)
                 VALUES (1, zeroblob(16), 1, ?1, ?2, 1)",
                [
                    ufvk.encode(&network),
                    ufvk.to_unified_incoming_viewing_key().encode(&network),
                ],
            )
            .unwrap();
        db_data
            .conn
            .execute_batch(
                "INSERT INTO ironwood_one_time_recovery
                     (account_id, enabled, filter_height, filter_hash, skipped_height,
                      restore_height, restore_done)
                 VALUES (1, 1, 500, zeroblob(32), 500, 400, 1);
                 INSERT INTO ironwood_one_time_keys (id, account_id, purpose, key_index, receiver)
                 VALUES (1, 1, 1, X'0000000000000000', zeroblob(43));
                 INSERT INTO ironwood_one_time_lookups
                     (one_time_key_id, done_from, done_height, read_complete)
                 VALUES (1, 280, 500, 1);",
            )
            .unwrap();

        migrator()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
            .unwrap();
        let recovery: (bool, Option<u32>, Option<u32>, bool, bool, bool) = db_data
            .conn
            .query_row(
                "SELECT enabled, filter_height, restore_height, restore_done, fresh, pir_coverage
                 FROM ironwood_one_time_recovery",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(recovery, (true, None, Some(400), true, false, false));
        let key: (Option<u32>, u32, u32) = db_data
            .conn
            .query_row(
                "SELECT k.covered_height, l.done_from, l.done_height
                 FROM ironwood_one_time_keys k
                 JOIN ironwood_one_time_lookups l ON l.one_time_key_id = k.id",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(key, (None, 280, 500));
    }
}
