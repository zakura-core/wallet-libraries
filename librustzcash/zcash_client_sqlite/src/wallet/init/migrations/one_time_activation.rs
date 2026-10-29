//! Adds the one-time use marker, and drops the recovery state that only served filter
//! re-checks: every newly watched key now gets a bootstrap lookup, so `pir_coverage` no
//! longer chooses between the two.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::one_time_new_work;
use crate::wallet::init::WalletMigrationError;

/// Adds `ironwood_one_time_recovery.used` and drops its `pir_coverage`.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x755fb50a_f4e6_4b3e_80f0_8a21829607df);

const DEPENDENCIES: &[Uuid] = &[one_time_new_work::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    /// This migration's identifier.
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    /// Runs after the new-work counter exists.
    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    /// Describes the stored-state change for migration diagnostics.
    fn description(&self) -> &'static str {
        "Add the one-time use marker and drop the complete-check flag."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    /// Drops the flag. Keys already behind the frontier keep their coverage and pending
    /// lookups; the next key to enter monitoring gets a bootstrap lookup.
    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(
            "ALTER TABLE ironwood_one_time_recovery ADD COLUMN used INTEGER NOT NULL DEFAULT 0
                CHECK (used IN (0, 1));
             ALTER TABLE ironwood_one_time_recovery DROP COLUMN pir_coverage;",
        )?;
        Ok(())
    }

    /// The dropped flag cannot be restored.
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

    /// A wallet migrated through the previous schema, with the flag set, keeps its recovery
    /// row and loses only the flag.
    #[test]
    fn upgrade_drops_only_the_flag() {
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
            .execute(
                "INSERT INTO ironwood_one_time_recovery
                     (account_id, enabled, filter_height, filter_hash, fresh, pir_coverage)
                 VALUES (1, 1, 500, zeroblob(32), 0, 1)",
                [],
            )
            .unwrap();

        migrator()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
            .unwrap();
        let recovery: (bool, u32, bool) = db_data
            .conn
            .query_row(
                "SELECT enabled, filter_height, fresh FROM ironwood_one_time_recovery",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(recovery, (true, 500, false));
        assert!(
            db_data
                .conn
                .prepare("SELECT pir_coverage FROM ironwood_one_time_recovery")
                .is_err()
        );
    }
}
