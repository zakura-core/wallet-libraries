//! Retains derivation origins independently of receiver ownership after promotion.
use std::collections::HashSet;

use crate::migration::SqliteMigration as RusqliteMigration;
use uuid::Uuid;

use super::transparent_activity_metadata;
use crate::wallet::{db::TABLE_TPIR_SHARED_DERIVATIONS, init::WalletMigrationError};

/// Adds empty shared-derivation bookkeeping without changing wallet authority.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0xa03b0d6a_6085_4859_ae77_bce948345214);
const DEPENDENCIES: &[Uuid] = &[transparent_activity_metadata::MIGRATION_ID];

pub(super) struct Migration;

impl crate::migration::Migration for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }
    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }
    fn description(&self) -> &'static str {
        "Retains transparent shared derivation origins."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;
    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(TABLE_TPIR_SHARED_DERIVATIONS)?;
        Ok(())
    }
    fn down(&self, _conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        WalletDb,
        testing::db::{test_clock, test_rng},
        wallet::init::{WalletMigrator, migrations::tests::test_migrate},
    };
    use zcash_protocol::consensus::Network;

    #[test]
    fn migrate() {
        test_migrate(&[MIGRATION_ID]);
    }

    #[test]
    fn upgrade_is_additive_and_grants_no_authority() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut db =
            WalletDb::for_path(file.path(), Network::TestNetwork, test_clock(), test_rng())
                .unwrap();
        WalletMigrator::new()
            .init_or_migrate_to(&mut db, DEPENDENCIES)
            .unwrap();
        let before: (i64, i64, i64) = db
            .conn
            .query_row(
                "SELECT applied_mode, policy_generation, min_reader_version FROM tpir_meta",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        WalletMigrator::new().init_or_migrate(&mut db).unwrap();
        let after: (i64, i64, i64) = db
            .conn
            .query_row(
                "SELECT applied_mode, policy_generation, min_reader_version FROM tpir_meta",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(before, after);
        assert_eq!(
            db.conn
                .query_row("SELECT COUNT(*) FROM tpir_shared_derivations", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert!(
            db.conn
                .execute("INSERT INTO tpir_shared_derivations VALUES (999, 0, 1)", [])
                .is_err()
        );
        assert_eq!(
            db.conn
                .query_row("PRAGMA foreign_keys", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}
