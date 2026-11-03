//! Adds empty historical inclusion receipts. Previously erased block identities cannot be rebuilt.
use super::status_reconfirmation;
use crate::migration::SqliteMigration as RusqliteMigration;
use crate::wallet::{init::WalletMigrationError, transaction_reconfirmation::RECEIPT_SCHEMA};
use std::collections::HashSet;
use uuid::Uuid;

/// Adds empty historical inclusion receipts without changing transaction authority.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x96bc0e72_51cf_4cdb_b11f_85a460db37ab);
const DEPENDENCIES: &[Uuid] = &[status_reconfirmation::MIGRATION_ID];
pub(super) struct Migration;
impl crate::migration::Migration for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }
    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }
    fn description(&self) -> &'static str {
        "Retains historical inclusion receipts for local transaction reconfirmation."
    }
}
impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;
    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(RECEIPT_SCHEMA)?;
        Ok(())
    }
    fn down(&self, _conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn additive_upgrade_keeps_existing_obligations_and_starts_without_receipts() {
        use crate::{
            WalletDb,
            testing::db::{test_clock, test_rng},
            wallet::init::WalletMigrator,
        };
        use zcash_protocol::consensus::Network;
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut db =
            WalletDb::for_path(file.path(), Network::TestNetwork, test_clock(), test_rng())
                .unwrap();
        WalletMigrator::new()
            .init_or_migrate_to(&mut db, super::DEPENDENCIES)
            .unwrap();
        db.conn.execute_batch("INSERT INTO transactions (txid,min_observed_height) VALUES(zeroblob(32),100); INSERT INTO tx_retrieval_queue(txid,query_type,policy_generation,reconfirm_mined) VALUES(zeroblob(32),0,0,1),(zeroblob(32),1,0,0)").unwrap();
        WalletMigrator::new().init_or_migrate(&mut db).unwrap();
        assert_eq!(
            db.conn
                .query_row("SELECT COUNT(*) FROM tx_reconfirmation_receipts", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            db.conn
                .query_row("SELECT COUNT(*) FROM tx_retrieval_queue", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            db.conn
                .query_row(
                    "SELECT reconfirm_mined FROM tx_retrieval_queue WHERE query_type=0",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
    }
    #[test]
    fn migrate() {
        super::super::tests::test_migrate(&[super::MIGRATION_ID]);
    }
}
