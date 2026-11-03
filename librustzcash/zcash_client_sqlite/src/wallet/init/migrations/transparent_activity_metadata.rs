//! Adds source-bound transaction facts without projecting fees into local send records.
use super::transparent_activation_schema;
use crate::migration::SqliteMigration as RusqliteMigration;
use crate::wallet::init::WalletMigrationError;
use std::collections::HashSet;
use uuid::Uuid;

/// Empty, seedless transaction metadata evidence table.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x935cd436_09fd_4f4f_a808_260ee399cb21);
const DEPENDENCIES: &[Uuid] = &[transparent_activation_schema::MIGRATION_ID];
pub(super) struct Migration;
impl crate::migration::Migration for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }
    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }
    fn description(&self) -> &'static str {
        "Adds source-bound transparent transaction metadata."
    }
}
impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;
    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(crate::wallet::db::TABLE_TPIR_TRANSACTION_METADATA)?;
        Ok(())
    }
    fn down(&self, _conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}
#[cfg(test)]
mod tests {
    use super::MIGRATION_ID;
    #[test]
    fn migrate() {
        crate::wallet::init::migrations::tests::test_migrate(&[MIGRATION_ID]);
    }
}
