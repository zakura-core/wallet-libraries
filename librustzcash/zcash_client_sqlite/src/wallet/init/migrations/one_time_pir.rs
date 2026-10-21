//! Removes abandoned feature state from databases already carrying the old migration IDs.
use super::one_time_ivk_discovery;
use crate::wallet::init::WalletMigrationError;
use schemerz_rusqlite::RusqliteMigration;
use std::collections::HashSet;
use uuid::Uuid;

/// Identifies the cutover independently of the earlier published schema.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x2eed2da7_2176_4d72_9461_c9ae27491b0a);
pub(super) struct Migration;
impl schemerz::Migration<Uuid> for Migration {
    /// Returns the unique cutover identifier.
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }
    /// Runs after the registry, ordinary note ownership and spend journal exist.
    fn dependencies(&self) -> HashSet<Uuid> {
        [one_time_ivk_discovery::MIGRATION_ID].into_iter().collect()
    }
    /// Describes the stored-state change for migration diagnostics.
    fn description(&self) -> &'static str {
        "Replace unlaunched one-time discovery state with the PIR queue."
    }
}
impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;
    /// Existing wallets discard only obsolete progress, then every wallet converges on one schema.
    fn up(&self, tx: &rusqlite::Transaction) -> Result<(), Self::Error> {
        let current: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'ironwood_one_time_recovery')",
            [], |r| r.get(0))?;
        if !current {
            one_time_ivk_discovery::Migration.up(tx)?;
        }
        tx.execute_batch(
            "ALTER TABLE ironwood_one_time_recovery ADD COLUMN receive_end BLOB NOT NULL
                DEFAULT X'0000000000000000' CHECK (length(receive_end) = 8);
             DROP INDEX IF EXISTS idx_ironwood_one_time_keys_account_receiver;
             ALTER TABLE ironwood_one_time_keys DROP COLUMN registered_at;
             CREATE TABLE ironwood_one_time_operation_receipts (
                operation_id INTEGER NOT NULL REFERENCES ironwood_one_time_operations(id) ON DELETE CASCADE,
                txid BLOB NOT NULL CHECK (length(txid) = 32),
                PRIMARY KEY (operation_id, txid)
             );
             CREATE TABLE ironwood_one_time_owed_receipts (
                one_time_key_id INTEGER NOT NULL REFERENCES ironwood_one_time_keys(id) ON DELETE CASCADE,
                nf BLOB NOT NULL CHECK (length(nf) = 32),
                PRIMARY KEY (one_time_key_id, nf)
             );",
        )?;
        Ok(())
    }
    /// Old discovery state cannot be reconstructed from the replacement queue.
    fn down(&self, _: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}
#[cfg(test)]
mod tests {
    /// The terminal migration keeps the normal wallet migration graph valid.
    #[test]
    fn migrate() {
        super::super::tests::test_migrate(&[super::MIGRATION_ID]);
    }
}
