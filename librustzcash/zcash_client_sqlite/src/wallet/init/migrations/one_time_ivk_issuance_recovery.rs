//! Tracks bounded checks of the monotone provider set separately from payment filters.
use crate::wallet::init::WalletMigrationError;
use schemerz_rusqlite::RusqliteMigration;
use std::collections::HashSet;
use uuid::Uuid;

/// Stable identity of the issuance recovery migration.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x89a9e3ac_0624_45e1_ae86_c942a55100b1);
pub(super) struct Migration;
impl schemerz::Migration<Uuid> for Migration {
    /// Identifies the new schema without rewriting a shipped migration.
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }
    /// Requires the block recovery account and window records.
    fn dependencies(&self) -> HashSet<Uuid> {
        [super::one_time_ivk_block_recovery::MIGRATION_ID].into()
    }
    /// Describes the durable issuance prerequisite.
    fn description(&self) -> &'static str {
        "Tracks checked provider membership for issuance."
    }
}
impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;
    /// Keeps prior keys and exposure facts while initially requiring a provider check.
    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch("CREATE TABLE ironwood_block_seen (
            account_id INTEGER PRIMARY KEY REFERENCES ironwood_block_recovery(account_id) ON DELETE CASCADE,
            digest BLOB NOT NULL CHECK(length(digest)=32), until_unix INTEGER NOT NULL CHECK(until_unix>=0));
            ALTER TABLE ironwood_block_windows ADD COLUMN seen_index BLOB NOT NULL DEFAULT X'00000000000000000000000000000000'
                CHECK(typeof(seen_index)='blob' AND length(seen_index)=16 AND seen_index<=end_index);")?;
        Ok(())
    }
    /// Never silently discard exposure or readiness state on downgrade.
    fn down(&self, _: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}
#[cfg(test)]
mod tests {
    /// Checks the supported predecessor paths and foreign-key constraints.
    #[test]
    fn migrate() {
        super::super::tests::test_migrate(&[super::MIGRATION_ID]);
    }
}
