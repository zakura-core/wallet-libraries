//! Retains Enhance PIR's transparent-output assertion and privately recovers it for existing
//! mixed transactions even when their received memos were already recovered.
use super::ironwood_unsupported_memo_retry;
use crate::wallet::init::WalletMigrationError;
use schemerz_rusqlite::RusqliteMigration;
use std::collections::HashSet;
use uuid::Uuid;

/// Adds nullable display evidence; no existing transaction is assumed to lack outputs.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x8f4c3210_04e1_49eb_9de2_d713ee0a8426);
pub(super) struct Migration;
impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }
    fn dependencies(&self) -> HashSet<Uuid> {
        [ironwood_unsupported_memo_retry::MIGRATION_ID]
            .into_iter()
            .collect()
    }
    fn description(&self) -> &'static str {
        "Retains transparent output shape from private Ironwood enhancement."
    }
}
impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;
    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(
            "ALTER TABLE ironwood_enhance_routing ADD COLUMN has_transparent_outputs INTEGER
                 CHECK (has_transparent_outputs IN (0, 1));",
        )?;
        // `ironwood_transparent_output_shape_height`, which always follows, queues the private
        // recovery of every unknown shape. The shared queueing statement reads its column.
        Ok(())
    }
    fn down(&self, _conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn migrate() {
        super::super::tests::test_migrate(&[super::MIGRATION_ID]);
    }
}
