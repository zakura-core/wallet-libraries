//! Moves one-time state to marker-based detection on Receiver's directory and companion
//! tables, and resets lookup and seed-walk progress recorded under the old rules. Keys,
//! operations, receipts and notes stay. Only development databases hold one-time data.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::one_time_pir;
use crate::wallet::init::WalletMigrationError;

/// Adds the use marker, binds candidates to directory and companion sessions, and resets
/// one-time progress.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0xf2d02e57_b25a_4d14_84ce_db2153fc66d3);

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
        "Reset one-time progress for marker-based detection on directory sessions."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    /// Adds the new columns, resets progress and drops the obsolete columns.
    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(
            "-- The use marker, and candidate bindings for the directory and companion tables.
             ALTER TABLE ironwood_one_time_recovery ADD COLUMN used INTEGER NOT NULL DEFAULT 0
                CHECK (used IN (0, 1));
             ALTER TABLE ironwood_one_time_payment_recovery RENAME COLUMN payments TO directory;
             ALTER TABLE ironwood_one_time_payment_recovery RENAME COLUMN witnesses TO companion;
             -- Lookups, candidates, cursors, the seed walk and the marker start over.
             DELETE FROM ironwood_one_time_lookups;
             DELETE FROM ironwood_one_time_payment_recovery;
             UPDATE ironwood_one_time_recovery SET generation = generation + 1,
                filter_height = NULL, filter_hash = NULL, restore_height = NULL,
                restore_next = X'0000000000000000', restore_gap = 0, restore_done = 0,
                manual_active = 0, manual_purpose = 0, manual_next = X'0000000000000000',
                manual_end = NULL, manual_height = NULL;
             -- The obsolete columns.
             ALTER TABLE ironwood_one_time_recovery DROP COLUMN skipped_height;
             ALTER TABLE ironwood_one_time_keys DROP COLUMN prebirthday_height;",
        )?;
        Ok(())
    }

    /// The reset progress cannot be restored.
    fn down(&self, _: &rusqlite::Transaction) -> Result<(), Self::Error> {
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
