//! Adds early restore of one-time IVK payments (see `one_time_ivk::restore::early`).
//!
//! Additive: existing queued payments have no witness and are no hints, existing sweeps
//! are not provisional, and no account has an early restore.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::one_time_ivk;
use crate::wallet::init::WalletMigrationError;

/// Identifier for the early restore migration.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0xc5b63b3b_8190_4d0f_b217_3921d7aac225);

const DEPENDENCIES: &[Uuid] = &[one_time_ivk::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds early restore of one-time IVK payments."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(
            "ALTER TABLE ironwood_one_time_payment_recovery
                ADD COLUMN witness BLOB CHECK (length(witness) = 1024);
            ALTER TABLE ironwood_one_time_payment_recovery
                ADD COLUMN scan_hint INTEGER NOT NULL DEFAULT 0 CHECK (scan_hint IN (0, 1));
            ALTER TABLE ironwood_one_time_sweeps
                ADD COLUMN provisional INTEGER NOT NULL DEFAULT 0 CHECK (provisional IN (0, 1));
            CREATE TABLE ironwood_one_time_restores (
                account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
                restore_from INTEGER NOT NULL CHECK (restore_from BETWEEN 0 AND 4294967295),
                anchor_height INTEGER NOT NULL CHECK (anchor_height BETWEEN 0 AND 4294967295),
                anchor_hash BLOB NOT NULL CHECK (length(anchor_hash) = 32),
                anchor_tree_size INTEGER NOT NULL CHECK (anchor_tree_size >= 0),
                state INTEGER NOT NULL DEFAULT 0 CHECK (state IN (0, 1, 2))
            );",
        )?;
        Ok(())
    }

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
