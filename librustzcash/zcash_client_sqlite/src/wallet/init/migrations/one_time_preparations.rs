//! Durable issuance preparations: the next receive or refund address, checked ahead by its
//! own lookup.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::one_time_filter_coverage;
use crate::wallet::init::WalletMigrationError;

/// Adds `ironwood_one_time_preparations`.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0xb8b5e3de_9535_491e_ba8c_c46e3dc407a4);

const DEPENDENCIES: &[Uuid] = &[one_time_filter_coverage::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    /// This migration's identifier.
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    /// Runs after per-key filter coverage exists.
    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    /// Describes the stored-state change for migration diagnostics.
    fn description(&self) -> &'static str {
        "Add durable one-time issuance preparations."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    /// Creates the empty preparations table.
    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(
            "CREATE TABLE ironwood_one_time_preparations (
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                purpose INTEGER NOT NULL CHECK (purpose IN (0, 1)),
                one_time_key_id INTEGER NOT NULL REFERENCES ironwood_one_time_keys(id) ON DELETE CASCADE,
                target_height INTEGER NOT NULL CHECK (target_height BETWEEN 0 AND 4294967295),
                PRIMARY KEY (account_id, purpose)
            );",
        )?;
        Ok(())
    }

    /// Drops the preparations, which only cache work a later call redoes.
    fn down(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch("DROP TABLE ironwood_one_time_preparations;")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn migrate() {
        super::super::tests::test_migrate(&[super::MIGRATION_ID]);
    }
}
