//! Durable reservations and recovered/lookahead keys for the local swap POC.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::ironwood_enhance;
use crate::wallet::init::WalletMigrationError;

/// Identifier for the swap receiving-key registry migration.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0xd91a2496_7a69_4f7e_b18f_b4f602f6a590);

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [ironwood_enhance::MIGRATION_ID].into_iter().collect()
    }

    fn description(&self) -> &'static str {
        "Adds the Ironwood swap receiving-key registry."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // Schema is independent of build features. Reopening without the POC
        // feature must preserve reservations rather than permit address reuse.
        transaction.execute_batch(
            "
CREATE TABLE ironwood_receiving_keys (
    id INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    purpose INTEGER NOT NULL CHECK (purpose IN (0, 1)),
    derivation_version INTEGER NOT NULL CHECK (derivation_version = 1),
    key_index BLOB NOT NULL CHECK (typeof(key_index) = 'blob' AND length(key_index) = 8),
    receiver BLOB NOT NULL CHECK (typeof(receiver) = 'blob' AND length(receiver) = 43),
    scan_from INTEGER NOT NULL CHECK (scan_from >= 0 AND scan_from <= 4294967295),
    advances_allocation INTEGER NOT NULL CHECK (advances_allocation IN (0, 1)),
    UNIQUE (account_id, purpose, derivation_version, key_index)
)
",
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
