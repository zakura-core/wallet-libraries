//! Preserve which derived receiving key owns each Ironwood note.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::swap_receiving_keys;
use crate::wallet::init::WalletMigrationError;

/// Identifier for the swap note key-reference migration.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x6875b2c8_105c_4c40_94ac_ee0dd6f48196);

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [swap_receiving_keys::MIGRATION_ID].into_iter().collect()
    }

    fn description(&self) -> &'static str {
        "Associates Ironwood notes with their swap receiving keys."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "ALTER TABLE ironwood_received_notes ADD COLUMN receiving_key_id INTEGER
                REFERENCES ironwood_receiving_keys(id)",
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
