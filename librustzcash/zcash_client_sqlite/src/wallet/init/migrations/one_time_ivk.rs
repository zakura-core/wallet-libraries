//! Unlaunched one-time receiver registry, reservation ownership and provider operations.
//! Note foreign keys preserve spending ownership independently of recovery policy.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::ironwood_enhance;
use crate::wallet::init::WalletMigrationError;

/// Identifier for the one-time IVK migration.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x57756102_9583_4af5_b411_5eead49fc9f0);

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [ironwood_enhance::MIGRATION_ID].into_iter().collect()
    }

    fn description(&self) -> &'static str {
        "Adds one-time receiver keys, operations and reservations."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, tx: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // Schema is independent of build features. Reopening without Orchard support
        // must preserve reservations rather than permit address reuse.
        tx.execute_batch(
            "CREATE TABLE ironwood_one_time_keys (
                id INTEGER PRIMARY KEY,
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                purpose INTEGER NOT NULL CHECK (purpose BETWEEN 0 AND 255),
                key_index BLOB NOT NULL CHECK (typeof(key_index) = 'blob' AND length(key_index) = 8),
                receiver BLOB NOT NULL CHECK (typeof(receiver) = 'blob' AND length(receiver) = 43),
                funding_height INTEGER CHECK (funding_height BETWEEN 0 AND 4294967295),
                used INTEGER NOT NULL DEFAULT 0 CHECK (used IN (0, 1)),
                prebirthday_height INTEGER CHECK (prebirthday_height BETWEEN 0 AND 4294967295),
                registered_at INTEGER NOT NULL DEFAULT 0,
                reserved_at INTEGER,
                released_at INTEGER,
                reservation_floor INTEGER,
                UNIQUE (account_id, purpose, key_index)
            );
            CREATE INDEX idx_ironwood_one_time_keys_account_receiver
                ON ironwood_one_time_keys(account_id, receiver);
            ALTER TABLE ironwood_received_notes ADD COLUMN one_time_key_id INTEGER
                REFERENCES ironwood_one_time_keys(id);
            CREATE INDEX idx_ironwood_received_notes_one_time_key ON ironwood_received_notes (
                one_time_key_id ASC
            ) WHERE one_time_key_id IS NOT NULL;
            CREATE TABLE ironwood_one_time_operations (
                id INTEGER PRIMARY KEY,
                one_time_key_id INTEGER NOT NULL REFERENCES ironwood_one_time_keys(id) ON DELETE CASCADE,
                request TEXT UNIQUE,
                reference TEXT,
                memo TEXT,
                deadline INTEGER NOT NULL,
                begun_at INTEGER NOT NULL,
                started INTEGER NOT NULL DEFAULT 0 CHECK (started IN (0, 1)),
                funded INTEGER NOT NULL DEFAULT 0 CHECK (funded IN (0, 1)),
                rejected INTEGER NOT NULL DEFAULT 0 CHECK (rejected IN (0, 1)),
                observed_at INTEGER NOT NULL DEFAULT 0,
                expectation INTEGER NOT NULL DEFAULT 0 CHECK (expectation BETWEEN 0 AND 255),
                expected_value INTEGER CHECK (expected_value > 0),
                CHECK (request IS NOT NULL OR reference IS NOT NULL)
            );
            CREATE INDEX idx_ironwood_one_time_operations_key
                ON ironwood_one_time_operations(one_time_key_id);",
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
