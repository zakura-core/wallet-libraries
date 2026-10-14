//! One-time IVKs: the key registry with its incoming reservations, provider operations,
//! restore sweeps, and their spend evidence.
//!
//! A note's `one_time_key_id` doesn't cascade: notes are funds, so a key can't be deleted
//! while it has notes. Deleting the account removes both.
//!
//! The `purpose` and `expectation` codes are stable, and their CHECKs only bound them to a
//! byte, leaving each set to code. A new code needs a migration that older builds refuse.
//!
//! A sweep's `content_failures` counts lookups whose answer failed on content, apart from
//! `attempts`, which also counts transport failures. Nothing writes it yet. It lets the
//! sweep cap content failures as the other PIR clients do (#186) without a new migration.

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
        "Adds one-time IVKs, their operations, reservations and restore sweeps."
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
                scan_from INTEGER NOT NULL CHECK (scan_from BETWEEN 0 AND 4294967295),
                advances_allocation INTEGER NOT NULL CHECK (advances_allocation IN (0, 1)),
                used INTEGER NOT NULL DEFAULT 0 CHECK (used IN (0, 1)),
                paid_before_birthday INTEGER NOT NULL DEFAULT 0
                    CHECK (paid_before_birthday IN (0, 1)),
                provider_seen INTEGER NOT NULL DEFAULT 0 CHECK (provider_seen IN (0, 1)),
                registered_at INTEGER NOT NULL DEFAULT 0,
                reserved_at INTEGER,
                released_at INTEGER,
                active_from INTEGER CHECK (active_from BETWEEN 0 AND 4294967295),
                closed_at INTEGER,
                UNIQUE (account_id, purpose, key_index)
            );
            CREATE INDEX idx_ironwood_one_time_keys_account_receiver
                ON ironwood_one_time_keys(account_id, receiver);
            CREATE INDEX idx_ironwood_one_time_keys_scanning
                ON ironwood_one_time_keys(closed_at, active_from);
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
                ON ironwood_one_time_operations(one_time_key_id);
            CREATE TABLE ironwood_one_time_sweeps (
                one_time_key_id INTEGER PRIMARY KEY REFERENCES ironwood_one_time_keys(id) ON DELETE CASCADE,
                lookup_height INTEGER CHECK (lookup_height BETWEEN 0 AND 4294967295),
                lookup_hash BLOB CHECK (length(lookup_hash) = 32),
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at INTEGER NOT NULL DEFAULT 0,
                done_height INTEGER CHECK (done_height BETWEEN 0 AND 4294967295),
                content_failures INTEGER NOT NULL DEFAULT 0 CHECK (content_failures >= 0)
            );
            CREATE INDEX idx_ironwood_one_time_sweeps_due ON ironwood_one_time_sweeps(done_height, next_attempt_at);
            CREATE TABLE ironwood_one_time_payment_recovery (
                one_time_key_id INTEGER NOT NULL REFERENCES ironwood_one_time_keys(id) ON DELETE CASCADE,
                txid BLOB NOT NULL CHECK (length(txid) = 32),
                action_index INTEGER NOT NULL CHECK (action_index BETWEEN 0 AND 4294967295),
                height INTEGER NOT NULL CHECK (height BETWEEN 0 AND 4294967295),
                block_hash BLOB NOT NULL CHECK (length(block_hash) = 32),
                tx_index INTEGER NOT NULL CHECK (tx_index BETWEEN 0 AND 65535),
                position INTEGER NOT NULL CHECK (position BETWEEN 0 AND 4294967295),
                encrypted_note BLOB NOT NULL CHECK (length(encrypted_note) = 148),
                PRIMARY KEY (txid, action_index)
            );
            CREATE TABLE ironwood_nullifier_scan_blocks (
                height INTEGER PRIMARY KEY CHECK (height BETWEEN 0 AND 4294967295)
            );
            CREATE TABLE ironwood_one_time_fresh_accounts (
                account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE
            );
            CREATE TABLE ironwood_one_time_spend_retention (
                account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
                nullifier_retention_height INTEGER NOT NULL DEFAULT 0
                    CHECK (nullifier_retention_height BETWEEN 0 AND 4294967295),
                replay_through INTEGER CHECK (replay_through BETWEEN 0 AND 4294967295)
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
