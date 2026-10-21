//! One account cursor, one resumable receiver queue and uncredited payment candidates.
//! This replaces the unlaunched pass/watch schema without preserving development state.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::one_time_ivk;
use crate::wallet::init::WalletMigrationError;

/// Identifier for the one-time IVK discovery migration.
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
        "Adds the private receiver recovery queue and spend journal."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    /// Creates recovery progress and spend evidence independently of build features.
    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // Published libraries created these tables even when the feature was unused.
        // Drop abandoned progress, but keep note ownership and unrelated wallet data.
        let legacy: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('ironwood_one_time_keys') WHERE name = 'scan_from')",
            [], |r| r.get(0))?;
        if legacy {
            conn.execute_batch(
                "DROP TABLE IF EXISTS ironwood_one_time_lookup_reads;
                 DROP TABLE IF EXISTS ironwood_one_time_discovery;
                 DROP TABLE IF EXISTS ironwood_one_time_lookups;
                 DROP TABLE IF EXISTS ironwood_one_time_publications;
                 DROP TABLE IF EXISTS ironwood_one_time_payment_recovery;
                 DROP TABLE IF EXISTS ironwood_one_time_fresh_accounts;
                 DROP TABLE IF EXISTS ironwood_nullifier_scan_blocks;
                 DROP TABLE IF EXISTS ironwood_one_time_spend_retention;
                 DROP TABLE IF EXISTS ironwood_one_time_sweeps;
                 DROP INDEX IF EXISTS idx_ironwood_one_time_keys_scanning;",
            )?;
            let columns: Vec<String> = conn
                .prepare("PRAGMA table_info(ironwood_one_time_keys)")?
                .query_map([], |r| r.get(1))?
                .collect::<Result<_, _>>()?;
            for column in [
                "scan_from",
                "advances_allocation",
                "paid_before_birthday",
                "provider_seen",
                "active_from",
                "closed_at",
                "pass_watch_height",
            ] {
                if columns.iter().any(|name| name == column) {
                    conn.execute_batch(&format!(
                        "ALTER TABLE ironwood_one_time_keys DROP COLUMN {column}"
                    ))?;
                }
            }
            if !columns.iter().any(|name| name == "reservation_floor") {
                conn.execute_batch(
                    "ALTER TABLE ironwood_one_time_keys ADD COLUMN reservation_floor INTEGER",
                )?;
            }
            conn.execute_batch(
                "ALTER TABLE ironwood_one_time_keys ADD COLUMN funding_height INTEGER CHECK (funding_height BETWEEN 0 AND 4294967295);
                 ALTER TABLE ironwood_one_time_keys ADD COLUMN prebirthday_height INTEGER CHECK (prebirthday_height BETWEEN 0 AND 4294967295);"
            )?;
        }
        conn.execute_batch(
            "CREATE TABLE ironwood_one_time_recovery (
                account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
                enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
                generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
                history_revision BLOB NOT NULL DEFAULT X'0000000000000000'
                    CHECK (length(history_revision) = 8),
                filter_height INTEGER CHECK (filter_height BETWEEN 0 AND 4294967295),
                filter_hash BLOB CHECK (length(filter_hash) = 32),
                skipped_height INTEGER CHECK (skipped_height BETWEEN 0 AND 4294967295),
                restore_height INTEGER CHECK (restore_height BETWEEN 0 AND 4294967295),
                restore_next BLOB NOT NULL DEFAULT X'0000000000000000' CHECK (length(restore_next) = 8),
                restore_gap INTEGER NOT NULL DEFAULT 0 CHECK (restore_gap BETWEEN 0 AND 4),
                restore_done INTEGER NOT NULL DEFAULT 0 CHECK (restore_done IN (0, 1)),
                manual_active INTEGER NOT NULL DEFAULT 0 CHECK (manual_active IN (0, 1)),
                manual_purpose INTEGER NOT NULL DEFAULT 0 CHECK (manual_purpose IN (0, 1)),
                manual_next BLOB NOT NULL DEFAULT X'0000000000000000' CHECK (length(manual_next) = 8),
                manual_end BLOB CHECK (length(manual_end) = 8),
                manual_height INTEGER CHECK (manual_height BETWEEN 0 AND 4294967295),
                CHECK ((filter_height IS NULL) = (filter_hash IS NULL))
            );
            CREATE TABLE ironwood_one_time_lookups (
                one_time_key_id INTEGER PRIMARY KEY REFERENCES ironwood_one_time_keys(id) ON DELETE CASCADE,
                target_height INTEGER CHECK (target_height BETWEEN 0 AND 4294967295),
                reasons INTEGER NOT NULL DEFAULT 0 CHECK (reasons BETWEEN 0 AND 7),
                done_height INTEGER CHECK (done_height BETWEEN 0 AND 4294967295),
                last_record BLOB CHECK (length(last_record) = 289),
                read_complete INTEGER NOT NULL DEFAULT 0 CHECK (read_complete IN (0, 1)),
                attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
                next_attempt_at INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE ironwood_one_time_payment_recovery (
                one_time_key_id INTEGER NOT NULL REFERENCES ironwood_one_time_keys(id) ON DELETE CASCADE,
                txid BLOB NOT NULL CHECK (length(txid) = 32),
                action_index INTEGER NOT NULL CHECK (action_index BETWEEN 0 AND 4294967295),
                height INTEGER NOT NULL CHECK (height BETWEEN 0 AND 4294967295),
                block_hash BLOB NOT NULL CHECK (length(block_hash) = 32),
                tx_index INTEGER NOT NULL CHECK (tx_index BETWEEN 0 AND 65535),
                position INTEGER NOT NULL CHECK (position BETWEEN 0 AND 4294967295),
                encrypted_note BLOB NOT NULL CHECK (length(encrypted_note) = 148),
                payments BLOB CHECK (length(payments) = 32),
                witnesses BLOB CHECK (length(witnesses) = 32),
                ordinal INTEGER CHECK (ordinal BETWEEN 0 AND 4294967295),
                witness BLOB CHECK (length(witness) = 512),
                witness_height INTEGER CHECK (witness_height BETWEEN 0 AND 4294967295),
                witness_hash BLOB CHECK (length(witness_hash) = 32),
                witness_size INTEGER CHECK (witness_size BETWEEN 0 AND 4294967296),
                PRIMARY KEY (txid, action_index),
                CHECK ((payments IS NULL) = (ordinal IS NULL)
                    AND (payments IS NULL) = (witnesses IS NULL)),
                CHECK ((witness IS NULL OR payments IS NOT NULL)
                    AND (witness IS NULL) = (witness_height IS NULL)
                    AND (witness IS NULL) = (witness_hash IS NULL)
                    AND (witness IS NULL) = (witness_size IS NULL))
            );
            CREATE TABLE IF NOT EXISTS ironwood_spend_journal (
                block_height INTEGER NOT NULL CHECK (block_height BETWEEN 0 AND 4294967295),
                tx_index INTEGER NOT NULL CHECK (tx_index BETWEEN 0 AND 65535),
                txid BLOB NOT NULL CHECK (length(txid) = 32),
                PRIMARY KEY (block_height, tx_index)
            );
            CREATE TABLE IF NOT EXISTS ironwood_spend_journal_nullifiers (
                block_height INTEGER NOT NULL,
                tx_index INTEGER NOT NULL,
                action_index INTEGER NOT NULL CHECK (action_index >= 0),
                nf BLOB NOT NULL CHECK (length(nf) = 32),
                PRIMARY KEY (block_height, tx_index, action_index),
                FOREIGN KEY (block_height, tx_index)
                    REFERENCES ironwood_spend_journal(block_height, tx_index) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_ironwood_spend_journal_nullifiers_nf
                ON ironwood_spend_journal_nullifiers(nf);
            CREATE TABLE IF NOT EXISTS ironwood_journal_coverage (
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                start_height INTEGER NOT NULL CHECK (start_height BETWEEN 0 AND 4294967295),
                end_height INTEGER NOT NULL
                    CHECK (end_height > start_height AND end_height <= 4294967296),
                PRIMARY KEY (account_id, start_height)
            );",
        )?;
        Ok(())
    }

    /// Development recovery state has no backwards-compatible downgrade.
    fn down(&self, _: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    /// The rebaselined schema applies to a fresh wallet with intact account dependencies.
    #[test]
    fn migrate() {
        super::super::tests::test_migrate(&[super::MIGRATION_ID]);
    }
}
