//! Replaces one-time IVK restore sweeps and nullifier retention with discovery (see
//! `one_time_ivk::restore`), adds the spend journal (see `one_time_ivk::journal`), and
//! adds each incoming reservation's operation floor.
//!
//! Released wallets hold no restore sweeps or queued payments, since no wallet ran a
//! swap restore, so those tables are replaced, not converted. No account has discovery
//! state, and no block is covered by the journal. The retained nullifiers' coverage marks
//! and floors are dropped; `nullifier_map` keeps its rows until ordinary pruning. Existing
//! reservations get no operation floor, so every operation on their keys counts as theirs.
//! No key has a pass's recent watch, since no pass ran.
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
        "Replaces one-time IVK restore sweeps and retention with discovery and the spend journal, and adds reservation operation floors."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(
            "DROP TABLE ironwood_nullifier_scan_blocks;
            DROP TABLE ironwood_one_time_spend_retention;
            DROP TABLE ironwood_one_time_sweeps;
            CREATE TABLE ironwood_one_time_publications (
                height INTEGER NOT NULL CHECK (height BETWEEN 0 AND 4294967295),
                hash BLOB NOT NULL CHECK (length(hash) = 32),
                tree_size INTEGER NOT NULL CHECK (tree_size >= 0),
                state INTEGER NOT NULL DEFAULT 0 CHECK (state IN (0, 1, 2)),
                PRIMARY KEY (height, hash)
            );
            CREATE TABLE ironwood_one_time_lookups (
                one_time_key_id INTEGER PRIMARY KEY REFERENCES ironwood_one_time_keys(id) ON DELETE CASCADE,
                cutoff_height INTEGER CHECK (cutoff_height BETWEEN 0 AND 4294967295),
                done_height INTEGER CHECK (done_height BETWEEN 0 AND 4294967295),
                applied INTEGER NOT NULL DEFAULT 0 CHECK (applied BETWEEN 0 AND 4294967295),
                last_position INTEGER CHECK (last_position >= 0),
                last_nullifier BLOB CHECK (length(last_nullifier) = 32),
                last_height INTEGER CHECK (last_height BETWEEN 0 AND 4294967295),
                attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
                next_attempt_at INTEGER NOT NULL DEFAULT 0,
                CHECK ((applied = 0) = (last_position IS NULL)
                    AND (last_position IS NULL) = (last_nullifier IS NULL)
                    AND (last_position IS NULL) = (last_height IS NULL))
            );
            CREATE TABLE ironwood_one_time_lookup_reads (
                one_time_key_id INTEGER NOT NULL
                    REFERENCES ironwood_one_time_lookups(one_time_key_id) ON DELETE CASCADE,
                publication_height INTEGER NOT NULL,
                publication_hash BLOB NOT NULL,
                PRIMARY KEY (one_time_key_id, publication_height, publication_hash),
                FOREIGN KEY (publication_height, publication_hash)
                    REFERENCES ironwood_one_time_publications(height, hash)
            );
            DROP TABLE ironwood_one_time_payment_recovery;
            CREATE TABLE ironwood_one_time_payment_recovery (
                one_time_key_id INTEGER NOT NULL REFERENCES ironwood_one_time_keys(id) ON DELETE CASCADE,
                txid BLOB NOT NULL CHECK (length(txid) = 32),
                action_index INTEGER NOT NULL CHECK (action_index BETWEEN 0 AND 4294967295),
                height INTEGER NOT NULL CHECK (height BETWEEN 0 AND 4294967295),
                block_hash BLOB NOT NULL CHECK (length(block_hash) = 32),
                tx_index INTEGER NOT NULL CHECK (tx_index BETWEEN 0 AND 65535),
                position INTEGER NOT NULL CHECK (position BETWEEN 0 AND 4294967295),
                encrypted_note BLOB NOT NULL CHECK (length(encrypted_note) = 148),
                publication_height INTEGER NOT NULL
                    CHECK (publication_height BETWEEN 0 AND 4294967295),
                publication_hash BLOB NOT NULL CHECK (length(publication_hash) = 32),
                scan_hint INTEGER NOT NULL CHECK (scan_hint IN (0, 1)),
                witness BLOB CHECK (length(witness) = 1024),
                witness_height INTEGER CHECK (witness_height BETWEEN 0 AND 4294967295),
                witness_hash BLOB CHECK (length(witness_hash) = 32),
                PRIMARY KEY (txid, action_index),
                CHECK ((witness IS NULL) = (witness_height IS NULL)
                    AND (witness IS NULL) = (witness_hash IS NULL))
            );
            CREATE TABLE ironwood_one_time_discovery (
                account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
                publication_height INTEGER NOT NULL
                    CHECK (publication_height BETWEEN 0 AND 4294967295),
                publication_hash BLOB NOT NULL CHECK (length(publication_hash) = 32),
                receive_next INTEGER NOT NULL DEFAULT 0 CHECK (receive_next >= 0),
                receive_reach INTEGER NOT NULL DEFAULT 0 CHECK (receive_reach >= 0),
                refund_next INTEGER NOT NULL DEFAULT 0 CHECK (refund_next >= 0),
                refund_reach INTEGER NOT NULL DEFAULT 0 CHECK (refund_reach >= 0),
                receive_done INTEGER NOT NULL DEFAULT 0 CHECK (receive_done IN (0, 1)),
                refund_done INTEGER NOT NULL DEFAULT 0 CHECK (refund_done IN (0, 1)),
                FOREIGN KEY (publication_height, publication_hash)
                    REFERENCES ironwood_one_time_publications(height, hash)
            );
            CREATE TABLE ironwood_spend_journal (
                block_height INTEGER NOT NULL CHECK (block_height BETWEEN 0 AND 4294967295),
                tx_index INTEGER NOT NULL CHECK (tx_index BETWEEN 0 AND 65535),
                txid BLOB NOT NULL CHECK (length(txid) = 32),
                PRIMARY KEY (block_height, tx_index)
            );
            CREATE TABLE ironwood_spend_journal_nullifiers (
                block_height INTEGER NOT NULL,
                tx_index INTEGER NOT NULL,
                action_index INTEGER NOT NULL CHECK (action_index >= 0),
                nf BLOB NOT NULL CHECK (length(nf) = 32),
                PRIMARY KEY (block_height, tx_index, action_index),
                FOREIGN KEY (block_height, tx_index)
                    REFERENCES ironwood_spend_journal(block_height, tx_index) ON DELETE CASCADE
            );
            CREATE INDEX idx_ironwood_spend_journal_nullifiers_nf
                ON ironwood_spend_journal_nullifiers(nf);
            CREATE TABLE ironwood_journal_coverage (
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                start_height INTEGER NOT NULL CHECK (start_height BETWEEN 0 AND 4294967295),
                end_height INTEGER NOT NULL
                    CHECK (end_height > start_height AND end_height <= 4294967296),
                PRIMARY KEY (account_id, start_height)
            );
            ALTER TABLE ironwood_one_time_keys ADD COLUMN reservation_floor INTEGER;

            ALTER TABLE ironwood_one_time_keys ADD COLUMN pass_watch_height INTEGER
                CHECK (pass_watch_height BETWEEN 0 AND 4294967295);",
        )?;
        Ok(())
    }

    fn down(&self, _: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use secrecy::Secret;
    use tempfile::NamedTempFile;
    use zcash_keys::keys::UnifiedSpendingKey;
    use zcash_protocol::consensus::Network;

    use super::{DEPENDENCIES, MIGRATION_ID};
    use crate::{
        WalletDb,
        testing::db::{test_clock, test_rng},
        wallet::init::WalletMigrator,
    };

    #[test]
    fn migrate() {
        super::super::tests::test_migrate(&[MIGRATION_ID]);
    }

    /// One-time keys and operations an earlier release stored keep their rows, and their
    /// reservations get no floor, so every request on a key belongs to its reservation
    /// (see `one_time_ivk::swap::reservations`, whose tests cover the behavior). Here one
    /// reservation's request was begun before `reserved_at`, after the clock was set back.
    #[test]
    fn existing_reservations_get_no_floor() {
        let network = Network::TestNetwork;
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data =
            WalletDb::for_path(data_file.path(), network, test_clock(), test_rng()).unwrap();
        let migrator = || {
            WalletMigrator::new()
                .with_seed(Secret::new([0xab; 32].to_vec()))
                .ignore_seed_relevance()
        };
        migrator()
            .init_or_migrate_to(&mut db_data, DEPENDENCIES)
            .unwrap();
        let operations = "SELECT o.id, o.one_time_key_id, o.request, o.deadline, o.begun_at
             FROM ironwood_one_time_operations o ORDER BY o.id";
        let read = |conn: &rusqlite::Connection| -> Vec<(i64, i64, String, i64, i64)> {
            conn.prepare(operations)
                .unwrap()
                .query_map([], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                })
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        let ufvk = UnifiedSpendingKey::from_seed(&network, &[0xab; 32], zip32::AccountId::ZERO)
            .unwrap()
            .to_unified_full_viewing_key();
        db_data
            .conn
            .execute(
                "INSERT INTO accounts (id, uuid, account_kind, ufvk, uivk, birthday_height)
                 VALUES (1, zeroblob(16), 1, ?1, ?2, 1)",
                [
                    ufvk.encode(&network),
                    ufvk.to_unified_incoming_viewing_key().encode(&network),
                ],
            )
            .unwrap();
        db_data
            .conn
            .execute_batch(
                "INSERT INTO ironwood_one_time_keys
                     (id, account_id, purpose, key_index, receiver, scan_from,
                      advances_allocation, registered_at, reserved_at, active_from)
                 VALUES (1, 1, 1, X'0000000000000000', zeroblob(43), 0, 1, 100, 200, 0),
                     (2, 1, 1, X'0000000000000001', zeroblob(43), 0, 1, 100, 100, 0);
                 INSERT INTO ironwood_one_time_operations
                     (one_time_key_id, request, deadline, begun_at, observed_at)
                 VALUES (1, 'live', 400, 150, 150), (2, 'expired', 160, 100, 100);",
            )
            .unwrap();
        let before = read(&db_data.conn);

        migrator()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
            .unwrap();
        assert_eq!(read(&db_data.conn), before);
        let floors: Vec<(i64, Option<i64>, i64)> = db_data
            .conn
            .prepare(
                "SELECT id, reservation_floor, reserved_at FROM ironwood_one_time_keys ORDER BY id",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(floors, [(1, None, 200), (2, None, 100)]);
    }
}
