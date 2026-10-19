//! Replaces one-time IVK restore sweeps and nullifier retention with continuous recovery
//! from a receiver directory (see `one_time_ivk::coverage` and `one_time_ivk::restore`),
//! adds the spend journal (see `one_time_ivk::journal`), and adds each incoming
//! reservation's operation floor.
//!
//! Released wallets hold no restore sweeps or queued payments, since no wallet ran a
//! swap restore, so those tables are replaced, not converted. No block is covered by the
//! journal. The retained nullifiers' coverage marks and floors are dropped;
//! `nullifier_map` keeps its rows until ordinary pruning. Existing reservations get no
//! operation floor, so every operation on their keys counts as theirs. Fresh accounts are
//! no longer marked: every account recovers alike, so the table is dropped.
//!
//! Recovery's state is each key's `authenticated` and `issuance_blocked` facts, each
//! account's receiver windows, directory coverage and seen check, historical obligations,
//! lookups and their target generations, and the publications lookups read from. A stored
//! key is authenticated if this wallet reserved it or it was paid, and blocked if
//! it was paid, seen, quoted and accepted, or is a refund key, which issuance never
//! reissued. No account has coverage yet.
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
        "Replaces one-time IVK restore sweeps and retention with continuous recovery and the spend journal, and adds reservation operation floors."
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
                generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
                dispatched_cutoff INTEGER CHECK (dispatched_cutoff BETWEEN 0 AND 4294967295),
                dispatched_generation INTEGER,
                CHECK ((applied = 0) = (last_position IS NULL)
                    AND (last_position IS NULL) = (last_nullifier IS NULL)
                    AND (last_position IS NULL) = (last_height IS NULL)),
                CHECK ((dispatched_cutoff IS NULL) = (dispatched_generation IS NULL))
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
            DROP TABLE ironwood_one_time_fresh_accounts;
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

            ALTER TABLE ironwood_one_time_keys ADD COLUMN authenticated INTEGER NOT NULL DEFAULT 0
                CHECK (authenticated IN (0, 1));
            ALTER TABLE ironwood_one_time_keys ADD COLUMN issuance_blocked INTEGER NOT NULL
                DEFAULT 0 CHECK (issuance_blocked IN (0, 1));
            UPDATE ironwood_one_time_keys SET
                authenticated = (reserved_at IS NOT NULL OR used = 1
                    OR (purpose = 0 AND advances_allocation = 1 AND provider_seen = 0)),
                issuance_blocked = (purpose = 0 OR used = 1 OR provider_seen = 1
                    OR EXISTS(SELECT 1 FROM ironwood_one_time_operations o
                        WHERE o.one_time_key_id = ironwood_one_time_keys.id
                          AND o.reference IS NOT NULL));
            CREATE TABLE ironwood_one_time_recovery (
                account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
                generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
                receive_end INTEGER NOT NULL DEFAULT 0 CHECK (receive_end >= 0),
                receive_derived INTEGER NOT NULL DEFAULT 0
                    CHECK (receive_derived BETWEEN 0 AND receive_end),
                refund_end INTEGER NOT NULL DEFAULT 0 CHECK (refund_end >= 0),
                refund_derived INTEGER NOT NULL DEFAULT 0
                    CHECK (refund_derived BETWEEN 0 AND refund_end),
                catalog BLOB CHECK (length(catalog) = 32),
                epoch INTEGER CHECK (epoch >= 0),
                frontier_height INTEGER CHECK (frontier_height BETWEEN 0 AND 4294967295),
                frontier_hash BLOB CHECK (length(frontier_hash) = 32),
                tested_generation INTEGER,
                bootstrap_height INTEGER CHECK (bootstrap_height BETWEEN 0 AND 4294967295),
                bootstrap_hash BLOB CHECK (length(bootstrap_hash) = 32),
                bootstrap_digest BLOB CHECK (length(bootstrap_digest) = 32),
                seen_checked_at INTEGER,
                seen_ready INTEGER NOT NULL DEFAULT 0 CHECK (seen_ready IN (0, 1)),
                CHECK ((catalog IS NULL) = (epoch IS NULL)),
                CHECK ((frontier_height IS NULL) = (frontier_hash IS NULL)
                    AND (frontier_height IS NULL) = (tested_generation IS NULL)
                    AND (frontier_height IS NULL OR catalog IS NOT NULL)),
                CHECK ((bootstrap_height IS NULL) = (bootstrap_hash IS NULL)
                    AND (bootstrap_height IS NULL) = (bootstrap_digest IS NULL))
            );
            CREATE TABLE ironwood_one_time_receiver_cache (
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                purpose INTEGER NOT NULL CHECK (purpose BETWEEN 0 AND 255),
                key_index BLOB NOT NULL CHECK (typeof(key_index) = 'blob' AND length(key_index) = 8),
                receiver BLOB NOT NULL CHECK (typeof(receiver) = 'blob' AND length(receiver) = 43),
                PRIMARY KEY (account_id, purpose, key_index)
            );
            CREATE TABLE ironwood_one_time_obligations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                purpose INTEGER NOT NULL CHECK (purpose BETWEEN 0 AND 255),
                one_time_key_id INTEGER REFERENCES ironwood_one_time_keys(id) ON DELETE CASCADE,
                range_start INTEGER CHECK (range_start >= 0),
                range_end INTEGER CHECK (range_end > range_start),
                lower_height INTEGER NOT NULL CHECK (lower_height BETWEEN 0 AND 4294967295),
                through_height INTEGER NOT NULL CHECK (through_height BETWEEN 0 AND 4294967295),
                cutoff_height INTEGER CHECK (cutoff_height BETWEEN 0 AND 4294967295),
                cutoff_hash BLOB CHECK (length(cutoff_hash) = 32),
                cutoff_digest BLOB CHECK (length(cutoff_digest) = 32),
                bridged_height INTEGER CHECK (bridged_height BETWEEN 0 AND 4294967295),
                CHECK ((one_time_key_id IS NULL) = (range_start IS NOT NULL)
                    AND (range_start IS NULL) = (range_end IS NULL)),
                CHECK ((cutoff_height IS NULL) = (cutoff_hash IS NULL)
                    AND (cutoff_height IS NULL) = (cutoff_digest IS NULL)
                    AND (bridged_height IS NULL OR cutoff_height IS NOT NULL))
            );
            CREATE INDEX idx_ironwood_one_time_obligations_account
                ON ironwood_one_time_obligations(account_id);",
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
    ///
    /// Each key gets the facts its row shows: one this wallet reserved or that was paid is
    /// authenticated, and every refund key, and an incoming key seen, paid or quoted and
    /// accepted, is blocked from issuance.
    #[test]
    fn existing_reservations_get_no_floor_and_their_facts() {
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
                 INSERT INTO ironwood_one_time_keys
                     (id, account_id, purpose, key_index, receiver, scan_from,
                      advances_allocation, provider_seen, used)
                 VALUES (3, 1, 0, X'0000000000000000', zeroblob(43), 0, 1, 0, 0),
                     (4, 1, 0, X'0000000000000001', zeroblob(43), 0, 1, 1, 0),
                     (5, 1, 1, X'0000000000000002', zeroblob(43), 0, 1, 0, 0),
                     (6, 1, 1, X'0000000000000003', zeroblob(43), 0, 0, 0, 0),
                     (7, 1, 1, X'0000000000000004', zeroblob(43), 0, 1, 0, 1),
                     (8, 1, 1, X'0000000000000005', zeroblob(43), 0, 1, 1, 0);
                 INSERT INTO ironwood_one_time_operations
                     (one_time_key_id, request, deadline, begun_at, observed_at)
                 VALUES (1, 'live', 400, 150, 150), (2, 'expired', 160, 100, 100);
                 INSERT INTO ironwood_one_time_operations
                     (one_time_key_id, request, reference, deadline, begun_at)
                 VALUES (5, 'accepted', 'deposit', 400, 100);",
            )
            .unwrap();
        let before = read(&db_data.conn);

        migrator()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
            .unwrap();
        assert_eq!(read(&db_data.conn), before);
        /// A key's ID, floor, reservation time and whether it is authenticated and blocked.
        type Key = (i64, Option<i64>, Option<i64>, bool, bool);
        let keys: Vec<Key> = db_data
            .conn
            .prepare(
                "SELECT id, reservation_floor, reserved_at, authenticated, issuance_blocked
                 FROM ironwood_one_time_keys ORDER BY id",
            )
            .unwrap()
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            keys,
            [
                (1, None, Some(200), true, false),
                (2, None, Some(100), true, false),
                (3, None, None, true, true),
                (4, None, None, false, true),
                (5, None, None, false, true),
                (6, None, None, false, false),
                (7, None, None, true, true),
                (8, None, None, false, true),
            ]
        );
    }
}
