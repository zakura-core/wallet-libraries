//! Adds the one-time use marker and moves existing one-time state to the rules that come
//! with it: payments before the birthday are ignored, accounts are never paused, and every
//! newly watched key gets a bootstrap lookup, so `pir_coverage` no longer chooses between
//! that and a filter re-check.
//!
//! It is deliberately conservative: no account that was being monitored stops. Only
//! development databases hold one-time data, since no released app used the feature.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::one_time_new_work;
use crate::wallet::init::WalletMigrationError;

/// Adds `ironwood_one_time_recovery.used`, and drops its `pir_coverage` and
/// `ironwood_one_time_keys.prebirthday_height`.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x755fb50a_f4e6_4b3e_80f0_8a21829607df);

const DEPENDENCIES: &[Uuid] = &[one_time_new_work::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    /// This migration's identifier.
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    /// Runs after the new-work counter exists.
    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    /// Describes the stored-state change for migration diagnostics.
    fn description(&self) -> &'static str {
        "Add the one-time use marker and drop the complete-check flag."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    /// Applies the steps in order, in the migration's transaction.
    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(
            "-- Payment candidates before their account's birthday are no longer handled, so
             -- they go without rejection repair, and a completed read they held settles.
             DELETE FROM ironwood_one_time_payment_recovery WHERE height < (
                 SELECT a.birthday_height FROM ironwood_one_time_keys k
                 JOIN accounts a ON a.id = k.account_id WHERE k.id = one_time_key_id);
             UPDATE ironwood_one_time_lookups SET target_height = NULL, reasons = 0
             WHERE read_complete = 1 AND done_height >= target_height
               AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery p
                   WHERE p.one_time_key_id = ironwood_one_time_lookups.one_time_key_id);
             -- A key marked paid only by a payment before the birthday would keep issuance
             -- skipping its index.
             UPDATE ironwood_one_time_keys SET used = 0, prebirthday_height = NULL
             WHERE prebirthday_height IS NOT NULL AND reserved_at IS NULL
               AND NOT EXISTS(SELECT 1 FROM ironwood_received_notes n
                   WHERE n.one_time_key_id = ironwood_one_time_keys.id)
               AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_operations o
                   WHERE o.one_time_key_id = ironwood_one_time_keys.id);
             -- Repair-only reads of a paused account may have skipped receipts, and the
             -- reset re-enabling used to run is gone with pausing.
             UPDATE ironwood_one_time_lookups SET inventory = NULL, shard = NULL,
                 segment = NULL, last_record = NULL, checked_height = NULL, read_complete = 0
             WHERE target_height IS NOT NULL AND (done_height IS NULL OR read_complete = 0)
               AND one_time_key_id IN (SELECT k.id FROM ironwood_one_time_keys k
                   JOIN ironwood_one_time_recovery r ON r.account_id = k.account_id
                   WHERE r.enabled = 0);",
        )?;
        // An account with a reservation or operation and no progress row, as published
        // schemas allowed, gets one whose receive window covers every receive index handed
        // out or paid, so those addresses stay monitored.
        let missing: Vec<(i64, Option<Vec<u8>>)> = conn
            .prepare(
                "SELECT a.id, (SELECT MAX(k.key_index) FROM ironwood_one_time_keys k
                     WHERE k.account_id = a.id AND k.purpose = 1 AND (k.reserved_at IS NOT NULL
                         OR k.used = 1 OR EXISTS(SELECT 1 FROM ironwood_one_time_operations o
                             WHERE o.one_time_key_id = k.id)))
                 FROM accounts a
                 WHERE NOT EXISTS(SELECT 1 FROM ironwood_one_time_recovery r
                     WHERE r.account_id = a.id)
                   AND EXISTS(SELECT 1 FROM ironwood_one_time_keys k WHERE k.account_id = a.id
                     AND (k.reserved_at IS NOT NULL OR EXISTS(SELECT 1
                         FROM ironwood_one_time_operations o WHERE o.one_time_key_id = k.id)))",
            )?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?;
        for (account, highest) in missing {
            let end = highest
                .map(|bytes| {
                    <[u8; 8]>::try_from(bytes)
                        .map(|b| u64::from_be_bytes(b).saturating_add(1))
                        .map_err(|_| WalletMigrationError::CorruptedData("key index".into()))
                })
                .transpose()?
                .unwrap_or(0);
            conn.execute(
                "INSERT INTO ironwood_one_time_recovery (account_id, receive_end) VALUES (?1, ?2)",
                rusqlite::params![account, end.to_be_bytes()],
            )?;
        }
        conn.execute_batch(
            "ALTER TABLE ironwood_one_time_recovery ADD COLUMN used INTEGER NOT NULL DEFAULT 0
                CHECK (used IN (0, 1));
             -- Every account that was monitored keeps being monitored: under always-on
             -- detection every enabled account, and any with evidence of use. A memo still
             -- queued marks its account at the next block batch.
             UPDATE ironwood_one_time_recovery SET used = 1 WHERE enabled = 1
                OR EXISTS(SELECT 1 FROM ironwood_one_time_keys k
                    WHERE k.account_id = ironwood_one_time_recovery.account_id
                      AND (k.reserved_at IS NOT NULL OR k.funding_height IS NOT NULL
                        OR EXISTS(SELECT 1 FROM ironwood_one_time_operations o
                            WHERE o.one_time_key_id = k.id)
                        OR EXISTS(SELECT 1 FROM ironwood_received_notes n
                            WHERE n.one_time_key_id = k.id)
                        OR EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery p
                            WHERE p.one_time_key_id = k.id)));
             -- The first round runs a complete check, which covers keys that waited on the
             -- deleted filter re-check.
             UPDATE ironwood_one_time_recovery SET filter_height = NULL, filter_hash = NULL;
             ALTER TABLE ironwood_one_time_recovery DROP COLUMN pir_coverage;
             ALTER TABLE ironwood_one_time_keys DROP COLUMN prebirthday_height;",
        )?;
        Ok(())
    }

    /// The dropped flag cannot be restored.
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

    use crate::{
        WalletDb,
        testing::db::{test_clock, test_rng},
        wallet::init::{WalletMigrator, migrations::tests::test_migrate},
    };

    use super::{DEPENDENCIES, MIGRATION_ID};

    #[test]
    fn migrate() {
        test_migrate(&[MIGRATION_ID]);
    }

    /// A wallet migrated through the previous schema, with an enabled account and the flag
    /// set, keeps that account monitored with its use marker set, owes a complete check by
    /// losing its filter frontier, and loses the flag. Reopening it twice changes nothing.
    #[test]
    fn upgrade_keeps_an_enabled_account_monitored_and_reopens() {
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
            .execute(
                "INSERT INTO ironwood_one_time_recovery
                     (account_id, enabled, filter_height, filter_hash, fresh, pir_coverage)
                 VALUES (1, 1, 500, zeroblob(32), 0, 1)",
                [],
            )
            .unwrap();

        for _ in 0..3 {
            migrator()
                .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
                .unwrap();
        }
        let recovery: (bool, Option<u32>, bool, bool) = db_data
            .conn
            .query_row(
                "SELECT enabled, filter_height, fresh, used FROM ironwood_one_time_recovery",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(recovery, (true, None, false, true));
        assert!(
            db_data
                .conn
                .prepare("SELECT pir_coverage FROM ironwood_one_time_recovery")
                .is_err()
        );
    }
}
