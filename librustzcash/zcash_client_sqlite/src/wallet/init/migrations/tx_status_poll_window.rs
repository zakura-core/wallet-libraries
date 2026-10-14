//! Fixes the private status polls of each transaction when its status work is queued: a window
//! of chain tips and an optional poll at its expiry height, so that the replies cannot steer
//! when polling stops.
//!
//! Additive. Status work for a transaction not known to be mined gets a window starting at the
//! tip the migration runs at, so an upgrade never strands it; without a known tip it gets one at
//! its first recorded poll.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::transparent_detail_content_failures;
use crate::wallet::init::WalletMigrationError;

/// Adds `tx_status_polls`.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x5f0b6c1e_8d2a_4f7e_9c3b_2a71d4e8b905);

const DEPENDENCIES: &[Uuid] = &[transparent_detail_content_failures::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Fixes the private status poll window of each queued transaction."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(
            "CREATE TABLE tx_status_polls (
                txid BLOB NOT NULL PRIMARY KEY,
                window_start_height INTEGER NOT NULL CHECK (window_start_height >= 0),
                window_end_height INTEGER NOT NULL,
                expiry_poll_height INTEGER,
                last_polled_height INTEGER,
                CHECK (window_end_height > window_start_height),
                CHECK (expiry_poll_height IS NULL OR expiry_poll_height >= window_end_height)
            );
            INSERT INTO tx_status_polls
                (txid, window_start_height, window_end_height, expiry_poll_height)
            SELECT q.txid, tip.h, tip.h + 10,
                   CASE WHEN t.expiry_height > 0 AND t.expiry_height >= tip.h + 10
                        THEN t.expiry_height END
            FROM tx_retrieval_queue q
            JOIN (SELECT MAX(MAX(block_range_end) - 1, 0) AS h FROM scan_queue) tip
            LEFT JOIN transactions t ON t.txid = q.txid
            WHERE q.query_type = 0 AND tip.h IS NOT NULL AND t.mined_height IS NULL;",
        )?;
        Ok(())
    }

    fn down(&self, _conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use secrecy::Secret;
    use tempfile::NamedTempFile;
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

    /// Pending status work queued before the migration gains a window starting at the tip the
    /// migration runs at, so an upgrade never strands it. Mined transactions gain none.
    #[test]
    fn pending_work_gains_a_window_at_the_migration_tip() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(
            data_file.path(),
            Network::TestNetwork,
            test_clock(),
            test_rng(),
        )
        .unwrap();
        let migrator = || {
            WalletMigrator::new()
                .with_seed(Secret::new([0xab; 32].to_vec()))
                .ignore_seed_relevance()
        };
        migrator()
            .init_or_migrate_to(&mut db_data, DEPENDENCIES)
            .unwrap();
        // Tip 100; status work for a pending transaction expiring past the window, one
        // expiring inside it, one without expiry, a mined one, and a txid with no row.
        db_data
            .conn
            .execute_batch(
                "INSERT INTO scan_queue (block_range_start, block_range_end, priority)
                 VALUES (90, 101, 10);
                 INSERT INTO transactions (id_tx, txid, expiry_height, min_observed_height)
                 VALUES (1, X'01', 150, 0), (2, X'02', 105, 0), (3, X'03', 0, 0);
                 INSERT INTO transactions (id_tx, txid, mined_height, min_observed_height)
                 VALUES (4, X'04', 95, 0);
                 INSERT INTO tx_retrieval_queue (txid, query_type)
                 VALUES (X'01', 0), (X'02', 0), (X'03', 0), (X'04', 0), (X'05', 0), (X'01', 1);",
            )
            .unwrap();

        migrator()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
            .unwrap();
        let rows = db_data
            .conn
            .prepare(
                "SELECT txid, window_start_height, window_end_height, expiry_poll_height,
                        last_polled_height
                 FROM tx_status_polls ORDER BY txid",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, u32>(2)?,
                    row.get::<_, Option<u32>>(3)?,
                    row.get::<_, Option<u32>>(4)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![
                (vec![1], 100, 110, Some(150), None),
                (vec![2], 100, 110, None, None),
                (vec![3], 100, 110, None, None),
                (vec![5], 100, 110, None, None),
            ]
        );
    }
}
