//! Gives status obligations that re-confirm a previously mined transaction their own durable
//! provenance, exempting them from expiry dormancy until one status observation completes.
//!
//! A rewind un-mines transactions that compact-block rescanning cannot re-observe. Expiry dormancy
//! assumes a scanned height past a transaction's expiry shows it was never mined, which does not
//! hold for such a transaction: a deep rewind followed by one rescan pass could make its
//! obligation dormant before it was ever served.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::unmined_status_obligations;
use crate::wallet::init::WalletMigrationError;

/// Adds `tx_retrieval_queue.reconfirm_mined`.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0xfeeaf359_3c5b_40d7_850b_309b1a7cd3a6);

const DEPENDENCIES: &[Uuid] = &[unmined_status_obligations::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds tx_retrieval_queue.reconfirm_mined for status obligations of rewound transactions."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // The backfill of `unmined_status_obligations` cannot tell a transaction a rewind un-mined
        // from one stored unmined, so every unmined transaction rescanning cannot observe is
        // re-confirmed once. Status code 0 is `TxQueryType::Status`.
        conn.execute_batch(
            "ALTER TABLE tx_retrieval_queue ADD COLUMN reconfirm_mined INTEGER NOT NULL DEFAULT 0;
             UPDATE tx_retrieval_queue SET reconfirm_mined = 1
             WHERE query_type = 0
             AND txid IN (
                 SELECT t.txid FROM transactions t
                 WHERE t.mined_height IS NULL
                 AND NOT EXISTS (SELECT 1 FROM sapling_received_notes n WHERE n.transaction_id = t.id_tx)
                 AND NOT EXISTS (SELECT 1 FROM sapling_received_note_spends s WHERE s.transaction_id = t.id_tx)
                 AND NOT EXISTS (SELECT 1 FROM orchard_received_notes n WHERE n.transaction_id = t.id_tx)
                 AND NOT EXISTS (SELECT 1 FROM orchard_received_note_spends s WHERE s.transaction_id = t.id_tx)
                 AND NOT EXISTS (SELECT 1 FROM ironwood_received_notes n WHERE n.transaction_id = t.id_tx)
                 AND NOT EXISTS (SELECT 1 FROM ironwood_received_note_spends s WHERE s.transaction_id = t.id_tx)
             );",
        )?;
        Ok(())
    }

    fn down(&self, _conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use super::{DEPENDENCIES, MIGRATION_ID};
    use crate::{
        WalletDb,
        testing::db::{test_clock, test_rng},
        wallet::init::{WalletMigrator, migrations::tests::test_migrate},
    };
    use zcash_protocol::consensus::Network;

    #[test]
    fn migrate() {
        test_migrate(&[MIGRATION_ID]);
    }

    #[test]
    fn backfilled_obligations_reconfirm_and_others_keep_ordinary_rules() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut db =
            WalletDb::for_path(file.path(), Network::TestNetwork, test_clock(), test_rng())
                .unwrap();
        WalletMigrator::new()
            .init_or_migrate_to(&mut db, DEPENDENCIES)
            .unwrap();
        db.conn
            .execute_batch(
                "INSERT INTO transactions (id_tx, txid, min_observed_height, mined_height)
                 VALUES (1, X'01', 100, NULL), (2, X'02', 100, 120);
                 INSERT INTO tx_retrieval_queue (txid, query_type, policy_generation)
                 VALUES (X'01', 0, 0), (X'02', 0, 0), (X'01', 1, 0);",
            )
            .unwrap();

        WalletMigrator::new().init_or_migrate(&mut db).unwrap();
        let rows: Vec<(Vec<u8>, i64, i64)> = db
            .conn
            .prepare(
                "SELECT txid, query_type, reconfirm_mined FROM tx_retrieval_queue
                 ORDER BY txid, query_type",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![(vec![1u8], 0, 1), (vec![1u8], 1, 0), (vec![2u8], 0, 0)]
        );
    }
}
