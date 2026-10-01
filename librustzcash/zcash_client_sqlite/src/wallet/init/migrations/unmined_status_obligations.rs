//! Queues a status observation for every unmined transaction that compact-block scanning cannot
//! re-observe.
//!
//! Earlier writers queued a status-observation intent only for a transaction stored while unmined.
//! A rewind, such as the one importing an account with an earlier birthday performs, un-mined
//! transactions without one, and a transaction without the wallet's shielded spends or outputs is
//! never marked mined again by rescanning. Such transactions were left unmined and eventually
//! reported as expired.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::transparent_utxo_absences;
use crate::wallet::init::WalletMigrationError;

/// Queues status observations for unmined transactions that rescanning cannot observe.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0xfa14da0b_94bb_417f_8bda_f9aac3d2a041);

const DEPENDENCIES: &[Uuid] = &[transparent_utxo_absences::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Queues status observations for unmined transactions that rescanning cannot observe."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // Status code 0 is `TxQueryType::Status`.
        conn.execute_batch(
            "INSERT INTO tx_retrieval_queue (txid, query_type, policy_generation)
             SELECT t.txid, 0, (SELECT policy_generation FROM tpir_meta WHERE id = 0)
             FROM transactions t
             WHERE t.mined_height IS NULL
             AND NOT EXISTS (SELECT 1 FROM sapling_received_notes n WHERE n.transaction_id = t.id_tx)
             AND NOT EXISTS (SELECT 1 FROM sapling_received_note_spends s WHERE s.transaction_id = t.id_tx)
             AND NOT EXISTS (SELECT 1 FROM orchard_received_notes n WHERE n.transaction_id = t.id_tx)
             AND NOT EXISTS (SELECT 1 FROM orchard_received_note_spends s WHERE s.transaction_id = t.id_tx)
             AND NOT EXISTS (SELECT 1 FROM ironwood_received_notes n WHERE n.transaction_id = t.id_tx)
             AND NOT EXISTS (SELECT 1 FROM ironwood_received_note_spends s WHERE s.transaction_id = t.id_tx)
             ON CONFLICT (txid, query_type) DO NOTHING;",
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
    fn unmined_transactions_without_shielded_involvement_get_a_status_observation() {
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
                 VALUES (1, X'01', 100, NULL), (2, X'02', 100, 120), (3, X'03', 100, NULL);
                 INSERT INTO tx_retrieval_queue (txid, query_type, policy_generation)
                 VALUES (X'03', 0, 0);",
            )
            .unwrap();

        WalletMigrator::new().init_or_migrate(&mut db).unwrap();
        let queued: Vec<Vec<u8>> = db
            .conn
            .prepare("SELECT txid FROM tx_retrieval_queue WHERE query_type = 0 ORDER BY txid")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(queued, vec![vec![1u8], vec![3u8]]);
    }
}
