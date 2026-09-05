//! Adds durable outgoing discovery and repairs prematurely retired private sends.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::{ironwood_enhance, tx_status_observation_intent};

pub const MIGRATION_ID: Uuid = Uuid::from_u128(0xa7de8f13_282e_46cb_b90d_5d55ec82439e);

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        HashSet::from([
            ironwood_enhance::MIGRATION_ID,
            tx_status_observation_intent::MIGRATION_ID,
        ])
    }

    fn description(&self) -> &'static str {
        "Preserve Ironwood enhancement across retroactive spend discovery."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, tx: &rusqlite::Transaction) -> Result<(), Self::Error> {
        tx.execute_batch(
            "CREATE TABLE ironwood_enhance_discovery_queue (
                transaction_id INTEGER PRIMARY KEY
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                suspended INTEGER NOT NULL DEFAULT 0 CHECK (suspended IN (0, 1))
            );
            INSERT INTO ironwood_enhance_discovery_queue (transaction_id)
            SELECT t.id_tx FROM transactions t
            JOIN ironwood_enhance_routing r ON r.transaction_id = t.id_tx
            WHERE r.route = 0 AND t.raw IS NULL AND t.mined_height IS NOT NULL
              AND EXISTS (
                  SELECT 1 FROM ironwood_received_note_spends s
                  JOIN ironwood_received_notes rn ON rn.id = s.ironwood_received_note_id
                  WHERE s.transaction_id = t.id_tx AND rn.nf IS NOT NULL
              );
            INSERT INTO tx_retrieval_queue (txid, query_type)
            SELECT t.txid, 1 FROM transactions t
            JOIN ironwood_enhance_discovery_queue q ON q.transaction_id = t.id_tx
            WHERE TRUE
            ON CONFLICT(txid, query_type) DO NOTHING;",
        )?;
        // Recheck every previously protected, wallet-funded send: the old queues cannot
        // distinguish complete recovery from work lost by a rescan. Reconstruction skips
        // already recovered outputs. Ordinary history and sticky LWD routes stay unchanged.
        Ok(())
    }

    fn down(&self, _: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;
    use schemerz_rusqlite::RusqliteMigration;

    #[test]
    fn migrate() {
        crate::wallet::init::migrations::tests::test_migrate(&[super::MIGRATION_ID]);
    }

    #[test]
    fn restores_only_private_mined_funded_sends_without_full_data() {
        let mut conn = Connection::open_in_memory().unwrap();
        let tx = conn.transaction().unwrap();
        tx.execute_batch(
            "CREATE TABLE transactions (id_tx INTEGER PRIMARY KEY, txid BLOB UNIQUE,
                raw BLOB, mined_height INTEGER);
             CREATE TABLE ironwood_enhance_routing (transaction_id INTEGER, route INTEGER);
             CREATE TABLE ironwood_received_notes (id INTEGER PRIMARY KEY, nf BLOB);
             CREATE TABLE ironwood_received_note_spends (
                ironwood_received_note_id INTEGER, transaction_id INTEGER);
             CREATE TABLE tx_retrieval_queue (txid BLOB, query_type INTEGER,
                UNIQUE(txid, query_type));
             INSERT INTO transactions VALUES
                (1, X'01', NULL, 100), (2, X'02', NULL, 100),
                (3, X'03', NULL, 100), (4, X'04', X'AA', 100),
                (5, X'05', NULL, NULL), (6, X'06', NULL, 100),
                (7, X'07', NULL, 100);
             INSERT INTO ironwood_enhance_routing VALUES
                (1, 0), (2, 1), (4, 0), (5, 0), (6, 0), (7, 0);
             INSERT INTO ironwood_received_notes VALUES (1, X'AA');
             INSERT INTO ironwood_received_note_spends VALUES
                (1, 1), (1, 2), (1, 3), (1, 4), (1, 5), (1, 7);
             INSERT INTO tx_retrieval_queue VALUES (X'01', 0), (X'07', 1);",
        )
        .unwrap();
        super::Migration.up(&tx).unwrap();
        let jobs: Vec<i64> = tx
            .prepare("SELECT transaction_id FROM ironwood_enhance_discovery_queue ORDER BY 1")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(jobs, vec![1, 7]);
        let requests: Vec<(Vec<u8>, i64)> = tx
            .prepare("SELECT txid, query_type FROM tx_retrieval_queue ORDER BY 1, 2")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(requests, vec![(vec![1], 0), (vec![1], 1), (vec![7], 1)]);
    }
}
