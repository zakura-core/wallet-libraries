//! Adds independent schema-v7 metadata work, including completed schema-v6 history.
use super::ironwood_enhance_discovery;
use crate::wallet::init::WalletMigrationError;
use schemerz_rusqlite::RusqliteMigration;
use std::collections::HashSet;
use uuid::Uuid;
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x8dedb150_10ed_42d7_a766_40626cf29a18);
pub(super) struct Migration;
impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }
    fn dependencies(&self) -> HashSet<Uuid> {
        HashSet::from([ironwood_enhance_discovery::MIGRATION_ID])
    }
    fn description(&self) -> &'static str {
        "Recover Ironwood transaction fee and expiry through PIR."
    }
}
impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;
    fn up(&self, tx: &rusqlite::Transaction) -> Result<(), Self::Error> {
        tx.execute_batch("CREATE TABLE ironwood_enhance_metadata_queue (
            transaction_id INTEGER PRIMARY KEY REFERENCES transactions(id_tx) ON DELETE CASCADE,
            commitment_tree_position INTEGER UNIQUE,
            output_index INTEGER,
            ephemeral_key BLOB,
            compact_ciphertext BLOB,
            CHECK ((commitment_tree_position IS NULL) = (output_index IS NULL)),
            CHECK (ephemeral_key IS NULL OR length(ephemeral_key) = 32),
            CHECK (compact_ciphertext IS NULL OR length(compact_ciphertext) = 52)
        );
        INSERT INTO ironwood_enhance_metadata_queue (transaction_id)
        SELECT t.id_tx FROM transactions t JOIN ironwood_enhance_routing r ON r.transaction_id = t.id_tx
        WHERE r.route = 0 AND t.raw IS NULL AND t.mined_height IS NOT NULL
          AND (t.fee IS NULL OR t.expiry_height IS NULL);
        UPDATE ironwood_enhance_metadata_queue AS q SET
            commitment_tree_position = (SELECT commitment_tree_position FROM ironwood_received_notes
                WHERE transaction_id = q.transaction_id AND note_version = 3 AND commitment_tree_position IS NOT NULL
                ORDER BY action_index LIMIT 1),
            output_index = (SELECT action_index FROM ironwood_received_notes
                WHERE transaction_id = q.transaction_id AND note_version = 3 AND commitment_tree_position IS NOT NULL
                ORDER BY action_index LIMIT 1);
        INSERT INTO tx_retrieval_queue (txid, query_type)
        SELECT t.txid, 1 FROM transactions t JOIN ironwood_enhance_metadata_queue q ON q.transaction_id = t.id_tx
        WHERE TRUE ON CONFLICT(txid, query_type) DO NOTHING;")?;
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
        crate::wallet::init::migrations::tests::test_migrate(&[super::MIGRATION_ID]);
    }
    #[test]
    fn backfills_only_protected_mined_missing_metadata_and_preserves_zeroes() {
        use schemerz_rusqlite::RusqliteMigration;
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        let tx = conn.transaction().unwrap();
        tx.execute_batch("CREATE TABLE transactions (id_tx INTEGER PRIMARY KEY, txid BLOB, raw BLOB, mined_height INTEGER, fee INTEGER, expiry_height INTEGER);
            CREATE TABLE ironwood_enhance_routing (transaction_id INTEGER, route INTEGER);
            CREATE TABLE ironwood_received_notes (transaction_id INTEGER, action_index INTEGER, note_version INTEGER, commitment_tree_position INTEGER);
            CREATE TABLE tx_retrieval_queue (txid BLOB, query_type INTEGER, UNIQUE(txid, query_type));
            INSERT INTO transactions VALUES
                (1,X'01',NULL,100,NULL,NULL), (2,X'02',NULL,100,0,0), (3,X'03',NULL,100,NULL,NULL),
                (4,X'04',X'AA',100,NULL,NULL), (5,X'05',NULL,NULL,NULL,NULL), (6,X'06',NULL,100,1,NULL);
            INSERT INTO ironwood_enhance_routing VALUES (1,0),(2,0),(3,1),(4,0),(5,0),(6,0);
            INSERT INTO ironwood_received_notes VALUES (1,1,3,10), (1,0,3,9);") .unwrap();
        super::Migration.up(&tx).unwrap();
        let jobs: Vec<(i64,Option<u64>)> = tx.prepare("SELECT transaction_id, commitment_tree_position FROM ironwood_enhance_metadata_queue ORDER BY transaction_id").unwrap()
            .query_map([], |r| Ok((r.get(0)?,r.get(1)?))).unwrap().collect::<Result<_,_>>().unwrap();
        assert_eq!(jobs, vec![(1, Some(9)), (6, None)]);
        let count: u64 = tx
            .query_row("SELECT COUNT(*) FROM tx_retrieval_queue", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }
}
