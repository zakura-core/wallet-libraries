//! Adds the position-keyed retrieval queue for unresolved Ironwood memos.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::ironwood_received_notes;

/// Adds and backfills the Ironwood memo retrieval queue.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0xe0b4dec3_51b1_4245_bc46_643dfb8b0219);

const DEPENDENCIES: &[Uuid] = &[ironwood_received_notes::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds the position-keyed Ironwood memo retrieval queue."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "CREATE TABLE ironwood_memo_retrieval_queue (
                received_note_id INTEGER PRIMARY KEY
                    REFERENCES ironwood_received_notes(id) ON DELETE CASCADE,
                commitment_tree_position INTEGER NOT NULL UNIQUE
                    CHECK (commitment_tree_position >= 0)
            );
            INSERT INTO ironwood_memo_retrieval_queue (
                received_note_id, commitment_tree_position
            )
            SELECT id, commitment_tree_position
            FROM ironwood_received_notes
            WHERE memo IS NULL AND commitment_tree_position IS NOT NULL;",
        )?;
        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;
    use schemerz_rusqlite::RusqliteMigration;

    use crate::wallet::init::migrations::tests::test_migrate;

    #[test]
    fn migrate() {
        test_migrate(&[super::MIGRATION_ID]);
    }

    #[test]
    fn backfills_only_positioned_notes_without_memos() {
        let mut conn = Connection::open_in_memory().unwrap();
        let tx = conn.transaction().unwrap();
        tx.execute_batch(
            "CREATE TABLE ironwood_received_notes (
                 id INTEGER PRIMARY KEY,
                 memo BLOB,
                 commitment_tree_position INTEGER
             );
             INSERT INTO ironwood_received_notes VALUES (1, NULL, 9);
             INSERT INTO ironwood_received_notes VALUES (2, X'F6', 10);
             INSERT INTO ironwood_received_notes VALUES (3, NULL, NULL);",
        )
        .unwrap();
        RusqliteMigration::up(&super::Migration, &tx).unwrap();

        let queued: Vec<(i64, i64)> = tx
            .prepare(
                "SELECT received_note_id, commitment_tree_position
                 FROM ironwood_memo_retrieval_queue",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(queued, vec![(1, 9)]);
    }
}
