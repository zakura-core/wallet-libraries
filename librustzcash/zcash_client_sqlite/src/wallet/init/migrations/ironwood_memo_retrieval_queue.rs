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

    /// Creates the queue and backfills it from the notes that are already scanned.
    ///
    /// The backfill is restricted to mined V3 notes, and groups by position, because neither
    /// property is guaranteed by `ironwood_received_notes`. A reorg un-mines a transaction
    /// without deleting its notes or clearing their commitment tree positions, so an existing
    /// wallet can already hold two notes claiming one position; without the grouping, the
    /// `UNIQUE` constraint would abort this migration and leave the wallet unopenable. Notes
    /// whose plaintext is not V3 can never be completed by memo PIR, so queuing them would
    /// create entries that are retried forever.
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
            SELECT MAX(rn.id), rn.commitment_tree_position
            FROM ironwood_received_notes rn
            JOIN transactions t ON t.id_tx = rn.transaction_id
            WHERE rn.memo IS NULL
              AND rn.commitment_tree_position IS NOT NULL
              AND rn.note_version = 3
              AND t.mined_height IS NOT NULL
            GROUP BY rn.commitment_tree_position;",
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

    /// Builds the subset of the pre-migration schema the backfill reads. `transaction_id` 1 is
    /// mined and 2 is not, so a note's minedness is chosen by which transaction it points at.
    fn pre_migration_schema(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE transactions (id_tx INTEGER PRIMARY KEY, mined_height INTEGER);
             INSERT INTO transactions VALUES (1, 100);
             INSERT INTO transactions VALUES (2, NULL);
             CREATE TABLE ironwood_received_notes (
                 id INTEGER PRIMARY KEY,
                 transaction_id INTEGER NOT NULL,
                 memo BLOB,
                 commitment_tree_position INTEGER,
                 note_version INTEGER NOT NULL
             );",
        )
        .unwrap();
    }

    fn queued(conn: &Connection) -> Vec<(i64, i64)> {
        conn.prepare(
            "SELECT received_note_id, commitment_tree_position
             FROM ironwood_memo_retrieval_queue
             ORDER BY commitment_tree_position",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    }

    #[test]
    fn backfills_only_completable_notes() {
        let mut conn = Connection::open_in_memory().unwrap();
        let tx = conn.transaction().unwrap();
        pre_migration_schema(&tx);
        tx.execute_batch(
            "-- Queued: mined, positioned, no memo, V3.
             INSERT INTO ironwood_received_notes VALUES (1, 1, NULL, 9, 3);
             -- Skipped: the memo is already known.
             INSERT INTO ironwood_received_notes VALUES (2, 1, X'F6', 10, 3);
             -- Skipped: no position, so there is nothing to query by.
             INSERT INTO ironwood_received_notes VALUES (3, 1, NULL, NULL, 3);
             -- Skipped: memo PIR can never complete a non-V3 note.
             INSERT INTO ironwood_received_notes VALUES (4, 1, NULL, 11, 2);
             -- Skipped: the transaction is not mined, so the position is not authoritative.
             INSERT INTO ironwood_received_notes VALUES (5, 2, NULL, 12, 3);",
        )
        .unwrap();
        RusqliteMigration::up(&super::Migration, &tx).unwrap();

        assert_eq!(queued(&tx), vec![(1, 9)]);
    }

    /// A reorg un-mines a transaction without deleting its notes or clearing their positions, so
    /// a wallet migrating from an earlier release can already hold two notes at one position.
    /// The backfill must survive that rather than leaving the wallet unopenable.
    #[test]
    fn backfill_survives_duplicate_positions_from_a_reorg() {
        let mut conn = Connection::open_in_memory().unwrap();
        let tx = conn.transaction().unwrap();
        pre_migration_schema(&tx);
        tx.execute_batch(
            "INSERT INTO ironwood_received_notes VALUES (1, 2, NULL, 100, 3);
             INSERT INTO ironwood_received_notes VALUES (2, 1, NULL, 100, 3);",
        )
        .unwrap();

        RusqliteMigration::up(&super::Migration, &tx).unwrap();

        // Only the mined claimant is queued; the un-mined leftover is dropped.
        assert_eq!(queued(&tx), vec![(2, 100)]);
    }

    /// Two mined notes at one position means the database is already corrupt. The migration
    /// still has to complete, because the alternative is a wallet that cannot be opened.
    #[test]
    fn backfill_survives_duplicate_mined_positions() {
        let mut conn = Connection::open_in_memory().unwrap();
        let tx = conn.transaction().unwrap();
        pre_migration_schema(&tx);
        tx.execute_batch(
            "INSERT INTO ironwood_received_notes VALUES (1, 1, NULL, 100, 3);
             INSERT INTO ironwood_received_notes VALUES (2, 1, NULL, 100, 3);",
        )
        .unwrap();

        RusqliteMigration::up(&super::Migration, &tx).unwrap();

        assert_eq!(queued(&tx), vec![(2, 100)]);
    }
}
