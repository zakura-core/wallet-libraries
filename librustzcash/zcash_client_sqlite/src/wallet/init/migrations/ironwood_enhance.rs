//! Adds durable Ironwood-only enhancement queues and transaction routing.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::ironwood_received_notes;

/// Identifier for the Ironwood-only Enhance PIR migration.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x329e7b26_86d1_4376_ae93_87275235eca4);

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
        "Adds Ironwood-only Enhance PIR queues and transaction routing."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    // Deliberately empty: existing history remains on ordinary enhancement until
    // explicitly rescanned. Database notes alone cannot establish pool eligibility.
    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "CREATE TABLE ironwood_memo_retrieval_queue (
                received_note_id INTEGER PRIMARY KEY
                    REFERENCES ironwood_received_notes(id) ON DELETE CASCADE,
                commitment_tree_position INTEGER NOT NULL UNIQUE
                    CHECK (commitment_tree_position >= 0)
            );
            CREATE TABLE ironwood_enhance_outgoing_queue (
                commitment_tree_position INTEGER PRIMARY KEY
                    CHECK (commitment_tree_position >= 0),
                transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                output_index INTEGER NOT NULL CHECK (output_index >= 0),
                nullifier BLOB NOT NULL CHECK (length(nullifier) = 32),
                cmx BLOB NOT NULL CHECK (length(cmx) = 32),
                ephemeral_key BLOB NOT NULL CHECK (length(ephemeral_key) = 32),
                compact_ciphertext BLOB NOT NULL CHECK (length(compact_ciphertext) = 52),
                not_recoverable INTEGER NOT NULL DEFAULT 0 CHECK (not_recoverable IN (0, 1)),
                UNIQUE(transaction_id, output_index)
            );
            CREATE TABLE ironwood_enhance_outgoing_accounts (
                commitment_tree_position INTEGER NOT NULL
                    REFERENCES ironwood_enhance_outgoing_queue(commitment_tree_position)
                    ON DELETE CASCADE,
                account_id INTEGER NOT NULL
                    REFERENCES accounts(id) ON DELETE CASCADE,
                PRIMARY KEY(commitment_tree_position, account_id)
            );
            CREATE TABLE ironwood_enhance_routing (
                transaction_id INTEGER PRIMARY KEY
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                route INTEGER NOT NULL CHECK (route IN (0, 1))
            );",
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

    #[test]
    fn migrate() {
        crate::wallet::init::migrations::tests::test_migrate(&[super::MIGRATION_ID]);
    }

    #[test]
    fn existing_history_is_not_backfilled() {
        let mut conn = Connection::open_in_memory().unwrap();
        let tx = conn.transaction().unwrap();
        tx.execute_batch(
            "CREATE TABLE transactions (id_tx INTEGER PRIMARY KEY);
             CREATE TABLE accounts (id INTEGER PRIMARY KEY);
             CREATE TABLE ironwood_received_notes (
                 id INTEGER PRIMARY KEY, transaction_id INTEGER NOT NULL
             );
             INSERT INTO transactions VALUES (1);
             INSERT INTO ironwood_received_notes VALUES (1, 1);",
        )
        .unwrap();
        RusqliteMigration::up(&super::Migration, &tx).unwrap();
        for table in [
            "ironwood_memo_retrieval_queue",
            "ironwood_enhance_outgoing_queue",
            "ironwood_enhance_outgoing_accounts",
            "ironwood_enhance_routing",
        ] {
            assert_eq!(
                tx.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
    }
}
