//! Adds durable Ironwood-only enhancement queues and transaction routing.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::{
    ironwood_compact_encryption, tx_status_observation_intent, v_transactions_zip318_kind,
};

/// Identifier for the Ironwood-only Enhance PIR migration.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0xcf147152_694f_47e8_8c05_c6dd853ac329);

const DEPENDENCIES: &[Uuid] = &[
    ironwood_compact_encryption::MIGRATION_ID,
    tx_status_observation_intent::MIGRATION_ID,
    // Rebuild the latest released history view, including its ZIP 318 column.
    v_transactions_zip318_kind::MIGRATION_ID,
];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds Ironwood Enhance PIR work, routing, and display-only expiry history."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    // All feature tables start empty: existing history remains on ordinary enhancement until
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
                route INTEGER NOT NULL CHECK (route IN (0, 1)),
                history_expiry_height INTEGER
                    CHECK (history_expiry_height >= 0 AND history_expiry_height < 500000000)
            );
            CREATE TABLE ironwood_enhance_discovery_queue (
                transaction_id INTEGER PRIMARY KEY
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                suspended INTEGER NOT NULL DEFAULT 0 CHECK (suspended IN (0, 1))
            );
            CREATE TABLE ironwood_enhance_metadata_queue (
                transaction_id INTEGER PRIMARY KEY REFERENCES transactions(id_tx) ON DELETE CASCADE,
                commitment_tree_position INTEGER UNIQUE CHECK (commitment_tree_position >= 0),
                output_index INTEGER CHECK (output_index >= 0),
                ephemeral_key BLOB,
                compact_ciphertext BLOB,
                CHECK ((commitment_tree_position IS NULL) = (output_index IS NULL)),
                CHECK ((ephemeral_key IS NULL) = (compact_ciphertext IS NULL)),
                CHECK (ephemeral_key IS NULL OR commitment_tree_position IS NOT NULL),
                CHECK (ephemeral_key IS NULL OR length(ephemeral_key) = 32),
                CHECK (compact_ciphertext IS NULL OR length(compact_ciphertext) = 52)
            );",
        )?;
        // Keep the existing history view's columns and spendability expression.
        // Only its displayed expiry can use a private service assertion.
        let view: String = transaction.query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'view' AND name = 'v_transactions'",
            [],
            |row| row.get(0),
        )?;
        let original = "transactions.expiry_height   AS expiry_height";
        if view.matches(original).count() != 1 {
            return Err(WalletMigrationError::CorruptedData(
                "unexpected v_transactions expiry expression".into(),
            ));
        }
        let updated = view.replacen(
            original,
            "COALESCE(transactions.expiry_height, (SELECT history_expiry_height \
             FROM ironwood_enhance_routing WHERE transaction_id = transactions.id_tx AND route = 0)) \
             AS expiry_height",
            1,
        );
        transaction.execute_batch("DROP VIEW v_transactions")?;
        transaction.execute_batch(&updated)?;
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
            "CREATE TABLE transactions (id_tx INTEGER PRIMARY KEY, expiry_height INTEGER);
             CREATE TABLE accounts (id INTEGER PRIMARY KEY);
             CREATE TABLE ironwood_received_notes (
                 id INTEGER PRIMARY KEY, transaction_id INTEGER NOT NULL
             );
             CREATE VIEW v_transactions AS SELECT transactions.expiry_height   AS expiry_height
                 FROM transactions;
             INSERT INTO transactions (id_tx) VALUES (1);
             INSERT INTO ironwood_received_notes VALUES (1, 1);",
        )
        .unwrap();
        RusqliteMigration::up(&super::Migration, &tx).unwrap();
        for expiry in [-1, 500_000_000] {
            assert!(tx.execute(
                "INSERT INTO ironwood_enhance_routing (transaction_id, route, history_expiry_height)
                 VALUES (1, 0, ?)",
                [expiry],
            ).is_err());
        }
        tx.execute(
            "INSERT INTO ironwood_enhance_routing (transaction_id, route, history_expiry_height)
             VALUES (1, 0, 0)",
            [],
        )
        .unwrap();
        let displayed_expiry = || {
            tx.query_row("SELECT expiry_height FROM v_transactions", [], |row| {
                row.get::<_, Option<u32>>(0)
            })
            .unwrap()
        };
        assert_eq!(displayed_expiry(), Some(0));
        tx.execute(
            "UPDATE transactions SET expiry_height = 10 WHERE id_tx = 1",
            [],
        )
        .unwrap();
        assert_eq!(displayed_expiry(), Some(10));
        tx.execute(
            "UPDATE transactions SET expiry_height = NULL WHERE id_tx = 1",
            [],
        )
        .unwrap();
        tx.execute("UPDATE ironwood_enhance_routing SET route = 1", [])
            .unwrap();
        assert_eq!(displayed_expiry(), None);
        tx.execute("DELETE FROM ironwood_enhance_routing", [])
            .unwrap();
        // Allow discovery, incoming-note binding, and complete compact binding.
        for fields in [
            "NULL, NULL, NULL, NULL",
            "0, 0, NULL, NULL",
            "0, 0, zeroblob(32), zeroblob(52)",
        ] {
            tx.execute_batch(&format!("INSERT INTO ironwood_enhance_metadata_queue VALUES (1, {fields}); DELETE FROM ironwood_enhance_metadata_queue;")).unwrap();
        }
        for fields in [
            "-1, 0, NULL, NULL",
            "0, -1, NULL, NULL",
            "NULL, 0, NULL, NULL",
            "0, NULL, NULL, NULL",
            "0, 0, zeroblob(32), NULL",
            "0, 0, NULL, zeroblob(52)",
            "NULL, NULL, zeroblob(32), zeroblob(52)",
            "0, 0, zeroblob(31), zeroblob(52)",
            "0, 0, zeroblob(32), zeroblob(51)",
        ] {
            assert!(
                tx.execute_batch(&format!(
                    "INSERT INTO ironwood_enhance_metadata_queue VALUES (1, {fields})"
                ))
                .is_err(),
                "accepted {fields}"
            );
        }
        for table in [
            "ironwood_memo_retrieval_queue",
            "ironwood_enhance_outgoing_queue",
            "ironwood_enhance_outgoing_accounts",
            "ironwood_enhance_routing",
            "ironwood_enhance_discovery_queue",
            "ironwood_enhance_metadata_queue",
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
