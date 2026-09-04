//! Adds durable outgoing Enhance PIR candidates and txid-protection markers.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::ironwood_memo_retrieval_queue;

/// Identifier for the outgoing Enhance PIR queue migration.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x6c4e73cb_7d1b_45db_b17f_56fd8162df26);

const DEPENDENCIES: &[Uuid] = &[ironwood_memo_retrieval_queue::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds outgoing Ironwood Enhance PIR recovery state."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    /// Creates the outgoing Enhance PIR queue and the transaction-wide protection markers.
    ///
    /// The protection table is created empty rather than backfilled from the memo retrieval
    /// queue. Protection asserts that a transaction is Enhance PIR's responsibility, and only
    /// scanning can establish that: eligibility means the compact transaction represented the
    /// Ironwood pool and no other, which is a property of the compact block, not of anything
    /// this database retains. Backfilling would protect mixed-pool transactions too, and
    /// protection is what allows their transaction-ID request to be retired — so a wallet
    /// upgrading with mixed-pool Ironwood transactions already scanned would lose the only
    /// route to their Sapling, Orchard and transparent data. Those transactions instead stay
    /// on ordinary transaction-ID enhancement until a rescan protects the ones that qualify.
    ///
    /// `ironwood_enhance_outgoing_queue.not_recoverable` records that a record authenticated
    /// against an action but held no outgoing plaintext any funding account could recover. Such a
    /// row is marked rather than deleted so that a position which was given up on stays
    /// distinguishable from one that completed: the transaction remains ineligible for retirement
    /// and keeps its transaction-ID fallback. See `wallet::enhance_pir::retire_outgoing` for why
    /// that distinction matters against a server that chooses what to return.
    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "CREATE TABLE ironwood_enhance_outgoing_queue (
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
            CREATE TABLE ironwood_enhance_tx_protection (
                transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                commitment_tree_position INTEGER NOT NULL
                    CHECK (commitment_tree_position >= 0),
                PRIMARY KEY(transaction_id, commitment_tree_position)
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

    /// Already-scanned notes must not arrive protected.
    ///
    /// Protection asserts that Enhance PIR is responsible for a transaction, which in turn is
    /// what permits its transaction-ID request to be retired. Nothing in the wallet database
    /// distinguishes a pure-Ironwood transaction from a mixed-pool one, so a backfill would
    /// hand that assertion to transactions whose Sapling, Orchard or transparent data only the
    /// transaction-ID request can reach.
    #[test]
    fn queued_notes_are_not_retroactively_protected() {
        let mut conn = Connection::open_in_memory().unwrap();
        let tx = conn.transaction().unwrap();
        tx.execute_batch(
            "CREATE TABLE transactions (id_tx INTEGER PRIMARY KEY);
             CREATE TABLE accounts (id INTEGER PRIMARY KEY);
             CREATE TABLE ironwood_received_notes (
                 id INTEGER PRIMARY KEY, transaction_id INTEGER NOT NULL
             );
             CREATE TABLE ironwood_memo_retrieval_queue (
                 received_note_id INTEGER PRIMARY KEY,
                 commitment_tree_position INTEGER NOT NULL UNIQUE
             );
             INSERT INTO transactions VALUES (1);
             INSERT INTO ironwood_received_notes VALUES (1, 1);
             INSERT INTO ironwood_memo_retrieval_queue VALUES (1, 9);",
        )
        .unwrap();

        RusqliteMigration::up(&super::Migration, &tx).unwrap();

        assert_eq!(
            tx.query_row(
                "SELECT COUNT(*) FROM ironwood_enhance_tx_protection",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0,
        );
    }
}
