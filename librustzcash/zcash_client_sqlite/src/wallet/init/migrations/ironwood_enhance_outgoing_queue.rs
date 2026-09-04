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
            );
            INSERT INTO ironwood_enhance_tx_protection (
                transaction_id, commitment_tree_position
            )
            SELECT rn.transaction_id, q.commitment_tree_position
            FROM ironwood_memo_retrieval_queue q
            JOIN ironwood_received_notes rn ON rn.id = q.received_note_id;",
        )?;
        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn migrate() {
        crate::wallet::init::migrations::tests::test_migrate(&[super::MIGRATION_ID]);
    }
}
