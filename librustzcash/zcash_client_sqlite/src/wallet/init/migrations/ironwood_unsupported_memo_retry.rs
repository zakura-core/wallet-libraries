//! Requeues the received Ironwood memos of transactions whose transparent details are
//! unsupported (route 2).
//!
//! Before this migration, marking a transaction's transparent details unsupported under
//! `PrivateRequired` cleared all of its private work, including memo retrieval for its received
//! Ironwood notes, which note decryption authenticates without the transparent details. Routing
//! now keeps that work. This repairs wallets that already hold such transactions with an
//! unknown memo and nothing queued, without resetting them: notes, spend links, fees, routes,
//! and public retrieval intents are untouched, and the queued work is dispatched only privately,
//! only while public authority is absent.
use std::collections::HashSet;

use crate::migration::SqliteMigration as RusqliteMigration;
use uuid::Uuid;

use super::{transaction_reconfirmation_receipts, v_transactions_legacy_projection};
use crate::wallet::init::WalletMigrationError;

/// Requeues the unknown memos of route-2 transactions' received Ironwood notes.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x3d1c7a52_8e0b_4f6d_9a47_5be2c0f19e84);

const DEPENDENCIES: &[Uuid] = &[
    v_transactions_legacy_projection::MIGRATION_ID,
    transaction_reconfirmation_receipts::MIGRATION_ID,
];

pub(super) struct Migration;

impl crate::migration::Migration for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Requeues privately recoverable memos of transactions with unsupported transparent details."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // Route 2 is `PRIVATE_DETAILS_UNSUPPORTED`. A position already claimed by another note
        // keeps its claim.
        conn.execute_batch(
            "INSERT INTO ironwood_memo_retrieval_queue (received_note_id, commitment_tree_position)
             SELECT rn.id, rn.commitment_tree_position
             FROM ironwood_received_notes rn
             JOIN transactions t ON t.id_tx = rn.transaction_id
             JOIN ironwood_enhance_routing r ON r.transaction_id = t.id_tx
             WHERE r.route = 2 AND t.raw IS NULL AND t.mined_height IS NOT NULL
               AND rn.memo IS NULL AND rn.note_version = 3
               AND rn.commitment_tree_position IS NOT NULL
             ON CONFLICT DO NOTHING;",
        )?;
        Ok(())
    }

    fn down(&self, _conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn migrate() {
        super::super::tests::test_migrate(&[super::MIGRATION_ID]);
    }
}
