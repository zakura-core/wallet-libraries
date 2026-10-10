//! Retains Enhance PIR's transparent-output assertion and privately recovers it for existing
//! mixed transactions even when their received memos were already recovered.
use super::ironwood_unsupported_memo_retry;
use crate::wallet::init::WalletMigrationError;
use schemerz_rusqlite::RusqliteMigration;
use std::collections::HashSet;
use uuid::Uuid;

/// Adds nullable display evidence; no existing transaction is assumed to lack outputs.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x8f4c3210_04e1_49eb_9de2_d713ee0a8426);
pub(super) struct Migration;
impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }
    fn dependencies(&self) -> HashSet<Uuid> {
        [ironwood_unsupported_memo_retry::MIGRATION_ID]
            .into_iter()
            .collect()
    }
    fn description(&self) -> &'static str {
        "Retains transparent output shape from private Ironwood enhancement."
    }
}
impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;
    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(
            "ALTER TABLE ironwood_enhance_routing ADD COLUMN has_transparent_outputs INTEGER
                 CHECK (has_transparent_outputs IN (0, 1));",
        )?;
        // `queue_ironwood_output_shape` without its dynamic-key filter: that column may not
        // exist yet, and no dynamic-key note can.
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
        crate::wallet::ironwood_hooks::queue_output_shape_metadata(conn, None)?;
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
