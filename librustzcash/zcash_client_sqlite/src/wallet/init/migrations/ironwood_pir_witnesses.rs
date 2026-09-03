//! Adds storage for externally supplied, verified Ironwood witnesses.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::ironwood_memo_retrieval_queue;

/// Adds the `ironwood_pir_witnesses` table.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x7c1d9a52_8e0f_4b6a_9d3e_2f5b8c41a6e7);

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
        "Adds storage for verified Ironwood witnesses obtained through PIR."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    /// One row per note: the path the client reconstructed and verified against
    /// the anchor's tree root. A note with a row here is spendable without the
    /// local shard tree having vouched for it.
    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "CREATE TABLE ironwood_pir_witnesses (
                received_note_id INTEGER PRIMARY KEY
                    REFERENCES ironwood_received_notes(id) ON DELETE CASCADE,
                anchor_height INTEGER NOT NULL,
                anchor_root BLOB NOT NULL CHECK (length(anchor_root) = 32),
                leaf BLOB NOT NULL CHECK (length(leaf) = 32),
                siblings BLOB NOT NULL CHECK (length(siblings) = 1024),
                subshard_leaves BLOB
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
    use crate::wallet::init::migrations::tests::test_migrate;

    #[test]
    fn migrate() {
        test_migrate(&[super::MIGRATION_ID]);
    }
}
