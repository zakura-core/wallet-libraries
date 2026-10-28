//! A new-work counter for one-time recovery rounds and a queue of refund memos waiting to
//! be accepted, so block batches no longer re-read every historical memo.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::one_time_preparations;
use crate::wallet::init::WalletMigrationError;

/// Adds `ironwood_one_time_work` and `ironwood_one_time_pending_memos`.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x39c5795c_fd41_41fb_8c39_be4fa277c96b);

const DEPENDENCIES: &[Uuid] = &[one_time_preparations::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    /// This migration's identifier.
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    /// Runs after issuance preparations exist.
    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    /// Describes the stored-state change for migration diagnostics.
    fn description(&self) -> &'static str {
        "Add the one-time new-work counter and pending refund memos."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    /// Adds the counter and the queue. Every refund memo already stored is queued once, so
    /// none is missed when batches stop re-reading them.
    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(
            "CREATE TABLE ironwood_one_time_work (
                id INTEGER PRIMARY KEY CHECK (id = 0),
                sequence INTEGER NOT NULL CHECK (sequence >= 0)
            );
             INSERT INTO ironwood_one_time_work (id, sequence) VALUES (0, 0);
             CREATE TABLE ironwood_one_time_pending_memos (
                note_id INTEGER PRIMARY KEY REFERENCES ironwood_received_notes(id) ON DELETE CASCADE
            );
             INSERT INTO ironwood_one_time_pending_memos (note_id)
             SELECT id FROM ironwood_received_notes
             WHERE recipient_key_scope = 1 AND one_time_key_id IS NULL
               AND substr(memo, 1, 5) = X'FF5A535750';",
        )?;
        Ok(())
    }

    /// The queue can be rebuilt from stored memos, but the counter cannot be removed safely.
    fn down(&self, _: &rusqlite::Transaction) -> Result<(), Self::Error> {
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
