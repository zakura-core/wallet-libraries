//! Records when each queued Ironwood Enhance position may first be queried, so that the first
//! query does not follow the sync that found its transaction.
//!
//! Additive: positions queued before the migration have no row and stay due at once.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::tx_status_poll_window;
use crate::wallet::init::WalletMigrationError;

/// Adds `ironwood_enhance_not_before`.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x9a4e2d71_3c6b_4b0f_a8e5_7d1f0c92b346);

const DEPENDENCIES: &[Uuid] = &[tx_status_poll_window::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Records the not-before time of each queued Ironwood Enhance position."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(
            "CREATE TABLE ironwood_enhance_not_before (
                commitment_tree_position INTEGER PRIMARY KEY CHECK (commitment_tree_position >= 0),
                not_before INTEGER NOT NULL CHECK (not_before >= 0)
            );",
        )?;
        Ok(())
    }

    fn down(&self, _conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}
