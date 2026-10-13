//! Fixes the private status polls of each transaction when its status work is queued: a window
//! of chain tips and an optional poll at its expiry height, so that the replies cannot steer
//! when polling stops.
//!
//! Additive.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::transparent_detail_content_failures;
use crate::wallet::init::WalletMigrationError;

/// Adds `tx_status_polls`.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x5f0b6c1e_8d2a_4f7e_9c3b_2a71d4e8b905);

const DEPENDENCIES: &[Uuid] = &[transparent_detail_content_failures::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Fixes the private status poll window of each queued transaction."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(
            "CREATE TABLE tx_status_polls (
                txid BLOB NOT NULL PRIMARY KEY,
                window_start_height INTEGER NOT NULL CHECK (window_start_height >= 0),
                window_end_height INTEGER NOT NULL,
                expiry_poll_height INTEGER,
                last_polled_height INTEGER,
                CHECK (window_end_height > window_start_height),
                CHECK (expiry_poll_height IS NULL OR expiry_poll_height >= window_end_height)
            );",
        )?;
        Ok(())
    }

    fn down(&self, _conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}
