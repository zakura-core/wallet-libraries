//! Records wallet transparent outputs that a complete query of their address's unspent outputs
//! did not return, so that a spend by a transaction the wallet has not seen stops counting the
//! output as spendable and starts a search for its spender.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::funding_attribution;
use crate::wallet::init::WalletMigrationError;

/// Creates the empty `transparent_utxo_absences` table.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x6309d4af_c73c_476f_acab_4f52f14d9675);

const DEPENDENCIES: &[Uuid] = &[funding_attribution::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Records transparent outputs observed absent from their address's unspent outputs."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(
            "CREATE TABLE transparent_utxo_absences (
                output_id INTEGER PRIMARY KEY
                    REFERENCES transparent_received_outputs(id) ON DELETE CASCADE,
                observed_height INTEGER NOT NULL
            );",
        )?;
        Ok(())
    }

    fn down(&self, _conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use super::MIGRATION_ID;
    use crate::wallet::init::migrations::tests::test_migrate;

    #[test]
    fn migrate() {
        test_migrate(&[MIGRATION_ID]);
    }
}
