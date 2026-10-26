//! Indexes `transparent_spend_map` by the output it spends.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::transactions_mined_height_index;

/// The identifier of this migration.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x5b1c2a9e_7d43_4f0e_9a6b_2c8e1f7d0a11);

const DEPENDENCIES: &[Uuid] = &[transactions_mined_height_index::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Indexes transparent_spend_map by the output spent, which storing a received transparent output looks up."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // `put_transparent_output` asks whether a wallet transaction already spends the output
        // being stored, by (prevout_txid, prevout_output_index). The table was indexed by the
        // spending transaction only, so that was a scan of the whole map per stored output.
        transaction.execute_batch(
            "CREATE INDEX idx_transparent_spend_map_prevout ON transparent_spend_map (
                prevout_txid ASC,
                prevout_output_index ASC
            );",
        )?;
        Ok(())
    }

    fn down(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch("DROP INDEX idx_transparent_spend_map_prevout;")?;
        Ok(())
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
