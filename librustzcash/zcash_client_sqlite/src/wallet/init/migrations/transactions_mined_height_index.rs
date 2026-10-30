//! Indexes `transactions` by `mined_height`.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::{one_time_pir, transparent_detail_content_failures};

/// The identifier of this migration.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0xc8583dab_3a2e_4aec_8408_2a11862fd44a);

const DEPENDENCIES: &[Uuid] = &[
    transparent_detail_content_failures::MIGRATION_ID,
    one_time_pir::MIGRATION_ID,
];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Indexes transactions by mined_height, which storing every scanned block looks up."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // `put_block` runs `UPDATE transactions SET block = :height WHERE mined_height = :height`
        // for every block scanned, to attach transactions learned from a transparent UTXO
        // query to their block once it is seen. Without an index that is a scan of the whole
        // `transactions` table per block - on a wallet with 70,000 transactions, several
        // milliseconds per block, most of what scanning a block costs.
        transaction.execute_batch(
            "CREATE INDEX idx_transactions_mined_height ON transactions (mined_height ASC);",
        )?;
        Ok(())
    }

    fn down(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch("DROP INDEX idx_transactions_mined_height;")?;
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
