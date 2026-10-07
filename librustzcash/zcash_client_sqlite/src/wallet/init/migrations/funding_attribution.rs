//! Queues stored transactions whose funding attribution must be derived again.
//!
//! Earlier writers attributed a transaction's sent outputs to an arbitrary funding account when
//! several accounts or parties funded it, and never recorded the sent outputs of a transaction
//! stored before the outputs it spends were known. Stored transactions that may be affected are
//! queued in `tx_attribution_queue`, which the next storage operation drains by re-deriving them
//! from their raw data.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::transparent_utxo_absences;
use crate::wallet::init::WalletMigrationError;

/// Creates `tx_attribution_queue` and queues the stored transactions earlier writers may have
/// attributed incorrectly.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0xa7bb8d3b_bc27_45e2_8f20_9fb42b758119);

const DEPENDENCIES: &[Uuid] = &[transparent_utxo_absences::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Queues stored transactions for funding re-attribution."
    }
}

/// Stored transactions whose sent outputs earlier writers may have attributed incorrectly or
/// failed to record: those, not constructed by this wallet, with any known wallet spend. This
/// includes a sole shielded spender whose input was linked after its raw data was stored: the
/// existing link will not trigger the new runtime re-derivation hook again.
pub(in crate::wallet) const QUEUE_AFFECTED_TRANSACTIONS: &str = "
    INSERT INTO tx_attribution_queue (transaction_id)
    SELECT t.id_tx FROM transactions t
    WHERE t.raw IS NOT NULL
    AND t.created IS NULL
    AND EXISTS (
        SELECT 1 FROM v_received_output_spends ros
        WHERE ros.transaction_id = t.id_tx
    )
    ON CONFLICT (transaction_id) DO NOTHING";

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(
            r#"
            CREATE TABLE tx_attribution_queue (
                transaction_id INTEGER PRIMARY KEY
                    REFERENCES transactions(id_tx) ON DELETE CASCADE
            );"#,
        )?;
        conn.execute(QUEUE_AFFECTED_TRANSACTIONS, [])?;
        Ok(())
    }

    fn down(&self, _conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use super::{DEPENDENCIES, MIGRATION_ID};
    use crate::{
        WalletDb,
        testing::db::{test_clock, test_rng},
        wallet::init::{WalletMigrator, migrations::tests::test_migrate},
    };
    use zcash_protocol::consensus::Network;

    #[test]
    fn migrate() {
        test_migrate(&[MIGRATION_ID]);
    }

    #[test]
    fn creates_an_empty_queue() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut db =
            WalletDb::for_path(file.path(), Network::TestNetwork, test_clock(), test_rng())
                .unwrap();
        WalletMigrator::new()
            .init_or_migrate_to(&mut db, DEPENDENCIES)
            .unwrap();
        WalletMigrator::new().init_or_migrate(&mut db).unwrap();
        let queued: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM tx_attribution_queue", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(queued, 0);
    }
}
