//! Track the ranges actually scanned with each swap receiving key.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::swap_receiving_notes;
use crate::wallet::init::WalletMigrationError;

/// Identifier for the swap key scan-coverage migration.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x9176a744_98b0_47d1_b0db_ce18525279bc);

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [swap_receiving_notes::MIGRATION_ID].into_iter().collect()
    }

    fn description(&self) -> &'static str {
        "Tracks scanned ranges for each Ironwood receiving key."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "
CREATE TABLE ironwood_receiving_key_scan_ranges (
    receiving_key_id INTEGER NOT NULL REFERENCES ironwood_receiving_keys(id) ON DELETE CASCADE,
    range_start INTEGER NOT NULL CHECK (range_start >= 0),
    range_end INTEGER NOT NULL CHECK (range_end > range_start AND range_end <= 4294967295),
    PRIMARY KEY (receiving_key_id, range_start)
)
",
        )?;
        Ok(())
    }

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

    // Runs both with and without swap support. The registry row is schema-only
    // test data: rewind must trim coverage without reconstructing viewing keys.
    #[test]
    fn rewind_preserves_only_retained_coverage() {
        use crate::testing::{BlockCache, db::TestDbFactory};
        use zcash_client_backend::data_api::testing::TestBuilder;
        use zcash_primitives::block::BlockHash;

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let (first, _) = st.generate_empty_block();
        for _ in 0..3 {
            st.generate_empty_block();
        }
        st.scan_cached_blocks(first, 4);
        st.wallet().conn().execute(
            "INSERT INTO ironwood_receiving_keys
             (id, account_id, purpose, derivation_version, key_index, receiver, scan_from, advances_allocation)
             SELECT 1, id, 0, 1, zeroblob(8), zeroblob(43), ?1, 1 FROM accounts LIMIT 1",
            [u32::from(first)],
        ).unwrap();
        st.wallet().conn().execute(
            "INSERT INTO ironwood_receiving_key_scan_ranges VALUES (1, ?1, ?1 + 2), (1, ?1 + 3, ?1 + 4)",
            [u32::from(first)],
        ).unwrap();
        st.truncate_to_height_retaining_cache(first);
        let ranges: Vec<(u32, u32)> = st
            .wallet()
            .conn()
            .prepare("SELECT range_start, range_end FROM ironwood_receiving_key_scan_ranges")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(ranges, vec![(u32::from(first), u32::from(first + 1))]);
    }
}
