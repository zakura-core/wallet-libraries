//! Functions for enforcing chain validity and handling chain reorgs.

use prost::Message;
use rusqlite::params;

use zcash_protocol::consensus::BlockHeight;

use zcash_client_backend::{data_api::chain::error::Error, proto::compact_formats::CompactBlock};

use crate::{BlockDb, error::SqliteClientError};

#[cfg(feature = "unstable")]
use {
    crate::{BlockHash, FsBlockDb, FsBlockDbError},
    rusqlite::{Connection, OptionalExtension, named_params},
    std::{
        fs::File,
        io::Read,
        path::{Path, PathBuf},
    },
};

pub mod init;
pub mod migrations;

/// Implements a traversal of `limit` blocks of the block cache database.
///
/// Starting at `from_height`, the `with_row` callback is invoked with each block retrieved from
/// the backing store. If the `limit` value provided is `None`, all blocks are traversed up to the
/// maximum height.
pub(crate) fn blockdb_with_blocks<F, DbErrT>(
    block_source: &BlockDb,
    from_height: Option<BlockHeight>,
    limit: Option<usize>,
    mut with_row: F,
) -> Result<(), Error<DbErrT, SqliteClientError>>
where
    F: FnMut(CompactBlock) -> Result<(), Error<DbErrT, SqliteClientError>>,
{
    fn to_chain_error<D, E: Into<SqliteClientError>>(err: E) -> Error<D, SqliteClientError> {
        Error::BlockSource(err.into())
    }

    // Fetch the CompactBlocks we need to scan
    let mut stmt_blocks = block_source
        .0
        .prepare(
            "SELECT height, data FROM compactblocks
            WHERE height >= ?
            ORDER BY height ASC LIMIT ?",
        )
        .map_err(to_chain_error)?;

    let mut rows = stmt_blocks
        .query(params![
            from_height.map_or(0u32, u32::from),
            limit
                .and_then(|l| u32::try_from(l).ok())
                .unwrap_or(u32::MAX)
        ])
        .map_err(to_chain_error)?;

    // Only look for the `from_height` in the scanned blocks if it is set.
    let mut from_height_found = from_height.is_none();
    while let Some(row) = rows.next().map_err(to_chain_error)? {
        let height = BlockHeight::from_u32(row.get(0).map_err(to_chain_error)?);
        if !from_height_found {
            // We will only perform this check on the first row.
            let from_height = from_height.expect("can only reach here if set");
            if from_height != height {
                return Err(to_chain_error(SqliteClientError::CacheMiss(from_height)));
            } else {
                from_height_found = true;
            }
        }

        let data: Vec<u8> = row.get(1).map_err(to_chain_error)?;
        let block = CompactBlock::decode(&data[..]).map_err(to_chain_error)?;
        if block.height() != height {
            return Err(to_chain_error(SqliteClientError::CorruptedData(format!(
                "Block height {} did not match row's height field value {}",
                block.height(),
                height
            ))));
        }

        with_row(block)?;
    }

    if !from_height_found {
        let from_height = from_height.expect("can only reach here if set");
        return Err(to_chain_error(SqliteClientError::CacheMiss(from_height)));
    }

    Ok(())
}

/// Data structure representing a row in the block metadata database.
#[cfg(feature = "unstable")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockMeta {
    /// The height of the block.
    pub height: BlockHeight,
    /// The hash of the block.
    pub block_hash: BlockHash,
    /// The block timestamp as a Unix epoch time.
    pub block_time: u32,
    /// The number of Sapling outputs in the block.
    pub sapling_outputs_count: u32,
    /// The number of Orchard actions in the block.
    pub orchard_actions_count: u32,
}

#[cfg(feature = "unstable")]
impl BlockMeta {
    /// Returns the path to this block's file within the given blocks directory.
    pub fn block_file_path<P: AsRef<Path>>(&self, blocks_dir: &P) -> PathBuf {
        blocks_dir.as_ref().join(Path::new(&format!(
            "{}-{}-compactblock",
            self.height, self.block_hash
        )))
    }
}

/// Inserts a batch of rows into the block metadata database.
#[cfg(feature = "unstable")]
pub(crate) fn blockmetadb_insert(
    conn: &Connection,
    block_meta: &[BlockMeta],
) -> Result<(), rusqlite::Error> {
    let mut stmt_insert = conn.prepare(
        "INSERT INTO compactblocks_meta (
            height,
            blockhash,
            time,
            sapling_outputs_count,
            orchard_actions_count
        )
        VALUES (
            :height,
            :blockhash,
            :time,
            :sapling_outputs_count,
            :orchard_actions_count
        )
        ON CONFLICT (height) DO UPDATE
        SET blockhash = :blockhash,
            time = :time,
            sapling_outputs_count = :sapling_outputs_count,
            orchard_actions_count = :orchard_actions_count",
    )?;

    conn.execute("BEGIN IMMEDIATE", [])?;
    let result = block_meta
        .iter()
        .map(|m| {
            stmt_insert.execute(named_params![
                ":height": u32::from(m.height),
                ":blockhash": &m.block_hash.0[..],
                ":time": m.block_time,
                ":sapling_outputs_count": m.sapling_outputs_count,
                ":orchard_actions_count": m.orchard_actions_count,
            ])
        })
        .collect::<Result<Vec<_>, _>>();
    match result {
        Ok(_) => {
            conn.execute("COMMIT", [])?;
            Ok(())
        }
        Err(error) => {
            match conn.execute("ROLLBACK", []) {
                Ok(_) => Err(error),
                Err(e) =>
                // Panicking here is probably the right thing to do, because it
                // means the database is corrupt.
                {
                    panic!(
                        "Rollback failed with error {e} while attempting to recover from error {error}; database is likely corrupt."
                    )
                }
            }
        }
    }
}

#[cfg(feature = "unstable")]
pub(crate) fn blockmetadb_truncate_to_height(
    conn: &Connection,
    block_height: BlockHeight,
) -> Result<(), rusqlite::Error> {
    conn.prepare("DELETE FROM compactblocks_meta WHERE height > ?")?
        .execute(params![u32::from(block_height)])?;
    Ok(())
}

#[cfg(feature = "unstable")]
pub(crate) fn blockmetadb_get_max_cached_height(
    conn: &Connection,
) -> Result<Option<BlockHeight>, rusqlite::Error> {
    conn.query_row("SELECT MAX(height) FROM compactblocks_meta", [], |row| {
        // `SELECT MAX(_)` will always return a row, but it will return `null` if the
        // table is empty, which has no integer type. We handle the optionality here.
        let h: Option<u32> = row.get(0)?;
        Ok(h.map(BlockHeight::from))
    })
}

/// Returns the metadata for the block with the given height, if it exists in the database.
#[cfg(feature = "unstable")]
pub(crate) fn blockmetadb_find_block(
    conn: &Connection,
    height: BlockHeight,
) -> Result<Option<BlockMeta>, rusqlite::Error> {
    conn.query_row(
        "SELECT blockhash, time, sapling_outputs_count, orchard_actions_count
        FROM compactblocks_meta
        WHERE height = ?",
        [u32::from(height)],
        |row| {
            Ok(BlockMeta {
                height,
                block_hash: BlockHash::from_slice(&row.get::<_, Vec<_>>(0)?),
                block_time: row.get(1)?,
                sapling_outputs_count: row.get(2)?,
                orchard_actions_count: row.get(3)?,
            })
        },
    )
    .optional()
}

/// Implements a traversal of `limit` blocks of the filesystem-backed
/// block cache.
///
/// Starting at `from_height`, the `with_row` callback is invoked with each block retrieved from
/// the backing store. If the `limit` value provided is `None`, all blocks are traversed up to the
/// maximum height for which metadata is available.
#[cfg(feature = "unstable")]
pub(crate) fn fsblockdb_with_blocks<F, DbErrT>(
    cache: &FsBlockDb,
    from_height: Option<BlockHeight>,
    limit: Option<usize>,
    mut with_block: F,
) -> Result<(), Error<DbErrT, FsBlockDbError>>
where
    F: FnMut(CompactBlock) -> Result<(), Error<DbErrT, FsBlockDbError>>,
{
    fn to_chain_error<D, E: Into<FsBlockDbError>>(err: E) -> Error<D, FsBlockDbError> {
        Error::BlockSource(err.into())
    }

    // Fetch the CompactBlocks we need to scan
    let mut stmt_blocks = cache
        .conn
        .prepare(
            "SELECT height, blockhash, time, sapling_outputs_count, orchard_actions_count
             FROM compactblocks_meta
             WHERE height >= ?
             ORDER BY height ASC LIMIT ?",
        )
        .map_err(to_chain_error)?;

    let rows = stmt_blocks
        .query_map(
            params![
                from_height.map_or(0u32, u32::from),
                limit
                    .and_then(|l| u32::try_from(l).ok())
                    .unwrap_or(u32::MAX)
            ],
            |row| {
                Ok(BlockMeta {
                    height: BlockHeight::from_u32(row.get(0)?),
                    block_hash: BlockHash::from_slice(&row.get::<_, Vec<_>>(1)?),
                    block_time: row.get(2)?,
                    sapling_outputs_count: row.get(3)?,
                    orchard_actions_count: row.get(4)?,
                })
            },
        )
        .map_err(to_chain_error)?;

    // Only look for the `from_height` in the scanned blocks if it is set.
    let mut from_height_found = from_height.is_none();
    for row_result in rows {
        let cbr = row_result.map_err(to_chain_error)?;
        if !from_height_found {
            // We will only perform this check on the first row.
            let from_height = from_height.expect("can only reach here if set");
            if from_height != cbr.height {
                return Err(to_chain_error(FsBlockDbError::CacheMiss(from_height)));
            } else {
                from_height_found = true;
            }
        }

        let mut block_file =
            File::open(cbr.block_file_path(&cache.blocks_dir)).map_err(to_chain_error)?;
        let mut block_data = vec![];
        block_file
            .read_to_end(&mut block_data)
            .map_err(to_chain_error)?;

        let block = CompactBlock::decode(&block_data[..]).map_err(to_chain_error)?;

        if block.height() != cbr.height {
            return Err(to_chain_error(FsBlockDbError::CorruptedData(format!(
                "Block height {} did not match row's height field value {}",
                block.height(),
                cbr.height
            ))));
        }

        with_block(block)?;
    }

    if !from_height_found {
        let from_height = from_height.expect("can only reach here if set");
        return Err(to_chain_error(FsBlockDbError::CacheMiss(from_height)));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use zcash_client_backend::data_api::testing::sapling::SaplingPoolTester;

    use crate::testing;

    #[cfg(feature = "orchard")]
    use zcash_client_backend::data_api::testing::orchard::OrchardPoolTester;

    #[test]
    fn valid_chain_states_sapling() {
        testing::pool::valid_chain_states::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn valid_chain_states_orchard() {
        testing::pool::valid_chain_states::<OrchardPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn invalid_chain_cache_disconnected_sapling() {
        testing::pool::invalid_chain_cache_disconnected::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn invalid_chain_cache_disconnected_orchard() {
        testing::pool::invalid_chain_cache_disconnected::<OrchardPoolTester>()
    }

    #[test]
    fn data_db_truncation_sapling() {
        testing::pool::data_db_truncation::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn data_db_truncation_orchard() {
        testing::pool::data_db_truncation::<OrchardPoolTester>()
    }

    #[test]
    fn truncate_to_chain_state_sapling() {
        testing::pool::truncate_to_chain_state::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn truncate_to_chain_state_orchard() {
        testing::pool::truncate_to_chain_state::<OrchardPoolTester>()
    }

    #[test]
    fn truncate_to_chain_state_below_birthday_sapling() {
        testing::pool::truncate_to_chain_state_below_birthday::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn truncate_to_chain_state_below_birthday_orchard() {
        testing::pool::truncate_to_chain_state_below_birthday::<OrchardPoolTester>()
    }

    #[test]
    fn truncate_to_chain_state_above_scanned_sapling() {
        testing::pool::truncate_to_chain_state_above_scanned::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn truncate_to_chain_state_above_scanned_orchard() {
        testing::pool::truncate_to_chain_state_above_scanned::<OrchardPoolTester>()
    }

    #[test]
    fn truncate_to_chain_state_commitment_tree_error_sapling() {
        testing::pool::truncate_to_chain_state_commitment_tree_error::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn truncate_to_chain_state_commitment_tree_error_orchard() {
        testing::pool::truncate_to_chain_state_commitment_tree_error::<OrchardPoolTester>()
    }

    #[test]
    fn put_blocks_commitment_tree_error_sapling() {
        testing::pool::put_blocks_commitment_tree_error::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn put_blocks_commitment_tree_error_orchard() {
        testing::pool::put_blocks_commitment_tree_error::<OrchardPoolTester>()
    }

    #[test]
    fn rewind_to_chain_state_deep_sapling() {
        testing::pool::rewind_to_chain_state_deep::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn rewind_to_chain_state_deep_orchard() {
        testing::pool::rewind_to_chain_state_deep::<OrchardPoolTester>()
    }

    #[test]
    fn rewind_to_chain_state_shallow_sapling() {
        testing::pool::rewind_to_chain_state_shallow::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn rewind_to_chain_state_shallow_orchard() {
        testing::pool::rewind_to_chain_state_shallow::<OrchardPoolTester>()
    }

    #[test]
    fn rewind_after_non_contiguous_scan_sapling() {
        testing::pool::rewind_after_non_contiguous_scan::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn rewind_after_non_contiguous_scan_orchard() {
        testing::pool::rewind_after_non_contiguous_scan::<OrchardPoolTester>()
    }

    #[test]
    #[cfg(feature = "expensive-tests")]
    #[cfg_attr(
        feature = "ignore-expensive-tests",
        ignore = "covered by the expensive-test CI matrix"
    )]
    fn stabilized_note_spendable_after_deep_rewind_sapling() {
        testing::pool::stabilized_note_spendable_after_deep_rewind::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(all(feature = "orchard", feature = "expensive-tests"))]
    #[cfg_attr(
        feature = "ignore-expensive-tests",
        ignore = "covered by the expensive-test CI matrix"
    )]
    fn stabilized_note_spendable_after_deep_rewind_orchard() {
        testing::pool::stabilized_note_spendable_after_deep_rewind::<OrchardPoolTester>()
    }

    #[test]
    #[cfg(feature = "expensive-tests")]
    #[cfg_attr(
        feature = "ignore-expensive-tests",
        ignore = "covered by the expensive-test CI matrix"
    )]
    fn newly_discovered_notes_become_stabilized_sapling() {
        testing::pool::newly_discovered_notes_become_stabilized::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(all(feature = "orchard", feature = "expensive-tests"))]
    #[cfg_attr(
        feature = "ignore-expensive-tests",
        ignore = "covered by the expensive-test CI matrix"
    )]
    fn newly_discovered_notes_become_stabilized_orchard() {
        testing::pool::newly_discovered_notes_become_stabilized::<OrchardPoolTester>()
    }

    #[test]
    fn reorg_to_checkpoint_sapling() {
        testing::pool::reorg_to_checkpoint::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn reorg_to_checkpoint_orchard() {
        testing::pool::reorg_to_checkpoint::<OrchardPoolTester>()
    }

    #[test]
    fn scan_cached_blocks_allows_blocks_out_of_order_sapling() {
        testing::pool::scan_cached_blocks_allows_blocks_out_of_order::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn scan_cached_blocks_allows_blocks_out_of_order_orchard() {
        testing::pool::scan_cached_blocks_allows_blocks_out_of_order::<OrchardPoolTester>()
    }

    #[test]
    fn scan_cached_blocks_finds_received_notes_sapling() {
        testing::pool::scan_cached_blocks_finds_received_notes::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn scan_cached_blocks_finds_received_notes_orchard() {
        testing::pool::scan_cached_blocks_finds_received_notes::<OrchardPoolTester>()
    }

    #[test]
    fn scan_decrypted_blocks_finds_received_notes_sapling() {
        testing::pool::scan_decrypted_blocks_finds_received_notes::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn scan_decrypted_blocks_finds_received_notes_orchard() {
        testing::pool::scan_decrypted_blocks_finds_received_notes::<OrchardPoolTester>()
    }

    #[test]
    fn scan_decrypted_blocks_decrypts_again_when_stale_sapling() {
        testing::pool::scan_decrypted_blocks_decrypts_again_when_stale::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn scan_decrypted_blocks_decrypts_again_when_stale_orchard() {
        testing::pool::scan_decrypted_blocks_decrypts_again_when_stale::<OrchardPoolTester>()
    }

    #[test]
    fn scan_decrypted_blocks_scans_replaced_blocks_sapling() {
        testing::pool::scan_decrypted_blocks_scans_replaced_blocks::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn scan_decrypted_blocks_scans_replaced_blocks_orchard() {
        testing::pool::scan_decrypted_blocks_scans_replaced_blocks::<OrchardPoolTester>()
    }

    #[test]
    fn scan_leaves_out_accounts_born_after_the_range_sapling() {
        testing::pool::scan_leaves_out_accounts_born_after_the_range::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn scan_leaves_out_accounts_born_after_the_range_orchard() {
        testing::pool::scan_leaves_out_accounts_born_after_the_range::<OrchardPoolTester>()
    }

    #[test]
    fn scan_cached_blocks_finds_change_notes_sapling() {
        testing::pool::scan_cached_blocks_finds_change_notes::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn scan_cached_blocks_finds_change_notes_orchard() {
        testing::pool::scan_cached_blocks_finds_change_notes::<OrchardPoolTester>()
    }

    #[test]
    fn scan_cached_blocks_detects_spends_out_of_order_sapling() {
        testing::pool::scan_cached_blocks_detects_spends_out_of_order::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn scan_cached_blocks_detects_spends_out_of_order_orchard() {
        testing::pool::scan_cached_blocks_detects_spends_out_of_order::<OrchardPoolTester>()
    }

    /// A scanning key cache kept across scans finds the notes of an account imported
    /// between them, and stops scanning for an account deleted between them.
    #[test]
    fn scanning_key_cache_follows_account_changes() {
        use zcash_client_backend::data_api::{
            Account as _, AccountBirthday, AccountPurpose, WalletRead, WalletWrite,
            chain::ScanningKeyCache,
            testing::{AddressType, TestBuilder, pool::ShieldedPoolTester},
        };
        use zcash_keys::keys::UnifiedSpendingKey;
        use zcash_primitives::block::BlockHash;
        use zcash_protocol::value::Zatoshis;

        let mut st = TestBuilder::new()
            .with_data_store_factory(testing::db::TestDbFactory::default())
            .with_block_cache(testing::BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let fvk_a = SaplingPoolTester::test_account_fvk(&st);
        let usk_b =
            UnifiedSpendingKey::from_seed(st.network(), &[7; 32], zip32::AccountId::ZERO).unwrap();
        let fvk_b = SaplingPoolTester::sk_to_fvk(SaplingPoolTester::usk_to_sk(&usk_b));
        let value = Zatoshis::const_from_u64(5);
        let mut cache = ScanningKeyCache::new();

        let (h1, _, _) = st.generate_next_block(&fvk_a, AddressType::DefaultExternal, value);
        let summary = st.scan_cached_blocks_with_cache(h1, 1, &mut cache);
        assert_eq!(summary.received_sapling_note_count(), 1);

        let birthday = AccountBirthday::from_sapling_activation(st.network(), BlockHash([0; 32]));
        let account_b = st
            .wallet_mut()
            .import_account_ufvk(
                "B",
                &usk_b.to_unified_full_viewing_key(),
                &birthday,
                AccountPurpose::ViewOnly,
                None,
            )
            .unwrap()
            .id();
        let (h2, _, _) = st.generate_next_block(&fvk_b, AddressType::DefaultExternal, value);
        let summary = st.scan_cached_blocks_with_cache(h2, 1, &mut cache);
        assert_eq!(summary.received_sapling_note_count(), 1);

        st.wallet_mut().delete_account(account_b).unwrap();
        assert!(st.wallet().get_account(account_b).unwrap().is_none());
        let (h3, _, _) = st.generate_next_block(&fvk_b, AddressType::DefaultExternal, value);
        let summary = st.scan_cached_blocks_with_cache(h3, 1, &mut cache);
        assert_eq!(summary.received_sapling_note_count(), 0);
    }

    /// Ordinary sync proceeds even when receiver recovery has pending network work.
    #[test]
    fn private_receiver_work_never_blocks_ordinary_sync() {
        use zcash_client_backend::data_api::testing::{
            AddressType, TestBuilder, pool::ShieldedPoolTester,
        };
        use zcash_primitives::block::BlockHash;
        use zcash_protocol::value::Zatoshis;
        let mut st = TestBuilder::new()
            .with_data_store_factory(testing::db::TestDbFactory::default())
            .with_block_cache(testing::BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let fvk = SaplingPoolTester::test_account_fvk(&st);
        let (height, _, _) = st.generate_next_block(
            &fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(5),
        );
        st.wallet()
            .conn()
            .execute_batch(
                "INSERT INTO ironwood_one_time_keys(account_id, purpose, key_index, receiver)
             SELECT id, 0, zeroblob(8), zeroblob(43) FROM accounts LIMIT 1;
             INSERT INTO ironwood_one_time_recovery(account_id) SELECT id FROM accounts;
             INSERT INTO ironwood_one_time_lookups(one_time_key_id, target_height, reasons)
             SELECT id, 4000000, 1 FROM ironwood_one_time_keys;",
            )
            .unwrap();
        st.scan_cached_blocks(height, 1);
        assert_eq!(
            st.wallet()
                .conn()
                .query_row("SELECT MAX(height) FROM blocks", [], |r| r.get::<_, u32>(0))
                .unwrap(),
            u32::from(height)
        );
    }

    /// Reorg repair invalidates pending results and journal coverage even in feature-off builds.
    #[test]
    fn a_rewind_repairs_one_time_state_in_every_build() {
        use zcash_client_backend::data_api::{
            WalletWrite,
            testing::{AddressType, TestBuilder, pool::ShieldedPoolTester},
        };
        use zcash_primitives::block::BlockHash;
        use zcash_protocol::value::Zatoshis;
        let mut st = TestBuilder::new()
            .with_data_store_factory(testing::db::TestDbFactory::default())
            .with_block_cache(testing::BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let fvk = SaplingPoolTester::test_account_fvk(&st);
        let amount = Zatoshis::const_from_u64(5);
        let (h1, _, _) = st.generate_next_block(&fvk, AddressType::DefaultExternal, amount);
        st.generate_next_block(&fvk, AddressType::DefaultExternal, amount);
        let (h3, _, _) = st.generate_next_block(&fvk, AddressType::DefaultExternal, amount);
        st.scan_cached_blocks(h1, 3);
        let conn = st.wallet().conn();
        conn.execute(
            "INSERT OR IGNORE INTO ironwood_spend_journal VALUES (?1, 0, zeroblob(32))",
            [u32::from(h3)],
        )
        .unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO ironwood_journal_coverage SELECT id, ?1, ?2 FROM accounts",
            [u32::from(h1), u32::from(h3) + 1],
        )
        .unwrap();
        conn.execute_batch(&format!(
            "INSERT INTO ironwood_one_time_keys(account_id, purpose, key_index, receiver)
             SELECT id, 0, zeroblob(8), zeroblob(43) FROM accounts LIMIT 1;
             INSERT INTO ironwood_one_time_recovery(account_id) SELECT id FROM accounts;
             INSERT INTO ironwood_one_time_lookups(one_time_key_id, target_height, reasons, done_height, read_complete)
             SELECT id, {h3}, 1, {h3}, 1 FROM ironwood_one_time_keys;")).unwrap();
        st.wallet_mut().truncate_to_height(h1).unwrap();
        let conn = st.wallet().conn();
        let repaired: (u64, u64, u64) = conn
            .query_row(
                "SELECT (SELECT generation FROM ironwood_one_time_recovery),
                (SELECT COUNT(*) FROM ironwood_spend_journal WHERE block_height > ?1),
                (SELECT COUNT(*) FROM ironwood_journal_coverage WHERE end_height > ?1 + 1)",
                [u32::from(h1)],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(repaired, (1, 0, 0));
        let cursor: (Option<u32>, Option<u32>, bool) = conn
            .query_row(
                "SELECT target_height, done_height, read_complete FROM ironwood_one_time_lookups",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(cursor, (Some(u32::from(h3)), None, false));
    }
}
