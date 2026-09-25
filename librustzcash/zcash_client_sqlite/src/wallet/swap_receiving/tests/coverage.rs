use std::{cell::Cell, ops::Range};

use zcash_client_backend::{
    data_api::{
        WalletRead,
        chain::{BlockSource, ChainState, error, scan_cached_blocks},
        testing::{AddressType, IronwoodFvk},
    },
    proto::compact_formats::CompactBlock,
};
use zcash_protocol::value::Zatoshis;

use super::*;

fn fixture() -> TestState<crate::testing::BlockCache, TestDb, LocalNetwork> {
    let activation = BlockHeight::from_u32(100_000);
    TestBuilder::new()
        .with_network(LocalNetwork {
            nu6: Some(activation),
            nu6_1: Some(activation),
            nu6_2: Some(activation),
            nu6_3: Some(activation),
            ..TestBuilder::<(), ()>::DEFAULT_NETWORK
        })
        .with_data_store_factory(TestDbFactory::file_backed())
        .with_block_cache(crate::testing::BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build()
}

fn covered(
    st: &TestState<crate::testing::BlockCache, TestDb, LocalNetwork>,
    key: KeyId,
) -> Vec<Range<BlockHeight>> {
    st.wallet()
        .db()
        .get_swap_receiving_scan_ranges(st.test_account().unwrap().id(), key)
        .unwrap()
        .unwrap()
}

#[test]
fn recovered_key_replays_already_scanned_refund_and_survives_reopen() {
    let mut st = fixture();
    let account = st.test_account().cloned().unwrap();
    let key = KeyId::new(Purpose::Refund, 7);
    let fvk = key
        .derive(&FullViewingKey::from(account.usk().orchard()))
        .unwrap();
    let (height, _, _) = st.generate_next_block(
        &IronwoodFvk(fvk),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(70_000),
    );
    st.scan_cached_blocks(height, 1);
    assert!(st.wallet().suggest_scan_ranges().unwrap().is_empty());
    assert!(
        st.wallet()
            .db()
            .get_unspent_ironwood_notes_at_historical_height(account.id(), height)
            .unwrap()
            .is_empty()
    );

    st.wallet_mut()
        .db_mut()
        .recover_swap_receiving_key(account.id(), key, height)
        .unwrap();
    assert!(covered(&st, key).is_empty());
    let pending = st.wallet().suggest_scan_ranges().unwrap();
    assert!(pending.iter().any(|r| r.block_range().contains(&height)));
    assert_ne!(
        st.wallet()
            .block_fully_scanned()
            .unwrap()
            .map(|b| b.block_height()),
        Some(height)
    );

    let reopened = WalletDb::for_path(
        st.wallet().data_file_path(),
        *st.network(),
        test_clock(),
        test_rng(),
    )
    .unwrap();
    *st.wallet_mut().db_mut() = reopened;
    // Asking for more than the cache holds must not credit absent blocks.
    st.scan_cached_blocks(height, 10);
    assert_eq!(covered(&st, key), vec![height..height + 1]);
    assert!(st.wallet().suggest_scan_ranges().unwrap().is_empty());
    let notes = st
        .wallet()
        .db()
        .get_unspent_ironwood_notes_at_historical_height(account.id(), height)
        .unwrap();
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].swap_key_id(), Some(key));
}

#[test]
fn recent_first_scanning_keeps_holes_and_rewind_removes_coverage() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let (first, _) = st.generate_empty_block();
    for _ in 0..3 {
        st.generate_empty_block();
    }
    // Establish ordinary history first, then discover a key whose history is missing.
    st.scan_cached_blocks(first, 4);
    let key = st
        .wallet_mut()
        .db_mut()
        .watch_swap_receive_key(account, 3, first + 1)
        .unwrap()
        .key_id();
    st.scan_cached_blocks(first + 2, 2);
    assert_eq!(covered(&st, key), vec![first + 2..first + 4]);
    assert!(
        st.wallet()
            .suggest_scan_ranges()
            .unwrap()
            .iter()
            .any(|r| r.block_range().contains(&(first + 1)))
    );
    // Recovery can move the required lower bound earlier without discarding coverage.
    st.wallet_mut()
        .db_mut()
        .watch_swap_receive_key(account, 3, first)
        .unwrap();
    assert!(
        st.wallet()
            .suggest_scan_ranges()
            .unwrap()
            .iter()
            .any(|r| r.block_range().contains(&first))
    );
    st.scan_cached_blocks(first, 1);
    assert_eq!(
        covered(&st, key),
        vec![first..first + 1, first + 2..first + 4]
    );
    st.scan_cached_blocks(first + 1, 1);
    assert_eq!(covered(&st, key), vec![first..first + 4]);
    assert!(st.wallet().suggest_scan_ranges().unwrap().is_empty());
    st.truncate_to_height_retaining_cache(first + 1);
    assert_eq!(covered(&st, key), vec![first..first + 2]);
    st.wallet_mut().update_chain_tip(first + 3).unwrap();
    st.scan_cached_blocks(first + 2, 2);
    assert_eq!(covered(&st, key), vec![first..first + 4]);
}

/// Registers a key after the scanner captures its keys, before its first cache read.
struct RegisterDuringScan<'a, B, F> {
    inner: &'a B,
    register: F,
    ran: Cell<bool>,
}

impl<B: BlockSource, F: Fn()> BlockSource for RegisterDuringScan<'_, B, F> {
    type Error = B::Error;

    fn with_blocks<C, E>(
        &self,
        from: Option<BlockHeight>,
        limit: Option<usize>,
        callback: C,
    ) -> Result<(), error::Error<E, Self::Error>>
    where
        C: FnMut(CompactBlock) -> Result<(), error::Error<E, Self::Error>>,
    {
        if !self.ran.replace(true) {
            (self.register)();
        }
        self.inner.with_blocks(from, limit, callback)
    }
}

#[test]
fn in_flight_scan_cannot_credit_or_erase_new_key_replay() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let (height, _) = st.generate_empty_block();
    let key = KeyId::new(Purpose::Receive, 2);
    let network = *st.network();
    let path = st.wallet().data_file_path();
    let mut scanning_db = WalletDb::for_path(path, network, test_clock(), test_rng()).unwrap();
    let source = RegisterDuringScan {
        inner: st.cache(),
        ran: Cell::new(false),
        register: || {
            let mut db = WalletDb::for_path(path, network, test_clock(), test_rng()).unwrap();
            db.watch_swap_receive_key(account, key.index(), height)
                .unwrap();
        },
    };
    scan_cached_blocks(
        &network,
        &source,
        &mut scanning_db,
        height,
        &ChainState::empty(height - 1, BlockHash([0; 32])),
        1,
    )
    .unwrap();
    assert!(covered(&st, key).is_empty());
    assert!(
        st.wallet()
            .suggest_scan_ranges()
            .unwrap()
            .iter()
            .any(|r| r.block_range().contains(&height))
    );
    st.scan_cached_blocks(height, 1);
    assert_eq!(covered(&st, key), vec![height..height + 1]);
    assert!(st.wallet().suggest_scan_ranges().unwrap().is_empty());
}

#[test]
fn empty_failed_and_uncommitted_scans_do_not_credit_coverage() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let (height, _) = st.generate_empty_block();
    let key = st
        .wallet_mut()
        .db_mut()
        .watch_swap_receive_key(account, 0, height)
        .unwrap()
        .key_id();
    assert!(st.try_scan_cached_blocks(height, 0).is_err());
    assert!(covered(&st, key).is_empty());
    let state = ChainState::empty(height - 1, BlockHash([0; 32]));
    assert!(
        st.wallet_mut()
            .db_mut()
            .put_blocks_with_swap_keys(&state, vec![], &[(account, key)])
            .is_ok()
    );
    assert!(covered(&st, key).is_empty());
    let keys = zcash_client_backend::scanning::ScanningKeys::from_account_ufvks(
        st.wallet().get_unified_full_viewing_keys().unwrap(),
    )
    .with_swap_receiving_keys(st.wallet().get_swap_scanning_keys().unwrap());
    let mut blocks = Vec::new();
    st.cache()
        .with_blocks::<_, SqliteClientError>(Some(height), Some(1), |block| {
            blocks.push(
                zcash_client_backend::scanning::scan_block(
                    st.network(),
                    block,
                    &keys,
                    &zcash_client_backend::scanning::Nullifiers::empty(),
                    None,
                )
                .unwrap(),
            );
            Ok(())
        })
        .unwrap();
    assert!(
        st.wallet_mut()
            .db_mut()
            // Fail after storing blocks and the first key's coverage.
            .put_blocks_with_swap_keys(
                &state,
                blocks,
                &[(account, key), (account, KeyId::new(Purpose::Receive, 999)),]
            )
            .is_err()
    );
    assert!(covered(&st, key).is_empty());
    assert!(st.wallet().block_metadata(height).unwrap().is_none());

    let result: Result<(), SqliteClientError> = st.wallet_mut().db_mut().transactionally(|db| {
        super::super::coverage::record(db.conn.0, &[(account, key)], height..height + 1)?;
        Err(SqliteClientError::CorruptedData("forced rollback".into()))
    });
    assert!(result.is_err());
    assert!(covered(&st, key).is_empty());
    st.scan_cached_blocks(height, 1);
    assert_eq!(covered(&st, key), vec![height..height + 1]);
}
