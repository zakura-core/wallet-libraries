//! Cached replay uses real encrypted compact notes and the ordinary persistence path.
use super::*;
use zcash_client_backend::data_api::{
    chain::{BlockSource, scan_cached_blocks_with_recovery},
    one_time_ivk::recovery::{
        BlockHints, FilterJudgment, History, OneTimeRecoveryRead, OneTimeRecoveryWrite,
        cache::{MAX_CACHE_BYTES, RecentBlocks},
    },
};

/// A late filter replays retained bytes with real predecessor trees and settles its obligation.
#[test]
fn cached_replay_settles_a_match_without_a_network_source() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    check_seen(st.wallet_mut().db_mut(), account);
    st.wallet_mut()
        .accept_one_time_history(
            account,
            History {
                genesis: [1; 32],
                archive: [2; 32],
                epoch: 0,
            },
        )
        .unwrap();
    let ordinary = IronwoodFvk(parent(&st));
    let (first, _, _) = st.generate_next_block(
        &ordinary,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(60_000),
    );
    let first_point = ChainPoint {
        height: first,
        hash: st.latest_cached_block().unwrap().chain_state().block_hash(),
    };
    st.scan_cached_blocks_with_recovery(first, 1, &[]);
    let predecessor = st.latest_cached_block().unwrap().chain_state().clone();
    let key = KeyId::new(Purpose::Receive, 0);
    let recipient = IronwoodFvk(derive(&st, key));
    let (height, _, _) = st.generate_next_block(
        &recipient,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(50_000),
    );
    let point = ChainPoint {
        height,
        hash: st.latest_cached_block().unwrap().chain_state().block_hash(),
    };
    st.scan_cached_blocks_with_recovery(height, 1, &[]);
    let mut cache = RecentBlocks::new(MAX_CACHE_BYTES);
    st.cache()
        .with_blocks::<_, SqliteClientError>(Some(height), Some(1), |block| {
            assert!(cache.insert(&block, &predecessor).unwrap());
            Ok(())
        })
        .unwrap();
    for _ in 0..2 {
        let prior = st.latest_cached_block().unwrap().chain_state().clone();
        let (next, _) = st.generate_empty_block();
        st.scan_cached_blocks_with_recovery(next, 1, &[]);
        st.cache()
            .with_blocks::<_, SqliteClientError>(Some(next), Some(1), |block| {
                assert!(cache.insert(&block, &prior).unwrap());
                Ok(())
            })
            .unwrap();
    }
    let work = st
        .wallet()
        .one_time_filter_work(account, 1024)
        .unwrap()
        .unwrap();
    assert!(
        st.wallet_mut()
            .record_one_time_filters(
                account,
                &work,
                &[
                    FilterJudgment {
                        block: first_point,
                        hits: vec![]
                    },
                    FilterJudgment {
                        block: point,
                        hits: vec![key]
                    },
                ]
            )
            .unwrap()
    );
    let pending = st.wallet().one_time_pending_matches(account, 1024).unwrap();
    assert_eq!(pending.len(), 1);
    let replay = cache.get(point).unwrap().unwrap();
    let network = *st.network();
    scan_cached_blocks_with_recovery(
        &network,
        &replay,
        st.wallet_mut(),
        height,
        &replay.predecessor,
        1,
        &[BlockHints {
            block: point,
            keys: vec![(account, key)],
        }],
    )
    .unwrap();
    assert_eq!(unspent_keys(&st, height + 2).len(), 2);
    assert!(
        st.wallet()
            .one_time_pending_matches(account, 1024)
            .unwrap()
            .is_empty()
    );
    assert_eq!(cache.blocks().count(), 3);
    assert!(cache.retained_bytes() <= MAX_CACHE_BYTES);
}
