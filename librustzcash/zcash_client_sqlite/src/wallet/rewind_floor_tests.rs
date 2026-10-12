//! Regression tests for `rewind_to_chain_state` on wallets whose pools pruned their oldest
//! checkpoints at different heights, with ZIP 318 anchors retained below the pruning window.
//!
//! A scan batch prunes each pool's tree after inserting that pool's own commitments and only
//! then adds the checkpoints the other pools contributed, so the pool with the most blocks of its
//! own in the batch keeps the fewest old checkpoints. Here the last scanned block carries only an
//! Ironwood output, which leaves Sapling and Orchard with one more old checkpoint than Ironwood.
#![cfg(feature = "orchard")]

use std::collections::BTreeMap;

use zcash_client_backend::{
    data_api::{
        AccountBirthday, AccountPurpose, WalletCommitmentTrees, WalletWrite,
        chain::ChainState,
        testing::{
            AddressType, FakeCompactOutput, IronwoodFvk, TestBuilder, TestFvk, TestRngCore,
            TestState, orchard::OrchardPoolTester, pool::ShieldedPoolTester,
            sapling::SaplingPoolTester,
        },
    },
    proto::compact_formats::CompactTx,
};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_primitives::block::BlockHash;
use zcash_protocol::{
    consensus::{self, BlockHeight},
    local_consensus::LocalNetwork,
    value::Zatoshis,
};

use crate::testing::{
    BlockCache,
    db::{TestDb, TestDbFactory},
};

type State = TestState<BlockCache, TestDb, LocalNetwork>;

const CHAIN_START: u32 = 100_000;
const CHAIN_LEN: u32 = 300;

/// A recipient in any one of the three shielded pools, so that one block can carry outputs of
/// several pools (`FakeCompactOutput` is generic over a single `TestFvk`).
#[derive(Clone)]
enum PoolFvk {
    Sapling(Box<<SaplingPoolTester as ShieldedPoolTester>::Fvk>),
    Orchard(<OrchardPoolTester as ShieldedPoolTester>::Fvk),
    Ironwood(IronwoodFvk),
}

impl TestFvk for PoolFvk {
    type Nullifier = ();
    type OutgoingViewingKey = ();

    fn to_ovk(&self, _: zip32::Scope) -> Self::OutgoingViewingKey {}

    fn ovk_bytes(&self, _: zip32::Scope) -> [u8; 32] {
        [0; 32]
    }

    fn add_spend<R: TestRngCore>(&self, _: &mut CompactTx, _: (), _: &mut R) {
        unimplemented!("these tests only create outputs")
    }

    fn add_output<P: consensus::Parameters, R: TestRngCore>(
        &self,
        ctx: &mut CompactTx,
        params: &P,
        height: BlockHeight,
        _: Option<&()>,
        recipient_address_type: AddressType,
        value: Zatoshis,
        initial_sapling_tree_size: u32,
        rng: &mut R,
    ) {
        match self {
            PoolFvk::Sapling(fvk) => {
                TestFvk::add_output(
                    fvk.as_ref(),
                    ctx,
                    params,
                    height,
                    None,
                    recipient_address_type,
                    value,
                    initial_sapling_tree_size,
                    rng,
                );
            }
            PoolFvk::Orchard(fvk) => {
                TestFvk::add_output(
                    fvk,
                    ctx,
                    params,
                    height,
                    None,
                    recipient_address_type,
                    value,
                    initial_sapling_tree_size,
                    rng,
                );
            }
            PoolFvk::Ironwood(fvk) => {
                TestFvk::add_output(
                    fvk,
                    ctx,
                    params,
                    height,
                    None,
                    recipient_address_type,
                    value,
                    initial_sapling_tree_size,
                    rng,
                );
            }
        }
    }

    fn add_logical_action<P: consensus::Parameters, R: TestRngCore>(
        &self,
        _: &mut CompactTx,
        _: &P,
        _: BlockHeight,
        _: (),
        _: Option<&()>,
        _: AddressType,
        _: Zatoshis,
        _: u32,
        _: &mut R,
    ) {
        unimplemented!("these tests only create outputs")
    }
}

fn out(fvk: &PoolFvk) -> FakeCompactOutput<PoolFvk> {
    FakeCompactOutput::new(
        fvk.clone(),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(10_000),
    )
}

/// Builds a wallet on a network with NU6.3 (and so ZIP 318 anchor retention, every 144 blocks)
/// active from `CHAIN_START`, and caches `CHAIN_LEN` blocks paying keys the wallet does not hold.
/// Every block carries one Sapling, one Orchard and one Ironwood output, except the last
/// `ironwood_only_tail` blocks, which carry only an Ironwood output. Scans the chain in batches
/// of `batch` blocks.
fn synced_wallet(ironwood_only_tail: u32, batch: u32) -> (State, BTreeMap<u32, ChainState>) {
    let activation = BlockHeight::from_u32(CHAIN_START);
    let mut st = TestBuilder::new()
        .with_network(LocalNetwork {
            nu6: Some(activation),
            nu6_1: Some(activation),
            nu6_2: Some(activation),
            nu6_3: Some(activation),
            ..TestBuilder::<(), ()>::DEFAULT_NETWORK
        })
        .with_data_store_factory(TestDbFactory::default())
        .with_block_cache(BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();
    let sapling = PoolFvk::Sapling(Box::new(SaplingPoolTester::sk_to_fvk(
        &SaplingPoolTester::sk(&[0xf5; 32]),
    )));
    let orchard = PoolFvk::Orchard(OrchardPoolTester::sk_to_fvk(&OrchardPoolTester::sk(
        &[0xf5; 32],
    )));
    let ironwood = PoolFvk::Ironwood(IronwoodFvk(OrchardPoolTester::sk_to_fvk(
        &OrchardPoolTester::sk(&[0xf6; 32]),
    )));

    let mut chain_states = BTreeMap::new();
    for off in 0..CHAIN_LEN {
        let outputs = if off + ironwood_only_tail >= CHAIN_LEN {
            vec![out(&ironwood)]
        } else {
            vec![out(&sapling), out(&orchard), out(&ironwood)]
        };
        let (h, _, _) = st.generate_next_block_multi(&outputs);
        chain_states.insert(
            u32::from(h),
            st.latest_cached_block().unwrap().chain_state().clone(),
        );
    }
    scan(&mut st, 0, CHAIN_LEN, batch);
    (st, chain_states)
}

/// Scans the cached blocks at offsets `[from, to)` from `CHAIN_START` in batches of `batch`.
fn scan(st: &mut State, from: u32, to: u32, batch: u32) {
    let mut start = from;
    while start < to {
        let count = batch.min(to - start);
        st.scan_cached_blocks(BlockHeight::from_u32(CHAIN_START + start), count as usize);
        start += count;
    }
}

/// Imports a view-only account with birthday `CHAIN_START + 10`, as an application does for
/// each account it restores. `add_account` rewinds to the chain state before the birthday.
fn import(
    st: &mut State,
    chain_states: &BTreeMap<u32, ChainState>,
    seed: u8,
) -> Result<(), String> {
    let birthday = AccountBirthday::from_parts(chain_states[&(CHAIN_START + 9)].clone(), None);
    let usk =
        UnifiedSpendingKey::from_seed(st.network(), &[seed; 32], zip32::AccountId::ZERO).unwrap();
    st.wallet_mut()
        .import_account_ufvk(
            "imported",
            &usk.to_unified_full_viewing_key(),
            &birthday,
            AccountPurpose::ViewOnly,
            None,
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn max_scanned(st: &State) -> Option<u32> {
    st.wallet()
        .conn()
        .query_row("SELECT MAX(height) FROM blocks", [], |row| row.get(0))
        .unwrap()
}

/// Asserts that every pool's tree has, at its checkpoint for `height`, the root of the chain's
/// note commitment tree after block `height`.
fn assert_roots_match_chain(st: &mut State, chain_states: &BTreeMap<u32, ChainState>, height: u32) {
    type TreeError = shardtree::error::ShardTreeError<crate::wallet::commitment_tree::Error>;
    let h = BlockHeight::from_u32(height);
    let chain = &chain_states[&height];
    let sapling = st
        .wallet_mut()
        .with_sapling_tree_mut(|t| -> Result<_, TreeError> { t.root_at_checkpoint_id(&h) })
        .unwrap();
    assert_eq!(sapling, Some(chain.final_sapling_tree().root()));
    let orchard = st
        .wallet_mut()
        .with_orchard_tree_mut(|t| -> Result<_, TreeError> { t.root_at_checkpoint_id(&h) })
        .unwrap();
    assert_eq!(orchard, Some(chain.final_orchard_tree().root()));
    let ironwood = st
        .wallet_mut()
        .with_ironwood_tree_mut(|t| -> Result<_, TreeError> { t.root_at_checkpoint_id(&h) })
        .unwrap();
    assert_eq!(ironwood, Some(Some(chain.final_ironwood_tree().root())));
}

/// Two accounts imported back to back, with no scan in between. The first rewind truncates the
/// wallet to its pruning floor. The second must use the same floor, which the chain tip still
/// determines: a floor taken from the lowered `MAX(blocks.height)` lands below Ironwood's oldest
/// ordinary checkpoint, where only Sapling and Orchard retain one, while Ironwood still retains
/// an anchor further down. Before the fix the second import failed with "Data DB is corrupted:
/// the Ironwood note commitment tree retains checkpoints both above and below height 100198, but
/// none at that height to truncate to".
#[test]
fn successive_imports_without_a_scan_share_the_pruning_floor() {
    let (mut st, chain_states) = synced_wallet(1, 10);
    let tip = CHAIN_START + CHAIN_LEN - 1;

    assert_eq!(import(&mut st, &chain_states, 0x40), Ok(()));
    assert_eq!(max_scanned(&st), Some(tip - 99));
    assert_eq!(import(&mut st, &chain_states, 0x41), Ok(()));
    assert_eq!(max_scanned(&st), Some(tip - 99));

    // The rescan the imports queued restores every tree to the chain's state.
    scan(&mut st, 10, CHAIN_LEN, 10);
    assert_roots_match_chain(&mut st, &chain_states, tip);
    assert_eq!(import(&mut st, &chain_states, 0x42), Ok(()));
}

/// Reorg handling (`truncate_to_height`) lowers the wallet's view of the chain tip along with
/// `MAX(blocks.height)` until the next `update_chain_tip`, so an import in between rewinds from
/// a floor below Ironwood's oldest ordinary checkpoint. The rewind must truncate at the deepest
/// height that no pool's checkpoints straddle.
#[test]
fn import_after_reorg_truncation_skips_heights_a_pool_straddles() {
    let (mut st, chain_states) = synced_wallet(30, CHAIN_LEN);
    let tip = CHAIN_START + CHAIN_LEN - 1;
    let truncated = st
        .wallet_mut()
        .truncate_to_height(BlockHeight::from_u32(tip - 10))
        .unwrap();
    assert_eq!(u32::from(truncated), tip - 10);

    assert_eq!(import(&mut st, &chain_states, 0x40), Ok(()));
    // Sapling and Orchard retain checkpoints down to `tip - 130`, Ironwood (besides anchors)
    // only down to `tip - 100`, which is where the truncation lands.
    assert_eq!(max_scanned(&st), Some(tip - 100));

    scan(&mut st, 10, CHAIN_LEN, 100);
    assert_roots_match_chain(&mut st, &chain_states, tip);
}
