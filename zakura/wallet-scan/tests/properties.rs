//! Property tests for the detection pass.
//!
//! These assert invariants that must hold for *every* block layout, not just
//! the hand-written ones in `detect.rs`. The most important is the last:
//! removing any single action from any block must always produce an error, and
//! must never produce a result with silently shifted positions.

use proptest::prelude::*;
use zakura_wallet_core::pool::{PoolId, TreeSizes};
use zakura_wallet_scan::{
    AccountId, DetectedBatch, KeyScope, NullifierSnapshot, ScanError, ScanKeys,
    detect_batch,
    testing::{ChainBuilder, IRONWOOD_ACTIVATION, fvk_from_seed, test_params},
};

const ALICE: AccountId = AccountId(1);
const START: u32 = IRONWOOD_ACTIVATION + 10;

/// One action in a generated block.
#[derive(Debug, Clone, Copy)]
enum Action {
    /// A note paying this wallet.
    Ours(PoolId, KeyScope),
    /// A note paying somebody else, or a padding dummy.
    Decoy(PoolId),
}

impl Action {
    fn pool(self) -> PoolId {
        match self {
            Action::Ours(pool, _) | Action::Decoy(pool) => pool,
        }
    }

    fn is_ours(self) -> bool {
        matches!(self, Action::Ours(..))
    }
}

/// A generated chain layout: blocks, each a list of transactions, each a list
/// of actions.
type Layout = Vec<Vec<Vec<Action>>>;

fn arb_pool() -> impl Strategy<Value = PoolId> {
    prop_oneof![Just(PoolId::Orchard), Just(PoolId::Ironwood)]
}

fn arb_action() -> impl Strategy<Value = Action> {
    prop_oneof![
        3 => arb_pool().prop_map(Action::Decoy),
        2 => (arb_pool(), prop_oneof![Just(KeyScope::External), Just(KeyScope::Internal)])
            .prop_map(|(pool, scope)| Action::Ours(pool, scope)),
    ]
}

fn arb_layout() -> impl Strategy<Value = Layout> {
    prop::collection::vec(
        prop::collection::vec(prop::collection::vec(arb_action(), 0..4), 0..3),
        1..4,
    )
}

/// A layout guaranteed to contain at least one action.
fn arb_nonempty_layout() -> impl Strategy<Value = Layout> {
    arb_layout().prop_filter("layout must contain at least one action", |layout| {
        layout.iter().flatten().any(|tx| !tx.is_empty())
    })
}

fn build(layout: &Layout, anchor_sizes: TreeSizes) -> ChainBuilder {
    let alice = fvk_from_seed(1);
    let mut chain = ChainBuilder::with_anchor(START, anchor_sizes);
    for block in layout {
        chain.block(|b| {
            for tx in block {
                b.tx(|t| {
                    for action in tx {
                        match *action {
                            Action::Ours(pool, scope) => {
                                t.receive(pool, &alice, scope, 1_000);
                            }
                            Action::Decoy(pool) => {
                                t.decoy(pool, 1_000);
                            }
                        }
                    }
                });
            }
        });
    }
    chain
}

fn keys() -> ScanKeys {
    ScanKeys::from_accounts([(ALICE, fvk_from_seed(1))])
}

fn run(chain: &ChainBuilder, keys: &ScanKeys) -> Result<DetectedBatch, ScanError> {
    detect_batch(
        &test_params(),
        keys,
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
}

/// Counts the actions of `pool` that precede the action at
/// `(block, tx, index)` in the whole layout.
fn preceding_in_pool(layout: &Layout, pool: PoolId, block: usize, tx: usize, index: usize) -> u64 {
    let mut count = 0u64;
    for (b, blk) in layout.iter().enumerate() {
        for (t, actions) in blk.iter().enumerate() {
            for (a, action) in actions.iter().enumerate() {
                if (b, t, a) == (block, tx, index) {
                    return count;
                }
                if action.pool() == pool {
                    count += 1;
                }
            }
        }
    }
    count
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Every note planted for this wallet is found, and nothing else is.
    #[test]
    fn every_planted_note_is_found(layout in arb_layout()) {
        let chain = build(&layout, TreeSizes::default());
        let batch = run(&chain, &keys()).expect("a well-formed chain detects cleanly");

        let expected = layout.iter().flatten().flatten().filter(|a| a.is_ours()).count();
        prop_assert_eq!(batch.received_notes().count(), expected);

        for note in batch.received_notes() {
            prop_assert_eq!(note.account, ALICE);
            prop_assert_eq!(note.note.value().inner(), 1_000);
        }
    }

    /// A note's position is exactly the number of same-pool actions before it,
    /// offset by the anchor's tree size.
    #[test]
    fn positions_count_preceding_actions_in_the_same_pool(
        layout in arb_layout(),
        orchard_offset in 0u32..5_000,
        ironwood_offset in 0u32..5_000,
    ) {
        let anchor_sizes = TreeSizes { orchard: orchard_offset, ironwood: ironwood_offset };
        let chain = build(&layout, anchor_sizes);
        let batch = run(&chain, &keys()).expect("a well-formed chain detects cleanly");

        // Walk the layout and the results in the same order; both are ordered by
        // block, then transaction, then action.
        let mut expected = Vec::new();
        for (b, blk) in layout.iter().enumerate() {
            for (t, actions) in blk.iter().enumerate() {
                // Detection reports a transaction's Orchard notes before its
                // Ironwood ones, so mirror that grouping here.
                for pool in [PoolId::Orchard, PoolId::Ironwood] {
                    for (a, action) in actions.iter().enumerate() {
                        if action.is_ours() && action.pool() == pool {
                            let offset = u64::from(anchor_sizes.get(pool));
                            expected.push(offset + preceding_in_pool(&layout, pool, b, t, a));
                        }
                    }
                }
            }
        }

        let actual: Vec<u64> = batch.received_notes().map(|n| n.position.into()).collect();
        prop_assert_eq!(actual, expected);
    }

    /// Every action contributes exactly one commitment to its pool, and the
    /// reported tree sizes agree with the blocks.
    #[test]
    fn commitments_account_for_every_action(layout in arb_layout()) {
        let chain = build(&layout, TreeSizes::default());
        let batch = run(&chain, &keys()).expect("a well-formed chain detects cleanly");

        for (detected, block) in batch.blocks.iter().zip(chain.blocks()) {
            for (pool, actions) in [
                (PoolId::Orchard, block.txs.iter().map(|t| t.orchard_actions.len()).sum::<usize>()),
                (PoolId::Ironwood, block.txs.iter().map(|t| t.ironwood_actions.len()).sum::<usize>()),
            ] {
                prop_assert_eq!(detected.commitments(pool).commitments.len(), actions);
            }
            prop_assert_eq!(detected.tree_sizes, block.tree_sizes);
            prop_assert_eq!(detected.orchard.final_tree_size, block.tree_sizes.orchard);
            prop_assert_eq!(detected.ironwood.final_tree_size, block.tree_sizes.ironwood);
        }
    }

    /// Scanning a run of blocks in one call, or in two calls chained through
    /// the intermediate anchor, gives the same answer.
    ///
    /// This is what makes a batch a safe unit of work: the engine can stop
    /// between any two blocks and resume without changing the outcome.
    #[test]
    fn splitting_a_batch_does_not_change_the_result(layout in arb_layout()) {
        let chain = build(&layout, TreeSizes::default());
        let keys = keys();
        let blocks = chain.blocks();
        let whole = run(&chain, &keys).expect("a well-formed chain detects cleanly");

        for split in 0..=blocks.len() {
            let (head, tail) = blocks.split_at(split);
            let first = detect_batch(
                &test_params(), &keys,
                &NullifierSnapshot::default(), &chain.anchor(), head,
            ).expect("the first half detects cleanly");
            let second = detect_batch(
                &test_params(), &keys,
                &NullifierSnapshot::default(), &first.end_anchor, tail,
            ).expect("the second half detects cleanly");

            let rejoined: Vec<_> = first.blocks.iter().chain(second.blocks.iter()).collect();
            let expected: Vec<_> = whole.blocks.iter().collect();
            prop_assert_eq!(rejoined, expected, "split at {}", split);
            prop_assert_eq!(&second.end_anchor, &whole.end_anchor);
        }
    }

    /// A wallet with no keys finds nothing, but still tracks the trees.
    #[test]
    fn without_keys_nothing_is_detected_but_the_trees_still_advance(layout in arb_layout()) {
        let chain = build(&layout, TreeSizes::default());
        let with_keys = run(&chain, &keys()).expect("detects cleanly");
        let without = run(&chain, &ScanKeys::from_accounts([])).expect("detects cleanly");

        prop_assert_eq!(without.received_notes().count(), 0);
        prop_assert_eq!(&without.end_anchor, &with_keys.end_anchor);
        for (a, b) in without.blocks.iter().zip(with_keys.blocks.iter()) {
            prop_assert_eq!(a.orchard.commitments.len(), b.orchard.commitments.len());
            prop_assert_eq!(a.ironwood.commitments.len(), b.ironwood.commitments.len());
        }
    }

    /// Removing any single action from any block is always an error.
    ///
    /// This is the invariant that protects every witness the wallet will ever
    /// build. A source that drops one action shifts the position of every note
    /// after it; if detection accepted that, the notes would still decrypt and
    /// the balances would still look right, and the damage would only surface
    /// when a spend proof was rejected. Detection must never return `Ok` here.
    #[test]
    fn dropping_any_action_is_always_an_error(
        layout in arb_nonempty_layout(),
        victim in 0usize..64,
    ) {
        let chain = build(&layout, TreeSizes::default());
        let anchor = chain.anchor();
        let mut blocks = chain.into_blocks();

        // Enumerate every action position in the built blocks, then remove one.
        let mut sites = Vec::new();
        for (b, block) in blocks.iter().enumerate() {
            for (t, tx) in block.txs.iter().enumerate() {
                for a in 0..tx.orchard_actions.len() {
                    sites.push((b, t, PoolId::Orchard, a));
                }
                for a in 0..tx.ironwood_actions.len() {
                    sites.push((b, t, PoolId::Ironwood, a));
                }
            }
        }
        prop_assume!(!sites.is_empty());

        let (b, t, pool, a) = sites[victim % sites.len()];
        match pool {
            PoolId::Orchard => { blocks[b].txs[t].orchard_actions.remove(a); }
            PoolId::Ironwood => { blocks[b].txs[t].ironwood_actions.remove(a); }
        }

        let result = detect_batch(
            &test_params(), &keys(),
            &NullifierSnapshot::default(), &anchor, &blocks,
        );

        match result {
            Err(ScanError::TreeSizeMismatch { pool: reported, at_height, given, computed }) => {
                prop_assert_eq!(reported, pool);
                prop_assert_eq!(at_height, blocks[b].height);
                prop_assert_eq!(given, computed + 1);
            }
            Err(other) => prop_assert!(false, "unexpected error: {other}"),
            Ok(_) => prop_assert!(
                false,
                "dropping action {a} of pool {pool:?} in block {b} tx {t} went undetected",
            ),
        }
    }

    /// Detection of a well-formed chain never fails.
    #[test]
    fn well_formed_chains_never_error(layout in arb_layout()) {
        let chain = build(&layout, TreeSizes::default());
        prop_assert!(run(&chain, &keys()).is_ok());
    }
}
