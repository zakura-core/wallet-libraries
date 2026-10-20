use incrementalmerkletree::frontier::Frontier;
use incrementalmerkletree::{Address, Level, Marking, Position, Retention};
use shardtree::{
    LocatedTree, PrunableTree, RetentionFlags, ShardTree,
    store::{ShardStore, memory::MemoryShardStore},
};
use zcash_protocol::consensus::BlockHeight;

use std::sync::atomic::{AtomicU64, Ordering};

use super::super::{build_subtrees, update_tree};
use super::{
    build_subtrees_except, checkpoints_pruned_on_insert, count_stored_root_mismatches,
    drop_checkpoint_retention, leave_out_shards_stored_as_root, shards_stored_as_root,
};

const MAX_CHECKPOINTS: usize = 3;

type Tree = ShardTree<MemoryShardStore<String, BlockHeight>, 6, 3>;
type Commitments = Vec<Option<(String, Retention<BlockHeight>)>>;

fn h(height: u32) -> BlockHeight {
    BlockHeight::from_u32(height)
}

/// Leaves at positions `from..to`, two to a block: the block holding position `p` is at
/// height `first_height + p / 2`, checkpointed at its second leaf. The leaf at `marked`
/// is the wallet's note.
fn leaves(from: u64, to: u64, first_height: u32, marked: Option<u64>) -> Commitments {
    (from..to)
        .map(|pos| {
            let is_marked = marked == Some(pos);
            let retention = if pos % 2 == 1 {
                Retention::Checkpoint {
                    id: h(first_height + ((pos - from) / 2) as u32),
                    marking: if is_marked {
                        Marking::Marked
                    } else {
                        Marking::None
                    },
                }
            } else if is_marked {
                Retention::Marked
            } else {
                Retention::Ephemeral
            };
            Some((((b'a' + (pos % 26) as u8) as char).to_string(), retention))
        })
        .collect()
}

fn insert(tree: &mut Tree, from: u64, mut commitments: Commitments) {
    for (subtree, checkpoints) in build_subtrees::<_, 3>(Position::from(from), &mut commitments, 4)
    {
        tree.insert_tree(subtree, checkpoints).unwrap();
    }
}

/// A tree whose positions 32..48 (heights 100..=107) were scanned first, as a chain
/// tip range is before history.
fn tip_first() -> Tree {
    let mut tree = Tree::new(MemoryShardStore::empty(), MAX_CHECKPOINTS);
    insert(&mut tree, 32, leaves(32, 48, 100, None));
    tree
}

fn checkpoints(tree: &Tree) -> Vec<(BlockHeight, Option<Position>)> {
    let mut out = vec![];
    tree.store()
        .for_each_checkpoint(usize::MAX, |id, checkpoint| {
            out.push((*id, checkpoint.position()));
            Ok(())
        })
        .unwrap();
    out
}

#[test]
fn history_without_checkpoints_leaves_the_same_tree() {
    let history = || leaves(0, 32, 10, Some(5));
    let heights = h(10)..=h(25);

    let mut with_checkpoints = tip_first();
    insert(&mut with_checkpoints, 0, history());

    let mut without = tip_first();
    assert!(checkpoints_pruned_on_insert(&without, &heights).unwrap());
    let mut downgraded = history();
    drop_checkpoint_retention(&mut downgraded);
    insert(&mut without, 0, downgraded);

    assert_eq!(checkpoints(&without), checkpoints(&with_checkpoints));
    for index in 0..6 {
        let addr = Address::from_parts(Level::from(3), index);
        assert_eq!(
            without.store().get_shard(addr).unwrap(),
            with_checkpoints.store().get_shard(addr).unwrap(),
            "shard {index}",
        );
    }
    assert_eq!(
        without.root_at_checkpoint_depth(Some(0)).unwrap(),
        with_checkpoints.root_at_checkpoint_depth(Some(0)).unwrap(),
    );
    assert_eq!(
        without
            .witness_at_checkpoint_depth(Position::from(5), 0)
            .unwrap(),
        with_checkpoints
            .witness_at_checkpoint_depth(Position::from(5), 0)
            .unwrap(),
    );
}

/// Stores each of `shards` as its root alone, as downloaded subtree roots are stored,
/// taking the roots from a tree holding the leaves at positions `0..32`.
fn store_roots(tree: &mut Tree, shards: core::ops::Range<u64>) {
    let mut reference = Tree::new(MemoryShardStore::empty(), MAX_CHECKPOINTS);
    let mut all = leaves(0, 32, 10, None);
    drop_checkpoint_retention(&mut all);
    insert(&mut reference, 0, all);
    for index in shards {
        let addr = Address::from_parts(Level::from(3), index);
        let root = reference
            .store()
            .get_shard(addr)
            .unwrap()
            .unwrap()
            .root_hash(Position::from((index + 1) * 8))
            .unwrap();
        tree.store_mut()
            .put_shard(
                LocatedTree::from_parts(
                    addr,
                    PrunableTree::leaf((root, RetentionFlags::EPHEMERAL)),
                )
                .unwrap(),
            )
            .unwrap();
    }
}

#[test]
fn note_free_shards_stored_as_roots_are_left_out() {
    // History positions 2..32: shard 0 is partial, shard 1 holds the wallet's note at
    // position 13, shards 2 and 3 hold no note.
    let history = || leaves(2, 32, 10, Some(13));
    let heights = h(10)..=h(24);

    let mut full = tip_first();
    store_roots(&mut full, 0..4);
    insert(&mut full, 2, history());

    let mut skipping = tip_first();
    store_roots(&mut skipping, 0..4);
    assert!(checkpoints_pruned_on_insert(&skipping, &heights).unwrap());
    let mut downgraded = history();
    drop_checkpoint_retention(&mut downgraded);
    let stored = leave_out_shards_stored_as_root(
        &mut skipping,
        Position::from(2),
        &downgraded,
        true,
        |_| false,
    )
    .unwrap();
    assert_eq!(stored.left_out, vec![2, 3]);
    // Shard 1 holds the note, so it is built and its stored root checked.
    assert_eq!(
        stored
            .audited
            .iter()
            .map(|(index, _)| *index)
            .collect::<Vec<_>>(),
        vec![1]
    );
    for (subtree, checkpoints) in
        build_subtrees_except::<_, 3>(Position::from(2), &mut downgraded, 4, &stored.left_out)
    {
        skipping.insert_tree(subtree, checkpoints).unwrap();
    }
    let mismatches = AtomicU64::new(0);
    count_stored_root_mismatches(&skipping, &stored.audited, &mismatches).unwrap();
    assert_eq!(mismatches.load(Ordering::Relaxed), 0);

    assert_eq!(checkpoints(&skipping), checkpoints(&full));
    for index in 0..6 {
        let addr = Address::from_parts(Level::from(3), index);
        assert_eq!(
            skipping.store().get_shard(addr).unwrap(),
            full.store().get_shard(addr).unwrap(),
            "shard {index}",
        );
    }
    assert_eq!(
        skipping.root_at_checkpoint_depth(Some(0)).unwrap(),
        full.root_at_checkpoint_depth(Some(0)).unwrap(),
    );
    assert_eq!(
        skipping
            .witness_at_checkpoint_depth(Position::from(13), 0)
            .unwrap(),
        full.witness_at_checkpoint_depth(Position::from(13), 0)
            .unwrap(),
    );
}

#[test]
fn shards_not_stored_as_roots_are_built() {
    let mut commitments = leaves(0, 32, 10, None);
    drop_checkpoint_retention(&mut commitments);

    let left_out = |tree: &Tree, commitments, allowed: bool, audited: &dyn Fn(u64) -> bool| {
        shards_stored_as_root(tree, Position::from(0), commitments, allowed, audited)
            .unwrap()
            .0
            .iter()
            .map(|shard| shard.root_addr().index())
            .collect::<Vec<_>>()
    };

    // No downloaded roots: every shard is built.
    let tree = tip_first();
    assert!(left_out(&tree, &commitments, true, &|_| false).is_empty());

    // A shard holding a leaf to keep is built even when its root is stored.
    let mut tree = tip_first();
    store_roots(&mut tree, 0..4);
    let mut with_checkpoint = commitments.clone();
    with_checkpoint[9].as_mut().unwrap().1 = Retention::Checkpoint {
        id: h(14),
        marking: Marking::None,
    };
    assert_eq!(
        left_out(&tree, &with_checkpoint, true, &|_| false),
        vec![0, 2, 3]
    );

    // Sampled shards are built, and nothing is left out once a mismatch was found.
    assert_eq!(
        left_out(&tree, &commitments, true, &|index| index == 2),
        vec![0, 1, 3]
    );
    assert!(left_out(&tree, &commitments, false, &|_| false).is_empty());

    // Leaving nothing out builds what build_subtrees builds.
    assert_eq!(
        build_subtrees_except::<_, 3>(Position::from(0), &mut commitments.clone(), 4, &[]),
        build_subtrees::<_, 3>(Position::from(0), &mut commitments, 4),
    );
}

/// Inserts history positions 2..32 over stored roots, leaving out the shards that may be
/// left out, and returns the tree with the number of stored roots found wrong.
fn insert_over_stored_roots(
    wrong_root_at: Option<u64>,
    audited: impl Fn(u64) -> bool,
) -> (Tree, Vec<u64>, u64) {
    let mut tree = tip_first();
    store_roots(&mut tree, 0..4);
    if let Some(index) = wrong_root_at {
        tree.store_mut()
            .put_shard(
                LocatedTree::from_parts(
                    Address::from_parts(Level::from(3), index),
                    PrunableTree::leaf(("wrong".to_string(), RetentionFlags::EPHEMERAL)),
                )
                .unwrap(),
            )
            .unwrap();
    }
    let mut commitments = leaves(2, 32, 10, Some(13));
    drop_checkpoint_retention(&mut commitments);
    let stored =
        leave_out_shards_stored_as_root(&mut tree, Position::from(2), &commitments, true, audited)
            .unwrap();
    for (subtree, checkpoints) in
        build_subtrees_except::<_, 3>(Position::from(2), &mut commitments, 4, &stored.left_out)
    {
        tree.insert_tree(subtree, checkpoints).unwrap();
    }
    let mismatches = AtomicU64::new(0);
    count_stored_root_mismatches(&tree, &stored.audited, &mismatches).unwrap();
    (tree, stored.left_out, mismatches.load(Ordering::Relaxed))
}

#[test]
fn sampled_shards_are_built_and_match_the_full_insertion() {
    let (sampled, left_out, mismatches) = insert_over_stored_roots(None, |index| index == 2);
    assert_eq!(left_out, vec![3]);
    assert_eq!(mismatches, 0);

    let mut full = tip_first();
    store_roots(&mut full, 0..4);
    insert(&mut full, 2, leaves(2, 32, 10, Some(13)));
    for index in 0..6 {
        let addr = Address::from_parts(Level::from(3), index);
        assert_eq!(
            sampled.store().get_shard(addr).unwrap(),
            full.store().get_shard(addr).unwrap(),
            "shard {index}",
        );
    }
}

#[test]
fn a_wrong_stored_root_is_counted_without_failing() {
    // A sampled note-free shard.
    let (_, _, mismatches) = insert_over_stored_roots(Some(2), |index| index == 2);
    assert_eq!(mismatches, 1);
    // The shard holding the note is always checked.
    let (_, _, mismatches) = insert_over_stored_roots(Some(1), |_| false);
    assert_eq!(mismatches, 1);
    // A shard left out goes unchecked.
    let (_, left_out, mismatches) = insert_over_stored_roots(Some(3), |_| false);
    assert_eq!((left_out, mismatches), (vec![2, 3], 0));
}

#[test]
fn checkpoints_kept_by_pruning_are_not_dropped() {
    let heights = h(10)..=h(25);

    // Too few newer checkpoints: the history ones would survive pruning.
    let mut few = Tree::new(MemoryShardStore::empty(), MAX_CHECKPOINTS);
    insert(&mut few, 32, leaves(32, 36, 100, None));
    assert!(!checkpoints_pruned_on_insert(&few, &heights).unwrap());

    // A retained height in the range must get its checkpoint.
    let mut retained_in_range = tip_first();
    retained_in_range.ensure_retained(h(15)).unwrap();
    assert!(!checkpoints_pruned_on_insert(&retained_in_range, &heights).unwrap());

    // Retained checkpoints sit outside the budget, so they do not count as newer.
    let mut retained_above = Tree::new(MemoryShardStore::empty(), MAX_CHECKPOINTS);
    insert(&mut retained_above, 32, leaves(32, 38, 100, None));
    retained_above.ensure_retained(h(100)).unwrap();
    assert!(!checkpoints_pruned_on_insert(&retained_above, &heights).unwrap());

    // A range above the newest checkpoints is the chain tip, not history.
    assert!(!checkpoints_pruned_on_insert(&tip_first(), &(h(200)..=h(210))).unwrap());
}

#[test]
fn dropping_checkpoint_retention_keeps_marks() {
    let mut commitments: Commitments = vec![
        Some(("a".into(), Retention::Ephemeral)),
        Some((
            "b".into(),
            Retention::Checkpoint {
                id: h(1),
                marking: Marking::None,
            },
        )),
        Some((
            "c".into(),
            Retention::Checkpoint {
                id: h(2),
                marking: Marking::Marked,
            },
        )),
        Some((
            "d".into(),
            Retention::Checkpoint {
                id: h(3),
                marking: Marking::Reference,
            },
        )),
        Some(("e".into(), Retention::Marked)),
    ];
    drop_checkpoint_retention(&mut commitments);
    assert_eq!(
        commitments
            .into_iter()
            .map(|c| c.unwrap().1)
            .collect::<Vec<_>>(),
        vec![
            Retention::Ephemeral,
            Retention::Ephemeral,
            Retention::Marked,
            Retention::Reference,
            Retention::Marked,
        ],
    );
}

#[test]
fn omitting_all_history_shards_prunes_the_empty_starting_checkpoint() {
    let mut full = tip_first();
    store_roots(&mut full, 0..4);
    let mut skipping = tip_first();
    store_roots(&mut skipping, 0..4);
    let mut commitments = leaves(0, 32, 10, None);
    let full_subtrees = build_subtrees::<_, 3>(Position::from(0), &mut commitments.clone(), 4);

    assert!(checkpoints_pruned_on_insert(&skipping, &(h(10)..=h(25))).unwrap());
    drop_checkpoint_retention(&mut commitments);
    let stored = leave_out_shards_stored_as_root(
        &mut skipping,
        Position::from(0),
        &commitments,
        true,
        |_| false,
    )
    .unwrap();
    assert_eq!(stored.left_out, vec![0, 1, 2, 3]);
    let skipped_subtrees =
        build_subtrees_except::<_, 3>(Position::from(0), &mut commitments, 4, &stored.left_out);

    for (tree, subtrees) in [
        (&mut full, full_subtrees),
        (&mut skipping, skipped_subtrees),
    ] {
        update_tree(
            "test",
            &Frontier::empty(),
            h(9),
            tree,
            None,
            subtrees.into_iter(),
            #[cfg(feature = "orchard")]
            std::iter::empty(),
        )
        .unwrap();
    }

    // An obsolete checkpoint below the scanned history makes SQLite treat a rewind into
    // that history as straddling checkpoints, rather than resetting to downloaded roots.
    assert_eq!(checkpoints(&skipping), checkpoints(&full));
    assert_eq!(checkpoints(&skipping).len(), MAX_CHECKPOINTS);
    assert!(
        checkpoints(&skipping)
            .iter()
            .all(|(height, _)| *height > h(25))
    );
    assert_eq!(
        skipping.root_at_checkpoint_depth(Some(0)).unwrap(),
        full.root_at_checkpoint_depth(Some(0)).unwrap(),
    );
}

#[test]
fn an_empty_history_batch_builds_no_subtrees() {
    let mut commitments: Commitments = vec![];
    assert!(build_subtrees_except::<_, 3>(Position::from(0), &mut commitments, 4, &[]).is_empty());
}

#[test]
fn an_empty_pool_prunes_old_checkpoints_but_keeps_retained_ones() {
    let mut tree = Tree::new(MemoryShardStore::empty(), MAX_CHECKPOINTS);
    tree.ensure_retained(h(5)).unwrap();
    for height in std::iter::once(5).chain(10..20) {
        update_tree(
            "test",
            &Frontier::empty(),
            h(height),
            &mut tree,
            None,
            std::iter::empty(),
            #[cfg(feature = "orchard")]
            std::iter::empty(),
        )
        .unwrap();
    }
    assert_eq!(
        checkpoints(&tree),
        vec![(h(5), None), (h(17), None), (h(18), None), (h(19), None)],
    );
}

#[cfg(feature = "orchard")]
#[test]
fn an_empty_pool_prunes_checkpoints_added_for_other_pools() {
    let mut tree = Tree::new(MemoryShardStore::empty(), MAX_CHECKPOINTS);
    for start in [100, 110, 120] {
        update_tree(
            "test",
            &Frontier::empty(),
            h(start),
            &mut tree,
            None,
            std::iter::empty(),
            (1..=5).map(|offset| {
                (
                    h(start + offset),
                    shardtree::store::Checkpoint::tree_empty(),
                )
            }),
        )
        .unwrap();
    }
    assert_eq!(
        checkpoints(&tree),
        vec![(h(123), None), (h(124), None), (h(125), None)],
    );
}
