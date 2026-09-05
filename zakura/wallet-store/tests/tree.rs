//! Tests for the pool-keyed commitment tree store.
//!
//! The load-bearing assertion is `a_witness_verifies_against_an_independent_root`:
//! it recomputes the tree root by hand from a leaf and its witness path, and
//! checks that against the root the tree reports. A store that returned
//! plausible-looking but wrong witnesses would pass every other test here and
//! produce spend proofs that consensus rejects.

use assert_matches::assert_matches;
use incrementalmerkletree::{Hashable, Level, Marking, Position, Retention};
use orchard::tree::MerkleHashOrchard;
use shardtree::store::ShardStore;
use zakura_wallet_core::pool::PoolId;
use zakura_wallet_store::{Error, TREE_DEPTH, TreeError, WalletDb, testing::test_db};
use zcash_protocol::consensus::BlockHeight;

/// A distinct, valid tree node for each `i`.
fn leaf(i: u64) -> MerkleHashOrchard {
    let mut repr = [0u8; 32];
    repr[..8].copy_from_slice(&i.to_le_bytes());
    // The top bits are cleared so the value is always a canonical Pallas base
    // field element.
    repr[31] = 0;
    Option::from(MerkleHashOrchard::from_bytes(&repr)).expect("a canonical field element")
}

fn h(n: u32) -> BlockHeight {
    BlockHeight::from_u32(n)
}

/// Appends `leaves` to `pool`'s tree, checkpointing at `height` after each
/// block of them, and marking the positions in `marked`.
fn append_block(
    db: &mut WalletDb,
    pool: PoolId,
    height: BlockHeight,
    leaves: impl IntoIterator<Item = (u64, bool)>,
) -> Result<(), TreeError> {
    let leaves: Vec<_> = leaves.into_iter().collect();
    let last = leaves.len() - 1;
    db.with_tree_for(pool, |tree| {
        for (i, (value, marked)) in leaves.iter().enumerate() {
            let retention = if i == last {
                Retention::Checkpoint {
                    id: height,
                    marking: if *marked {
                        Marking::Marked
                    } else {
                        Marking::None
                    },
                }
            } else if *marked {
                Retention::Marked
            } else {
                Retention::Ephemeral
            };
            tree.append(leaf(*value), retention)?;
        }
        Ok(())
    })
}

// -------------------------------------------------------------- schema

#[test]
fn a_new_wallet_has_exactly_the_declared_schema() {
    let db = test_db().unwrap();

    let mut stmt = db
        .connection()
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .unwrap();
    let durable: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();

    let mut stmt = db
        .connection()
        .prepare("SELECT name FROM cache.sqlite_master WHERE type = 'table' ORDER BY name")
        .unwrap();
    let derived: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();

    assert_eq!(durable, zakura_wallet_store::schema::DURABLE_TABLES);
    assert_eq!(derived, zakura_wallet_store::schema::DERIVED_TABLES);
}

#[test]
fn the_two_halves_are_separate_databases() {
    // The whole migration strategy depends on the derived half being separately
    // droppable, which requires it to be a separate file.
    let db = test_db().unwrap();
    let count: u32 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM pragma_database_list WHERE name = 'cache'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);

    // Durable tables are not in the cache schema, and vice versa.
    let in_cache: u32 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM cache.sqlite_master WHERE name = 'accounts'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(in_cache, 0);
}

#[test]
fn schema_versions_are_recorded_on_creation() {
    let db = test_db().unwrap();
    assert_eq!(
        db.meta_u32("detection_version").unwrap(),
        Some(zakura_wallet_store::schema::DETECTION_VERSION)
    );
    assert_eq!(
        db.meta_u32("layout_version").unwrap(),
        Some(zakura_wallet_store::schema::LAYOUT_VERSION)
    );
    assert_eq!(
        db.meta_u32("tree_version").unwrap(),
        Some(zakura_wallet_store::schema::TREE_VERSION)
    );
}

#[test]
fn a_version_mismatch_names_its_remedy() {
    use zakura_wallet_store::VersionKind;

    // Each version carries a different cost, which is the entire reason there
    // are three of them rather than one.
    for (key, kind, remedy) in [
        (
            "detection_version",
            VersionKind::Detection,
            "rescan the chain",
        ),
        ("layout_version", VersionKind::Layout, "rebuild the derived"),
        ("tree_version", VersionKind::Tree, "refetch subtree roots"),
    ] {
        let dir = tempdir();
        let (wallet, cache) = (dir.join("wallet.db"), dir.join("cache.db"));

        let mut db = WalletDb::open(&wallet, &cache).unwrap();
        db.set_meta_u32(key, 99).unwrap();
        drop(db);

        let err = WalletDb::open(&wallet, &cache).unwrap_err();
        assert_matches!(
            err,
            Error::VersionMismatch { kind: k, found: 99, .. } if k == kind
        );
        assert!(err.to_string().contains(remedy), "{err}");
        assert_eq!(kind.remedy(), kind.remedy());
    }
}

#[test]
fn a_wallet_reopens_without_losing_anything() {
    let dir = tempdir();
    let (wallet, cache) = (dir.join("wallet.db"), dir.join("cache.db"));

    let mut db = WalletDb::open(&wallet, &cache).unwrap();
    append_block(&mut db, PoolId::Ironwood, h(10), [(1, true), (2, false)]).unwrap();
    let root = db
        .with_tree_for(PoolId::Ironwood, |tree| {
            Ok(tree.root_at_checkpoint_id(&h(10))?)
        })
        .unwrap();
    drop(db);

    let mut db = WalletDb::open(&wallet, &cache).unwrap();
    let reopened = db
        .with_tree_for(PoolId::Ironwood, |tree| {
            Ok(tree.root_at_checkpoint_id(&h(10))?)
        })
        .unwrap();
    assert_eq!(reopened, root);
}

// ---------------------------------------------------------------- trees

#[test]
fn a_witness_verifies_against_an_independent_root() {
    // Recompute the root by hand from the leaf and its authentication path,
    // and check it against the root the tree reports. This is what a verifier
    // does with a spend proof, so it is the only check that proves the stored
    // witnesses are usable.
    for pool in PoolId::ALL {
        let mut db = test_db().unwrap();

        // Three blocks, with a marked leaf in the middle one.
        append_block(&mut db, pool, h(1), [(0, false), (1, false)]).unwrap();
        append_block(&mut db, pool, h(2), [(2, false), (3, true), (4, false)]).unwrap();
        append_block(&mut db, pool, h(3), [(5, false)]).unwrap();

        let marked = Position::from(3);
        let (path, root) = db
            .with_tree_for(pool, |tree| {
                let path = tree
                    .witness_at_checkpoint_id(marked, &h(3))?
                    .expect("the marked leaf has a witness");
                let root = tree
                    .root_at_checkpoint_id(&h(3))?
                    .expect("checkpoint 3 has a root");
                Ok((path, root))
            })
            .unwrap();

        assert_eq!(path.position(), marked);
        assert_eq!(path.path_elems().len(), usize::from(TREE_DEPTH));

        // Fold the path into a root, exactly as a verifier would.
        let mut node = leaf(3);
        let mut index = u64::from(marked);
        for (level, sibling) in path.path_elems().iter().enumerate() {
            let level = Level::from(level as u8);
            node = if index & 1 == 0 {
                MerkleHashOrchard::combine(level, &node, sibling)
            } else {
                MerkleHashOrchard::combine(level, sibling, &node)
            };
            index >>= 1;
        }

        assert_eq!(node, root, "recomputed root disagrees for {pool:?}");
    }
}

#[test]
fn an_empty_tree_has_the_empty_root() {
    let mut db = test_db().unwrap();
    let root = db
        .with_tree_for(PoolId::Orchard, |tree| {
            Ok(tree.root(
                incrementalmerkletree::Address::from_parts(Level::from(TREE_DEPTH), 0),
                Position::from(0),
            )?)
        })
        .unwrap();
    assert_eq!(root, MerkleHashOrchard::empty_root(Level::from(TREE_DEPTH)));
}

#[test]
fn the_two_pools_do_not_see_each_others_trees() {
    // The pool is a column, not a table name, so this is the assertion that the
    // key actually separates them.
    let mut db = test_db().unwrap();

    append_block(&mut db, PoolId::Orchard, h(1), [(10, true)]).unwrap();
    append_block(&mut db, PoolId::Ironwood, h(1), [(20, true), (21, true)]).unwrap();

    let orchard_max = db
        .with_tree_for(PoolId::Orchard, |tree| {
            Ok(tree.max_leaf_position(None)?)
        })
        .unwrap();
    let ironwood_max = db
        .with_tree_for(PoolId::Ironwood, |tree| {
            Ok(tree.max_leaf_position(None)?)
        })
        .unwrap();

    assert_eq!(orchard_max, Some(Position::from(0)));
    assert_eq!(ironwood_max, Some(Position::from(1)));

    let orchard_root = db
        .with_tree_for(PoolId::Orchard, |tree| {
            Ok(tree.root_at_checkpoint_id(&h(1))?)
        })
        .unwrap();
    let ironwood_root = db
        .with_tree_for(PoolId::Ironwood, |tree| {
            Ok(tree.root_at_checkpoint_id(&h(1))?)
        })
        .unwrap();
    assert_ne!(orchard_root, ironwood_root);
}

#[test]
fn marked_positions_are_retained_per_pool() {
    let mut db = test_db().unwrap();
    append_block(
        &mut db,
        PoolId::Ironwood,
        h(1),
        [(0, true), (1, false), (2, true)],
    )
    .unwrap();

    let marked = db
        .with_tree_for(PoolId::Ironwood, |tree| {
            Ok(tree.marked_positions()?)
        })
        .unwrap();
    assert_eq!(
        marked.into_iter().collect::<Vec<_>>(),
        vec![Position::from(0), Position::from(2)]
    );

    let other = db
        .with_tree_for(PoolId::Orchard, |tree| {
            Ok(tree.marked_positions()?)
        })
        .unwrap();
    assert!(other.is_empty());
}

// ----------------------------------------------------------- truncation

#[test]
fn truncating_to_a_checkpoint_round_trips() {
    // A rewind must restore the tree exactly as it was, or every witness built
    // afterwards is anchored to a tree that never existed.
    for pool in PoolId::ALL {
        let mut db = test_db().unwrap();

        append_block(&mut db, pool, h(1), [(0, true), (1, false)]).unwrap();
        append_block(&mut db, pool, h(2), [(2, false), (3, true)]).unwrap();

        let (root_at_2, witness_at_2) = db
            .with_tree_for(pool, |tree| {
                Ok((
                    tree.root_at_checkpoint_id(&h(2))?,
                    tree.witness_at_checkpoint_id(Position::from(0), &h(2))?,
                ))
            })
            .unwrap();

        // Extend past the checkpoint, then rewind back to it.
        append_block(&mut db, pool, h(3), [(4, true), (5, true)]).unwrap();
        let truncated = db
            .with_tree_for(pool, |tree| {
                Ok(tree.truncate_to_checkpoint(&h(2))?)
            })
            .unwrap();
        assert!(truncated, "{pool:?}");

        let (root_after, witness_after, max_position, count) = db
            .with_tree_for(pool, |tree| {
                Ok((
                    tree.root_at_checkpoint_id(&h(2))?,
                    tree.witness_at_checkpoint_id(Position::from(0), &h(2))?,
                    tree.max_leaf_position(None)?,
                    tree.store().checkpoint_count()?,
                ))
            })
            .unwrap();

        assert_eq!(root_after, root_at_2, "{pool:?}");
        assert_eq!(witness_after, witness_at_2, "{pool:?}");
        assert_eq!(max_position, Some(Position::from(3)), "{pool:?}");
        assert_eq!(count, 2, "{pool:?}: checkpoint 3 should be gone");

        // The tree is usable again: appending after a rewind works.
        append_block(&mut db, pool, h(3), [(9, true)]).unwrap();
        let max = db
            .with_tree_for(pool, |tree| {
                Ok(tree.max_leaf_position(None)?)
            })
            .unwrap();
        assert_eq!(max, Some(Position::from(4)), "{pool:?}");
    }
}

#[test]
fn truncating_to_an_unknown_checkpoint_changes_nothing() {
    let mut db = test_db().unwrap();
    append_block(&mut db, PoolId::Orchard, h(1), [(0, true)]).unwrap();

    let (truncated, max) = db
        .with_tree_for(PoolId::Orchard, |tree| {
            Ok((
                tree.truncate_to_checkpoint(&h(999))?,
                tree.max_leaf_position(None)?,
            ))
        })
        .unwrap();

    assert!(!truncated);
    assert_eq!(max, Some(Position::from(0)));
}

#[test]
fn truncating_one_pool_leaves_the_other_alone() {
    let mut db = test_db().unwrap();
    append_block(&mut db, PoolId::Orchard, h(1), [(0, true)]).unwrap();
    append_block(&mut db, PoolId::Orchard, h(2), [(1, true)]).unwrap();
    append_block(&mut db, PoolId::Ironwood, h(1), [(5, true)]).unwrap();
    append_block(&mut db, PoolId::Ironwood, h(2), [(6, true)]).unwrap();

    db.with_tree_for(PoolId::Orchard, |tree| {
        Ok(tree.truncate_to_checkpoint(&h(1))?)
    })
    .unwrap();

    let ironwood_count = db
        .with_tree_for(PoolId::Ironwood, |tree| {
            Ok(tree.store().checkpoint_count()?)
        })
        .unwrap();
    assert_eq!(ironwood_count, 2, "Ironwood must be untouched");
}

// -------------------------------------------------------- anchor retention

#[test]
fn a_retained_checkpoint_survives_pruning() {
    // ZIP 318 pool-crossing transfers prove against the tree state at a
    // boundary block on a shared grid, long after that block has passed. If
    // ordinary pruning discards the boundary, the transfer becomes permanently
    // unprovable — there is no way to reconstruct the checkpoint short of a
    // rescan.
    let mut db = test_db().unwrap();
    let retained = h(1);

    append_block(&mut db, PoolId::Ironwood, retained, [(0, true)]).unwrap();
    db.with_tree_for(PoolId::Ironwood, |tree| {
        Ok(tree.store_mut().add_retained_checkpoint(retained)?)
    })
    .unwrap();

    // Push far more checkpoints than the pruning depth allows.
    for height in 2..(zakura_wallet_store::PRUNING_DEPTH as u32 + 50) {
        append_block(&mut db, PoolId::Ironwood, h(height), [(height as u64, false)]).unwrap();
    }

    let (retained_set, still_there, neighbour, root) = db
        .with_tree_for(PoolId::Ironwood, |tree| {
            Ok((
                tree.store().retained_checkpoints()?,
                tree.store().get_checkpoint(&retained)?.is_some(),
                // Its unretained neighbour, one block later.
                tree.store().get_checkpoint(&h(2))?.is_some(),
                tree.root_at_checkpoint_id(&retained)?,
            ))
        })
        .unwrap();

    assert!(retained_set.contains(&retained));
    assert!(
        still_there,
        "the retained checkpoint was pruned along with the ordinary ones"
    );
    // Without this the test would pass vacuously if nothing had been pruned at
    // all: the unretained checkpoint one block later must be gone.
    assert!(
        !neighbour,
        "nothing was pruned, so surviving proves nothing"
    );

    // And it is still usable as an anchor, which is the whole point: a ZIP 318
    // transfer is proved against this root long after the block has passed.
    let root = root.expect("the retained checkpoint still yields a root");
    let expected = db
        .with_tree_for(PoolId::Ironwood, |tree| {
            Ok(tree
                .witness_at_checkpoint_id(Position::from(0), &retained)?
                .expect("the marked leaf still has a witness at the retained anchor"))
        })
        .unwrap();
    let mut node = leaf(0);
    let mut index = 0u64;
    for (level, sibling) in expected.path_elems().iter().enumerate() {
        let level = Level::from(level as u8);
        node = if index & 1 == 0 {
            MerkleHashOrchard::combine(level, &node, sibling)
        } else {
            MerkleHashOrchard::combine(level, sibling, &node)
        };
        index >>= 1;
    }
    assert_eq!(node, root, "the retained anchor's witness no longer verifies");
}

#[test]
fn ordinary_checkpoints_are_pruned_to_the_depth() {
    let mut db = test_db().unwrap();
    let total = zakura_wallet_store::PRUNING_DEPTH as u32 + 40;

    for height in 1..=total {
        append_block(&mut db, PoolId::Orchard, h(height), [(height as u64, false)]).unwrap();
    }

    let count = db
        .with_tree_for(PoolId::Orchard, |tree| {
            Ok(tree.store().checkpoint_count()?)
        })
        .unwrap();

    assert!(
        count <= zakura_wallet_store::PRUNING_DEPTH,
        "kept {count} checkpoints, which exceeds the pruning depth"
    );
}

#[test]
fn retention_can_be_added_before_the_tree_reaches_the_height() {
    // The anchor grid is known in advance, so retention may be recorded for a
    // height the tree has not reached. Forgetting it in the meantime would lose
    // exactly the boundary the migration scheduler is counting on.
    let mut db = test_db().unwrap();

    db.with_tree_for(PoolId::Ironwood, |tree| {
        Ok(tree.store_mut().add_retained_checkpoint(h(144))?)
    })
    .unwrap();

    let retained = db
        .with_tree_for(PoolId::Ironwood, |tree| {
            Ok(tree.store().retained_checkpoints()?)
        })
        .unwrap();
    assert!(retained.contains(&h(144)));
}

#[test]
fn retention_can_be_lifted() {
    let mut db = test_db().unwrap();
    append_block(&mut db, PoolId::Orchard, h(1), [(0, true)]).unwrap();

    db.with_tree_for(PoolId::Orchard, |tree| {
        tree.store_mut().add_retained_checkpoint(h(1))?;
        Ok(())
    })
    .unwrap();
    db.with_tree_for(PoolId::Orchard, |tree| {
        tree.store_mut().remove_retained_checkpoint(&h(1))?;
        Ok(())
    })
    .unwrap();

    let retained = db
        .with_tree_for(PoolId::Orchard, |tree| {
            Ok(tree.store().retained_checkpoints()?)
        })
        .unwrap();
    assert!(retained.is_empty());

    // Lifting retention leaves the checkpoint itself in place.
    let present = db
        .with_tree_for(PoolId::Orchard, |tree| {
            Ok(tree.store().get_checkpoint(&h(1))?.is_some())
        })
        .unwrap();
    assert!(present);
}

// ------------------------------------------------------------- integrity

#[test]
fn a_conflicting_checkpoint_is_rejected() {
    // Re-adding a checkpoint at a height where a different one exists means the
    // chain moved without the wallet rewinding. Overwriting would leave the
    // tree describing a chain that never existed.
    let mut db = test_db().unwrap();
    append_block(&mut db, PoolId::Orchard, h(1), [(0, true)]).unwrap();

    let err = db
        .with_tree_for(PoolId::Orchard, |tree| {
            use shardtree::store::{Checkpoint, TreeState};
            tree.store_mut().add_checkpoint(
                h(1),
                Checkpoint::from_parts(
                    TreeState::AtPosition(Position::from(99)),
                    Default::default(),
                ),
            )?;
            Ok(())
        })
        .unwrap_err();

    assert_matches!(
        err,
        TreeError::Store(Error::CheckpointConflict { checkpoint_id }) if checkpoint_id == h(1)
    );
}

#[test]
fn re_adding_an_identical_checkpoint_is_accepted() {
    // Idempotence matters: a batch may be applied twice after an interrupted
    // commit, and that must not be an error.
    let mut db = test_db().unwrap();
    append_block(&mut db, PoolId::Orchard, h(1), [(0, true)]).unwrap();

    db.with_tree_for(PoolId::Orchard, |tree| {
        let existing = tree
            .store()
            .get_checkpoint(&h(1))?
            .expect("the checkpoint exists");
        tree.store_mut().add_checkpoint(h(1), existing)?;
        Ok(())
    })
    .unwrap();
}

#[test]
fn a_shard_that_would_leave_a_gap_is_rejected() {
    // Shards must be contiguous: a gap means the region beyond it cannot be
    // reached from the root, and every witness past it is unbuildable.
    use incrementalmerkletree::Address;
    use shardtree::LocatedPrunableTree;

    let mut db = test_db().unwrap();
    append_block(&mut db, PoolId::Orchard, h(1), [(0, true)]).unwrap();

    let err = db
        .with_tree_for(PoolId::Orchard, |tree| {
            let far_away = Address::from_parts(
                Level::from(zakura_wallet_store::SHARD_HEIGHT),
                5,
            );
            let subtree = LocatedPrunableTree::empty(far_away);
            tree.store_mut().put_shard(subtree)?;
            Ok(())
        })
        .unwrap_err();

    assert_matches!(
        err,
        TreeError::Store(Error::ShardDiscontinuity { attempted, existing })
            if attempted == (5..6) && existing == (0..1)
    );
}

#[test]
fn a_failed_transaction_leaves_the_tree_untouched() {
    // One batch is one transaction: a partially applied set of commitments must
    // never be observable, because the sync engine's resumability depends on it.
    let mut db = test_db().unwrap();
    append_block(&mut db, PoolId::Orchard, h(1), [(0, true)]).unwrap();

    let result: Result<(), TreeError> = db.with_tree_for(PoolId::Orchard, |tree| {
            tree.append(leaf(77), Retention::Ephemeral)?;
            tree.append(
                leaf(78),
                Retention::Checkpoint {
                    id: h(2),
                    marking: Marking::None,
                },
            )?;
            // Fail after the appends have been staged.
            Err(TreeError::Store(Error::CheckpointConflict {
                checkpoint_id: h(2),
            }))
        });
    assert!(result.is_err());

    let (max, count) = db
        .with_tree_for(PoolId::Orchard, |tree| {
            Ok((
                tree.max_leaf_position(None)?,
                tree.store().checkpoint_count()?,
            ))
        })
        .unwrap();

    assert_eq!(max, Some(Position::from(0)), "the appends must have rolled back");
    assert_eq!(count, 1);
}

/// Returns a fresh temporary directory that is cleaned up on process exit.
fn tempdir() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "zakura-wallet-store-{}-{n}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).expect("temporary directory");
    path
}

// ------------------------------------------------------- checkpoint access

#[test]
fn checkpoints_are_reachable_by_id_depth_and_iteration() {
    let mut db = test_db().unwrap();
    for height in 1..=3u32 {
        append_block(
            &mut db,
            PoolId::Ironwood,
            h(height),
            [(height as u64, height == 2)],
        )
        .unwrap();
    }

    let (min, max, count, by_id, at_depth, listed) = db
        .with_tree_for(PoolId::Ironwood, |tree| {
            let store = tree.store();
            let mut listed = Vec::new();
            store.for_each_checkpoint(10, |id, checkpoint| {
                listed.push((*id, checkpoint.position()));
                Ok(())
            })?;
            Ok((
                store.min_checkpoint_id()?,
                store.max_checkpoint_id()?,
                store.checkpoint_count()?,
                store.get_checkpoint(&h(2))?.map(|c| c.position()),
                // Depth 0 is the most recent checkpoint.
                store.get_checkpoint_at_depth(0)?.map(|(id, _)| id),
                listed,
            ))
        })
        .unwrap();

    assert_eq!(min, Some(h(1)));
    assert_eq!(max, Some(h(3)));
    assert_eq!(count, 3);
    assert_eq!(by_id, Some(Some(Position::from(1))));
    assert_eq!(at_depth, Some(h(3)));
    assert_eq!(
        listed,
        vec![
            (h(1), Some(Position::from(0))),
            (h(2), Some(Position::from(1))),
            (h(3), Some(Position::from(2))),
        ]
    );

    // An empty pool has no checkpoints at all.
    let (min, at_depth) = db
        .with_tree_for(PoolId::Orchard, |tree| {
            Ok((
                tree.store().min_checkpoint_id()?,
                tree.store().get_checkpoint_at_depth(0)?,
            ))
        })
        .unwrap();
    assert_eq!(min, None);
    assert!(at_depth.is_none());
}

#[test]
fn removing_a_mark_records_it_against_the_next_checkpoint() {
    // A checkpoint's removed marks are what a rewind restores. They are stored
    // in their own table, keyed by pool and checkpoint.
    let mut db = test_db().unwrap();
    append_block(&mut db, PoolId::Ironwood, h(1), [(0, true), (1, true)]).unwrap();

    db.with_tree_for(PoolId::Ironwood, |tree| {
        assert!(tree.remove_mark(Position::from(0), Some(&h(1)))?);
        Ok(())
    })
    .unwrap();

    let marks = db
        .with_tree_for(PoolId::Ironwood, |tree| {
            Ok(tree
                .store()
                .get_checkpoint(&h(1))?
                .expect("checkpoint 1 exists")
                .marks_removed()
                .clone())
        })
        .unwrap();
    assert!(marks.contains(&Position::from(0)));

    // And the row is scoped to this pool.
    let other: u32 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM cache.tree_checkpoint_marks_removed WHERE pool = ?",
            [PoolId::Orchard.code()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(other, 0);
}

#[test]
fn a_checkpoint_can_be_updated_and_removed() {
    let mut db = test_db().unwrap();
    append_block(&mut db, PoolId::Orchard, h(1), [(0, true)]).unwrap();
    append_block(&mut db, PoolId::Orchard, h(2), [(1, true)]).unwrap();

    // `remove_mark` reaches the store through `update_checkpoint_with`, which
    // rewrites the checkpoint in place.
    db.with_tree_for(PoolId::Orchard, |tree| {
        assert!(tree.remove_mark(Position::from(0), Some(&h(2)))?);
        Ok(())
    })
    .unwrap();

    let marks = db
        .with_tree_for(PoolId::Orchard, |tree| {
            Ok(tree
                .store()
                .get_checkpoint(&h(2))?
                .expect("checkpoint 2 exists")
                .marks_removed()
                .clone())
        })
        .unwrap();
    assert!(marks.contains(&Position::from(0)));

    // Updating a checkpoint that does not exist reports that, rather than
    // creating one.
    let missing = db
        .with_tree_for(PoolId::Orchard, |tree| {
            Ok(tree
                .store_mut()
                .update_checkpoint_with(&h(99), |_| Ok(()))?)
        })
        .unwrap();
    assert!(!missing);

    // Removing takes the marks with it, via the cascade.
    db.with_tree_for(PoolId::Orchard, |tree| {
        tree.store_mut().remove_checkpoint(&h(2))?;
        Ok(())
    })
    .unwrap();

    let (gone, orphaned) = db
        .with_tree_for(PoolId::Orchard, |tree| {
            Ok((tree.store().get_checkpoint(&h(2))?.is_none(), {
                let count: u32 = tree.store().checkpoint_count()? as u32;
                count
            }))
        })
        .unwrap();
    assert!(gone);
    assert_eq!(orphaned, 1);

    let marks_left: u32 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM cache.tree_checkpoint_marks_removed WHERE checkpoint_id = 2",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(marks_left, 0, "the cascade should have removed the marks");
}

#[test]
fn an_unscanned_shard_reads_back_with_its_server_supplied_root() {
    // Backfill records a subtree root the server supplied before the shard's
    // contents have been scanned. It is stored as a single ephemeral leaf
    // holding that hash, plus the hash again as the row's root annotation, and
    // must read back carrying the annotation.
    use incrementalmerkletree::Address;

    let mut db = test_db().unwrap();
    let root = leaf(4242);
    let root_bytes = root.to_bytes().to_vec();
    // A version byte, a leaf tag, the hash, and ephemeral retention flags.
    let mut shard_data = vec![1u8, 1u8];
    shard_data.extend_from_slice(&root_bytes);
    shard_data.push(0u8);

    db.connection()
        .execute(
            "INSERT INTO cache.tree_shards (pool, shard_index, root_hash, shard_data)
             VALUES (?, 0, ?, ?)",
            rusqlite::params![PoolId::Ironwood.code(), root_bytes, shard_data],
        )
        .unwrap();

    let addr = Address::from_parts(Level::from(zakura_wallet_store::SHARD_HEIGHT), 0);
    let (shard, last) = db
        .with_tree_for(PoolId::Ironwood, |tree| {
            Ok((tree.store().get_shard(addr)?, tree.store().last_shard()?))
        })
        .unwrap();

    let shard = shard.expect("the row is a shard");
    assert_eq!(shard.root_addr(), addr);
    // The stored leaf sits at the shard's own root address, so it stands for the
    // whole shard: its hash is only computable once the whole shard is in range.
    // That hash is the one the server supplied, which is what makes the shard
    // usable as a witness anchor before its contents have been scanned.
    let shard_end = Position::from(1u64 << zakura_wallet_store::SHARD_HEIGHT);
    assert_eq!(
        shard
            .root_hash(shard_end)
            .expect("the whole shard is in range"),
        root
    );

    let last = last.expect("it is also the last shard");
    assert_eq!(last.root_addr(), addr);
    assert_eq!(
        last.root_hash(shard_end)
            .expect("the whole shard is in range"),
        root
    );
}

#[test]
fn a_shard_with_a_corrupt_root_hash_is_rejected() {
    use incrementalmerkletree::Address;

    let mut db = test_db().unwrap();
    db.connection()
        .execute(
            "INSERT INTO cache.tree_shards (pool, shard_index, root_hash, shard_data)
             VALUES (?, 0, ?, X'0100')",
            // All-ones is not a canonical Pallas base field element.
            rusqlite::params![PoolId::Orchard.code(), vec![0xffu8; 32]],
        )
        .unwrap();

    let err = db
        .with_tree_for(PoolId::Orchard, |tree| {
            Ok(tree.store().get_shard(Address::from_parts(
                Level::from(zakura_wallet_store::SHARD_HEIGHT),
                0,
            ))?)
        })
        .unwrap_err();

    assert_matches!(err, TreeError::Store(Error::Serialization(_)));
}

#[test]
fn a_shard_with_corrupt_contents_is_rejected() {
    use incrementalmerkletree::Address;

    let mut db = test_db().unwrap();
    db.connection()
        .execute(
            "INSERT INTO cache.tree_shards (pool, shard_index, root_hash, shard_data)
             VALUES (?, 0, NULL, ?)",
            rusqlite::params![PoolId::Orchard.code(), vec![0x7fu8; 4]],
        )
        .unwrap();

    for result in [
        db.with_tree_for(PoolId::Orchard, |tree| {
            Ok(tree.store().get_shard(Address::from_parts(
                Level::from(zakura_wallet_store::SHARD_HEIGHT),
                0,
            ))?)
        })
        .err(),
        db.with_tree_for(PoolId::Orchard, |tree| Ok(tree.store().last_shard()?))
            .err(),
    ] {
        assert_matches!(result, Some(TreeError::Store(Error::Serialization(_))));
    }
}

#[test]
fn a_corrupt_cap_is_rejected() {
    let mut db = test_db().unwrap();
    db.connection()
        .execute(
            "INSERT INTO cache.tree_cap (pool, cap_data) VALUES (?, ?)",
            rusqlite::params![PoolId::Ironwood.code(), vec![0x7fu8]],
        )
        .unwrap();

    let err = db
        .with_tree_for(PoolId::Ironwood, |tree| Ok(tree.store().get_cap()?))
        .unwrap_err();
    assert_matches!(err, TreeError::Store(Error::Serialization(_)));
}

#[test]
fn the_typed_and_untyped_tree_accessors_agree() {
    use zakura_wallet_core::Ironwood;

    let mut db = test_db().unwrap();
    append_block(&mut db, PoolId::Ironwood, h(1), [(0, true)]).unwrap();

    let typed = db
        .with_tree::<Ironwood, _, _>(|tree| Ok(tree.root_at_checkpoint_id(&h(1))?))
        .unwrap();
    let untyped = db
        .with_tree_for(PoolId::Ironwood, |tree| {
            Ok(tree.root_at_checkpoint_id(&h(1))?)
        })
        .unwrap();
    assert_eq!(typed, untyped);
}

#[test]
fn a_transaction_spans_both_databases() {
    let mut db = test_db().unwrap();

    db.transactionally::<_, _, Error>(|tx| {
        tx.execute(
            "INSERT INTO wallet_meta (key, value) VALUES ('durable', 1)",
            [],
        )?;
        tx.execute(
            "INSERT INTO cache.blocks
                (height, hash, time, orchard_tree_size, ironwood_tree_size,
                 orchard_action_count, ironwood_action_count)
             VALUES (1, X'00', 0, 0, 0, 0, 0)",
            [],
        )?;
        Ok(())
    })
    .unwrap();

    assert_eq!(db.meta_u32("durable").unwrap(), Some(1));

    // A failure rolls back both halves together.
    let result: Result<(), Error> = db.transactionally(|tx| {
        tx.execute(
            "INSERT INTO wallet_meta (key, value) VALUES ('rolled_back', 1)",
            [],
        )?;
        Err(Error::CheckpointConflict {
            checkpoint_id: h(1),
        })
    });
    assert!(result.is_err());
    assert_eq!(db.meta_u32("rolled_back").unwrap(), None);
}

#[test]
fn a_wallet_never_renders_its_contents() {
    let db = test_db().unwrap();
    assert_eq!(format!("{db:?}"), "WalletDb");
}
