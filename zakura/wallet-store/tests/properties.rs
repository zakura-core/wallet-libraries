//! Property tests for the store.

use incrementalmerkletree::{Marking, Position, Retention};
use orchard::tree::MerkleHashOrchard;
use proptest::prelude::*;
use shardtree::store::ShardStore;
use zakura_wallet_core::pool::PoolId;
use zakura_wallet_store::testing::{roundtrip_shard, test_db};
use zcash_protocol::consensus::BlockHeight;

fn leaf(i: u64) -> MerkleHashOrchard {
    let mut repr = [0u8; 32];
    repr[..8].copy_from_slice(&i.to_le_bytes());
    Option::from(MerkleHashOrchard::from_bytes(&repr)).expect("a canonical field element")
}

fn arb_pool() -> impl Strategy<Value = PoolId> {
    prop_oneof![Just(PoolId::Orchard), Just(PoolId::Ironwood)]
}

/// A block: how many leaves it appends, and which of them the wallet owns.
fn arb_block() -> impl Strategy<Value = Vec<bool>> {
    prop::collection::vec(proptest::bool::weighted(0.3), 1..5)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// A shard survives a write-read round trip unchanged.
    ///
    /// The encoding is byte-identical to the fork's, so this also guards the
    /// compatibility the differential test will depend on.
    #[test]
    fn shards_round_trip_through_their_encoding(
        blocks in prop::collection::vec(arb_block(), 1..6),
        pool in arb_pool(),
    ) {
        let mut db = test_db().unwrap();
        let mut next = 0u64;

        for (i, block) in blocks.iter().enumerate() {
            let height = BlockHeight::from_u32(i as u32 + 1);
            let last = block.len() - 1;
            db.with_tree_for(pool, |tree| {
                for (j, marked) in block.iter().enumerate() {
                    let retention = if j == last {
                        Retention::Checkpoint {
                            id: height,
                            marking: if *marked { Marking::Marked } else { Marking::None },
                        }
                    } else if *marked {
                        Retention::Marked
                    } else {
                        Retention::Ephemeral
                    };
                    tree.append(leaf(next), retention)?;
                    next += 1;
                }
                Ok(())
            }).unwrap();
        }

        // Read every shard back out and re-encode it; the bytes must match.
        let shards = db.with_tree_for(pool, |tree| Ok(tree.store().get_shard_roots()?)).unwrap();
        for addr in shards {
            let shard = db
                .with_tree_for(pool, |tree| Ok(tree.store().get_shard(addr)?))
                .unwrap()
                .expect("a listed shard is readable");
            prop_assert!(roundtrip_shard(shard.root()).unwrap());
        }
    }

    /// Truncating to any checkpoint restores exactly the state that checkpoint
    /// described, for every checkpoint the tree still holds.
    #[test]
    fn truncation_restores_the_checkpointed_state(
        blocks in prop::collection::vec(arb_block(), 2..7),
        pool in arb_pool(),
        target in 0usize..6,
    ) {
        let mut db = test_db().unwrap();
        let mut next = 0u64;
        let mut roots = Vec::new();

        for (i, block) in blocks.iter().enumerate() {
            let height = BlockHeight::from_u32(i as u32 + 1);
            let last = block.len() - 1;
            db.with_tree_for(pool, |tree| {
                for (j, marked) in block.iter().enumerate() {
                    let retention = if j == last {
                        Retention::Checkpoint {
                            id: height,
                            marking: if *marked { Marking::Marked } else { Marking::None },
                        }
                    } else if *marked {
                        Retention::Marked
                    } else {
                        Retention::Ephemeral
                    };
                    tree.append(leaf(next), retention)?;
                    next += 1;
                }
                Ok(())
            }).unwrap();

            let root = db
                .with_tree_for(pool, |tree| Ok(tree.root_at_checkpoint_id(&height)?))
                .unwrap();
            roots.push((height, root, next - 1));
        }

        let (height, expected_root, expected_max) = roots[target % roots.len()];

        let truncated = db
            .with_tree_for(pool, |tree| Ok(tree.truncate_to_checkpoint(&height)?))
            .unwrap();
        prop_assert!(truncated);

        let (root, max) = db
            .with_tree_for(pool, |tree| {
                Ok((
                    tree.root_at_checkpoint_id(&height)?,
                    tree.max_leaf_position(None)?,
                ))
            })
            .unwrap();

        prop_assert_eq!(root, expected_root);
        prop_assert_eq!(max, Some(Position::from(expected_max)));
    }

    /// Whatever happens to one pool's tree, the other's is unaffected.
    #[test]
    fn the_pools_are_isolated(
        blocks in prop::collection::vec(arb_block(), 1..5),
        pool in arb_pool(),
    ) {
        let other = match pool {
            PoolId::Orchard => PoolId::Ironwood,
            PoolId::Ironwood => PoolId::Orchard,
        };

        let mut db = test_db().unwrap();
        // Give the other pool a fixed, known state first.
        db.with_tree_for(other, |tree| {
            tree.append(leaf(1_000), Retention::Checkpoint {
                id: BlockHeight::from_u32(1),
                marking: Marking::Marked,
            })?;
            Ok(())
        }).unwrap();
        let before = db
            .with_tree_for(other, |tree| Ok(tree.root_at_checkpoint_id(&BlockHeight::from_u32(1))?))
            .unwrap();

        let mut next = 0u64;
        for (i, block) in blocks.iter().enumerate() {
            let height = BlockHeight::from_u32(i as u32 + 1);
            let last = block.len() - 1;
            db.with_tree_for(pool, |tree| {
                for (j, _) in block.iter().enumerate() {
                    let retention = if j == last {
                        Retention::Checkpoint { id: height, marking: Marking::None }
                    } else {
                        Retention::Ephemeral
                    };
                    tree.append(leaf(next), retention)?;
                    next += 1;
                }
                Ok(())
            }).unwrap();
        }
        db.with_tree_for(pool, |tree| {
            tree.truncate_to_checkpoint(&BlockHeight::from_u32(1))?;
            Ok(())
        }).unwrap();

        let after = db
            .with_tree_for(other, |tree| Ok(tree.root_at_checkpoint_id(&BlockHeight::from_u32(1))?))
            .unwrap();
        prop_assert_eq!(before, after);

        let marked = db
            .with_tree_for(other, |tree| Ok(tree.marked_positions()?))
            .unwrap();
        prop_assert_eq!(marked.into_iter().collect::<Vec<_>>(), vec![Position::from(0)]);
    }
}
