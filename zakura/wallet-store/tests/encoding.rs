//! Tests for the shard encoding and the store's error reporting.
//!
//! The encoding is byte-identical to the one `zcash_client_backend` uses, so a
//! database written by either implementation can be read by the other. These
//! tests pin that format and check that malformed input is rejected rather than
//! silently misread — a shard decoded wrongly would produce witnesses that fail
//! only at proving time.

use assert_matches::assert_matches;
use incrementalmerkletree::{Marking, Position, Retention};
use orchard::tree::MerkleHashOrchard;
use shardtree::store::ShardStore;
use zakura_wallet_core::pool::PoolId;
use zakura_wallet_store::{Error, TreeError, VersionKind, testing::test_db};
use zcash_protocol::consensus::BlockHeight;

fn leaf(i: u64) -> MerkleHashOrchard {
    let mut repr = [0u8; 32];
    repr[..8].copy_from_slice(&i.to_le_bytes());
    Option::from(MerkleHashOrchard::from_bytes(&repr)).expect("a canonical field element")
}

/// Writes `shard_data` into a shard row and tries to read it back.
fn read_back(shard_data: Vec<u8>) -> Result<(), TreeError> {
    use incrementalmerkletree::{Address, Level};

    let mut db = test_db().unwrap();
    db.connection()
        .execute(
            "INSERT INTO cache.tree_shards (pool, shard_index, root_hash, shard_data)
             VALUES (?, 0, NULL, ?)",
            rusqlite::params![PoolId::Orchard.code(), shard_data],
        )
        .unwrap();

    db.with_tree_for(PoolId::Orchard, |tree| {
        tree.store().get_shard(Address::from_parts(
            Level::from(zakura_wallet_store::SHARD_HEIGHT),
            0,
        ))?;
        Ok(())
    })
}

#[test]
fn the_encoding_matches_the_documented_layout() {
    // A shard holding one checkpointed note is a parent node: version byte 1,
    // parent tag 2, an annotation presence flag, then its two children.
    let mut db = test_db().unwrap();
    db.with_tree_for(PoolId::Orchard, |tree| {
        tree.append(
            leaf(7),
            Retention::Checkpoint {
                id: BlockHeight::from_u32(1),
                marking: Marking::None,
            },
        )?;
        Ok(())
    })
    .unwrap();

    let stored: Vec<u8> = db
        .connection()
        .query_row(
            "SELECT shard_data FROM cache.tree_shards WHERE pool = ? AND shard_index = 0",
            [PoolId::Orchard.code()],
            |row| row.get(0),
        )
        .unwrap();

    assert_eq!(stored[0], 1, "format version");
    assert_eq!(stored[1], 2, "parent tag");
    assert!(matches!(stored[2], 0 | 1), "annotation presence flag");

    // The leaf holding the note appears verbatim further in: leaf tag, the
    // 32-byte hash, then a retention-flags byte.
    let expected_leaf = {
        let mut v = vec![1u8];
        v.extend_from_slice(&leaf(7).to_bytes());
        v
    };
    assert!(
        stored
            .windows(expected_leaf.len())
            .any(|w| w == expected_leaf),
        "the encoded shard should contain the note's leaf verbatim"
    );

    // And the whole thing survives a round trip byte-identically.
    let shard = db
        .with_tree_for(PoolId::Orchard, |tree| Ok(tree.store().last_shard()?))
        .unwrap()
        .expect("a shard exists");
    assert!(zakura_wallet_store::testing::roundtrip_shard(shard.root()).unwrap());
}

#[test]
fn an_unknown_format_version_is_rejected() {
    let err = read_back(vec![99, 0]).unwrap_err();
    assert_matches!(err, TreeError::Store(Error::Serialization(_)));
    assert!(err.to_string().contains("99"), "{err}");
}

#[test]
fn an_unknown_node_tag_is_rejected() {
    let err = read_back(vec![1, 42]).unwrap_err();
    assert_matches!(err, TreeError::Store(Error::Serialization(_)));
    assert!(err.to_string().contains("42"), "{err}");
}

#[test]
fn an_invalid_annotation_presence_flag_is_rejected() {
    // A parent node, then a presence byte that is neither 0 nor 1.
    let err = read_back(vec![1, 2, 7]).unwrap_err();
    assert_matches!(err, TreeError::Store(Error::Serialization(_)));
    assert!(err.to_string().contains("presence flag"), "{err}");
}

#[test]
fn invalid_retention_flags_are_rejected() {
    let mut data = vec![1, 1];
    data.extend_from_slice(&leaf(1).to_bytes());
    data.push(0xff); // not a valid combination of retention flags

    let err = read_back(data).unwrap_err();
    assert_matches!(err, TreeError::Store(Error::Serialization(_)));
    assert!(err.to_string().contains("retention flags"), "{err}");
}

#[test]
fn a_non_canonical_node_hash_is_rejected() {
    let mut data = vec![1, 1];
    data.extend_from_slice(&[0xff; 32]); // outside the Pallas base field
    data.push(0);

    let err = read_back(data).unwrap_err();
    assert_matches!(err, TreeError::Store(Error::Serialization(_)));
    assert!(err.to_string().contains("non-canonical"), "{err}");
}

#[test]
fn a_truncated_shard_is_rejected() {
    // The hash is cut short, so the read runs out of input.
    let err = read_back(vec![1, 1, 0, 0, 0]).unwrap_err();
    assert_matches!(err, TreeError::Store(Error::Serialization(_)));
}

#[test]
fn an_annotated_parent_round_trips() {
    // Annotations are only carried by parent nodes, and are what let a shard
    // serve as a witness anchor without its subtree being present.
    use zakura_wallet_store::testing::roundtrip_shard;

    let mut db = test_db().unwrap();
    for i in 0..4u64 {
        db.with_tree_for(PoolId::Ironwood, |tree| {
            tree.append(
                leaf(i),
                Retention::Checkpoint {
                    id: BlockHeight::from_u32(i as u32 + 1),
                    marking: Marking::Marked,
                },
            )?;
            Ok(())
        })
        .unwrap();
    }

    let shard = db
        .with_tree_for(PoolId::Ironwood, |tree| Ok(tree.store().last_shard()?))
        .unwrap()
        .expect("a shard exists");
    assert!(roundtrip_shard(shard.root()).unwrap());
}

// ------------------------------------------------------------ error text

#[test]
fn every_error_renders_and_exposes_its_cause() {
    use std::error::Error as _;

    let query = Error::Query(rusqlite::Error::QueryReturnedNoRows);
    let serialization = Error::Serialization(std::io::Error::other("boom"));
    let discontinuity = Error::ShardDiscontinuity {
        attempted: 5..6,
        existing: 0..1,
    };
    let conflict = Error::CheckpointConflict {
        checkpoint_id: BlockHeight::from_u32(7),
    };
    let version = Error::VersionMismatch {
        kind: VersionKind::Layout,
        found: 2,
        expected: 1,
    };

    assert!(query.to_string().contains("query failed"));
    assert!(query.source().is_some());
    assert!(serialization.to_string().contains("boom"));
    assert!(serialization.source().is_some());
    assert!(discontinuity.to_string().contains("gap"), "{discontinuity}");
    assert!(discontinuity.source().is_none());
    assert!(conflict.to_string().contains('7'), "{conflict}");
    assert!(conflict.source().is_none());
    assert!(version.to_string().contains("rebuild"), "{version}");
    assert!(version.source().is_none());

    // `TreeError` distinguishes a storage failure from a tree-logic failure,
    // and forwards both to its source.
    let store = TreeError::Store(Error::CheckpointConflict {
        checkpoint_id: BlockHeight::from_u32(7),
    });
    assert!(store.to_string().contains('7'), "{store}");
    assert!(store.source().is_some());

    let tree = TreeError::Tree(shardtree::error::ShardTreeError::Query(
        shardtree::error::QueryError::CheckpointPruned,
    ));
    assert!(tree.to_string().contains("commitment tree"), "{tree}");
    assert!(tree.source().is_some());

    // Both error types accept a bare rusqlite error, which is what lets the
    // store's statements use `?` directly.
    let from_sql: Error = rusqlite::Error::QueryReturnedNoRows.into();
    assert_matches!(from_sql, Error::Query(_));
    let from_sql: TreeError = rusqlite::Error::QueryReturnedNoRows.into();
    assert_matches!(from_sql, TreeError::Store(Error::Query(_)));
}

#[test]
fn each_version_kind_names_a_different_remedy() {
    let remedies: Vec<_> = [
        VersionKind::Detection,
        VersionKind::Layout,
        VersionKind::Tree,
    ]
    .iter()
    .map(|k| k.remedy())
    .collect();

    // Three versions exist precisely because the three remedies differ in cost.
    assert_eq!(remedies.len(), 3);
    assert_ne!(remedies[0], remedies[1]);
    assert_ne!(remedies[1], remedies[2]);
    assert!(remedies[0].contains("rescan"));
}

#[test]
fn a_missing_position_is_reported_rather_than_guessed() {
    // Asking for a witness at a position the tree does not hold must fail, not
    // return a plausible-looking path.
    let mut db = test_db().unwrap();
    db.with_tree_for(PoolId::Orchard, |tree| {
        tree.append(
            leaf(0),
            Retention::Checkpoint {
                id: BlockHeight::from_u32(1),
                marking: Marking::None,
            },
        )?;
        Ok(())
    })
    .unwrap();

    let err = db
        .with_tree_for(PoolId::Orchard, |tree| {
            Ok(tree.witness_at_checkpoint_id(Position::from(500), &BlockHeight::from_u32(1))?)
        })
        .unwrap_err();
    assert_matches!(err, TreeError::Tree(_));
}

#[test]
fn an_annotated_parent_survives_the_encoding() {
    // Annotations record a subtree's root hash without its children being
    // present. They are what lets a shard whose contents were pruned — or were
    // never scanned — still serve as a witness anchor, so losing one in the
    // encoding would silently break witness generation for old notes.
    use shardtree::{RetentionFlags, Tree};
    use zakura_wallet_store::testing::roundtrip_shard;

    let annotated = Tree::parent(
        Some(std::sync::Arc::new(leaf(31))),
        Tree::leaf((leaf(32), RetentionFlags::MARKED)),
        Tree::leaf((leaf(33), RetentionFlags::EPHEMERAL)),
    );
    assert!(roundtrip_shard(&annotated).unwrap());

    // An unannotated parent round-trips too, so the presence flag is carried
    // in both directions.
    let bare = Tree::parent(
        None,
        Tree::leaf((leaf(34), RetentionFlags::EPHEMERAL)),
        Tree::empty(),
    );
    assert!(roundtrip_shard(&bare).unwrap());
}

#[test]
fn a_shard_deeper_than_its_address_is_rejected() {
    // A shard root sits at level 16, so it can hold at most sixteen levels of
    // parent nodes. Deeper data means the row does not describe the shard it is
    // filed under, and accepting it would place notes at positions outside the
    // shard's range.
    fn nested(depth: usize) -> Vec<u8> {
        if depth == 0 {
            vec![0] // Nil
        } else {
            let mut v = vec![2, 0]; // parent, no annotation
            v.extend(nested(depth - 1));
            v.push(0); // right: Nil
            v
        }
    }

    let mut data = vec![1u8]; // format version
    data.extend(nested(usize::from(zakura_wallet_store::SHARD_HEIGHT) + 1));

    let err = read_back(data).unwrap_err();
    assert_matches!(err, TreeError::Store(Error::Serialization(_)));
    assert!(err.to_string().contains("invalid data at address"), "{err}");
}
