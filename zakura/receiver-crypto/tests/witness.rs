#![cfg(feature = "crypto")]
//! Lower witness payloads, checked against an independent commitment tree.
mod common;
use common::leaves;
use incrementalmerkletree::{frontier::CommitmentTree, witness::IncrementalWitness};
use orchard::{note::ExtractedNoteCommitment, tree::MerkleHashOrchard};
use zakura_receiver_crypto::{
    Error, Hash,
    wire::{decode_payload, is_final},
    witness::{SHARD_LEAVES, ShardPaths},
};

/// The full independent path of `position` in a tree over `cmxs`.
fn independent(cmxs: &[Hash], position: usize) -> Vec<Hash> {
    let mut tree = CommitmentTree::<MerkleHashOrchard, 32>::empty();
    let mut witness: Option<IncrementalWitness<MerkleHashOrchard, 32>> = None;
    for (i, cmx) in cmxs.iter().enumerate() {
        let leaf = MerkleHashOrchard::from_cmx(&ExtractedNoteCommitment::from_bytes(cmx).unwrap());
        match &mut witness {
            Some(w) => w.append(leaf).unwrap(),
            None => {
                tree.append(leaf).unwrap();
                if i == position {
                    witness = IncrementalWitness::from_tree(tree.clone());
                }
            }
        }
    }
    let path: orchard::tree::MerklePath = witness.unwrap().path().unwrap().into();
    path.auth_path().iter().map(|h| h.to_bytes()).collect()
}

/// Every supplied sibling equals the independent path's, and no partial sibling is supplied.
#[test]
fn provisional_payloads_supply_exactly_the_complete_siblings() {
    let cmxs = leaves(21);
    for split in [0, 1, 7, 20] {
        let mut paths = ShardPaths::new(0);
        paths.extend(&cmxs[..split]).unwrap();
        paths.extend(&cmxs[split..]).unwrap();
        assert_eq!(paths.tree_size(), 21);
        assert_eq!(paths.root(), None);
        for position in 0..21u64 {
            let full = independent(&cmxs, position as usize);
            let payload = paths.payload(position).unwrap();
            let siblings = decode_payload(&payload, position, 21).unwrap();
            for (level, sibling) in siblings.iter().enumerate() {
                let start = ((position >> level) ^ 1) << level;
                let end = start + (1 << level);
                match sibling {
                    Some(hash) => assert_eq!(*hash, full[level], "{position} {level}"),
                    None => assert!(end > 21, "{position} {level}"),
                }
            }
        }
    }
    assert_eq!(ShardPaths::new(0).payload(0), Err(Error::Coverage));
}

/// A full shard yields final paths whose sixteen levels match the independent path, and
/// later shards address their own positions.
#[test]
fn a_full_shard_is_final_and_later_shards_are_offset() {
    let cmxs = leaves(SHARD_LEAVES as usize + 3);
    let mut first = ShardPaths::new(0);
    first.extend(&cmxs[..SHARD_LEAVES as usize]).unwrap();
    assert!(first.root().is_some());
    assert_eq!(
        first.extend(&cmxs[..1]),
        Err(Error::Capacity),
        "a shard holds 2^16 leaves"
    );
    for position in [0u64, 12_345, SHARD_LEAVES - 1] {
        assert!(is_final(position, first.tree_size()));
        let full = independent(&cmxs, position as usize);
        let siblings =
            decode_payload(&first.payload(position).unwrap(), position, SHARD_LEAVES).unwrap();
        assert_eq!(
            siblings.map(Option::unwrap).as_slice(),
            &full[..16],
            "{position}"
        );
    }
    let mut second = ShardPaths::new(1);
    second.extend(&cmxs[SHARD_LEAVES as usize..]).unwrap();
    assert_eq!(second.tree_size(), SHARD_LEAVES + 3);
    let position = SHARD_LEAVES + 1;
    let full = independent(&cmxs, position as usize);
    let siblings = decode_payload(
        &second.payload(position).unwrap(),
        position,
        SHARD_LEAVES + 3,
    )
    .unwrap();
    assert_eq!(siblings[0], Some(full[0]));
    assert!(siblings[1..].iter().all(Option::is_none));
    assert_eq!(second.payload(1), Err(Error::Coverage));
}

/// A noncanonical commitment leaves the shard unchanged.
#[test]
fn malformed_commitments_do_not_change_the_shard() {
    let mut paths = ShardPaths::new(0);
    paths.extend(&leaves(3)).unwrap();
    let before = paths.payload(2).unwrap();
    assert_eq!(paths.extend(&[[0xff; 32]]), Err(Error::Malformed));
    assert_eq!(paths.tree_size(), 3);
    assert_eq!(paths.payload(2).unwrap(), before);
}

/// The whole-tree helper matches incremental shards, in the requested order.
#[test]
fn payloads_match_their_shards() {
    let cmxs = leaves(9);
    let mut paths = ShardPaths::new(0);
    paths.extend(&cmxs).unwrap();
    let got = zakura_receiver_crypto::witness::payloads(&cmxs, &[8, 0, 3]).unwrap();
    assert_eq!(got, [8, 0, 3].map(|p| paths.payload(p).unwrap()).to_vec());
    assert_eq!(
        zakura_receiver_crypto::witness::payloads(&cmxs, &[9]),
        Err(Error::Coverage)
    );
}
