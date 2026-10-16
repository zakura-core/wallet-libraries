#![cfg(feature = "crypto")]
//! Byte-only hashing keeps Common types inside the library.
use incrementalmerkletree::Hashable;
use orchard::tree::MerkleHashOrchard;
use zakura_receiver_crypto::{
    Error,
    witness::{combine, empty_root},
};

#[test]
fn empty_roots_match_retained_protocol_vectors() {
    // Retained from Common Orchard 1.0.1's commitment_tree test vectors, sourced
    // there from zcash-test-vectors/orchard_empty_roots.py. The unchanged Common
    // 3.0.0 vector file carries the same 33 expectations; these are not regenerated.
    let roots: Vec<[u8; 32]> = include_str!("fixtures/orchard-empty-roots.txt")
        .lines()
        .map(|line| hex::decode(line).unwrap().try_into().unwrap())
        .collect();
    assert_eq!(roots.len(), 33);
    for (height, expected) in roots.iter().enumerate() {
        assert_eq!(empty_root(height as u8).unwrap(), *expected);
        assert_eq!(
            MerkleHashOrchard::empty_root((height as u8).into()).to_bytes(),
            *expected
        );
        if height < 32 {
            assert_eq!(
                combine(height as u8, expected, expected).unwrap(),
                roots[height + 1]
            );
        }
    }
}

#[test]
fn nonempty_nodes_match_common_at_every_level() {
    let mut left = [0; 32];
    left[0] = 7;
    let mut right = [0; 32];
    right[0] = 11;
    let l = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&left)).unwrap();
    let r = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&right)).unwrap();
    for level in 0..32u8 {
        assert_eq!(
            combine(level, &left, &right).unwrap(),
            MerkleHashOrchard::combine(level.into(), &l, &r).to_bytes()
        );
        assert_eq!(
            combine(level, &right, &left).unwrap(),
            MerkleHashOrchard::combine(level.into(), &r, &l).to_bytes()
        );
    }
}

#[test]
fn malformed_nodes_and_levels_are_rejected() {
    let leaf = empty_root(0).unwrap();
    let invalid = [0xff; 32];
    for level in 0..32 {
        assert_eq!(combine(level, &invalid, &leaf), Err(Error::Malformed));
        assert_eq!(combine(level, &leaf, &invalid), Err(Error::Malformed));
    }
    for level in [32, 33, 255] {
        assert_eq!(combine(level, &leaf, &leaf), Err(Error::Malformed));
    }
    for height in [33, 255] {
        assert_eq!(empty_root(height), Err(Error::Malformed));
    }
}
