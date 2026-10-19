//! Durable fixed-universe seen membership, independent of payment publications.
use receiver_directory::{
    seen::{self, SeenSet, DEFAULT_P, MAX_SEEN_BYTES},
    Error, Hash, ReceiverBytes,
};
use sha2::{Digest, Sha512};
const GENESIS: Hash = [1; 32];

/// Fixed hash identity and canonical seen bytes survive the old planner's removal.
#[test]
fn seen_reproduces_preserved_vectors() {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/seen-vectors.json")).unwrap();
    let genesis: Hash = hex::decode(vector["genesis"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let members: Vec<ReceiverBytes> = vector["receivers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            hex::decode(r.as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        })
        .collect();
    let expected = &vector["seen"];
    let mut set = SeenSet::new(genesis, expected["since_unix"].as_i64().unwrap()).union(&members);
    set.until_unix = expected["until_unix"].as_i64().unwrap();
    let hashes: Vec<_> = members.iter().map(|r| seen::hash(&genesis, r)).collect();
    assert_eq!(serde_json::to_value(hashes).unwrap(), expected["hashes"]);
    assert_eq!(hex::encode(set.encode().unwrap()), expected["encoding"]);
    assert_eq!(hex::encode(set.digest().unwrap()), expected["digest"]);
}

/// `n` distinct pseudorandom receivers; the sets hash bytes and never parse them.
fn receivers(n: u32, seed: u8) -> Vec<ReceiverBytes> {
    (0..n)
        .map(|i| {
            let digest = Sha512::new()
                .chain_update([seed])
                .chain_update(i.to_le_bytes());
            digest.finalize()[..43].try_into().unwrap()
        })
        .collect()
}

/// A seen set of 30,000 values stays near 70 KB, decodes to itself, matches every
/// member and falsely matches about `K / U` of others.
#[test]
fn seen_sets_round_trip_and_never_miss_a_member() {
    let members = receivers(30_000, 1);
    let mut seen = SeenSet::new(GENESIS, 1_000).union(&members);
    seen.until_unix = 2_000;
    assert_eq!(seen.p(), DEFAULT_P);
    assert_eq!(seen.count(), 30_000);
    let bytes = seen.encode().unwrap();
    // About 70 KB at 30,000 values.
    assert!(bytes.len() < 75_000, "{}", bytes.len());
    let decoded = SeenSet::decode(&bytes).unwrap();
    assert_eq!(decoded, seen);
    assert!(decoded.matches(&members).iter().all(|m| *m));
    // About 7e-6 per test.
    let others = receivers(100_000, 2);
    let false_matches = decoded.matches(&others).iter().filter(|m| **m).count();
    assert!(false_matches <= 6, "{false_matches} false matches");
    // A value depends only on the network and the receiver.
    assert_eq!(
        seen::hash(&GENESIS, &members[0]),
        seen::hash(&GENESIS, &members[0])
    );
    assert_ne!(
        seen::hash(&GENESIS, &members[0]),
        seen::hash(&[2; 32], &members[0])
    );
}

/// Two receivers with the same value, so the second matches a set holding only the
/// first: a false match.
fn colliding_pair() -> (ReceiverBytes, ReceiverBytes) {
    let mut by_value = std::collections::HashMap::new();
    for receiver in receivers(400_000, 9) {
        if let Some(first) = by_value.insert(seen::hash(&GENESIS, &receiver), receiver) {
            return (first, receiver);
        }
    }
    panic!("no collision");
}

/// A false match, once published, stays a match after any union, any re-encoding
/// and any decoding.
#[test]
fn seen_membership_is_monotone() {
    let (member, false_match) = colliding_pair();
    let first = SeenSet::new(GENESIS, 0).union([&member]);
    assert_eq!(first.matches(&[member, false_match]), [true, true]);
    let mut set = first.clone();
    for round in 0..4u8 {
        let next = set.union(&receivers(5_000, round));
        assert!(next.is_superset(&set) && next.is_superset(&first));
        set = next;
    }
    for p in [8, DEFAULT_P, 20, 32] {
        let decoded = SeenSet::decode(&set.with_p(p).unwrap().encode().unwrap()).unwrap();
        assert_eq!(decoded.p(), p);
        assert!(decoded.is_superset(&first) && set.is_superset(&decoded));
        assert_eq!(decoded.matches(&[member, false_match]), [true, true]);
    }
    assert!(!first.is_superset(&set));
    let other_network = SeenSet::new([2; 32], 0).union([&member]);
    assert!(!other_network.is_superset(&first));
}

/// Unsupported parameters, reversed feed times, truncation, extension, corrupted
/// header fields and oversized encodings are refused.
#[test]
fn seen_decoding_is_strict() {
    assert!(SeenSet::new(GENESIS, 0).with_p(0).is_err());
    assert!(SeenSet::new(GENESIS, 0).with_p(33).is_err());
    let mut backwards = SeenSet::new(GENESIS, 10);
    backwards.until_unix = 9;
    assert!(matches!(backwards.encode(), Err(Error::Malformed)));
    let empty = SeenSet::new(GENESIS, 0);
    assert_eq!(SeenSet::decode(&empty.encode().unwrap()).unwrap(), empty);
    let bytes = empty.union(&receivers(100, 1)).encode().unwrap();
    for end in 0..bytes.len() {
        assert!(SeenSet::decode(&bytes[..end]).is_err(), "{end}");
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(SeenSet::decode(&trailing).is_err());
    // Header layout: magic 8, version 2, profile 30, genesis 32, since 8, until 8,
    // P 1, count 4, payload length 4. A negative until precedes since.
    for (at, name) in [
        (0, "magic"),
        (8, "version"),
        (87, "until"),
        (88, "P"),
        (89, "count"),
        (93, "payload length"),
    ] {
        let mut corrupt = bytes.clone();
        corrupt[at] ^= 0x80;
        assert!(SeenSet::decode(&corrupt).is_err(), "{name}");
    }
    let mut oversized = bytes;
    oversized.resize(MAX_SEEN_BYTES + 1, 0);
    assert!(SeenSet::decode(&oversized).is_err());
    // A parameter of one writes about 2^14 bits per value here, over the bound.
    let large = SeenSet::new(GENESIS, 0).union(&receivers(30_000, 1));
    assert!(matches!(
        large.with_p(1).unwrap().encode(),
        Err(Error::Capacity)
    ));
}
