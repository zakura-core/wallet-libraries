//! Paid buckets, cumulative paid sets, the seen set and the catalog.
use receiver_directory::{
    catalog::{BucketIndex, CatalogHead, MAX_INDEX_BUCKETS},
    paid::{bucket_start, PaidSet, Span, BUCKET_BLOCKS, MAX_PAID_BYTES},
    seen::{self, SeenSet, DEFAULT_P, MAX_SEEN_BYTES},
    Error, Hash, ReceiverBytes,
};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};

const GENESIS: Hash = [1; 32];

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

/// The bucket starting at `start`, with boundary hashes derived from the heights.
fn bucket_span(start: u32) -> Span {
    Span {
        start,
        start_hash: [(start / BUCKET_BLOCKS) as u8; 32],
        end: start + BUCKET_BLOCKS,
        end_hash: [(start / BUCKET_BLOCKS + 1) as u8; 32],
    }
}

/// A cumulative span ending at the end of the bucket starting at `start`.
fn cumulative_span(start: u32) -> Span {
    Span {
        start: 0,
        start_hash: GENESIS,
        ..bucket_span(start)
    }
}

/// The 32 bytes a vector field holds in hex.
fn hex32(value: &Value) -> Hash {
    hex::decode(value.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

/// Builds the paid set a vector describes from the vector's receivers.
fn vector_paid(v: &Value, genesis: Hash, all: &[ReceiverBytes]) -> PaidSet {
    let span = Span {
        start: v["start"].as_u64().unwrap() as u32,
        start_hash: hex32(&v["start_hash"]),
        end: v["end"].as_u64().unwrap() as u32,
        end_hash: hex32(&v["end_hash"]),
    };
    let chosen: Vec<_> = v["receivers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| all[i.as_u64().unwrap() as usize])
        .collect();
    PaidSet::build(genesis, v["epoch"].as_u64().unwrap(), span, &chosen).unwrap()
}

/// Every object reproduces the encodings and digests pinned in
/// `fixtures/recovery-vectors.json`, which publishers can check their output against.
#[test]
fn objects_reproduce_their_pinned_vectors() {
    let v: Value = serde_json::from_str(include_str!("fixtures/recovery-vectors.json")).unwrap();
    let genesis = hex32(&v["genesis"]);
    let all: Vec<ReceiverBytes> = v["receivers"]
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
    let mut digests = std::collections::BTreeMap::new();
    for name in ["bucket", "empty_bucket", "cumulative"] {
        let set = vector_paid(&v[name], genesis, &all);
        let encoding = set.encode();
        assert_eq!(
            hex::encode(set.span().salt(&genesis)),
            v[name]["salt"],
            "{name}"
        );
        assert_eq!(hex::encode(&encoding), v[name]["encoding"], "{name}");
        assert_eq!(hex::encode(set.digest()), v[name]["digest"], "{name}");
        assert_eq!(PaidSet::decode(&encoding).unwrap(), set);
        digests.insert(name, set.digest());
    }

    let sv = &v["seen"];
    let mut seen = SeenSet::new(genesis, sv["since_unix"].as_i64().unwrap());
    seen.until_unix = sv["until_unix"].as_i64().unwrap();
    let seen = seen.union(&all);
    let hashes: Vec<u32> = all.iter().map(|r| seen::hash(&genesis, r)).collect();
    assert_eq!(serde_json::to_value(&hashes).unwrap(), sv["hashes"]);
    assert_eq!(hex::encode(seen.encode().unwrap()), sv["encoding"]);
    assert_eq!(hex::encode(seen.digest().unwrap()), sv["digest"]);

    let index = BucketIndex::new(
        genesis,
        vec![
            (
                v["bucket"]["start"].as_u64().unwrap() as u32,
                digests["bucket"],
            ),
            (
                v["empty_bucket"]["start"].as_u64().unwrap() as u32,
                digests["empty_bucket"],
            ),
        ],
    )
    .unwrap();
    assert_eq!(hex::encode(index.encode()), v["index"]["encoding"]);
    assert_eq!(hex::encode(index.digest()), v["index"]["digest"]);

    let hv = &v["head"];
    let head = CatalogHead {
        genesis,
        epoch: hv["epoch"].as_u64().unwrap(),
        oldest_start: hv["oldest_start"].as_u64().unwrap() as u32,
        latest_end: hv["latest_end"].as_u64().unwrap() as u32,
        paid: digests["cumulative"],
        seen: seen.digest().unwrap(),
        index: index.digest(),
    };
    assert_eq!(hex::encode(head.encode().unwrap()), hv["encoding"]);
    assert_eq!(hex::encode(head.digest().unwrap()), hv["digest"]);
    assert_eq!(CatalogHead::decode(&head.encode().unwrap()).unwrap(), head);
}

/// A bucket and a cumulative set decode to themselves, count repeat recipients once,
/// match every member and rarely match anything else.
#[test]
fn paid_sets_round_trip_and_never_miss_a_member() {
    let members = receivers(500, 1);
    // Repeat recipients count once.
    let doubled: Vec<_> = members.iter().chain(&members).collect();
    let bucket = PaidSet::build(GENESIS, 3, bucket_span(4992), doubled).unwrap();
    assert!(bucket.span().is_bucket());
    assert_eq!(bucket.count(), 500);
    assert_eq!(PaidSet::decode(&bucket.encode()).unwrap(), bucket);
    assert!(bucket.matches(&members).iter().all(|m| *m));
    // About one in 1.5 million others matches falsely.
    let others = receivers(20_000, 2);
    let false_matches = bucket.matches(&others).iter().filter(|m| **m).count();
    assert!(false_matches <= 2, "{false_matches} false matches");
    // About 2.75 bytes per receiver.
    assert!(bucket.encode().len() < 200 + 500 * 3);

    let cumulative = PaidSet::build(GENESIS, 3, cumulative_span(4992), &members).unwrap();
    assert!(!cumulative.span().is_bucket());
    assert_eq!(PaidSet::decode(&cumulative.encode()).unwrap(), cumulative);
    assert!(cumulative.matches(&members).iter().all(|m| *m));
}

/// A bucket without payments builds, round-trips and matches nothing.
#[test]
fn empty_buckets_are_valid() {
    let empty = PaidSet::build(GENESIS, 0, bucket_span(48), []).unwrap();
    assert_eq!(empty.count(), 0);
    assert_eq!(PaidSet::decode(&empty.encode()).unwrap(), empty);
    assert_eq!(empty.matches(&receivers(10, 1)), [false; 10]);
}

/// Only aligned 48-block spans are buckets, and every height above zero lies in the
/// bucket that `bucket_start` names.
#[test]
fn buckets_are_aligned() {
    assert!(bucket_span(0).is_bucket());
    assert!(bucket_span(4992).is_bucket());
    assert!(!Span {
        start: 4993,
        end: 5041,
        ..bucket_span(4992)
    }
    .is_bucket());
    assert!(!Span {
        end: 5041,
        ..bucket_span(4992)
    }
    .is_bucket());
    assert!(!Span {
        start: u32::MAX - u32::MAX % BUCKET_BLOCKS,
        end: u32::MAX,
        ..bucket_span(0)
    }
    .is_bucket());
    assert_eq!(bucket_start(0), None);
    assert_eq!(bucket_start(1), Some(0));
    assert_eq!(bucket_start(48), Some(0));
    assert_eq!(bucket_start(49), Some(48));
    assert_eq!(bucket_start(5040), Some(4992));
}

/// The salt is a domain-separated hash of the network and the boundary hashes only:
/// the epoch, the heights, a PIR table's placement salt and its size never enter it.
#[test]
fn the_salt_depends_only_on_network_and_boundaries() {
    let span = bucket_span(4992);
    let expected: Hash = Sha256::new()
        .chain_update(b"ironwood-receiver/v1/paid-salt\0")
        .chain_update(GENESIS)
        .chain_update(span.start_hash)
        .chain_update(span.end_hash)
        .finalize()
        .into();
    assert_eq!(span.salt(&GENESIS), expected);
    let moved = Span {
        start: 96,
        end: 144,
        ..span
    };
    assert_eq!(moved.salt(&GENESIS), expected);
    assert_ne!(span.salt(&[2; 32]), expected);
    let members = receivers(20, 1);
    let one = PaidSet::build(GENESIS, 1, span, &members).unwrap();
    let two = PaidSet::build(GENESIS, 2, span, &members).unwrap();
    assert_eq!(one.matches(&members), two.matches(&members));
    assert_ne!(one.digest(), two.digest());
}

/// Empty spans fail to build, and truncated, extended, corrupted or oversized
/// encodings fail to decode.
#[test]
fn paid_decoding_is_strict() {
    assert!(matches!(
        PaidSet::build(
            GENESIS,
            0,
            Span {
                end: 4992,
                ..bucket_span(4992)
            },
            []
        ),
        Err(Error::Malformed)
    ));
    let bytes = PaidSet::build(GENESIS, 0, bucket_span(4992), &receivers(30, 1))
        .unwrap()
        .encode();
    for end in 0..bytes.len() {
        assert!(PaidSet::decode(&bytes[..end]).is_err(), "{end}");
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(PaidSet::decode(&trailing).is_err());
    // Header layout: magic 8, version 2, profile 30, genesis 32, epoch 8, start 4,
    // start hash 32, end 4, end hash 32, salt 32, P 1, M 8, count 4, payload length 4.
    for (at, name) in [
        (0, "magic"),
        (8, "version"),
        (11, "profile"),
        (84, "start hash"),
        (152, "salt"),
        (184, "P"),
        (185, "M"),
        (193, "count"),
        (197, "payload length"),
    ] {
        let mut corrupt = bytes.clone();
        corrupt[at] ^= 1;
        assert!(PaidSet::decode(&corrupt).is_err(), "{name}");
    }
    let mut oversized = bytes.clone();
    oversized.resize(MAX_PAID_BYTES + 1, 0);
    assert!(PaidSet::decode(&oversized).is_err());
}

/// A bucket over its bound fails to build, and the same receivers fit a cumulative set.
#[test]
fn buckets_have_a_size_bound() {
    let many = receivers(400_000, 4);
    assert!(matches!(
        PaidSet::build(GENESIS, 0, bucket_span(0), &many),
        Err(Error::Capacity)
    ));
    let cumulative = PaidSet::build(GENESIS, 0, cumulative_span(48), &many).unwrap();
    assert_eq!(PaidSet::decode(&cumulative.encode()).unwrap(), cumulative);
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

/// A head with `buckets` retained buckets from 4,992, and its index and sets.
fn catalog(buckets: u32) -> (CatalogHead, BucketIndex, Vec<PaidSet>, PaidSet, SeenSet) {
    let sets: Vec<_> = (0..buckets)
        .map(|i| {
            let members = receivers(i, i as u8);
            PaidSet::build(GENESIS, 7, bucket_span(4992 + i * BUCKET_BLOCKS), &members).unwrap()
        })
        .collect();
    let index = BucketIndex::new(
        GENESIS,
        sets.iter().map(|s| (s.span().start, s.digest())).collect(),
    )
    .unwrap();
    let latest_end = 4992 + buckets * BUCKET_BLOCKS;
    let paid = PaidSet::build(
        GENESIS,
        7,
        cumulative_span(latest_end - 48),
        &receivers(9, 9),
    )
    .unwrap();
    let seen = SeenSet::new(GENESIS, 0).union(&receivers(9, 9));
    let head = CatalogHead {
        genesis: GENESIS,
        epoch: 7,
        oldest_start: 4992,
        latest_end,
        paid: paid.digest(),
        seen: seen.digest().unwrap(),
        index: index.digest(),
    };
    (head, index, sets, paid, seen)
}

/// A head accepts exactly the index, buckets, cumulative set and seen set it names,
/// built under its epoch on its network.
#[test]
fn catalogs_check_every_object_they_name() {
    let (head, index, buckets, paid, seen) = catalog(3);
    assert_eq!(CatalogHead::decode(&head.encode().unwrap()).unwrap(), head);
    assert_eq!(BucketIndex::decode(&index.encode()).unwrap(), index);
    head.check_index(&index).unwrap();
    for bucket in &buckets {
        assert_eq!(index.get(bucket.span().start), Some(bucket.digest()));
        head.check_bucket(&index, bucket).unwrap();
    }
    assert_eq!(index.get(4991), None);
    assert_eq!(index.get(4992 + 3 * 48), None);
    assert_eq!(
        index.iter().map(|(start, _)| start).collect::<Vec<_>>(),
        [4992, 5040, 5088]
    );
    head.check_paid(&paid).unwrap();
    head.check_seen(&seen).unwrap();

    // Another epoch's bucket, a bucket the index does not list and a cumulative set
    // are refused as buckets.
    let stale = PaidSet::build(GENESIS, 6, bucket_span(4992), []).unwrap();
    assert!(head.check_bucket(&index, &stale).is_err());
    let unlisted = PaidSet::build(GENESIS, 7, bucket_span(4992), &receivers(1, 50)).unwrap();
    assert!(head.check_bucket(&index, &unlisted).is_err());
    let beyond = PaidSet::build(GENESIS, 7, bucket_span(5136), []).unwrap();
    assert!(head.check_bucket(&index, &beyond).is_err());
    assert!(head.check_bucket(&index, &paid).is_err());
    let foreign = PaidSet::build([2; 32], 7, bucket_span(4992), []).unwrap();
    assert!(head.check_bucket(&index, &foreign).is_err());

    // A cumulative set must be the named one and end at or after the oldest retained
    // bucket's start. Its cutoff may lie at that start, inside the open bucket
    // `(5136, 5184]` or past it, since the wallet bridges with the buckets after it.
    assert!(head.check_paid(&buckets[0]).is_err());
    let (_, _, _, older, _) = catalog(2);
    assert!(head.check_paid(&older).is_err());
    for (end, accepted) in [(4991, false), (4992, true), (5150, true), (6000, true)] {
        let mut moved = head.clone();
        let cutoff = PaidSet::build(
            GENESIS,
            7,
            Span {
                end,
                ..cumulative_span(0)
            },
            [],
        )
        .unwrap();
        moved.paid = cutoff.digest();
        assert_eq!(moved.check_paid(&cutoff).is_ok(), accepted, "{end}");
    }
    let mut epoch = head.clone();
    epoch.epoch = 8;
    assert!(epoch.check_paid(&paid).is_err());

    let grown = seen.union(&receivers(1, 10));
    assert!(head.check_seen(&grown).is_err());
}

/// Indexes are contiguous, aligned and bounded, and a head accepts only the index
/// listing exactly its retained buckets.
#[test]
fn bucket_indexes_are_contiguous_and_match_their_head() {
    let (head, index, buckets, _, _) = catalog(3);
    let digest = |i: usize| buckets[i].digest();
    // Gaps, misalignment, repeats and disorder are refused.
    for starts in [
        vec![(4992, digest(0)), (5088, digest(2))],
        vec![(4993, digest(0))],
        vec![(4992, digest(0)), (4992, digest(0))],
        vec![(5040, digest(1)), (4992, digest(0))],
        vec![(u32::MAX - u32::MAX % 48, digest(0))],
    ] {
        assert!(BucketIndex::new(GENESIS, starts).is_err());
    }
    let too_many = (0..=MAX_INDEX_BUCKETS)
        .map(|i| (i * BUCKET_BLOCKS, [0; 32]))
        .collect();
    assert!(BucketIndex::new(GENESIS, too_many).is_err());

    // The head commits to exactly its retained buckets.
    let shorter = BucketIndex::new(GENESIS, index.iter().take(2).collect()).unwrap();
    let later = BucketIndex::new(GENESIS, index.iter().skip(1).collect()).unwrap();
    let foreign = BucketIndex::new([2; 32], index.iter().collect()).unwrap();
    for wrong in [&shorter, &later, &foreign] {
        assert!(head.check_index(wrong).is_err());
        let mut renamed = head.clone();
        renamed.index = wrong.digest();
        assert!(renamed.check_index(wrong).is_err());
    }
    let mut misnamed = head.clone();
    misnamed.index = [0; 32];
    assert!(misnamed.check_index(&index).is_err());

    // No retained buckets is an empty index.
    let empty = BucketIndex::new(GENESIS, Vec::new()).unwrap();
    let none = CatalogHead {
        latest_end: 4992,
        index: empty.digest(),
        ..head.clone()
    };
    none.check_index(&empty).unwrap();

    let bytes = index.encode();
    for end in 0..bytes.len() {
        assert!(BucketIndex::decode(&bytes[..end]).is_err(), "{end}");
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(BucketIndex::decode(&trailing).is_err());
}

/// Heads with unaligned, reversed or too many retained buckets fail to encode and
/// decode, as do truncated and extended encodings.
#[test]
fn catalog_heads_are_validated() {
    let (head, ..) = catalog(1);
    for bad in [
        CatalogHead {
            oldest_start: 4993,
            ..head.clone()
        },
        CatalogHead {
            latest_end: 5041,
            ..head.clone()
        },
        CatalogHead {
            oldest_start: 5088,
            ..head.clone()
        },
        CatalogHead {
            oldest_start: 0,
            latest_end: (MAX_INDEX_BUCKETS + 1) * BUCKET_BLOCKS,
            ..head.clone()
        },
    ] {
        assert!(bad.encode().is_err());
    }
    let bytes = head.encode().unwrap();
    for end in 0..bytes.len() {
        assert!(CatalogHead::decode(&bytes[..end]).is_err(), "{end}");
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(CatalogHead::decode(&trailing).is_err());
    let mut unaligned = bytes.clone();
    // Header 72, epoch 8, then the oldest start.
    unaligned[80] ^= 1;
    assert!(CatalogHead::decode(&unaligned).is_err());
}
