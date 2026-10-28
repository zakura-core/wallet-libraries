use sha2::{Digest, Sha256};
use zakura_pir_protocol::receiver::{
    Error, ReceiverBytes,
    blocks::{BlockId, Head, HeightSet, MAX_RANGE_BYTES, MAX_RECEIVERS, RANGE_HEADER, Range},
};

const GENESIS: [u8; 32] = [9; 32];

/// Returns deterministic distinct receivers.
fn receivers(count: u32) -> Vec<ReceiverBytes> {
    (0..count)
        .map(|i| {
            let mut receiver = [0; 43];
            receiver[..4].copy_from_slice(&i.to_le_bytes());
            receiver
        })
        .collect()
}

/// Heights 10 to 14 with payments at 11 and 14 only.
fn sample() -> (Range, Vec<ReceiverBytes>) {
    let members = receivers(12);
    let sets = [11, 14]
        .into_iter()
        .map(|h| HeightSet::build(&GENESIS, h, &members).unwrap().unwrap())
        .collect();
    (
        Range::new(3, 10, 5, [9; 32], [14; 32], sets).unwrap(),
        members,
    )
}

/// The head that served `sample`.
fn head() -> Head {
    Head {
        genesis: GENESIS,
        revision: 3,
        first: 1,
        sealed: 0,
        tip: BlockId {
            height: 20,
            hash: [20; 32],
        },
    }
}

/// Only nonempty blocks are carried, every member matches at its own heights, and empty
/// heights never match.
#[test]
fn round_trip_carries_only_paying_blocks() {
    let (range, members) = sample();
    let bytes = range.encode().unwrap();
    let decoded = Range::decode(&bytes).unwrap();
    assert_eq!(decoded, range);
    assert_eq!(decoded.heights().collect::<Vec<_>>(), [11, 14]);
    assert_eq!(
        (decoded.from(), decoded.end()),
        (
            10,
            BlockId {
                height: 14,
                hash: [14; 32]
            }
        )
    );
    let hits = decoded.matches(&GENESIS, &members);
    assert_eq!(hits.len(), 2 * members.len());
    assert!(hits.iter().all(|(h, _)| *h == 11 || *h == 14));
    // A server re-issues stored sets under another revision without decoding them.
    let raw = Range::raw_sets(&bytes).unwrap();
    assert_eq!(raw.iter().map(|(h, _)| *h).collect::<Vec<_>>(), [11, 14]);
    let end = decoded.end();
    let reissued = Range::write(9, 10, 5, decoded.parent(), end.hash, &raw).unwrap();
    assert_eq!(reissued.len(), bytes.len());
    let built: Vec<_> = sample().0.encode().unwrap();
    assert_eq!(built, bytes);
    assert_eq!(
        Range::decode(&reissued)
            .unwrap()
            .matches(&GENESIS, &members),
        hits
    );
    for wrong in [
        vec![raw[1], raw[0]],
        vec![(9, raw[0].1)],
        vec![(15, raw[0].1)],
    ] {
        assert!(Range::write(9, 10, 5, [0; 32], [0; 32], &wrong).is_err());
    }
}

/// A range of only empty blocks is a header and nothing else.
#[test]
fn an_empty_range_is_just_its_header() {
    let range = Range::new(0, 100, 1_000, [1; 32], [2; 32], vec![]).unwrap();
    let bytes = range.encode().unwrap();
    assert_eq!(bytes.len(), RANGE_HEADER);
    assert_eq!(Range::decode(&bytes).unwrap(), range);
    assert!(
        HeightSet::build(&GENESIS, 5, &receivers(0))
            .unwrap()
            .is_none()
    );
}

/// A set's key depends on its height, so the same receivers code differently at another
/// height, and the wire bytes match an independent BIP 158 writer.
#[test]
fn sets_are_keyed_by_height_and_match_an_independent_codec() {
    let members = receivers(100);
    let set = HeightSet::build(&GENESIS, 10, members.iter().chain(&members))
        .unwrap()
        .unwrap();
    let encoded = Range::new(0, 10, 1, [0; 32], [0; 32], vec![set])
        .unwrap()
        .encode()
        .unwrap();
    let salt = Sha256::new()
        .chain_update(b"ironwood-receiver/v2/height-hints\0")
        .chain_update(GENESIS)
        .chain_update(10u32.to_le_bytes())
        .finalize();
    let digest = Sha256::new()
        .chain_update(b"ironwood-receiver/v1/filter\0")
        .chain_update(salt)
        .finalize();
    let k0 = u64::from_le_bytes(digest[..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(digest[8..16].try_into().unwrap());
    let mut expected = Vec::new();
    let mut writer = bitcoin::bip158::GcsFilterWriter::new(&mut expected, k0, k1, 1_569_792, 20);
    for receiver in &members {
        writer.add_element(receiver);
    }
    writer.finish().unwrap();
    // Header, then a one-byte gap of zero before the set.
    assert_eq!(encoded[RANGE_HEADER], 0);
    assert_eq!(&encoded[RANGE_HEADER + 1..], expected);
    let moved = HeightSet::build(&GENESIS, 11, &members).unwrap().unwrap();
    let range = Range::new(0, 11, 1, [0; 32], [0; 32], vec![moved]).unwrap();
    let hits = range.matches(&GENESIS, &members);
    assert_eq!(hits.len(), members.len());
}

/// Truncation, trailing bytes, foreign magic, empty sets and sets outside the range never
/// decode into negative membership.
#[test]
fn malformed_ranges_are_rejected() {
    let (range, _) = sample();
    let bytes = range.encode().unwrap();
    for cut in 0..bytes.len() {
        assert!(Range::decode(&bytes[..cut]).is_err(), "cut at {cut}");
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Range::decode(&trailing).is_err());
    let mut magic = bytes.clone();
    magic[7] ^= 1;
    assert!(Range::decode(&magic).is_err());
    // A gap that lands past the range's last height.
    let mut far = bytes.clone();
    far[RANGE_HEADER] = 9;
    assert!(Range::decode(&far).is_err());
    // A canonical gap so large that adding it to the height overflows.
    let mut overflow = Range::new(3, 10, 5, [9; 32], [14; 32], vec![])
        .unwrap()
        .encode()
        .unwrap();
    let entries = RANGE_HEADER - 4;
    overflow[entries..RANGE_HEADER].copy_from_slice(&1u32.to_le_bytes());
    overflow.push(0xff);
    overflow.extend(u64::MAX.to_le_bytes());
    overflow.extend([1, 0]);
    assert!(Range::decode(&overflow).is_err());
    // An entry whose set is empty.
    let mut empty = Range::new(3, 10, 5, [9; 32], [14; 32], vec![])
        .unwrap()
        .encode()
        .unwrap();
    let entries = RANGE_HEADER - 4;
    empty[entries..RANGE_HEADER].copy_from_slice(&1u32.to_le_bytes());
    empty.extend([0, 0]);
    assert!(Range::decode(&empty).is_err());
    assert!(Range::new(3, 10, 0, [9; 32], [9; 32], vec![]).is_err());
    assert!(Range::new(3, 0, 1, [9; 32], [9; 32], vec![]).is_err());
}

/// A response is bound to the head's revision and tip and to the request, and may start
/// at an earlier chunk boundary as long as it covers the requested height.
#[test]
fn check_binds_head_and_request() {
    let (range, _) = sample();
    range.check(&head(), 10, 5).unwrap();
    range.check(&head(), 12, 3).unwrap();
    let stale = Head {
        revision: 4,
        ..head()
    };
    assert!(range.check(&stale, 10, 5).is_err());
    assert!(
        range.check(&head(), 9, 5).is_err(),
        "starts after the request"
    );
    assert!(
        range.check(&head(), 15, 5).is_err(),
        "ends before the request"
    );
    assert!(range.check(&head(), 10, 4).is_err(), "longer than asked");
    let at_tip = Head {
        tip: BlockId {
            height: 14,
            hash: [99; 32],
        },
        ..head()
    };
    assert!(range.check(&at_tip, 10, 5).is_err(), "tip hash differs");
    let later = Head {
        first: 11,
        ..head()
    };
    assert!(
        range.check(&later, 11, 4).is_err(),
        "starts below the served history"
    );
    assert!(head().check_range(1, 0).is_err());
    assert!(
        Head {
            sealed: 21,
            ..head()
        }
        .validate(&GENESIS)
        .is_err()
    );
    assert!(head().validate(&[8; 32]).is_err());
}

/// A range follows another only from the next height and with its end hash as parent.
#[test]
fn ranges_chain_by_parent_hash() {
    let (range, _) = sample();
    let next = Range::new(3, 15, 5, [14; 32], [19; 32], vec![]).unwrap();
    assert!(next.follows(&range));
    assert!(
        !Range::new(3, 15, 5, [13; 32], [19; 32], vec![])
            .unwrap()
            .follows(&range)
    );
    assert!(
        !Range::new(3, 16, 5, [14; 32], [20; 32], vec![])
            .unwrap()
            .follows(&range)
    );
}

/// Encoding refuses a range past the byte cap, and a block never holds more than the
/// receiver limit.
#[test]
fn capacity_is_bounded() {
    let dense = receivers(MAX_RECEIVERS);
    assert!(matches!(
        HeightSet::build(&GENESIS, 1, &receivers(MAX_RECEIVERS + 1)),
        Err(Error::Capacity)
    ));
    let mut sets = Vec::new();
    let mut size = RANGE_HEADER;
    let mut height = 1;
    while size <= MAX_RANGE_BYTES {
        let set = HeightSet::build(&GENESIS, height, &dense).unwrap().unwrap();
        size += 1 + set.encoded_len();
        sets.push(set);
        height += 1;
    }
    let range = Range::new(0, 1, height - 1, [0; 32], [0; 32], sets).unwrap();
    assert!(matches!(range.encode(), Err(Error::Capacity)));
}

/// A non-member matches a block's set with probability about 1 in 1,569,792, so 2,000
/// non-members almost never match.
#[test]
fn non_members_rarely_match() {
    let (range, members) = sample();
    let others: Vec<ReceiverBytes> = (0..2_000u32)
        .map(|i| {
            let mut receiver = [0xff; 43];
            receiver[..4].copy_from_slice(&i.to_le_bytes());
            receiver
        })
        .filter(|r| !members.contains(r))
        .collect();
    assert!(range.matches(&GENESIS, &others).len() <= 1);
}
