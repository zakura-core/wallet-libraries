use sha2::{Digest, Sha256};
use zakura_pir_protocol::receiver::{
    Error, ReceiverBytes,
    blocks::{
        Batch, BlockFilter, BlockId, Head, MAX_BATCH_BYTES, MAX_BLOCKS, MAX_RANGE_BLOCKS,
        MAX_RECEIVERS, Range,
    },
};

const GENESIS: [u8; 32] = [9; 32];

/// Returns deterministic distinct inputs without depending on filter internals.
fn receivers(count: u32) -> Vec<ReceiverBytes> {
    (0..count)
        .map(|i| {
            let mut receiver = [0; 43];
            receiver[..4].copy_from_slice(&i.to_le_bytes());
            receiver
        })
        .collect()
}

/// Builds connected sample blocks, including an explicit empty block.
fn sample() -> (Head, Batch, Vec<ReceiverBytes>) {
    let members = receivers(12);
    let blocks = (10u32..13)
        .map(|height| {
            BlockFilter::build(
                &GENESIS,
                BlockId {
                    height,
                    hash: [height as u8; 32],
                },
                [(height - 1) as u8; 32],
                if height == 11 {
                    &members[..0]
                } else {
                    &members[..]
                },
            )
            .unwrap()
        })
        .collect();
    let head = Head {
        genesis: GENESIS,
        revision: 3,
        first: 10,
        tip: BlockId {
            height: 12,
            hash: [12; 32],
        },
    };
    (head, Batch::new(GENESIS, 3, blocks).unwrap(), members)
}

/// Every member survives encoding and decoding while explicit empty blocks remain negative.
#[test]
fn round_trip_preserves_members_and_empty_blocks() {
    let (head, batch, members) = sample();
    let bytes = batch.encode().unwrap();
    let decoded = Batch::decode(&bytes).unwrap();
    decoded.check(&head, 10, 3).unwrap();
    assert_eq!(decoded, batch);
    assert_eq!(
        decoded.matches(0, &members).unwrap(),
        vec![true; members.len()]
    );
    assert_eq!(
        decoded.matches(1, &members).unwrap(),
        vec![false; members.len()]
    );
    assert_eq!(
        decoded.matches(2, &members).unwrap(),
        vec![true; members.len()]
    );
    assert!(decoded.matches(3, &members).is_err());
}

/// The independent BIP158 writer agrees with the actual serialized block payload.
#[test]
fn payload_matches_independent_codec() {
    let members = receivers(100);
    let block = BlockId {
        height: 10,
        hash: [10; 32],
    };
    let filter =
        BlockFilter::build(&GENESIS, block, [9; 32], members.iter().chain(&members)).unwrap();
    let encoded = Batch::new(GENESIS, 0, vec![filter])
        .unwrap()
        .encode()
        .unwrap();
    let salt = Sha256::new()
        .chain_update(b"ironwood-receiver/v1/block-hints\0")
        .chain_update(GENESIS)
        .chain_update(10u32.to_le_bytes())
        .chain_update([10; 32])
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
    // Header: magic/genesis/revision/count; block: height/hash/parent/payload length.
    assert_eq!(&encoded[52 + 72..], expected);
}

/// Truncation and extra bytes cannot turn malformed data into negative membership.
#[test]
fn malformed_envelopes_and_gcs_are_rejected() {
    let (_, batch, _) = sample();
    let bytes = batch.encode().unwrap();
    for end in 0..bytes.len() {
        assert!(Batch::decode(&bytes[..end]).is_err(), "prefix {end}");
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(Batch::decode(&extra).is_err());
    let mut bad_magic = bytes.clone();
    bad_magic[0] ^= 1;
    assert!(Batch::decode(&bad_magic).is_err());
    let mut bad_count = bytes.clone();
    bad_count[48..52].copy_from_slice(&(MAX_BLOCKS + 1).to_le_bytes());
    assert!(Batch::decode(&bad_count).is_err());
    let mut bad_payload = bytes.clone();
    bad_payload[124] = 250;
    assert!(Batch::decode(&bad_payload).is_err());
    assert!(Batch::decode(&vec![0; MAX_BATCH_BYTES + 1]).is_err());
}

/// A publication correction, foreign network or mismatched requested range is refused.
#[test]
fn captured_head_and_requested_range_are_binding() {
    let (head, batch, _) = sample();
    let mut wrong = head.clone();
    wrong.revision += 1;
    assert!(batch.check(&wrong, 10, 3).is_err());
    wrong = head.clone();
    wrong.genesis[0] ^= 1;
    assert!(batch.check(&wrong, 10, 3).is_err());
    wrong = head.clone();
    wrong.tip.hash[0] ^= 1;
    assert!(batch.check(&wrong, 10, 3).is_err());
    assert!(batch.check(&head, 11, 3).is_err());
    assert!(batch.check(&head, 10, 2).is_err());
    assert!(batch.check(&head, 10, 0).is_err());
    assert!(head.check_request(9, 3).is_err());
    assert!(head.check_request(13, 3).is_err());
    assert!(head.validate(&[1; 32]).is_err());
    wrong = head;
    wrong.first = 0;
    assert!(wrong.validate(&GENESIS).is_err());
}

/// Gaps, disconnected parents and foreign builder inputs cannot produce valid batches.
#[test]
fn mixed_chains_and_networks_are_rejected() {
    let (_, batch, _) = sample();
    let bytes = batch.encode().unwrap();
    let first_len = u32::from_le_bytes(bytes[120..124].try_into().unwrap()) as usize;
    let second = 124 + first_len;
    let mut gap = bytes.clone();
    gap[second..second + 4].copy_from_slice(&12u32.to_le_bytes());
    assert!(Batch::decode(&gap).is_err());
    let mut fork = bytes;
    fork[second + 36] ^= 1;
    assert!(Batch::decode(&fork).is_err());
    assert!(Batch::new([1; 32], 3, batch.filters().to_vec()).is_err());
}

/// Byte-limited serving may return a consecutive prefix, never an empty success.
#[test]
fn bounded_prefix_progress_is_unambiguous() {
    let (head, batch, _) = sample();
    let prefix = Batch::new(GENESIS, 3, batch.filters()[..1].to_vec()).unwrap();
    prefix.check(&head, 10, 3).unwrap();
    assert_eq!(prefix.filters().last().unwrap().block().height + 1, 11);
    assert!(Batch::new(GENESIS, 3, vec![]).is_err());
    assert!(head.check_request(10, MAX_BLOCKS + 1).is_err());
}

/// Capacity applies to distinct recipients rather than input repetition.
#[test]
fn capacity_is_bounded_before_filter_allocation() {
    let members = receivers(MAX_RECEIVERS + 1);
    let block = BlockId {
        height: 1,
        hash: [1; 32],
    };
    assert!(BlockFilter::build(&GENESIS, block, GENESIS, &members).is_err());
    assert!(
        BlockFilter::build(
            &GENESIS,
            block,
            GENESIS,
            std::iter::repeat_n(&members[0], MAX_RECEIVERS as usize + 1)
        )
        .is_ok()
    );
}

/// One block's batch at height 10 whose GCS payload is `payload`, encoded by hand.
fn with_payload(payload: &[u8]) -> Vec<u8> {
    let block = BlockId {
        height: 10,
        hash: [10; 32],
    };
    let filter = BlockFilter::build(&GENESIS, block, [9; 32], &receivers(0)).unwrap();
    let mut bytes = Batch::new(GENESIS, 0, vec![filter])
        .unwrap()
        .encode()
        .unwrap();
    // Header: magic/genesis/revision/count; block: height/hash/parent/payload length.
    bytes.truncate(120);
    bytes.extend((payload.len() as u32).to_le_bytes());
    bytes.extend(payload);
    bytes
}

/// The decoder accepts only canonical sets: every value below the set's range, a minimal
/// count, zero padding bits and no bytes after the last value. Each one-value payload
/// codes quotient 1 or 2 in unary, then a zero 20-bit remainder.
#[test]
fn only_canonical_gcs_payloads_decode() {
    // Quotient 1: value 2^20, below the range 1 * M.
    let canonical = [1, 0b1000_0000, 0, 0];
    assert!(Batch::decode(&with_payload(&canonical)).is_ok());
    // Quotient 2: value 2^21, at or past the range.
    assert!(matches!(
        Batch::decode(&with_payload(&[1, 0b1100_0000, 0, 0])),
        Err(Error::Malformed)
    ));
    // The same count as a three-byte CompactSize.
    assert!(matches!(
        Batch::decode(&with_payload(&[0xfd, 1, 0, 0b1000_0000, 0, 0])),
        Err(Error::Malformed)
    ));
    // A set bit in the two padding bits.
    assert!(matches!(
        Batch::decode(&with_payload(&[1, 0b1000_0000, 0, 1])),
        Err(Error::Malformed)
    ));
    // A byte after the last value, inside the declared payload.
    assert!(matches!(
        Batch::decode(&with_payload(&[1, 0b1000_0000, 0, 0, 0])),
        Err(Error::Malformed)
    ));
    // A real set's last byte with a padding bit set.
    let (_, batch, _) = sample();
    let mut bytes = batch.encode().unwrap();
    let len = u32::from_le_bytes(bytes[120..124].try_into().unwrap()) as usize;
    bytes[124 + len - 1] |= 1;
    assert!(Batch::decode(&bytes).is_err());
}

/// Batches are bounded in bytes before decoding and when built, and a block's declared
/// receiver count is bounded before its set is decoded.
#[test]
fn batches_and_block_sets_are_bounded() {
    let (_, batch, _) = sample();
    let mut padded = batch.encode().unwrap();
    padded.resize(MAX_BATCH_BYTES + 1, 0);
    assert!(matches!(Batch::decode(&padded), Err(Error::Capacity)));

    let mut count = vec![0xfe];
    count.extend((MAX_RECEIVERS + 1).to_le_bytes());
    assert!(matches!(
        Batch::decode(&with_payload(&count)),
        Err(Error::Capacity)
    ));

    // Full blocks of distinct receivers exceed the byte bound long before the block bound.
    let members = receivers(MAX_RECEIVERS);
    let mut filters = Vec::new();
    let mut parent = [0; 32];
    for height in 1..=24u32 {
        let block = BlockId {
            height,
            hash: Sha256::digest(height.to_le_bytes()).into(),
        };
        filters.push(BlockFilter::build(&GENESIS, block, parent, &members).unwrap());
        parent = block.hash;
    }
    assert!(matches!(
        Batch::new(GENESIS, 0, filters.clone()),
        Err(Error::Capacity)
    ));
    filters.truncate(4);
    assert!(Batch::new(GENESIS, 0, filters).is_ok());
}

/// A non-member matches a block's set with probability about 1 in 1,569,792, so 2,000
/// non-members almost never match a populated block.
#[test]
fn non_members_rarely_match() {
    let (_, batch, members) = sample();
    let others: Vec<ReceiverBytes> = (0..2_000u32)
        .map(|i| {
            let mut receiver = [0xff; 43];
            receiver[..4].copy_from_slice(&i.to_le_bytes());
            receiver
        })
        .filter(|r| !members.contains(r))
        .collect();
    let matched = batch
        .matches(0, &others)
        .unwrap()
        .into_iter()
        .filter(|m| *m)
        .count();
    assert!(matched <= 1, "{matched} false matches");
}

/// The consumer-side hashes for `sample`: the parent of height 10, then heights 10 to 12.
fn sample_chain() -> ([u8; 32], Vec<[u8; 32]>) {
    ([9; 32], vec![[10; 32], [11; 32], [12; 32]])
}

/// A range carries only the sets, so an empty block costs one byte, and binding it to the
/// consumer's own hashes recovers the exact batch the service holds.
#[test]
fn range_round_trip_binds_to_the_consumers_chain() {
    let (head, batch, members) = sample();
    let bytes = Range::encode(&GENESIS, 3, batch.filters()).unwrap();
    let sets: usize = batch
        .filters()
        .iter()
        .map(|f| {
            let one = Batch::new(GENESIS, 3, vec![f.clone()]).unwrap();
            // A batch of one adds its header and the block's height, hash, parent and length.
            one.encode().unwrap().len() - (8 + 32 + 8 + 4) - (4 + 32 + 32 + 4)
        })
        .sum();
    assert_eq!(bytes.len(), 8 + 8 + 4 + 4 + 32 + sets);
    let range = Range::decode(&bytes).unwrap();
    range.check(&head, 10, 3).unwrap();
    assert_eq!((range.from(), range.end()), (10, 12));
    let (parent, hashes) = sample_chain();
    let bound = range.bind(&GENESIS, parent, &hashes).unwrap();
    assert_eq!(bound, vec![batch]);
    assert_eq!(
        bound[0].matches(1, &members).unwrap(),
        vec![false; members.len()]
    );
    assert_eq!(
        bound[0].matches(2, &members).unwrap(),
        vec![true; members.len()]
    );
}

/// Any difference from the chain the service coded on fails closed instead of matching
/// under the wrong keys.
#[test]
fn range_bind_rejects_another_chain() {
    let (_, batch, _) = sample();
    let range = Range::decode(&Range::encode(&GENESIS, 3, batch.filters()).unwrap()).unwrap();
    let (parent, hashes) = sample_chain();
    let mut middle = hashes.clone();
    middle[1] = [99; 32];
    for (genesis, parent, hashes) in [
        (GENESIS, [8; 32], hashes.clone()),
        (GENESIS, parent, middle),
        (GENESIS, parent, hashes[..2].to_vec()),
        ([7; 32], parent, hashes.clone()),
    ] {
        assert!(matches!(
            range.bind(&genesis, parent, &hashes),
            Err(Error::Coverage)
        ));
    }
}

/// Truncation, trailing bytes, foreign magic and impossible counts never decode.
#[test]
fn malformed_ranges_are_rejected() {
    let (_, batch, _) = sample();
    let bytes = Range::encode(&GENESIS, 3, batch.filters()).unwrap();
    for cut in 0..bytes.len() {
        assert!(Range::decode(&bytes[..cut]).is_err(), "cut at {cut}");
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Range::decode(&trailing).is_err());
    assert!(Range::decode(&batch.encode().unwrap()).is_err());
    for count in [0, MAX_RANGE_BLOCKS + 1] {
        let mut wrong = bytes.clone();
        wrong[20..24].copy_from_slice(&count.to_le_bytes());
        assert!(Range::decode(&wrong).is_err());
    }
}

/// A response is bound to the captured head's revision, the requested start and limit,
/// and the advertised tip.
#[test]
fn range_check_binds_head_and_request() {
    let (head, batch, _) = sample();
    let range = Range::decode(&Range::encode(&GENESIS, 3, batch.filters()).unwrap()).unwrap();
    range.check(&head, 10, MAX_RANGE_BLOCKS).unwrap();
    let stale = Head {
        revision: 4,
        ..head.clone()
    };
    let behind = Head {
        tip: BlockId {
            height: 11,
            hash: [11; 32],
        },
        ..head.clone()
    };
    assert!(range.check(&stale, 10, 3).is_err());
    assert!(range.check(&behind, 10, 3).is_err());
    assert!(range.check(&head, 11, 3).is_err());
    assert!(range.check(&head, 10, 2).is_err());
    assert!(range.check(&head, 10, MAX_RANGE_BLOCKS + 1).is_err());
}

/// One response covers more than a batch's worth of blocks and binds back into batches of
/// at most `MAX_BLOCKS`.
#[test]
fn one_range_spans_many_batches() {
    let members = receivers(3);
    let count = 2 * MAX_BLOCKS + 88;
    let hash = |height: u32| -> [u8; 32] { Sha256::digest(height.to_le_bytes()).into() };
    let filters: Vec<_> = (100..100 + count)
        .map(|height| {
            BlockFilter::build(
                &GENESIS,
                BlockId {
                    height,
                    hash: hash(height),
                },
                hash(height - 1),
                if height % 97 == 0 {
                    &members[..]
                } else {
                    &members[..0]
                },
            )
            .unwrap()
        })
        .collect();
    let bytes = Range::encode(&GENESIS, 1, &filters).unwrap();
    // Empty blocks dominate, at one byte each.
    assert!(bytes.len() < 2 * count as usize, "{} bytes", bytes.len());
    let range = Range::decode(&bytes).unwrap();
    let head = Head {
        genesis: GENESIS,
        revision: 1,
        first: 100,
        tip: filters.last().unwrap().block(),
    };
    range.check(&head, 100, MAX_RANGE_BLOCKS).unwrap();
    let hashes: Vec<_> = (100..100 + count).map(hash).collect();
    let bound = range.bind(&GENESIS, hash(99), &hashes).unwrap();
    assert_eq!(
        bound.iter().map(|b| b.filters().len()).collect::<Vec<_>>(),
        vec![256, 256, 88]
    );
    let rebuilt: Vec<_> = bound
        .iter()
        .flat_map(|b| b.filters().iter().cloned())
        .collect();
    assert_eq!(rebuilt, filters);
}

/// A range just under the byte cap stays usable: restoring each block's identity would
/// push one batch past `MAX_BATCH_BYTES`, so binding splits by size as well as count.
#[test]
fn a_dense_range_binds_into_batches_within_the_byte_cap() {
    let hash = |height: u32| -> [u8; 32] { Sha256::digest(height.to_le_bytes()).into() };
    let block = |height: u32, members: &[ReceiverBytes]| {
        BlockFilter::build(
            &GENESIS,
            BlockId {
                height,
                hash: hash(height),
            },
            hash(height - 1),
            members,
        )
        .unwrap()
    };
    let dense = receivers(MAX_RECEIVERS);
    let range_bytes = |filters: &[BlockFilter]| {
        Range::decode(&Range::encode(&GENESIS, 1, filters).unwrap())
            .map(|range| (range.end() - range.from() + 1) as usize == filters.len())
            .unwrap()
            .then(|| Range::encode(&GENESIS, 1, filters).unwrap().len())
    };
    // Fill with full blocks while the whole range still fits one response.
    let mut filters = Vec::new();
    loop {
        filters.push(block(100 + filters.len() as u32, &dense));
        if range_bytes(&filters).is_none() {
            filters.pop();
            break;
        }
    }
    // Then size one last block so the range fits but a single batch of it would not.
    let blocks = filters.len() + 1;
    let (mut low, mut high) = (0u32, MAX_RECEIVERS);
    let mut tail = None;
    while low <= high {
        let mid = low + (high - low) / 2;
        let mut candidate = filters.clone();
        candidate.push(block(100 + filters.len() as u32, &dense[..mid as usize]));
        match range_bytes(&candidate) {
            Some(bytes) if bytes - 4 + 72 * blocks > MAX_BATCH_BYTES => {
                tail = Some(candidate);
                break;
            }
            Some(_) => low = mid + 1,
            None => high = mid - 1,
        }
    }
    let filters = tail.expect("a tail size puts the range within 72 bytes per block of the cap");
    assert!(matches!(
        Batch::new(GENESIS, 1, filters.clone()),
        Err(Error::Capacity)
    ));
    let range = Range::decode(&Range::encode(&GENESIS, 1, &filters).unwrap()).unwrap();
    let hashes: Vec<_> = (100..100 + filters.len() as u32).map(hash).collect();
    let bound = range.bind(&GENESIS, hash(99), &hashes).unwrap();
    assert!(bound.len() > 1);
    for batch in &bound {
        assert!(batch.encode().unwrap().len() <= MAX_BATCH_BYTES);
    }
    let rebuilt: Vec<_> = bound
        .iter()
        .flat_map(|b| b.filters().iter().cloned())
        .collect();
    assert_eq!(rebuilt, filters);
}
