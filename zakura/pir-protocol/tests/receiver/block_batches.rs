use sha2::{Digest, Sha256};
use zakura_pir_protocol::receiver::{
    Error, ReceiverBytes,
    blocks::{Batch, BlockFilter, BlockId, Head, MAX_BATCH_BYTES, MAX_BLOCKS, MAX_RECEIVERS},
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
