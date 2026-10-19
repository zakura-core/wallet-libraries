//! Per-block hints retain strict decoding and the independent upstream GCS oracle.
use bitcoin::bip158::GcsFilterWriter;
use receiver_directory::{
    blocks::{BlockFilter, BlockId, M, MAX_BLOCK_FILTER_BYTES, MAX_RECEIVERS, P},
    snapshot::PROFILE,
    Error, Hash, ReceiverBytes,
};
use sha2::{Digest, Sha256, Sha512};

const GENESIS: Hash = [1; 32];
const BLOCK: BlockId = BlockId {
    height: 100,
    hash: [2; 32],
};
const HEADER: usize = 8 + 2 + 1 + PROFILE.len() + 32;
const COUNT: usize = HEADER + 4 + 32 + 32 + 1 + 8;
const PAYLOAD: usize = COUNT + 4 + 4;

/// Generates deterministic distinct byte strings without assuming receiver validity.
fn receivers(count: u32) -> Vec<ReceiverBytes> {
    (0..count)
        .map(|i| Sha512::digest(i.to_le_bytes())[..43].try_into().unwrap())
        .collect()
}

/// Repeated recipients count once and every member matches after canonical decoding.
#[test]
fn block_membership_and_payload_match_upstream() {
    for count in [0, 1, 2, 252, 253, 1_000] {
        let members = receivers(count);
        let filter = BlockFilter::build(GENESIS, BLOCK, members.iter().chain(&members)).unwrap();
        assert_eq!(filter.count(), count);
        assert_eq!(filter.genesis(), GENESIS);
        assert_eq!(filter.block(), BLOCK);
        let bytes = filter.encode();
        let decoded = BlockFilter::decode(&bytes).unwrap();
        assert_eq!(decoded, filter);
        assert!(decoded.matches(&members).into_iter().all(|hit| hit));
        let salt = Sha256::new()
            .chain_update(b"ironwood-receiver/v1/block-filter-salt\0")
            .chain_update(GENESIS)
            .chain_update(100u32.to_le_bytes())
            .chain_update([2; 32])
            .finalize();
        let keys = Sha256::new()
            .chain_update(b"ironwood-receiver/v1/filter\0")
            .chain_update(salt)
            .finalize();
        let mut expected = Vec::new();
        let mut upstream = GcsFilterWriter::new(
            &mut expected,
            u64::from_le_bytes(keys[..8].try_into().unwrap()),
            u64::from_le_bytes(keys[8..16].try_into().unwrap()),
            M,
            P,
        );
        for receiver in &members {
            upstream.add_element(receiver);
        }
        upstream.finish().unwrap();
        assert_eq!(&bytes[PAYLOAD..], expected);
        assert_eq!(filter.digest(), <Hash>::from(Sha256::digest(&bytes)));
    }
}

/// Empty blocks are explicit valid objects, not absent data or a reused earlier filter.
#[test]
fn empty_blocks_and_chain_binding() {
    let first = BlockFilter::build(GENESIS, BLOCK, []).unwrap();
    assert_eq!(first.matches(&receivers(4)), [false; 4]);
    assert_eq!(&first.encode()[PAYLOAD..], [0]);
    let next = BlockId {
        height: 101,
        ..BLOCK
    };
    let fork = BlockId {
        hash: [3; 32],
        ..BLOCK
    };
    for (genesis, block) in [(GENESIS, next), (GENESIS, fork), ([4; 32], BLOCK)] {
        assert_ne!(block.salt(&genesis), BLOCK.salt(&GENESIS));
        assert_ne!(
            BlockFilter::build(genesis, block, []).unwrap().digest(),
            first.digest()
        );
    }
}

/// Truncation, surplus bytes and inconsistent metadata never certify a complete block.
#[test]
fn malformed_blocks_are_rejected_before_use() {
    let bytes = BlockFilter::build(GENESIS, BLOCK, &receivers(4))
        .unwrap()
        .encode();
    for end in 0..bytes.len() {
        assert!(BlockFilter::decode(&bytes[..end]).is_err(), "{end}");
    }
    for offset in [
        0,
        8,
        10,
        11,
        HEADER - 1,
        HEADER,
        HEADER + 4,
        HEADER + 36,
        HEADER + 68,
        HEADER + 69,
        COUNT,
        COUNT + 4,
    ] {
        let mut corrupt = bytes.clone();
        corrupt[offset] ^= 1;
        assert!(BlockFilter::decode(&corrupt).is_err(), "offset {offset}");
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(BlockFilter::decode(&trailing).is_err());
    let mut count = bytes;
    count[COUNT..COUNT + 4].copy_from_slice(&MAX_RECEIVERS.to_le_bytes());
    assert!(BlockFilter::decode(&count).is_err());
    assert!(BlockFilter::decode(&vec![0; MAX_BLOCK_FILTER_BYTES + 1]).is_err());
}

/// An inner forged count or noncanonical CompactSize is rejected before allocation.
#[test]
fn payload_count_and_trailing_bits_are_checked() {
    let empty = BlockFilter::build(GENESIS, BLOCK, []).unwrap().encode();
    for payload in [
        &[0xfd, 0, 0][..],
        &[0, 0],
        &[0xff, 255, 255, 255, 255, 255, 255, 255, 255],
    ] {
        let mut bytes = empty[..PAYLOAD].to_vec();
        bytes[COUNT + 4..PAYLOAD].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend(payload);
        assert!(BlockFilter::decode(&bytes).is_err());
    }
    let members = receivers(1);
    let mut bytes = BlockFilter::build(GENESIS, BLOCK, &members)
        .unwrap()
        .encode();
    let mut padding = bytes.clone();
    *padding.last_mut().unwrap() |= 1;
    assert!(BlockFilter::decode(&padding).is_err());
    bytes[PAYLOAD] = 0;
    assert!(BlockFilter::decode(&bytes).is_err());
}

/// Capacity is applied to unique recipients and before building an oversized set.
#[test]
fn block_capacity_is_bounded() {
    let members = receivers(MAX_RECEIVERS + 1);
    assert!(matches!(
        BlockFilter::build(GENESIS, BLOCK, &members),
        Err(Error::Capacity)
    ));
    let bounded = &members[..MAX_RECEIVERS as usize];
    let filter = BlockFilter::build(GENESIS, BLOCK, bounded.iter().chain(bounded)).unwrap();
    assert_eq!(filter.count(), MAX_RECEIVERS);
    assert_eq!(BlockFilter::decode(&filter.encode()).unwrap(), filter);
}
