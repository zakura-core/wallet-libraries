//! Sealed shard filters: bounds separate from block hints, binding and strict parsing.
use zakura_pir_protocol::receiver::{
    Error, ReceiverBytes, blocks,
    shards::{Coverage, MAX_FILTER_BYTES, ShardFilter},
};

/// `n` distinct receiver encodings; the filter checks structure only.
fn receivers(n: u32) -> Vec<ReceiverBytes> {
    (0..n)
        .map(|i| {
            let mut r = [0x5a; 43];
            r[..4].copy_from_slice(&i.to_le_bytes());
            r
        })
        .collect()
}

fn coverage() -> Coverage {
    Coverage {
        start_height: 100,
        end_height: 199,
        end_hash: [3; 32],
    }
}

/// A shard holds more receivers than one block may, and every member matches.
#[test]
fn a_shard_filter_exceeds_the_block_bound_and_matches_its_members() {
    let members = receivers(blocks::MAX_RECEIVERS + 4_464);
    let filter = ShardFilter::build([1; 32], 7, coverage(), &members).unwrap();
    assert_eq!(filter.receivers(), u64::from(blocks::MAX_RECEIVERS) + 4_464);
    let decoded = ShardFilter::decode(filter.bytes()).unwrap();
    assert_eq!(decoded, filter);
    assert_eq!(decoded.digest(), filter.digest());
    assert!(decoded.matches(&members).iter().all(|m| *m));
    let outsiders: Vec<_> = (0..1_000u32)
        .map(|i| {
            let mut r = [0xa5; 43];
            r[..4].copy_from_slice(&i.to_le_bytes());
            r
        })
        .collect();
    let false_positives = decoded.matches(&outsiders).iter().filter(|m| **m).count();
    assert!(false_positives <= 2, "{false_positives}");
    // Repeated and interleaved queries keep their order.
    let mixed = [outsiders[0], members[5], members[5], outsiders[1]];
    assert_eq!(decoded.matches(&mixed)[1..3], [true, true]);
}

/// The filter binds network, correction and coverage; a duplicate receiver counts once.
#[test]
fn filters_bind_network_correction_and_coverage() {
    let members = receivers(3);
    let filter =
        ShardFilter::build([1; 32], 7, coverage(), members.iter().chain(&members)).unwrap();
    assert_eq!(filter.receivers(), 3);
    filter.check(&[1; 32], 7, &coverage()).unwrap();
    assert!(filter.check(&[2; 32], 7, &coverage()).is_err());
    assert!(filter.check(&[1; 32], 8, &coverage()).is_err());
    let mut other = coverage();
    other.end_hash = [4; 32];
    assert!(filter.check(&[1; 32], 7, &other).is_err());
    // Coverage keys the hashing, so the same receivers under other coverage differ.
    let moved = ShardFilter::build([1; 32], 7, other, &members).unwrap();
    assert_ne!(moved.digest(), filter.digest());
    let empty = ShardFilter::build([1; 32], 7, coverage(), &[]).unwrap();
    assert_eq!(empty.matches(&members), [false; 3]);
    let backwards = Coverage {
        start_height: 200,
        ..coverage()
    };
    assert!(matches!(
        ShardFilter::build([1; 32], 7, backwards, &members),
        Err(Error::Coverage)
    ));
}

/// Truncation, trailing bytes, a wrong length, a count the bits cannot hold and an
/// oversized input are refused before any value is used.
#[test]
fn malformed_filters_are_refused() {
    let filter = ShardFilter::build([1; 32], 7, coverage(), &receivers(50)).unwrap();
    let bytes = filter.bytes().to_vec();
    for len in [0, 8, 91, 92, bytes.len() - 1] {
        assert!(ShardFilter::decode(&bytes[..len]).is_err(), "{len}");
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(ShardFilter::decode(&trailing).is_err());
    let mut magic = bytes.clone();
    magic[0] ^= 1;
    assert!(ShardFilter::decode(&magic).is_err());
    // A count far beyond what the remaining bits can encode.
    let mut inflated = bytes[..92].to_vec();
    let set = [0xfe, 0xff, 0xff, 0x7f, 0x00, 0x00];
    inflated[88..92].copy_from_slice(&(set.len() as u32).to_le_bytes());
    inflated.extend(set);
    assert!(matches!(
        ShardFilter::decode(&inflated),
        Err(Error::Malformed)
    ));
    let oversized = vec![0; MAX_FILTER_BYTES + 1];
    assert!(matches!(
        ShardFilter::decode(&oversized),
        Err(Error::Capacity)
    ));
}

/// A body a shard descriptor names by digest is hashed before its set is decoded. A
/// substituted body of the named length, here one whose set is a single long unary run that
/// a decode would walk bit by bit, is refused as another filter, not as a malformed one,
/// so it was never decoded. The named body decodes.
#[test]
fn a_substituted_filter_body_is_refused_before_decoding() {
    let filter = ShardFilter::build([1; 32], 7, coverage(), &receivers(1_000)).unwrap();
    let named = filter.digest();
    let mut substituted = filter.bytes().to_vec();
    // Header: magic, genesis, generation, coverage and the set length.
    let header = 8 + 32 + 8 + 4 + 4 + 32 + 4;
    substituted[header..].fill(0xff);
    assert!(matches!(
        ShardFilter::decode(&substituted),
        Err(Error::Malformed)
    ));
    assert!(matches!(
        ShardFilter::decode_named(&substituted, &named),
        Err(Error::Coverage)
    ));
    assert_eq!(
        ShardFilter::decode_named(filter.bytes(), &named).unwrap(),
        filter
    );
}
