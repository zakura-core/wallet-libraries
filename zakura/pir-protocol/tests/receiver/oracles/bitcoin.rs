//! Receiver height-range payload comparison with the pinned Bitcoin codec.
use sha2::{Digest, Sha256};
use zakura_pir_protocol::receiver::{ReceiverBytes, blocks::{HeightSet, Range, RANGE_HEADER}};

const GENESIS: [u8; 32] = [9; 32];

fn receivers(count: u32) -> Vec<ReceiverBytes> {
    (0..count).map(|i| {
        let mut receiver = [0; 43];
        receiver[..4].copy_from_slice(&i.to_le_bytes());
        receiver
    }).collect()
}

/// A set's key depends on its height, so the same receivers code differently at another
/// height, and the wire bytes match an independent BIP 158 writer.
#[test]
fn payload_matches_independent_codec() {
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

