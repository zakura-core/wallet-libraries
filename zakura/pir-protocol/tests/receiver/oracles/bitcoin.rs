//! Receiver block payload comparison with the pinned Bitcoin codec.
use sha2::{Digest, Sha256};
use zakura_pir_protocol::receiver::{
    ReceiverBytes,
    blocks::{Batch, BlockFilter, BlockId},
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
