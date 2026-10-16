//! A golden envelope fixture.
//!
//! The expected bytes were derived by hand from the format specification in
//! `transparent/docs/filter-envelope.md`, not printed from this crate's
//! encoder, so the test compares the encoder against the written spec.
//!
//! They are written out in full so that a change to the serialization
//! fails loudly here rather than silently invalidating every cached filter a
//! deployed wallet holds. If this test needs updating, the envelope version
//! must change too.

use transparent_filter::{BlockHash, FilterBatch, FilterRecord, ENVELOPE_VERSION};

const GOLDEN_HEX: &str = concat!(
    // magic "ZTFB", version 1
    "5a544642",
    "0100",
    // genesis: mainnet genesis in internal (reversed) byte order
    "08ce3d9731b000c08338455c8a4a6bd05da16e26b11daa1b917184ece80f0400",
    // profile length 26, "zcash-transparent-basic-v1"
    "1a",
    "7a636173682d7472616e73706172656e742d62617369632d7631",
    // start height 3428143, little-endian
    "2f4f340000000000",
    // stop block hash: 0xab repeated
    "abababababababababababababababababababababababababababababababab",
    // record count 2
    "02",
    // record 0: height 3428143, hash 0x11.., filter length 1, the empty filter
    "2f4f340000000000",
    "1111111111111111111111111111111111111111111111111111111111111111",
    "01",
    "00",
    // record 1: height 3428144, hash 0x22.., filter length 4
    "304f340000000000",
    "2222222222222222222222222222222222222222222222222222222222222222",
    "04",
    "01deadbe",
);

fn golden_batch() -> FilterBatch {
    FilterBatch {
        version: ENVELOPE_VERSION,
        genesis: BlockHash::from_display_hex(transparent_filter::MAINNET_GENESIS_DISPLAY)
            .expect("genesis"),
        profile: transparent_filter::PROFILE.to_string(),
        start_height: 3_428_143,
        stop_block_hash: BlockHash::from_internal_bytes([0xab; 32]),
        records: vec![
            FilterRecord {
                height: 3_428_143,
                block_hash: BlockHash::from_internal_bytes([0x11; 32]),
                filter: vec![0x00],
            },
            FilterRecord {
                height: 3_428_144,
                block_hash: BlockHash::from_internal_bytes([0x22; 32]),
                filter: vec![0x01, 0xde, 0xad, 0xbe],
            },
        ],
    }
}

#[test]
fn the_encoding_matches_the_committed_golden_bytes() {
    assert_eq!(hex::encode(golden_batch().encode()), GOLDEN_HEX);
}

#[test]
fn the_golden_bytes_decode_to_the_golden_batch() {
    let bytes = hex::decode(GOLDEN_HEX).expect("golden hex");
    assert_eq!(FilterBatch::decode(&bytes).expect("decode"), golden_batch());
}

#[test]
fn the_genesis_hash_is_stored_reversed_from_its_display_form() {
    let bytes = hex::decode(GOLDEN_HEX).expect("golden hex");
    let stored = &bytes[6..38];
    let display = hex::decode(transparent_filter::MAINNET_GENESIS_DISPLAY).expect("display");
    let mut reversed = display.clone();
    reversed.reverse();
    assert_eq!(stored, reversed.as_slice());
    assert_ne!(stored, display.as_slice());
}
