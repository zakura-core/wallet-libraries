//! A range filter the publisher builds, as the wallet matches it: under the
//! shard's keying every element matches, under a block's keying nothing does.

use zakura_transparent_private_server::filter::build_range_filter;
use zakura_transparent_private_shared::filter::{
    BlockHash, FilterLimits, MAINNET_GENESIS_DISPLAY, RANGE_PROFILE, ScriptBytes, ShardKey,
    validate_filter,
};
use zakura_transparent_private_wallet::filter::{match_range_scripts, match_scripts};

fn hash() -> BlockHash {
    BlockHash::from_internal_bytes([7u8; 32])
}

fn shard_key() -> ShardKey {
    ShardKey::derive(
        RANGE_PROFILE,
        BlockHash::from_display_hex(MAINNET_GENESIS_DISPLAY).unwrap(),
        0,
        3_428_143,
        3_429_166,
        hash(),
    )
}

fn script(tag: u8) -> ScriptBytes {
    ScriptBytes::new(vec![0x76, 0xa9, 0x14, tag])
}

/// A shard filter matched under block keying must not report its own
/// elements. This is the failure a wallet would actually hit if the two
/// profiles were confused, and it must look like "nothing matched" rather
/// than a decode error that some caller might treat as retryable.
#[test]
fn a_shard_filter_does_not_match_under_block_keying() {
    let elements: Vec<ScriptBytes> = (0..64).map(script).collect();
    let bytes = build_range_filter(shard_key(), &elements).unwrap();
    let validated = validate_filter(bytes.as_slice(), FilterLimits::default()).unwrap();

    let correct = match_range_scripts(&validated, shard_key(), &elements).unwrap();
    assert_eq!(correct, (0..elements.len()).collect::<Vec<_>>());

    // Under the wrong keying the wallet's scripts map to unrelated values.
    // A handful of the 64 could collide by chance at 1/M each; requiring
    // near-zero rather than exactly zero keeps the test honest.
    let wrong = match_scripts(&validated, hash(), &elements).unwrap();
    assert!(
        wrong.len() < 4,
        "matched {} of 64 under block keying",
        wrong.len()
    );
}
