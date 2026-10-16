//! The official BIP 158 basic-filter vectors.
//!
//! These are Bitcoin testnet vectors. They exercise this crate's generic
//! encoding path — SipHash keying from the block hash, mapping to `[0, N*M)`,
//! Golomb-Rice coding, CompactSize framing and zero padding — against values
//! produced by the reference implementation rather than by this crate.
//!
//! Bitcoin block parsing appears only here, to turn a vector's raw block into
//! its output scripts. Zcash source data is never parsed as a Bitcoin block.

use bitcoin::consensus::Decodable;
use transparent_filter::{
    build_filter, filter_hash, filter_header, validate_filter, BlockHash, FilterHeader,
    FilterLimits, ScriptBytes,
};

const VECTORS: &str = include_str!("vectors/testnet-19.json");

struct Vector {
    height: u64,
    block_hash: String,
    block: Vec<u8>,
    previous_output_scripts: Vec<Vec<u8>>,
    previous_header: String,
    basic_filter: Vec<u8>,
    basic_header: String,
}

fn vectors() -> Vec<Vector> {
    let rows: Vec<serde_json::Value> = serde_json::from_str(VECTORS).expect("vector json");
    rows.into_iter()
        // The first row is the column-name header, not a vector.
        .filter(|row| row.as_array().is_some_and(|row| row.len() > 1))
        .map(|row| {
            let row = row.as_array().expect("row array");
            Vector {
                height: row[0].as_u64().expect("height"),
                block_hash: row[1].as_str().expect("hash").to_string(),
                block: hex::decode(row[2].as_str().expect("block")).expect("block hex"),
                previous_output_scripts: row[3]
                    .as_array()
                    .expect("prev scripts")
                    .iter()
                    .map(|script| {
                        hex::decode(script.as_str().expect("script")).expect("script hex")
                    })
                    .collect(),
                previous_header: row[4].as_str().expect("prev header").to_string(),
                basic_filter: hex::decode(row[5].as_str().expect("filter")).expect("filter hex"),
                basic_header: row[6].as_str().expect("header").to_string(),
            }
        })
        .collect()
}

/// The basic filter's element set: every nonempty output script that does not
/// begin with OP_RETURN, plus every supplied previous output script.
fn elements(vector: &Vector) -> Vec<ScriptBytes> {
    let block = bitcoin::Block::consensus_decode(&mut vector.block.as_slice()).expect("block");
    let mut elements: Vec<ScriptBytes> = Vec::new();
    for transaction in &block.txdata {
        for output in &transaction.output {
            elements.push(ScriptBytes::new(output.script_pubkey.to_bytes()));
        }
    }
    for script in &vector.previous_output_scripts {
        elements.push(ScriptBytes::new(script.clone()));
    }
    elements
}

#[test]
fn vectors_are_present_and_parse() {
    let vectors = vectors();
    assert!(vectors.len() >= 7, "expected the published vector set");
    assert_eq!(vectors[0].height, 0);
}

#[test]
fn encoded_filters_match_the_reference_bytes_exactly() {
    for vector in vectors() {
        let hash = BlockHash::from_display_hex(&vector.block_hash).expect("hash");
        let built = build_filter(hash, &elements(&vector)).expect("build");
        assert_eq!(
            hex::encode(built.as_slice()),
            hex::encode(&vector.basic_filter),
            "filter bytes differ at height {}",
            vector.height
        );
    }
}

#[test]
fn reference_filters_pass_our_strict_validation() {
    for vector in vectors() {
        let validated = validate_filter(&vector.basic_filter, FilterLimits::default())
            .unwrap_or_else(|error| panic!("height {} failed validation: {error}", vector.height));
        // The reference filter's own element count must agree with the
        // deduplicated element set we would have encoded.
        let hash = BlockHash::from_display_hex(&vector.block_hash).expect("hash");
        let expected = transparent_filter::element_count(&elements(&vector));
        assert_eq!(
            validated.element_count(),
            expected,
            "element count differs at height {}",
            vector.height
        );
        let _ = hash;
    }
}

#[test]
fn every_element_matches_its_reference_filter() {
    for vector in vectors() {
        let hash = BlockHash::from_display_hex(&vector.block_hash).expect("hash");
        let validated =
            validate_filter(&vector.basic_filter, FilterLimits::default()).expect("validate");
        let included: Vec<ScriptBytes> = elements(&vector)
            .into_iter()
            .filter(|script| script.is_filter_element())
            .collect();
        let matched =
            transparent_filter::match_scripts(&validated, hash, &included).expect("match");
        assert_eq!(
            matched.len(),
            included.len(),
            "not every element matched at height {}",
            vector.height
        );
    }
}

#[test]
fn filter_headers_chain_to_the_reference_headers() {
    for vector in vectors() {
        let previous_bytes =
            BlockHash::from_display_hex(&vector.previous_header).expect("previous header");
        let previous = FilterHeader(*previous_bytes.internal_bytes());
        let header = filter_header(filter_hash(&vector.basic_filter), previous);
        assert_eq!(
            header.to_display_hex(),
            vector.basic_header,
            "filter header differs at height {}",
            vector.height
        );
    }
}

#[test]
fn the_key_byte_order_is_load_bearing() {
    // Building with the display-order bytes must not reproduce the reference
    // filter. If it did, the display/internal distinction would be untested and
    // a future change could silently swap them.
    let vector = vectors()
        .into_iter()
        .find(|vector| vector.basic_filter.len() > 1)
        .expect("a nonempty vector");
    let mut reversed = *BlockHash::from_display_hex(&vector.block_hash)
        .expect("hash")
        .internal_bytes();
    reversed.reverse();
    let wrong =
        build_filter(BlockHash::from_internal_bytes(reversed), &elements(&vector)).expect("build");
    assert_ne!(wrong.as_slice(), vector.basic_filter.as_slice());
}
