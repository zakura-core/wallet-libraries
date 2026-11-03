//! Frozen tuple encodings generated and checked before replacing `serde_with`.

use alloc::{collections::BTreeMap, vec::Vec};
use serde::{Deserialize, Serialize};

const ARRAY_LEN: usize = 64;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Fixture {
    #[serde(
        serialize_with = "crate::serde_arrays::serialize",
        deserialize_with = "crate::serde_arrays::deserialize"
    )]
    array: [u8; ARRAY_LEN],
    #[serde(
        default,
        serialize_with = "crate::serde_arrays::serialize_option",
        deserialize_with = "crate::serde_arrays::deserialize_option"
    )]
    optional_32: Option<[u8; 32]>,
    #[serde(
        default,
        serialize_with = "crate::serde_arrays::serialize_option",
        deserialize_with = "crate::serde_arrays::deserialize_option"
    )]
    optional_43: Option<[u8; 43]>,
    #[serde(
        default,
        serialize_with = "crate::serde_arrays::serialize_option",
        deserialize_with = "crate::serde_arrays::deserialize_option"
    )]
    optional_64: Option<[u8; 64]>,
    #[serde(
        default,
        serialize_with = "crate::serde_arrays::serialize_option",
        deserialize_with = "crate::serde_arrays::deserialize_option"
    )]
    optional_96: Option<[u8; 96]>,
    #[serde(
        default,
        serialize_with = "crate::serde_arrays::serialize_option",
        deserialize_with = "crate::serde_arrays::deserialize_option"
    )]
    optional_192: Option<[u8; 192]>,
    #[serde(
        serialize_with = "crate::serde_arrays::serialize_map",
        deserialize_with = "crate::serde_arrays::deserialize_map"
    )]
    map: BTreeMap<[u8; 33], Vec<u8>>,
}

fn bytes<const N: usize>(offset: u8) -> [u8; N] {
    core::array::from_fn(|i| (i as u8).wrapping_mul(17).wrapping_add(offset))
}

fn populated_fixture() -> Fixture {
    let mut map = BTreeMap::new();
    // Insertion order differs from the encoded key order.
    map.insert([254; 33], vec![128, 255]);
    map.insert(
        [1; 33],
        (0..129).map(|i| (i as u8).wrapping_mul(3)).collect(),
    );
    Fixture {
        array: bytes(1),
        optional_32: Some(bytes(2)),
        optional_43: Some(bytes(3)),
        optional_64: Some(bytes(4)),
        optional_96: Some(bytes(5)),
        optional_192: Some(bytes(6)),
        map,
    }
}

fn absent_fixture() -> Fixture {
    Fixture {
        array: bytes(1),
        optional_32: None,
        optional_43: None,
        optional_64: None,
        optional_96: None,
        optional_192: None,
        map: BTreeMap::new(),
    }
}

const POPULATED: &[u8] = include_bytes!("test_vectors/serde_arrays_populated.bin");
const ABSENT: &[u8] = include_bytes!("test_vectors/serde_arrays_absent.bin");

#[test]
fn populated_arrays_and_sorted_map_keep_the_frozen_encoding() {
    let fixture = populated_fixture();
    assert_eq!(postcard::to_allocvec(&fixture).unwrap(), POPULATED);
    assert_eq!(postcard::from_bytes::<Fixture>(POPULATED).unwrap(), fixture);
}

#[test]
fn absent_arrays_and_empty_map_keep_the_frozen_encoding() {
    let fixture = absent_fixture();
    assert_eq!(postcard::to_allocvec(&fixture).unwrap(), ABSENT);
    assert_eq!(postcard::from_bytes::<Fixture>(ABSENT).unwrap(), fixture);
}

#[test]
fn truncated_arrays_and_map_entries_are_rejected() {
    for len in 0..POPULATED.len() {
        assert!(
            postcard::from_bytes::<Fixture>(&POPULATED[..len]).is_err(),
            "accepted truncated fixture at {len}",
        );
    }
}

#[test]
fn an_invalid_option_discriminant_is_rejected() {
    let mut invalid = POPULATED.to_vec();
    invalid[ARRAY_LEN] = 2;
    assert!(postcard::from_bytes::<Fixture>(&invalid).is_err());
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct MapFixture {
    #[serde(
        serialize_with = "crate::serde_arrays::serialize_map",
        deserialize_with = "crate::serde_arrays::deserialize_map"
    )]
    map: BTreeMap<[u8; 33], Vec<u8>>,
}

#[test]
fn duplicate_map_keys_retain_the_last_value() {
    // A map of two entries with the same fixed-length key and distinct values.
    let mut encoded = vec![2];
    for value in [1, 2] {
        encoded.extend_from_slice(&[7; 33]);
        encoded.extend_from_slice(&[1, value]);
    }
    let decoded = postcard::from_bytes::<MapFixture>(&encoded).unwrap();
    assert_eq!(decoded.map, BTreeMap::from([([7; 33], vec![2])]));
}

#[test]
fn array_length_and_byte_range_are_checked() {
    use serde::de::value::{Error, SeqDeserializer};

    fn decode<const N: usize>(values: &[u16]) -> Result<[u8; N], Error> {
        crate::serde_arrays::deserialize(SeqDeserializer::new(values.iter().copied()))
    }

    assert_eq!(decode::<0>(&[]).unwrap(), []);
    assert_eq!(decode::<3>(&[0, 128, 255]).unwrap(), [0, 128, 255]);
    assert!(decode::<3>(&[0, 128]).is_err());
    assert!(decode::<3>(&[0, 128, 255, 1]).is_err());
    assert!(decode::<3>(&[0, 128, 256]).is_err());
}
