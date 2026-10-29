//! Compatibility oracle pinned to the implementation the applications originally used.
use bitcoin::{
    bip158::{BitStreamReader as UpstreamBits, GcsFilterReader, GcsFilterWriter as UpstreamWriter},
    consensus::{Decodable, Encodable, encode::VarInt},
};
use zakura_filters::{BitStreamReader, GcsFilterWriter, read_compact_size, write_compact_size};

#[test]
fn filter_bytes_match_upstream_for_every_application_profile() {
    for count in [0u32, 1, 2, 252, 253, 254, 1000, 65535, 65536] {
        let elements: Vec<_> = (0..count).map(|i| i.to_le_bytes()).collect();
        for (m, p) in [
            (784931, 19),
            (1024, 10),
            (1533, 10),
            (100, 6),
            (1, 0),
            (1, 63),
        ] {
            for (k0, k1) in [(0, 0), (u64::MAX, 17)] {
                let mut actual = Vec::new();
                let mut expected = Vec::new();
                let mut writer = GcsFilterWriter::new(&mut actual, k0, k1, m, p);
                let mut upstream = UpstreamWriter::new(&mut expected, k0, k1, m, p);
                // Empty items are excluded and duplicate raw items count once.
                writer.add_element(&[]);
                upstream.add_element(&[]);
                for element in elements.iter().chain(&elements) {
                    writer.add_element(element);
                    upstream.add_element(element);
                }
                assert_eq!(writer.finish().unwrap(), upstream.finish().unwrap());
                assert_eq!(actual, expected, "count={count}, m={m}, p={p}");
                assert!(
                    GcsFilterReader::new(k0, k1, m, p)
                        .match_all(
                            &mut actual.as_slice(),
                            elements.iter().map(|e| e.as_slice())
                        )
                        .unwrap()
                );
            }
        }
    }
}

fn compare_compact_size(bytes: &[u8]) {
    let mut actual_input = bytes;
    let mut expected_input = bytes;
    let actual = read_compact_size(&mut actual_input);
    let expected = VarInt::consensus_decode(&mut expected_input).map(|v| v.0);
    match (actual, expected) {
        (Ok(actual), Ok(expected)) => assert_eq!(actual, expected),
        (Err(_), Err(_)) => (),
        (actual, expected) => {
            panic!("CompactSize disagrees for {bytes:?}: {actual:?}, {expected:?}")
        }
    }
    assert_eq!(actual_input, expected_input, "unread bytes for {bytes:?}");
}

#[test]
fn compact_size_matches_upstream_at_every_integer_boundary_and_truncation() {
    for value in [
        0,
        1,
        252,
        253,
        254,
        65535,
        65536,
        u64::from(u32::MAX),
        1u64 << 32,
        u64::MAX,
    ] {
        let mut actual = Vec::new();
        let mut expected = Vec::new();
        let length = write_compact_size(&mut actual, value).unwrap();
        assert_eq!(
            length,
            VarInt(value).consensus_encode(&mut expected).unwrap()
        );
        assert_eq!(actual, expected);
        for end in 0..actual.len() {
            assert!(read_compact_size(&mut &actual[..end]).is_err());
            compare_compact_size(&actual[..end]);
        }
        assert_eq!(read_compact_size(&mut actual.as_slice()).unwrap(), value);
        actual.extend([0x42, 0x43]);
        compare_compact_size(&actual);
    }
    // Non-minimal encodings must never become accepted lengths.
    for bytes in [
        &[0xfd, 0xfc, 0][..],
        &[0xfe, 0xff, 0xff, 0, 0],
        &[0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0],
    ] {
        assert!(read_compact_size(&mut &bytes[..]).is_err());
        compare_compact_size(bytes);
    }
}

#[test]
fn bit_reads_match_upstream_across_boundaries_and_malformed_widths() {
    let bytes: Vec<u8> = (0u8..=255).collect();
    for length in [0, 1, 2, 7, 8, 9, 32, 256] {
        let mut actual_input = &bytes[..length];
        let mut expected_input = &bytes[..length];
        {
            let mut actual = BitStreamReader::new(&mut actual_input);
            let mut expected = UpstreamBits::new(&mut expected_input);
            for width in [0, 1, 7, 8, 9, 32, 63, 64, 65, 0, 1, 64] {
                assert_eq!(
                    actual.read(width).map_err(|e| e.kind()),
                    expected.read(width).map_err(|e| e.kind()),
                    "length={length}, width={width}",
                );
            }
        }
        assert_eq!(actual_input, expected_input);
    }
}
