//! Independent IPIR comparisons, compiled only by dependency verification.
use candidate_protocol::{enhance::parameters as enhance, native::*};
use ipir_sp::{SimplePirProfile, server::IPIRServer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

mod reference_bits {
    include!("reference_bits.rs");
}

fn digest_words(words: &[u64]) -> String {
    let mut hash = Sha256::new();
    for word in words {
        hash.update(word.to_le_bytes());
    }
    hex::encode(hash.finalize())
}

fn metadata() -> Value {
    [2048, 4096, 8192, 16384, 32768]
        .into_iter()
        .map(|rows| {
            let (_, old) = ipir_sp::params_for_simplepir_profile(
                rows,
                enhance::ITEM_SIZE_BITS,
                SimplePirProfile::P16Q48,
            )
            .unwrap();
            let q48 = serde_json::to_string(&old).unwrap();
            let served = if rows >= 4096 {
                let mut served = old;
                served.query_bits = QUERY_BITS;
                served.q_prime_1 = 1 << RESPONSE_BITS;
                Some(serde_json::to_string(&served).unwrap())
            } else {
                None
            };
            (rows.to_string(), json!({"q48": q48, "served": served}))
        })
        .collect()
}

fn receiver_scans() -> Value {
    use candidate_protocol::receiver::{DIRECTORY_ROWS, ROW_BYTES, native::COLS};
    [DIRECTORY_ROWS as usize, 2 * DIRECTORY_ROWS as usize]
        .into_iter()
        .map(|rows| {
            let values = (0..rows * COLS).map(|i| (i as u8).wrapping_mul(157).wrapping_add(19));
            let (_, params) = ipir_sp::params_for_simplepir_profile(
                rows as u64,
                (ROW_BYTES * 16) as u64,
                SimplePirProfile::P16Q48,
            )
            .unwrap();
            let previous = IPIRServer::<u8>::new(params, values, false, false);
            assert_eq!(previous.db_rows_padded(), rows);
            let mut hash = Sha256::new();
            for value in previous.db() {
                hash.update(value.to_le_bytes());
            }
            let scans: Vec<_> = [
                vec![0; rows],
                vec![Q - 1; rows],
                (0..rows)
                    .map(|i| (i as u64).wrapping_mul(Q / 3) & (Q - 1))
                    .collect(),
            ]
            .iter()
            .map(|query| digest_words(&previous.try_multiply_power_of_two(Q, query).unwrap()))
            .collect();
            (
                rows.to_string(),
                json!({"database": hex::encode(hash.finalize()), "scans": scans}),
            )
        })
        .collect()
}

fn main() {
    let metadata = metadata();
    let scans = receiver_scans();
    if std::env::args().nth(1).as_deref() == Some("--emit-fixtures") {
        // Explicit maintainer capture from the pinned previous implementation.
        println!("{}", json!({"metadata": metadata, "receiver_scans": scans}));
        return;
    }
    assert_eq!(
        metadata,
        serde_json::from_str::<Value>(include_str!("metadata.json")).unwrap()
    );
    assert_eq!(
        scans,
        serde_json::from_str::<Value>(include_str!("receiver_scans.json")).unwrap()
    );
    for profile in [P8, P16] {
        for (rows, cols) in [(D, D), (2 * D, 3 * D), (16 * D, 6 * D)] {
            let previous =
                ipir_native_client::NativeProfile::new(profile.params(), rows, cols).unwrap();
            for seed in [[0; 32], [0x91; 32]] {
                let previous =
                    ipir_native_client::NativePublicSetup::new(previous.clone(), seed, [0; 32]);
                assert_eq!(
                    profile.public_query_masks(seed, rows, cols).unwrap(),
                    previous.query_masks()
                );
            }
        }
        for (rows, cols) in [
            (0, D),
            (D, 0),
            (D + 1, D),
            (D, D + 1),
            (usize::MAX, D),
            (1 << 21, 1 << 21),
        ] {
            let previous = ipir_native_client::NativeProfile::new(profile.params(), rows, cols)
                .map(|_| ())
                .map_err(|e| e.to_string());
            assert_eq!(
                profile.public_query_masks([0; 32], rows, cols).map(|_| ()),
                previous
            );
        }
    }
    let words = [0, 1, 3, 127, 65535, 0x123456789abc, u64::MAX];
    for width in [8, 10, 16, 19, 22, 27, 28, 29, 44, 49, 54, 64] {
        let expected = ipir_native_client::bits::u64s_to_contiguous_bytes(&words, width);
        assert_eq!(
            reference_bits::u64s_to_contiguous_bytes(&words, width),
            expected
        );
        assert_eq!(bits::u64s_to_contiguous_bytes(&words, width), expected);
        assert_eq!(
            bits::contiguous_bytes_to_u64s(&expected, width),
            ipir_native_client::bits::contiguous_bytes_to_u64s(&expected, width)
        );
    }
    let row_bytes = INSTANCE_BYTES;
    let rows: Vec<u8> = (0..2 * row_bytes).map(|i| (i * 37 % 251) as u8).collect();
    for (row, col) in [(0, 0), (0, D - 1), (1, 5), (1, D - 1)] {
        assert_eq!(
            candidate_protocol::transparent::native::row_coefficient(&rows, row_bytes, row, col)
                as u64,
            ipir_native_client::bits::read_bits(
                &rows[row * row_bytes..(row + 1) * row_bytes],
                col * P_BITS,
                P_BITS
            )
        );
    }
    println!("previous provider: masks, codecs, metadata and Receiver scan fixtures passed");
}
