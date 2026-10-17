//! Queries prepared and decoded by the wallet against tables preprocessed,
//! parsed and answered with the server's operations: the native round trip
//! both sides of every Transparent table rely on.

use rand::RngCore;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use zakura_pir_native::{D, Q, hint, pack, preprocess, publish, request_len};
use zakura_transparent_private_server::native::{TableServe as _, batched_hint};
use zakura_transparent_private_shared::native::{TableProfile, dithered_request_len};
use zakura_transparent_private_wallet::native::{TableQuery as _, decode_cols};

fn database(rows: usize, cols: usize, seed: u8) -> Vec<u16> {
    // Column-major, deterministic, spanning the whole u16 range.
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    (0..rows * cols).map(|_| rng.next_u32() as u16).collect()
}

fn scan(db: &[u16], rows: usize, cols: usize, query: &[u64]) -> Vec<u64> {
    (0..cols)
        .map(|c| {
            db[c * rows..(c + 1) * rows]
                .iter()
                .zip(query)
                .fold(0u64, |a, (&x, &q)| {
                    a.wrapping_add((x as u64).wrapping_mul(q))
                })
                & (Q - 1)
        })
        .collect()
}

/// End-to-end over the primitives the server and wallet use.
#[test]
fn two_mask_rounded_roundtrip() {
    let profile = TableProfile::new("test", "g", "t", 4_096, 4_096).unwrap();
    let (rows, cols) = (profile.rows, profile.cols);
    let db = database(rows, cols, 7);
    let hint = hint(&profile.masks, rows, cols, |c| {
        &db[c * rows..(c + 1) * rows]
    })
    .unwrap();
    let blocks = preprocess(&profile.setup, &hint).unwrap();
    let published = publish(&blocks).unwrap();
    assert_eq!(published.len(), profile.scheme.public_bytes);
    for target in [0, 1234, rows - 1] {
        let (secret, body) = profile.prepare(target).unwrap();
        assert_eq!(body.len(), profile.scheme.request_bytes);
        let (keys, query) = profile.parse(&body).unwrap();
        let response = pack(&blocks, &keys, &scan(&db, rows, cols, &query)).unwrap();
        assert_eq!(response.len(), profile.scheme.response_bytes);
        let row = profile.decode(&secret, &published, &response).unwrap();
        let expected: Vec<u8> = (0..cols)
            .flat_map(|c| db[c * rows + target].to_le_bytes())
            .collect();
        assert_eq!(row, expected, "target {target}");
    }
    // The dithered query decodes the same rows, through the same parse.
    for target in [0, 2_047, rows - 1] {
        let (secret, body) = profile.prepare_dithered(target).unwrap();
        assert_eq!(
            body.len(),
            profile.dithered_scheme.as_ref().unwrap().request_bytes
        );
        assert!(profile.accepts_request_len(body.len()));
        let (keys, query) = profile.parse(&body).unwrap();
        let response = pack(&blocks, &keys, &scan(&db, rows, cols, &query)).unwrap();
        let row = profile.decode(&secret, &published, &response).unwrap();
        let expected: Vec<u8> = (0..cols)
            .flat_map(|c| db[c * rows + target].to_le_bytes())
            .collect();
        assert_eq!(row, expected, "dithered target {target}");
    }
    // Only those two lengths parse.
    for len in [
        profile.scheme.request_bytes - 1,
        profile.scheme.request_bytes + 1,
        profile.dithered_scheme.as_ref().unwrap().request_bytes - 1,
        profile.dithered_scheme.as_ref().unwrap().request_bytes + 1,
    ] {
        assert!(!profile.accepts_request_len(len));
        assert!(profile.parse(&vec![0; len]).is_err(), "{len} bytes");
    }
    // A key from another table's setup is refused rather than packed.
    let other = TableProfile::new("test", "g", "txother", 4_096, 4_096).unwrap();
    let (_, body) = other.prepare(0).unwrap();
    let (keys, query) = other.parse(&body).unwrap();
    assert!(pack(&blocks, &keys, &scan(&db, rows, cols, &query)).is_err());
}

/// End to end over an 8-bit history table, full and prefix uploads.
#[test]
fn eight_bit_roundtrip() {
    let profile = TableProfile::new("test", "g", "pages", 4_096, 4_096).unwrap();
    let (rows, cols) = (profile.rows, profile.cols);
    let mut rng = ChaCha20Rng::from_seed([9; 32]);
    // Column-major bytes; rows from 2,048 on are zero, for the prefix.
    let mut db = vec![0u8; rows * cols];
    for c in 0..cols {
        for r in 0..D {
            db[c * rows + r] = rng.next_u32() as u8;
        }
    }
    let hint = hint(&profile.masks, rows, cols, |c| {
        &db[c * rows..(c + 1) * rows]
    })
    .unwrap();
    assert_eq!(
        hint,
        batched_hint::hint(&profile.masks, rows, cols, |c| &db
            [c * rows..(c + 1) * rows])
        .unwrap()
    );
    let blocks = preprocess(&profile.setup, &hint).unwrap();
    let published = profile.native.publish(&blocks).unwrap();
    assert_eq!(published.len(), profile.scheme.public_bytes);
    let scan = |query: &[u64]| -> Vec<u64> {
        (0..cols)
            .map(|c| {
                db[c * rows..(c + 1) * rows]
                    .iter()
                    .zip(query)
                    .fold(0u64, |a, (&x, &q)| {
                        a.wrapping_add((x as u64).wrapping_mul(q))
                    })
                    & (Q - 1)
            })
            .collect()
    };
    for target in [0, 1_234, D - 1] {
        let expected: Vec<u8> = (0..cols).map(|c| db[c * rows + target]).collect();
        for (secret, body) in [
            profile.prepare(target).unwrap(),
            profile.prepare_prefix(D, target).unwrap(),
        ] {
            assert!(profile.accepts_selection_len(D, body.len()));
            let (keys, query) = profile.parse_selection(&body, D).unwrap();
            let response = profile.native.pack(&blocks, &keys, &scan(&query)).unwrap();
            assert_eq!(response.len(), profile.scheme.response_bytes);
            let row = profile.decode(&secret, &published, &response).unwrap();
            assert_eq!(row, expected, "target {target}");
        }
    }
    // The 16-bit lengths are refused.
    assert!(!profile.accepts_request_len(request_len(rows)));
    assert!(!profile.accepts_request_len(dithered_request_len(rows)));
}

/// Transparent's response decoder refuses an empty response for zero
/// columns, as it always has, rather than taking `zakura-pir-native`'s.
#[test]
fn decode_cols_refuses_zero_columns() {
    let profile = TableProfile::new("test", "g", "t", 4_096, 4_096).unwrap();
    let (secret, _) = profile.prepare(0).unwrap();
    assert_eq!(
        decode_cols(&secret, &[], &[], 0),
        Err("native response shape".to_string())
    );
}
