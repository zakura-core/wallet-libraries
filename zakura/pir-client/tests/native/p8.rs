//! The 8-bit profile end to end: a u8 table, its hint and preprocessing, a
//! full and a prefix upload, the scan, packing and decoding back to the row's
//! bytes, at the sizes the profile publishes.
use zakura_pir_query_server::native::ProfileQueryExt as _;
use zakura_pir_server_core::native::{ProfilePublicationExt as _, hint, preprocess};

use rand::RngCore;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use zakura_pir_client::native::*;

#[test]
fn sizes_are_the_p8_profile() {
    assert_eq!(P8.key_bytes(), 13_824);
    assert_eq!(P8.public_len(4_096), 22_528);
    assert_eq!(P8.response_len(4_096), 5_120);
    assert_eq!(P8.request_len_bits(2_048, 28), 21_000 - 8);
    assert_eq!(P8.request_len_bits(32_768, 28), 128_520 - 8);
    assert_eq!(
        P8.accepted_query_bits(2 * D, P8.request_len_bits(2 * D, 28)),
        Some(28)
    );
    assert_eq!(
        P8.accepted_query_bits(2 * D, P8.request_len_bits(2 * D, 44)),
        None
    );
    assert_eq!(
        P8.accepted_query_bits(2 * D, P16.request_len_bits(2 * D, 49)),
        None
    );
    assert_eq!(
        P8.prepared_block_planned_bytes(),
        P8.prepared_block_max_bytes()
    );
    assert!(P8.prepared_block_min_bytes() < P8.prepared_block_max_bytes());
}

#[test]
fn p8_full_and_prefix_uploads_decode_the_row() {
    full_and_prefix_uploads_decode_the_row(2 * D);
}

/// A txid display row is 8,192 bytes, four blocks.
#[test]
fn p8_four_block_rows_decode() {
    full_and_prefix_uploads_decode_the_row(4 * D);
}

fn full_and_prefix_uploads_decode_the_row(cols: usize) {
    let (rows, query_rows, target) = (3 * D, D, 1_789usize);
    let masks = P8.public_query_masks([31; 32], rows, cols).unwrap();
    assert_ne!(masks, public_query_masks([31; 32], rows, cols));
    let setup = NativeSetup::new(P8.params(), [32; 32]);
    let mut rng = ChaCha20Rng::from_seed([33; 32]);
    // Column-major bytes, every row past the prefix zero.
    let mut db = vec![0u8; rows * cols];
    for c in 0..cols {
        for r in 0..query_rows {
            db[c * rows + r] = rng.next_u32() as u8;
        }
    }
    let hint = hint(&masks, rows, cols, |c| &db[c * rows..(c + 1) * rows]).unwrap();
    let blocks = preprocess(&setup, &hint).unwrap();
    let public = P8.publish(&blocks).unwrap();
    assert_eq!(public.len(), P8.public_len(cols));
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
    let expected: Vec<u8> = (0..cols).map(|c| db[c * rows + target]).collect();
    for sent in [rows, query_rows] {
        let (secret, upload) = P8.prepare(&setup, &masks, sent, target).unwrap();
        assert_eq!(upload.len(), P8.request_len_bits(sent, 28));
        let (keys, query) = P8
            .parse_selection(&setup, &upload, query_rows, rows)
            .unwrap();
        assert_eq!(query.len(), rows);
        let response = P8.pack(&blocks, &keys, &scan(&query)).unwrap();
        assert_eq!(response.len(), P8.response_len(cols));
        assert_eq!(
            P8.decode_cols(&secret, &public, &response, cols).unwrap(),
            expected,
            "{sent} rows sent"
        );
    }
}
