//! Byte-for-byte pins for the shared native helpers.
//!
//! The digests were produced on 2026-09-29 by the two copies this crate
//! replaced, `enhance_pir::native` and `transparent_native`, which agreed on
//! every value (source revision 8448d274). A change here changes what Enhance,
//! Status and Transparent servers publish or answer, and what wallets send.

use ipir_native_client::bits::u64s_to_contiguous_bytes;
use rand::RngCore;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use sha2::{Digest, Sha256};
use zakura_pir_native::*;

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn digest_words(words: &[u64]) -> String {
    digest(
        &words
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect::<Vec<_>>(),
    )
}

/// `prepare_with`'s framing over a seeded secret, so the upload is fixed.
fn upload(
    setup: &NativeSetup,
    masks: &[Vec<u64>],
    rows: usize,
    target: usize,
) -> (NativeSecret, Vec<u8>) {
    let round = |x: u64, bits: usize| {
        (((x as u128 * (1u128 << bits) + (Q / 2) as u128) / Q as u128) as u64) & ((1 << bits) - 1)
    };
    let mut rng = ChaCha20Rng::from_seed([14; 32]);
    let secret = NativeSecret::sample(&params(), &mut rng);
    let keys = NativeKeys::generate_one_key(setup, &secret, &mut rng).unwrap();
    let query = secret
        .encrypt_selection(&masks[..rows / D], target, &mut rng)
        .unwrap();
    let mut bytes = u64s_to_contiguous_bytes(&keys.kg_words(), Q_BITS);
    let switched: Vec<_> = query.iter().map(|&x| round(x, QUERY_BITS)).collect();
    bytes.extend(u64s_to_contiguous_bytes(&switched, QUERY_BITS));
    (secret, bytes)
}

#[test]
fn helpers_reproduce_the_replaced_copies() {
    let (rows, cols, target) = (4_096usize, 2 * D, 4_089usize);
    let masks = public_query_masks([11; 32], rows, cols);
    let mut rng = ChaCha20Rng::from_seed([12; 32]);
    let db: Vec<u16> = (0..rows * cols).map(|_| rng.next_u32() as u16).collect();
    let hint = hint(&masks, rows, cols, |c| &db[c * rows..(c + 1) * rows]).unwrap();
    let setup = NativeSetup::new(params(), [13; 32]);
    let blocks = preprocess(&setup, &hint).unwrap();
    let public = publish(&blocks).unwrap();
    let (secret, upload) = upload(&setup, &masks, rows, target);
    assert_eq!(upload.len(), request_len(rows));
    let (keys, query) = parse_with(&setup, &upload, rows).unwrap();
    let scan: Vec<u64> = (0..cols)
        .map(|c| {
            db[c * rows..(c + 1) * rows]
                .iter()
                .zip(&query)
                .fold(0u64, |a, (&x, &q)| {
                    a.wrapping_add((x as u64).wrapping_mul(q))
                })
                & (Q - 1)
        })
        .collect();
    let response = pack(&blocks, &keys, &scan).unwrap();
    let decoded = decode_cols(&secret, &public, &response, cols).unwrap();
    let expected: Vec<u8> = (0..cols)
        .flat_map(|c| db[c * rows + target].to_le_bytes())
        .collect();
    assert_eq!(decoded, expected);

    let masks: Vec<u64> = masks.into_iter().flatten().collect();
    let hint: Vec<u64> = hint.into_iter().flatten().flatten().collect();
    let got = [
        ("masks", digest_words(&masks)),
        ("hint", digest_words(&hint)),
        ("public", digest(&public)),
        ("upload", digest(&upload)),
        ("query", digest_words(&query)),
        ("scan", digest_words(&scan)),
        ("response", digest(&response)),
        ("decoded", digest(&decoded)),
    ];
    let want = [
        (
            "masks",
            "aef3721ff659ceaa1f7ed7276319fd40cc7fe629881f66fe2ae9c951cf1a59aa",
        ),
        (
            "hint",
            "21f8d5421240f1a20c9ceb343255320127f47d1d45db378cc9c111860bd3a137",
        ),
        (
            "public",
            "155f977c9e4517aaca352a8f0cbee05f01ce3c62e8c8024feb51338314efe960",
        ),
        (
            "upload",
            "103331c5c9a85d22403881eb67237c3c5c24d90d9afee0f735630aa1f1a82eae",
        ),
        (
            "query",
            "00689956544bf2b717e57cd11b35d01a27d67c6d65648bcf8effc5eb86dfbc17",
        ),
        (
            "scan",
            "a0836382fface222d434aa29d20f39a26c14f4f66c322539b961530e17a54021",
        ),
        (
            "response",
            "c5f48bce370133e159b2a81de3396619017a25ace7c9872a8a3b0e08bcd18241",
        ),
        (
            "decoded",
            "3069d9e5e6f4c406ce30d7a2425a4d6fee38b123ef5206bdf0c13ca3aba66361",
        ),
    ];
    for ((name, got), (_, want)) in got.iter().zip(want) {
        assert_eq!(got, want, "{name}");
    }
}

#[test]
fn sizes_are_the_deployed_profile() {
    assert_eq!(KEY_BYTES, 27_648);
    assert_eq!(public_len(12_288), 89_088);
    assert_eq!(request_len(8_192), 27_648 + 50_176);
    assert_eq!(response_len(D), BLOCK_RESPONSE_BYTES);
}

/// A prefix upload over the rows that can hold data is the full upload's byte
/// prefix, and over a table that is zero from `query_rows` on it is answered
/// bit-identically. One nonzero row past the prefix breaks decoding, which is
/// why servers check the zero tail before accepting prefixes.
#[test]
fn prefix_upload_is_exact_over_a_zero_tail() {
    let (rows, query_rows, cols, target) = (3 * D, D, D, 1_789usize);
    let masks = public_query_masks([21; 32], rows, cols);
    let setup = NativeSetup::new(params(), [22; 32]);
    let mut rng = ChaCha20Rng::from_seed([23; 32]);
    let mut db = vec![0u16; rows * cols];
    for c in 0..cols {
        for r in 0..query_rows {
            db[c * rows + r] = rng.next_u32() as u16;
        }
    }
    let answer = |db: &[u16], query: &[u64]| {
        let hint = hint(&masks, rows, cols, |c| &db[c * rows..(c + 1) * rows]).unwrap();
        let blocks = preprocess(&setup, &hint).unwrap();
        let scan: Vec<u64> = (0..cols)
            .map(|c| {
                db[c * rows..(c + 1) * rows]
                    .iter()
                    .zip(query)
                    .fold(0u64, |a, (&x, &q)| {
                        a.wrapping_add((x as u64).wrapping_mul(q))
                    })
                    & (Q - 1)
            })
            .collect();
        (publish(&blocks).unwrap(), blocks, scan)
    };

    let (secret, full) = upload(&setup, &masks, rows, target);
    let (_, short) = upload(&setup, &masks, query_rows, target);
    assert_eq!(short.len(), request_len(query_rows));
    assert_eq!(short, full[..request_len(query_rows)]);

    let (full_keys, full_query) = parse_with(&setup, &full, rows).unwrap();
    let (keys, query) = parse_selection(&setup, &short, query_rows, rows).unwrap();
    assert_eq!(query.len(), rows);
    assert_eq!(query[..query_rows], full_query[..query_rows]);
    assert!(query[query_rows..].iter().all(|&x| x == 0));

    let (public, blocks, scan) = answer(&db, &query);
    let (_, _, full_scan) = answer(&db, &full_query);
    assert_eq!(scan, full_scan);
    let response = pack(&blocks, &keys, &scan).unwrap();
    assert_eq!(response, pack(&blocks, &full_keys, &full_scan).unwrap());
    let expected: Vec<u8> = (0..cols)
        .flat_map(|c| db[c * rows + target].to_le_bytes())
        .collect();
    assert_eq!(
        decode_cols(&secret, &public, &response, cols).unwrap(),
        expected
    );

    // Data past the prefix is in the hint but not in the zero-filled scan.
    for c in 0..cols {
        db[c * rows + query_rows + 7] = rng.next_u32() as u16 | 1;
    }
    let (public, blocks, scan) = answer(&db, &query);
    let response = pack(&blocks, &keys, &scan).unwrap();
    assert_ne!(
        decode_cols(&secret, &public, &response, cols).unwrap(),
        expected
    );
}

#[test]
fn selection_parse_takes_only_full_or_prefix_lengths() {
    let setup = NativeSetup::new(params(), [24; 32]);
    let masks = public_query_masks([25; 32], 2 * D, D);
    let (_, short) = upload(&setup, &masks, D, 3);
    let (_, dithered) =
        prepare_dithered_with(&setup, &masks, D, 3, &mut ChaCha20Rng::from_seed([26; 32])).unwrap();
    assert_eq!(dithered.len(), request_len_bits(D, DITHERED_QUERY_BITS));
    for upload in [&short, &dithered] {
        let (_, query) = parse_selection(&setup, upload, D, 2 * D).unwrap();
        assert_eq!(query.len(), 2 * D);
        assert!(query[D..].iter().all(|&x| x == 0));
        // Over a one-block table the same bytes are a full upload.
        assert_eq!(parse_selection(&setup, upload, D, D).unwrap().1.len(), D);
        assert_eq!(
            parse_selection(&setup, upload, 2 * D, D).unwrap().1.len(),
            D
        );
        // A table whose queries select every row takes no prefix.
        assert!(parse_selection(&setup, upload, 2 * D, 2 * D).is_err());
        assert!(parse_selection(&setup, &upload[..upload.len() - 1], D, 2 * D).is_err());
        assert!(parse_selection(&setup, upload, 0, 2 * D).is_err());
        assert!(parse_selection(&setup, upload, 4 * D, 2 * D).is_err());
        assert!(parse_selection(&setup, upload, D, D + 8).is_err());
        assert!(parse_selection(&setup, upload, D / 2, 2 * D).is_err());
    }
    assert!(parse_with(&setup, &short, 2 * D).is_err());
}

/// Full and prefix uploads at either width have four distinct lengths for
/// every table shape the products serve, so the length alone names the rows
/// and width a server parses.
#[test]
fn full_and_prefix_lengths_never_collide() {
    for rows in (D..=65_536).step_by(D) {
        for query_rows in (D..rows).step_by(D) {
            let lengths = [
                request_len_bits(rows, QUERY_BITS),
                request_len_bits(rows, DITHERED_QUERY_BITS),
                request_len_bits(query_rows, QUERY_BITS),
                request_len_bits(query_rows, DITHERED_QUERY_BITS),
            ];
            for (i, a) in lengths.iter().enumerate() {
                assert!(
                    lengths[i + 1..].iter().all(|b| a != b),
                    "{rows} {query_rows}"
                );
                assert_eq!(
                    accepted_query_shape(rows, query_rows, *a),
                    Some((
                        if i < 2 { rows } else { query_rows },
                        if i % 2 == 0 {
                            QUERY_BITS
                        } else {
                            DITHERED_QUERY_BITS
                        }
                    ))
                );
            }
        }
    }
}

/// A dithered upload over only the first block, under the leading full-shape
/// masks, decodes the target from a table that is zero past that block.
#[test]
fn dithered_prefix_upload_decodes_over_a_zero_tail() {
    let (rows, query_rows, cols, target) = (2 * D, D, D, 777usize);
    let masks = public_query_masks([27; 32], rows, cols);
    let setup = NativeSetup::new(params(), [28; 32]);
    let mut rng = ChaCha20Rng::from_seed([29; 32]);
    let db: Vec<u16> = (0..rows * cols)
        .map(|i| {
            if i % rows < query_rows {
                rng.next_u32() as u16
            } else {
                0
            }
        })
        .collect();
    let hint = hint(&masks, rows, cols, |c| &db[c * rows..(c + 1) * rows]).unwrap();
    let blocks = preprocess(&setup, &hint).unwrap();
    let (secret, upload) = prepare_dithered_with(
        &setup,
        &masks,
        query_rows,
        target,
        &mut ChaCha20Rng::from_seed([30; 32]),
    )
    .unwrap();
    let (keys, query) = parse_selection(&setup, &upload, query_rows, rows).unwrap();
    let scan: Vec<u64> = (0..cols)
        .map(|c| {
            db[c * rows..(c + 1) * rows]
                .iter()
                .zip(&query)
                .fold(0u64, |a, (&x, &q)| {
                    a.wrapping_add((x as u64).wrapping_mul(q))
                })
                & (Q - 1)
        })
        .collect();
    let response = pack(&blocks, &keys, &scan).unwrap();
    let expected: Vec<u8> = (0..cols)
        .flat_map(|c| db[c * rows + target].to_le_bytes())
        .collect();
    assert_eq!(
        decode_cols(&secret, &publish(&blocks).unwrap(), &response, cols).unwrap(),
        expected
    );
}
