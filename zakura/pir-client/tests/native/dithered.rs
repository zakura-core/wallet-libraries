//! The dithered 44-bit query: its bytes, its parse and its decode.
//!
//! Nothing here touches the 49-bit query, whose bytes `golden.rs` pins.
use zakura_pir_query_server::native::{pack, parse_accepted, parse_bits, parse_with};
use zakura_pir_server_core::native::{hint, preprocess, publish};

#[path = "../support/reference_bits.rs"]
mod reference_bits;
use rand::RngCore;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use reference_bits::u64s_to_contiguous_bytes;
use sha2::{Digest, Sha256};
use zakura_pir_client::native::*;

const ROWS: usize = 4_096;
const COLS: usize = 2 * D;

fn round_nearest(x: u64, bits: usize) -> u64 {
    (((x as u128 * (1u128 << bits) + (Q / 2) as u128) / Q as u128) as u64) & ((1 << bits) - 1)
}

/// `prepare_dithered_with`, rebuilt by hand from the reinspiring primitives:
/// the secret, the key and the selection drawn in `prepare_with`'s order, then
/// one coin per row. Returns the upload and the unrounded selection.
fn rebuild(setup: &NativeSetup, masks: &[Vec<u64>], target: usize) -> (Vec<u8>, Vec<u64>) {
    let mut rng = ChaCha20Rng::from_seed([14; 32]);
    let secret = NativeSecret::sample(&params(), &mut rng);
    let keys = NativeKeys::generate_one_key(setup, &secret, &mut rng).unwrap();
    let query = secret
        .encrypt_selection(&masks[..ROWS / D], target, &mut rng)
        .unwrap();
    let shift = Q_BITS - DITHERED_QUERY_BITS;
    let low = (1u64 << shift) - 1;
    let switched: Vec<u64> = query
        .iter()
        .map(|&x| {
            let up = u64::from((rng.next_u64() & low) < (x & low));
            ((x >> shift) + up) & ((1 << DITHERED_QUERY_BITS) - 1)
        })
        .collect();
    let mut bytes = u64s_to_contiguous_bytes(&keys.kg_words(), Q_BITS);
    bytes.extend(u64s_to_contiguous_bytes(&switched, DITHERED_QUERY_BITS));
    (bytes, query)
}

#[test]
fn a_seeded_dithered_upload_is_the_rebuilt_one() {
    let masks = public_query_masks([11; 32], ROWS, COLS);
    let setup = NativeSetup::new(params(), [13; 32]);
    let target = 4_089;
    let (_, upload) = prepare_dithered_with(
        &setup,
        &masks,
        ROWS,
        target,
        &mut ChaCha20Rng::from_seed([14; 32]),
    )
    .unwrap();
    let (rebuilt, query) = rebuild(&setup, &masks, target);
    assert_eq!(upload, rebuilt);
    assert_eq!(upload.len(), request_len_bits(ROWS, DITHERED_QUERY_BITS));
    assert_eq!(upload.len(), KEY_BYTES + 22_528);
    assert_eq!(
        hex::encode(Sha256::digest(&upload)),
        "44a9636fc29ac8fc20add327928187aa097c57579c021ae77fcc3f02ec40d85d",
        "the dithered upload of a fixed generator"
    );

    // The same query rounded to nearest at 44 bits: the key is the same bytes,
    // the selection is not, so the coins really were used.
    let nearest: Vec<u64> = query
        .iter()
        .map(|&x| round_nearest(x, DITHERED_QUERY_BITS))
        .collect();
    let nearest = u64s_to_contiguous_bytes(&nearest, DITHERED_QUERY_BITS);
    assert_eq!(upload[..KEY_BYTES], rebuilt[..KEY_BYTES]);
    assert_ne!(upload[KEY_BYTES..], nearest[..]);

    // Every lifted coefficient is the floor or ceiling of the exact one.
    let (_, lifted) = parse_bits(&setup, &upload, ROWS, DITHERED_QUERY_BITS).unwrap();
    let unit = 1u64 << (Q_BITS - DITHERED_QUERY_BITS);
    for (&x, &y) in query.iter().zip(&lifted) {
        let error = y.wrapping_sub(x) & (Q - 1);
        assert!(error < unit || Q - error < unit, "{x} lifted to {y}");
    }
}

#[test]
fn a_dithered_query_round_trips_and_decodes() {
    let masks = public_query_masks([11; 32], ROWS, COLS);
    let mut rng = ChaCha20Rng::from_seed([12; 32]);
    let db: Vec<u16> = (0..ROWS * COLS).map(|_| rng.next_u32() as u16).collect();
    let hint = hint(&masks, ROWS, COLS, |c| &db[c * ROWS..(c + 1) * ROWS]).unwrap();
    let setup = NativeSetup::new(params(), [13; 32]);
    let blocks = preprocess(&setup, &hint).unwrap();
    let public = publish(&blocks).unwrap();
    for target in [0, 1_234, ROWS - 1] {
        let (secret, upload) = prepare_dithered(&setup, &masks, ROWS, target).unwrap();
        assert_eq!(upload.len(), request_len_bits(ROWS, DITHERED_QUERY_BITS));
        // The 49-bit parser refuses it; the width-dispatching one takes it.
        assert!(parse_with(&setup, &upload, ROWS).is_err());
        let (keys, query) = parse_accepted(&setup, &upload, ROWS).unwrap();
        let (same_keys, same_query) =
            parse_bits(&setup, &upload, ROWS, DITHERED_QUERY_BITS).unwrap();
        assert_eq!(
            (keys.kg_words(), &query),
            (same_keys.kg_words(), &same_query)
        );
        let scan: Vec<u64> = (0..COLS)
            .map(|c| {
                db[c * ROWS..(c + 1) * ROWS]
                    .iter()
                    .zip(&query)
                    .fold(0u64, |a, (&x, &q)| {
                        a.wrapping_add((x as u64).wrapping_mul(q))
                    })
                    & (Q - 1)
            })
            .collect();
        let response = pack(&blocks, &keys, &scan).unwrap();
        let decoded = decode_cols(&secret, &public, &response, COLS).unwrap();
        let expected: Vec<u8> = (0..COLS)
            .flat_map(|c| db[c * ROWS + target].to_le_bytes())
            .collect();
        assert_eq!(decoded, expected, "target {target}");
    }

    // The 49-bit query still parses through the dispatching parser, to the
    // same words as its own parser.
    let (_, legacy) = prepare_with(&setup, &masks, ROWS, 7).unwrap();
    let (a, qa) = parse_accepted(&setup, &legacy, ROWS).unwrap();
    let (b, qb) = parse_with(&setup, &legacy, ROWS).unwrap();
    assert_eq!((a.kg_words(), qa), (b.kg_words(), qb));
}

#[test]
fn other_lengths_and_widths_are_refused() {
    let setup = NativeSetup::new(params(), [13; 32]);
    let dithered = request_len_bits(ROWS, DITHERED_QUERY_BITS);
    for len in [dithered - 1, dithered + 1, request_len(ROWS) + 1, KEY_BYTES] {
        assert!(
            parse_accepted(&setup, &vec![0; len], ROWS).is_err(),
            "{len}"
        );
    }
    // A width is only ever one of the two the servers accept.
    let other = request_len_bits(ROWS, 43);
    assert!(parse_bits(&setup, &vec![0; other], ROWS, 43).is_err());
    // The right length for another row count is the wrong length here.
    let taller = request_len_bits(2 * ROWS, DITHERED_QUERY_BITS);
    assert!(parse_accepted(&setup, &vec![0; taller], ROWS).is_err());
}
