//! Native PIR client facade and shared client/server profiles.
//! Protocol envelopes and seeds remain with each protocol.
pub mod profile;
pub use profile::{
    D, DITHERED_QUERY_BITS, KEY_BYTES, MASK_BITS, NativeSecret, NativeSetup, Q, Q_BITS, QUERY_BITS,
    RESPONSE_BITS,
};
#[cfg(test)]
use rand::RngCore;
#[cfg(test)]
use rand_chacha::ChaCha20Rng;
pub const KEY_WORDS: usize = 2 * D;
pub use profile::{
    decode_cols, params, prepare_dithered, prepare_with, public_len, request_len, request_len_bits,
    response_len,
};
/// Derive the packing setup from the protocol's packing seed.
pub fn packing_setup(seed: [u8; 32]) -> NativeSetup {
    NativeSetup::new(params(), seed)
}
/// Masks over a valid protocol geometry; invalid geometry panics, as before.
pub fn public_query_masks(seed: [u8; 32], rows: usize, cols: usize) -> Vec<Vec<u64>> {
    profile::public_query_masks(seed, rows, cols).expect("fixed experimental profile")
}
#[cfg(test)]
fn prepare_from(
    setup: &NativeSetup,
    masks: &[Vec<u64>],
    rows: usize,
    target: usize,
    dithered: bool,
    rng: &mut ChaCha20Rng,
) -> Result<(NativeSecret, Vec<u8>), String> {
    profile::P16.prepare_rounded(
        setup,
        masks,
        rows,
        target,
        (
            if dithered {
                DITHERED_QUERY_BITS
            } else {
                QUERY_BITS
            },
            dithered,
        ),
        rng,
    )
}
/// In-process protocol test evaluator using the production native operations.
#[cfg(any(test, feature = "test-server"))]
pub mod test_server {
    use super::*;
    pub struct Database {
        db: Vec<Vec<u16>>,
        setup: NativeSetup,
        blocks: Vec<profile::NativePreprocessed>,
        public: Vec<u8>,
    }
    impl Database {
        pub fn new(db: Vec<Vec<u16>>, masks: &[Vec<u64>], packing_seed: [u8; 32]) -> Self {
            let setup = packing_setup(packing_seed);
            let hint =
                profile::hint(masks, db[0].len(), db.len(), |col| db[col].as_slice()).unwrap();
            let blocks = profile::preprocess(&setup, &hint).unwrap();
            let public = profile::publish(&blocks).unwrap();
            Self {
                db,
                setup,
                blocks,
                public,
            }
        }
        pub fn public(&self) -> &[u8] {
            &self.public
        }
        pub fn answer(&self, payload: &[u8]) -> Vec<u8> {
            let (keys, query) =
                profile::parse_selection(&self.setup, payload, self.db[0].len(), self.db[0].len())
                    .unwrap();
            let scan: Vec<u64> = self
                .db
                .iter()
                .map(|col| {
                    col.iter().zip(&query).fold(0u64, |a, (&x, &q)| {
                        a.wrapping_add((x as u64).wrapping_mul(q))
                    }) & (Q - 1)
                })
                .collect();
            profile::pack(&self.blocks, &keys, &scan).unwrap()
        }
    }
}
#[cfg(test)]
fn round(x: u64, bits: usize) -> u64 {
    (((x as u128 * (1u128 << bits) + (Q / 2) as u128) / Q as u128) as u64) & ((1 << bits) - 1)
}

/// Round each `x` in `[0, Q)` to `bits` bits, with wraparound at `2^bits`:
/// up with probability equal to the dropped fraction, otherwise down, so the
/// rounding error has zero mean. Draws one coin per word from `rng`.
#[cfg(test)]
fn dither(words: &[u64], bits: usize, rng: &mut ChaCha20Rng) -> Vec<u64> {
    let shift = Q_BITS - bits;
    let low = (1u64 << shift) - 1;
    words
        .iter()
        .map(|&x| {
            let up = u64::from((rng.next_u64() & low) < (x & low));
            ((x >> shift) + up) & ((1 << bits) - 1)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipir_sp::bits::u64s_to_contiguous_bytes;
    use profile::NativeKeys;
    use rand::{Rng, RngCore};
    use rand_chacha::rand_core::SeedableRng;

    /// End-to-end over the library primitives a server uses: two-mask
    /// preprocessing, one-key upload, 29-bit masks and 22-bit responses.
    #[test]
    fn two_mask_rounded_roundtrip() {
        let (rows, cols) = (D, D);
        let mut rng = ChaCha20Rng::from_seed([7; 32]);
        let db: Vec<Vec<u16>> = (0..cols)
            .map(|_| (0..rows).map(|_| rng.r#gen()).collect())
            .collect();
        let masks = public_query_masks([3; 32], rows, cols);
        let setup = packing_setup([9; 32]);
        let server = test_server::Database::new(db.clone(), &masks, [9; 32]);
        assert_eq!(server.public().len(), public_len(cols));
        let target = 1234;
        let (secret, body) = prepare_with(&setup, &masks, rows, target).unwrap();
        assert_eq!(body.len(), request_len(rows));
        let response = server.answer(&body);
        assert_eq!(response.len(), response_len(cols));
        let row = decode_cols(&secret, server.public(), &response, cols).unwrap();
        let expected: Vec<u8> = db.iter().flat_map(|c| c[target].to_le_bytes()).collect();
        assert_eq!(row, expected);
    }

    /// Over a table whose second block is zero, a selection over only the
    /// first block, under the leading full-shape masks, decodes the target.
    #[test]
    fn prefix_selection_over_a_zero_tail_roundtrips() {
        let (rows, cols) = (2 * D, D);
        let mut rng = ChaCha20Rng::from_seed([8; 32]);
        let db: Vec<Vec<u16>> = (0..cols)
            .map(|_| {
                (0..rows)
                    .map(|r| if r < D { rng.r#gen() } else { 0 })
                    .collect()
            })
            .collect();
        let masks = public_query_masks([3; 32], rows, cols);
        let setup = packing_setup([9; 32]);
        let server = test_server::Database::new(db.clone(), &masks, [9; 32]);
        let target = 1234;
        let (secret, body) = prepare_with(&setup, &masks, D, target).unwrap();
        assert_eq!(body.len(), request_len(D));
        let row = decode_cols(&secret, server.public(), &server.answer(&body), cols).unwrap();
        let expected: Vec<u8> = db.iter().flat_map(|c| c[target].to_le_bytes()).collect();
        assert_eq!(row, expected);
    }

    #[test]
    fn rounding_and_shape_checks() {
        assert_eq!(round(0, QUERY_BITS), 0);
        assert_eq!(round(Q - 1, QUERY_BITS), 0);
        assert_eq!(round(Q / 2, MASK_BITS), 1 << (MASK_BITS - 1));
        assert_eq!(KEY_BYTES, 27_648);
        let setup = packing_setup([9; 32]);
        let masks = public_query_masks([3; 32], D, D);
        assert!(prepare_with(&setup, &masks, D, D).is_err());
        assert!(prepare_with(&setup, &masks, D + 1, 0).is_err());
        assert!(prepare_with(&setup, &masks, 2 * D, 0).is_err());
        let (secret, _) = prepare_with(&setup, &masks, D, D - 1).unwrap();
        assert!(decode_cols(&secret, &vec![0; public_len(D)], &[0; 1], D).is_err());
        assert!(decode_cols(&secret, &[0; 1], &vec![0; response_len(D)], D).is_err());
        assert!(
            decode_cols(
                &secret,
                &vec![0; public_len(D + 1)],
                &vec![0; response_len(D + 1)],
                D + 1
            )
            .is_err()
        );
    }

    /// The draws a request makes before rounding, rebuilt by hand from the RNG
    /// order: secret, packing key, selection. Returns the key bytes, the
    /// unrounded selection and the RNG positioned at the first rounding coin.
    fn draw(
        setup: &NativeSetup,
        masks: &[Vec<u64>],
        rows: usize,
        target: usize,
        seed: u64,
    ) -> (Vec<u8>, Vec<u64>, ChaCha20Rng) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let secret = NativeSecret::sample(&params(), &mut rng);
        let keys = NativeKeys::generate_one_key(setup, &secret, &mut rng).unwrap();
        let query = secret
            .encrypt_selection(&masks[..rows / D], target, &mut rng)
            .unwrap();
        (
            u64s_to_contiguous_bytes(&keys.kg_words(), Q_BITS),
            query,
            rng,
        )
    }

    #[test]
    fn requests_match_hand_rebuild_and_dithering_uses_its_coins() {
        let rows = 2 * D;
        let setup = packing_setup([9; 32]);
        let masks = public_query_masks([3; 32], rows, D);
        assert!(prepare_dithered(&setup, &masks, rows, rows).is_err());
        assert!(prepare_dithered(&setup, &masks, D + 1, 0).is_err());
        assert!(prepare_dithered(&setup, &masks, 2 * rows, 0).is_err());
        assert_eq!(request_len_bits(rows, QUERY_BITS), request_len(rows));
        assert_eq!(
            request_len_bits(rows, DITHERED_QUERY_BITS),
            KEY_BYTES + 22_528
        );
        let encode = |words: &[u64], bits| u64s_to_contiguous_bytes(words, bits);
        let nearest_at = |query: &[u64], bits: usize| -> Vec<u64> {
            let shift = Q_BITS - bits;
            query
                .iter()
                .map(|&x| ((x + (1 << (shift - 1))) >> shift) % (1 << bits))
                .collect()
        };
        for (target, seed) in [(0, 42), (rows - 1, 43)] {
            let prepare = |dithered| {
                let mut rng = ChaCha20Rng::seed_from_u64(seed);
                prepare_from(&setup, &masks, rows, target, dithered, &mut rng)
                    .unwrap()
                    .1
            };
            let (key, query, mut rng) = draw(&setup, &masks, rows, target, seed);
            // Nearest: the unchanged 49-bit request.
            let nearest = prepare(false);
            assert_eq!(
                nearest,
                [
                    key.clone(),
                    encode(&nearest_at(&query, QUERY_BITS), QUERY_BITS)
                ]
                .concat()
            );
            assert_eq!(nearest.len(), request_len(rows));
            // Dithered: the same draws, then one coin per row; round up when
            // the coin falls below the dropped fraction.
            let shift = Q_BITS - DITHERED_QUERY_BITS;
            let coins: Vec<u64> = query
                .iter()
                .map(|&x| {
                    let up = u64::from(rng.next_u64() % (1 << shift) < x % (1 << shift));
                    ((x >> shift) + up) % (1 << DITHERED_QUERY_BITS)
                })
                .collect();
            let dithered = prepare(true);
            assert_eq!(
                dithered,
                [key.clone(), encode(&coins, DITHERED_QUERY_BITS)].concat()
            );
            assert_eq!(dithered.len(), request_len_bits(rows, DITHERED_QUERY_BITS));
            // Nearest rounding at the same width differs only in the
            // selection, so this fails if the coins are ever skipped.
            let flat = [
                key,
                encode(
                    &nearest_at(&query, DITHERED_QUERY_BITS),
                    DITHERED_QUERY_BITS,
                ),
            ]
            .concat();
            assert_eq!(flat.len(), dithered.len());
            assert_eq!(flat[..KEY_BYTES], dithered[..KEY_BYTES]);
            assert_ne!(flat, dithered);
        }
    }

    #[test]
    fn dithered_rounding_is_unbiased_floor_or_ceiling() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        for bits in [DITHERED_QUERY_BITS, QUERY_BITS] {
            let shift = Q_BITS - bits;
            let unit = 1u64 << shift;
            let mask = (1u64 << bits) - 1;
            // Exact multiples never move, whatever the coins.
            let exact = [0, unit, Q - unit];
            assert_eq!(
                dither(&exact, bits, &mut rng),
                exact.iter().map(|&x| x >> shift).collect::<Vec<_>>()
            );
            for x in [1, unit / 4, unit / 2, unit - 1, Q - 1, Q - unit / 3] {
                let trials = 1 << 16;
                let floor = x >> shift;
                let ups = dither(&vec![x; trials], bits, &mut rng)
                    .into_iter()
                    .filter(|&y| {
                        // Only floor or ceiling; the ceiling of Q-1 wraps to 0.
                        assert!(y == floor || y == (floor + 1) & mask);
                        y != floor
                    })
                    .count();
                // Round-up frequency matches the dropped fraction (zero-mean
                // error): within 6 binomial standard deviations at p = 1/2.
                let expected = trials as f64 * (x & (unit - 1)) as f64 / unit as f64;
                let sd = (trials as f64 / 4.0).sqrt();
                assert!(
                    (ups as f64 - expected).abs() <= 6.0 * sd,
                    "bits={bits} x={x}: {ups} round-ups, expected {expected}"
                );
            }
        }
    }

    /// One server answers both selection widths, chosen by exact length.
    #[test]
    fn dithered_and_nearest_requests_share_a_server() {
        let (rows, cols) = (D, D);
        let mut rng = ChaCha20Rng::from_seed([8; 32]);
        let db: Vec<Vec<u16>> = (0..cols)
            .map(|_| (0..rows).map(|_| rng.r#gen()).collect())
            .collect();
        let masks = public_query_masks([3; 32], rows, cols);
        let setup = packing_setup([9; 32]);
        let server = test_server::Database::new(db.clone(), &masks, [9; 32]);
        for (target, dithered) in [(1234, true), (0, true), (rows - 1, true), (77, false)] {
            let (secret, body) = if dithered {
                prepare_dithered(&setup, &masks, rows, target).unwrap()
            } else {
                prepare_with(&setup, &masks, rows, target).unwrap()
            };
            let bits = if dithered {
                DITHERED_QUERY_BITS
            } else {
                QUERY_BITS
            };
            assert_eq!(body.len(), request_len_bits(rows, bits));
            let response = server.answer(&body);
            assert_eq!(response.len(), response_len(cols));
            let row = decode_cols(&secret, server.public(), &response, cols).unwrap();
            let expected: Vec<u8> = db.iter().flat_map(|c| c[target].to_le_bytes()).collect();
            assert_eq!(row, expected, "target={target} dithered={dithered}");
        }
        let other = vec![0; request_len_bits(rows, 45)];
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| server.answer(&other)))
                .is_err()
        );
    }
}
