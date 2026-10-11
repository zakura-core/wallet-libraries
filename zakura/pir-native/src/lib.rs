//! Native two-mask packing primitives shared by the Zakura PIR clients.
//!
//! The client uploads one `K_g` packing key and a selection query per request,
//! and decodes each response block under the two published masks, which are
//! rounded to [`MASK_BITS`]. The selection is either rounded to nearest at
//! [`QUERY_BITS`] ([`prepare_with`]) or dithered to [`DITHERED_QUERY_BITS`]
//! ([`prepare_dithered`]); a server tells the two apart by exact length.
//! Setup seeds, database shapes and request envelopes belong to each protocol;
//! nothing here is protocol-specific.
//!
//! This profile is experimental: ipir-sp's cryptographic gates for the native
//! path remain open, and correctness certificates are snapshot-specific.
use ipir_sp::{
    bits::{contiguous_bytes_to_u64s, u64s_to_contiguous_bytes},
    native::{NativeProfile, NativePublicSetup},
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use reinspiring::native::{NativeKeys, NativeParams, NativeTwoMaskCiphertext, SecretDistribution};

pub use reinspiring::native::{NativeSecret, NativeSetup};

pub const Q: u64 = 1 << 54;
pub const Q_BITS: usize = 54;
pub const D: usize = 2048;
pub const MASK_BITS: usize = 29;
pub const QUERY_BITS: usize = 49;
/// Selection width of [`prepare_dithered`] requests.
pub const DITHERED_QUERY_BITS: usize = 44;
pub const RESPONSE_BITS: usize = 22;
pub const KEY_WORDS: usize = 2 * D;
pub const KEY_BYTES: usize = KEY_WORDS * Q_BITS / 8;

pub fn params() -> NativeParams {
    NativeParams::new(D, 54, 16, 19, 2, SecretDistribution::Gaussian)
        .expect("fixed experimental profile")
}

/// Packing key-switching setup derived from a protocol's packing seed.
pub fn packing_setup(seed: [u8; 32]) -> NativeSetup {
    NativeSetup::new(params(), seed)
}

/// Domain-separated first-dimension masks for a `rows` by `cols` database.
pub fn public_query_masks(seed: [u8; 32], rows: usize, cols: usize) -> Vec<Vec<u64>> {
    NativePublicSetup::new(
        NativeProfile::new(params(), rows, cols).expect("fixed experimental profile"),
        seed,
        [0; 32],
    )
    .query_masks()
    .to_vec()
}

/// Canonical published bytes for two-mask blocks: every first mask, then
/// every second mask, each coefficient rounded to [`MASK_BITS`].
pub fn public_len(cols: usize) -> usize {
    (2 * cols * MASK_BITS).div_ceil(8)
}

/// Response body length for `cols` packed columns at [`RESPONSE_BITS`].
pub fn response_len(cols: usize) -> usize {
    (cols * RESPONSE_BITS).div_ceil(8)
}

/// Request payload length for `rows`: one `K_g` key and a [`QUERY_BITS`] selection.
pub fn request_len(rows: usize) -> usize {
    request_len_bits(rows, QUERY_BITS)
}

/// Request payload length for `rows`: one `K_g` key and a `bits`-bit selection.
pub fn request_len_bits(rows: usize, bits: usize) -> usize {
    KEY_BYTES + (rows * bits).div_ceil(8)
}

/// Round `x` in `[0, Q)` to `bits` bits, nearest, with wraparound at `2^bits`.
fn round(x: u64, bits: usize) -> u64 {
    (((x as u128 * (1u128 << bits) + (Q / 2) as u128) / Q as u128) as u64) & ((1 << bits) - 1)
}

/// Round each `x` in `[0, Q)` to `bits` bits, with wraparound at `2^bits`:
/// up with probability equal to the dropped fraction, otherwise down, so the
/// rounding error has zero mean. Draws one coin per word from `rng`.
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

/// Fresh secret, one-key packing upload and 49-bit selection query.
pub fn prepare_with(
    setup: &NativeSetup,
    masks: &[Vec<u64>],
    rows: usize,
    target: usize,
) -> Result<(NativeSecret, Vec<u8>), String> {
    prepare_from(setup, masks, rows, target, false, &mut fresh_rng())
}

/// Fresh secret, one-key packing upload and a selection query dithered to
/// [`DITHERED_QUERY_BITS`]: [`request_len_bits`]`(rows, DITHERED_QUERY_BITS)`
/// bytes. Each coefficient's rounding coin is fresh, so rounding errors are
/// independent and zero-mean.
pub fn prepare_dithered(
    setup: &NativeSetup,
    masks: &[Vec<u64>],
    rows: usize,
    target: usize,
) -> Result<(NativeSecret, Vec<u8>), String> {
    prepare_from(setup, masks, rows, target, true, &mut fresh_rng())
}

fn fresh_rng() -> ChaCha20Rng {
    let mut entropy = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut entropy);
    ChaCha20Rng::from_seed(entropy)
}

/// Draws the secret, the packing key and the encrypted selection from `rng`
/// in that order, then, when `dithered`, one rounding coin per row. `rng` must
/// be freshly seeded from OS entropy for every request.
fn prepare_from(
    setup: &NativeSetup,
    masks: &[Vec<u64>],
    rows: usize,
    target: usize,
    dithered: bool,
    rng: &mut ChaCha20Rng,
) -> Result<(NativeSecret, Vec<u8>), String> {
    if target >= rows || !rows.is_multiple_of(D) || masks.len() < rows / D {
        return Err("native query shape".into());
    }
    let secret = NativeSecret::sample(&params(), rng);
    let keys = NativeKeys::generate_one_key(setup, &secret, rng).map_err(|e| e.to_string())?;
    let query = secret
        .encrypt_selection(&masks[..rows / D], target, rng)
        .map_err(|e| e.to_string())?;
    let mut bytes = u64s_to_contiguous_bytes(&keys.kg_words(), Q_BITS);
    let (bits, switched) = if dithered {
        (
            DITHERED_QUERY_BITS,
            dither(&query, DITHERED_QUERY_BITS, rng),
        )
    } else {
        (
            QUERY_BITS,
            query.iter().map(|&x| round(x, QUERY_BITS)).collect(),
        )
    };
    bytes.extend(u64s_to_contiguous_bytes(&switched, bits));
    Ok((secret, bytes))
}

/// Decode every little-endian u16 plaintext coefficient of a two-mask response.
pub fn decode_cols(
    secret: &NativeSecret,
    public: &[u8],
    body: &[u8],
    cols: usize,
) -> Result<Vec<u8>, String> {
    if !cols.is_multiple_of(D)
        || public.len() != public_len(cols)
        || body.len() != response_len(cols)
    {
        return Err("native response shape".into());
    }
    let masks: Vec<_> = contiguous_bytes_to_u64s(public, MASK_BITS)
        .into_iter()
        .map(|x| x << (Q_BITS - MASK_BITS))
        .collect();
    let (a, a_other) = masks[..2 * cols].split_at(cols);
    let b: Vec<_> = contiguous_bytes_to_u64s(body, RESPONSE_BITS)
        .into_iter()
        .map(|x| x << (Q_BITS - RESPONSE_BITS))
        .collect();
    let mut out = Vec::with_capacity(cols * 2);
    for ((a, a_other), b) in a
        .as_chunks::<D>()
        .0
        .iter()
        .zip(a_other.as_chunks::<D>().0)
        .zip(b[..cols].as_chunks::<D>().0)
    {
        let ct =
            NativeTwoMaskCiphertext::from_rows(&params(), a.to_vec(), a_other.to_vec(), b.to_vec())
                .map_err(|e| e.to_string())?;
        for x in secret.decrypt_two_mask(&ct).map_err(|e| e.to_string())? {
            out.extend((x as u16).to_le_bytes());
        }
    }
    Ok(out)
}

/// Server-side counterparts of the client primitives, so protocol crates can
/// exercise their clients over the library operations a server performs
/// without depending on a server implementation.
#[cfg(any(test, feature = "test-server"))]
pub mod test_server {
    use super::*;
    use reinspiring::native::NativePreprocessed;

    /// An in-memory database of u16 coefficients, `db[col][row]`, with the
    /// preprocessing and published two-mask material a server would hold.
    pub struct Database {
        db: Vec<Vec<u16>>,
        setup: NativeSetup,
        blocks: Vec<NativePreprocessed>,
        public: Vec<u8>,
    }

    impl Database {
        /// `rows` and `cols` must be multiples of [`D`]; `masks` come from
        /// [`public_query_masks`] over the same shape, and `packing_seed` is
        /// the seed the client passes to [`packing_setup`].
        pub fn new(db: Vec<Vec<u16>>, masks: &[Vec<u64>], packing_seed: [u8; 32]) -> Self {
            let setup = packing_setup(packing_seed);
            let cols = db.len();
            let rows = db[0].len();
            assert!(cols.is_multiple_of(D) && rows.is_multiple_of(D));
            let lift = reinspiring::lift_ntt::LiftContext::new(D, Q).unwrap();
            let public = lift.prepare_public_dot(masks, 65535).unwrap();
            let hint: Vec<_> = db
                .iter()
                .map(|col| {
                    let poly: Vec<Vec<u64>> = col
                        .as_chunks::<D>()
                        .0
                        .iter()
                        .map(|c| c.iter().map(|&x| x as u64).collect())
                        .collect();
                    lift.public_dot(&public, &poly).unwrap()
                })
                .collect();
            let blocks: Vec<_> = hint
                .as_chunks::<D>()
                .0
                .iter()
                .map(|h| NativePreprocessed::build_two_mask(&setup, h).unwrap())
                .collect();
            let words: Vec<_> = blocks
                .iter()
                .flat_map(|b| b.mask().iter())
                .chain(
                    blocks
                        .iter()
                        .flat_map(|b| b.other_mask().expect("two-mask preprocessing").iter()),
                )
                .map(|&x| round(x, MASK_BITS))
                .collect();
            let public = u64s_to_contiguous_bytes(&words, MASK_BITS);
            Self {
                db,
                setup,
                blocks,
                public,
            }
        }

        /// Published two-mask material, [`public_len`] bytes.
        pub fn public(&self) -> &[u8] {
            &self.public
        }

        /// Answers a [`prepare_with`] or [`prepare_dithered`] payload with a
        /// [`response_len`] body. The selection may cover every row or, as a
        /// client omits rows that hold no data, a whole-block prefix; its
        /// row count and width come from the exact payload length, and any
        /// other length panics.
        pub fn answer(&self, payload: &[u8]) -> Vec<u8> {
            let (rows, bits) = (D..=self.db[0].len())
                .step_by(D)
                .flat_map(|rows| [QUERY_BITS, DITHERED_QUERY_BITS].map(|bits| (rows, bits)))
                .find(|&(rows, bits)| payload.len() == request_len_bits(rows, bits))
                .expect("a full or whole-block prefix selection at a supported width");
            let keys = NativeKeys::from_kg_words(
                &self.setup,
                &contiguous_bytes_to_u64s(&payload[..KEY_BYTES], Q_BITS),
            )
            .unwrap();
            let query: Vec<u64> = contiguous_bytes_to_u64s(&payload[KEY_BYTES..], bits)
                .into_iter()
                .take(rows)
                .map(|x| x << (Q_BITS - bits))
                .collect();
            let scan: Vec<u64> = self
                .db
                .iter()
                .map(|col| {
                    col.iter().zip(&query).fold(0u64, |a, (&x, &q)| {
                        a.wrapping_add((x as u64).wrapping_mul(q))
                    }) & (Q - 1)
                })
                .collect();
            let prepared = self.blocks[0].prepare_keys(&keys).unwrap();
            let values: Vec<u64> = self
                .blocks
                .iter()
                .zip(scan.as_chunks::<D>().0)
                .flat_map(|(p, b)| {
                    p.prepare_pack(&prepared)
                        .unwrap()
                        .finish_two_mask(b)
                        .unwrap()
                        .rows()
                        .2
                        .to_vec()
                })
                .collect();
            let switched: Vec<_> = values.iter().map(|&x| round(x, RESPONSE_BITS)).collect();
            u64s_to_contiguous_bytes(&switched, RESPONSE_BITS)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

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
