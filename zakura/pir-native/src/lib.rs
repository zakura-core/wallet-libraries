//! Native two-mask packing primitives shared by the Zakura PIR clients.
//!
//! The client uploads one `K_g` packing key and a [`QUERY_BITS`]-bit selection
//! query per request, and decodes each response block under the two published
//! masks, which are rounded to [`MASK_BITS`]. Setup seeds, database shapes and
//! request envelopes belong to each protocol; nothing here is protocol-specific.
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
    KEY_BYTES + (rows * QUERY_BITS).div_ceil(8)
}

/// Round `x` in `[0, Q)` to `bits` bits, nearest, with wraparound at `2^bits`.
fn round(x: u64, bits: usize) -> u64 {
    (((x as u128 * (1u128 << bits) + (Q / 2) as u128) / Q as u128) as u64) & ((1 << bits) - 1)
}

/// Fresh secret, one-key packing upload and 49-bit selection query.
pub fn prepare_with(
    setup: &NativeSetup,
    masks: &[Vec<u64>],
    rows: usize,
    target: usize,
) -> Result<(NativeSecret, Vec<u8>), String> {
    if target >= rows || !rows.is_multiple_of(D) || masks.len() < rows / D {
        return Err("native query shape".into());
    }
    let mut entropy = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut entropy);
    let mut rng = ChaCha20Rng::from_seed(entropy);
    let secret = NativeSecret::sample(&params(), &mut rng);
    let keys = NativeKeys::generate_one_key(setup, &secret, &mut rng).map_err(|e| e.to_string())?;
    let query = secret
        .encrypt_selection(&masks[..rows / D], target, &mut rng)
        .map_err(|e| e.to_string())?;
    let mut bytes = u64s_to_contiguous_bytes(&keys.kg_words(), Q_BITS);
    let switched: Vec<_> = query.iter().map(|&x| round(x, QUERY_BITS)).collect();
    bytes.extend(u64s_to_contiguous_bytes(&switched, QUERY_BITS));
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

        /// Answers a [`prepare_with`] payload with a [`response_len`] body. The
        /// payload may select over every row or over a whole-block prefix, as
        /// a client omits rows that hold no data.
        pub fn answer(&self, payload: &[u8]) -> Vec<u8> {
            let rows = (D..=self.db[0].len())
                .step_by(D)
                .find(|&rows| request_len(rows) == payload.len())
                .expect("a full or whole-block prefix selection");
            let keys = NativeKeys::from_kg_words(
                &self.setup,
                &contiguous_bytes_to_u64s(&payload[..KEY_BYTES], Q_BITS),
            )
            .unwrap();
            let query: Vec<u64> = contiguous_bytes_to_u64s(&payload[KEY_BYTES..], QUERY_BITS)
                .into_iter()
                .take(rows)
                .map(|x| x << (Q_BITS - QUERY_BITS))
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
}
