//! Experimental native two-mask packing profile (protocol revision
//! `ironwood-enhance-pir-v9-native-two-mask-m29`), ported from wallet-pir's
//! `enhance-pir` crate. Snapshot and request binding come from the versioned
//! `EPQ7` envelope, exactly as for v7; only the PIR payloads differ.
//!
//! The client uploads one `K_g` packing key and a 49-bit selection query per
//! request, and decodes each response block under the two published masks,
//! which are rounded to [`MASK_BITS`]. Query masks are derived from the same
//! per-shard setup seed as v7, so they stay stable across publications.
//!
//! This profile is experimental: ipir-sp's cryptographic gates for the native
//! path remain open, and correctness certificates are snapshot-specific.
use ipir_sp::{
    bits::{contiguous_bytes_to_u64s, u64s_to_contiguous_bytes},
    native::{NativeProfile, NativePublicSetup},
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use reinspiring::native::{
    NativeKeys, NativeParams, NativeSecret, NativeSetup, NativeTwoMaskCiphertext,
    SecretDistribution,
};

pub const Q: u64 = 1 << 54;
pub const Q_BITS: usize = 54;
pub const D: usize = 2048;
pub const COLS: usize = 12288;
pub const MASK_BITS: usize = 29;
pub const QUERY_BITS: usize = 49;
pub const RESPONSE_BITS: usize = 22;
pub const KEY_WORDS: usize = 2 * D;
pub const KEY_BYTES: usize = KEY_WORDS * Q_BITS / 8;
/// Largest shard the native query shape supports.
pub const MAX_ROWS: usize = 32768;

pub fn params() -> NativeParams {
    NativeParams::new(D, 54, 16, 19, 2, SecretDistribution::Gaussian)
        .expect("fixed experimental profile")
}

/// Packing masks shared by every shard; seeded from the crate's public setup seed.
pub fn packing_setup() -> NativeSetup {
    NativeSetup::new(params(), crate::types::setup_seed_bytes())
}

/// First-dimension query masks for `shard`, over the maximal shard shape.
pub fn query_masks(shard: u64) -> Vec<Vec<u64>> {
    public_query_masks(crate::types::setup_seed(shard), MAX_ROWS, COLS)
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

/// Round `x` in `[0, Q)` to `bits` bits, nearest, with wraparound at `2^bits`.
fn round(x: u64, bits: usize) -> u64 {
    (((x as u128 * (1u128 << bits) + (Q / 2) as u128) / Q as u128) as u64) & ((1 << bits) - 1)
}

/// Response body length for `cols` packed columns at [`RESPONSE_BITS`].
pub fn response_len(cols: usize) -> usize {
    (cols * RESPONSE_BITS).div_ceil(8)
}

/// Request payload length for `rows`: one `K_g` key and a [`QUERY_BITS`] selection.
pub fn request_len(rows: usize) -> usize {
    KEY_BYTES + (rows * QUERY_BITS).div_ceil(8)
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

/// Decode an Enhance row, truncated to its logical width.
pub fn decode(secret: &NativeSecret, public: &[u8], body: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = decode_cols(secret, public, body, COLS)?;
    out.truncate(crate::types::ROW_BYTES);
    Ok(out)
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

/// One shard's client-side native state: the packing setup, the shard's
/// expanded query masks, its logical row count and the published two-mask
/// material. Built once per session so each query only samples fresh secrets.
pub struct NativeSession {
    setup: NativeSetup,
    masks: Vec<Vec<u64>>,
    rows: usize,
    public: Vec<u8>,
}

impl NativeSession {
    /// `public` must already match the manifest's digest; only its shape is
    /// checked here.
    pub fn new(shard: u64, rows: usize, public: Vec<u8>) -> Result<Self, String> {
        if rows == 0 || rows > MAX_ROWS || !rows.is_multiple_of(D) {
            return Err("native query shape".into());
        }
        if public.len() != public_len(COLS) {
            return Err("native public material mismatch".into());
        }
        Ok(Self {
            setup: packing_setup(),
            masks: query_masks(shard),
            rows,
            public,
        })
    }
    pub fn rows(&self) -> usize {
        self.rows
    }
    pub fn public(&self) -> &[u8] {
        &self.public
    }
    pub fn prepare(&self, target: usize) -> Result<(NativeSecret, Vec<u8>), String> {
        prepare_with(&self.setup, &self.masks, self.rows, target)
    }
    pub fn decode(&self, secret: &NativeSecret, body: &[u8]) -> Result<Vec<u8>, String> {
        decode(secret, &self.public, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use reinspiring::native::NativePreprocessed;

    // Server-side helpers, mirrored from wallet-pir's `native.rs` so the
    // client can be exercised without the server crate.
    fn publish(blocks: &[NativePreprocessed]) -> Vec<u8> {
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
        u64s_to_contiguous_bytes(&words, MASK_BITS)
    }
    fn parse_with(setup: &NativeSetup, bytes: &[u8], rows: usize) -> (NativeKeys, Vec<u64>) {
        assert!(rows.is_multiple_of(D) && bytes.len() == request_len(rows));
        let keys = NativeKeys::from_kg_words(
            setup,
            &contiguous_bytes_to_u64s(&bytes[..KEY_BYTES], Q_BITS),
        )
        .unwrap();
        let query = contiguous_bytes_to_u64s(&bytes[KEY_BYTES..], QUERY_BITS)
            .into_iter()
            .map(|x| x << (Q_BITS - QUERY_BITS))
            .collect();
        (keys, query)
    }
    fn pack(blocks: &[NativePreprocessed], keys: &NativeKeys, intermediate: &[u64]) -> Vec<u8> {
        assert_eq!(intermediate.len(), blocks.len() * D);
        assert!(intermediate.iter().all(|&x| x < Q));
        let prepared = blocks[0].prepare_keys(keys).unwrap();
        let values: Vec<u64> = blocks
            .iter()
            .zip(intermediate.as_chunks::<D>().0)
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

    /// End-to-end over the library primitives the server uses: two-mask
    /// preprocessing, one-key upload, 29-bit masks and 22-bit responses.
    #[test]
    fn two_mask_rounded_roundtrip() {
        let rows = D;
        let cols = D;
        let mut rng = ChaCha20Rng::from_seed([7; 32]);
        let db: Vec<Vec<u16>> = (0..cols)
            .map(|_| (0..rows).map(|_| rng.r#gen()).collect())
            .collect();
        let masks = public_query_masks([3; 32], rows, cols);
        let lift = reinspiring::lift_ntt::LiftContext::new(D, Q).unwrap();
        let public = lift.prepare_public_dot(&masks, 65535).unwrap();
        let hint: Vec<_> = db
            .iter()
            .map(|col| {
                let poly = vec![col.iter().map(|&x| x as u64).collect::<Vec<_>>()];
                lift.public_dot(&public, &poly).unwrap()
            })
            .collect();
        let setup = NativeSetup::new(params(), [9; 32]);
        let blocks = vec![NativePreprocessed::build_two_mask(&setup, &hint).unwrap()];
        let published = publish(&blocks);
        assert_eq!(published.len(), public_len(cols));
        assert_eq!(public_len(COLS), 89_088);
        assert_eq!(KEY_BYTES, 27_648);
        let target = 1234;
        let (secret, body) = prepare_with(&setup, &masks, rows, target).unwrap();
        assert_eq!(body.len(), request_len(rows));
        let (keys, query) = parse_with(&setup, &body, rows);
        let scan: Vec<u64> = db
            .iter()
            .map(|col| {
                col.iter().zip(&query).fold(0u64, |a, (&x, &q)| {
                    a.wrapping_add((x as u64).wrapping_mul(q))
                }) & (Q - 1)
            })
            .collect();
        let response = pack(&blocks, &keys, &scan);
        let row = decode_cols(&secret, &published, &response, cols).unwrap();
        let expected: Vec<u8> = db.iter().flat_map(|c| c[target].to_le_bytes()).collect();
        assert_eq!(row, expected);
    }

    #[test]
    fn rounding_and_shape_checks() {
        assert_eq!(round(0, QUERY_BITS), 0);
        assert_eq!(round(Q - 1, QUERY_BITS), 0);
        assert_eq!(round(Q / 2, MASK_BITS), 1 << (MASK_BITS - 1));
        assert_eq!(
            request_len(MAX_ROWS),
            KEY_BYTES + (MAX_ROWS * QUERY_BITS).div_ceil(8)
        );
        assert_eq!(response_len(COLS), (COLS * RESPONSE_BITS).div_ceil(8));
        assert!(NativeSession::new(0, MAX_ROWS + D, vec![0; public_len(COLS)]).is_err());
        assert!(NativeSession::new(0, D + 1, vec![0; public_len(COLS)]).is_err());
        assert!(NativeSession::new(0, D, vec![0; public_len(COLS) - 1]).is_err());
        let session = NativeSession::new(0, D, vec![0; public_len(COLS)]).unwrap();
        assert!(session.prepare(D).is_err());
        let (secret, body) = session.prepare(D - 1).unwrap();
        assert_eq!(body.len(), request_len(D));
        assert!(session.decode(&secret, &[0; 1]).is_err());
        assert_eq!(
            session
                .decode(&secret, &vec![0; response_len(COLS)])
                .unwrap(),
            vec![0; crate::types::ROW_BYTES]
        );
    }
}
