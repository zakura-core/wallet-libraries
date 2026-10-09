//! Native two-mask packing profile (protocol revision
//! `ironwood-enhance-pir-v9-native-two-mask-m29`), ported from wallet-pir's
//! `enhance-pir` crate. Snapshot and request binding come from the versioned
//! `EPQ7` envelope, exactly as for v7; only the PIR payloads differ.
//!
//! The protocol-neutral primitives live in `zakura-pir-native` and are
//! re-exported here. This module holds the Enhance-specific shape and seeds:
//! query masks are derived from the same per-shard setup seed as v7, so they
//! stay stable across publications.
//!
//! This profile is experimental: ipir-sp's cryptographic gates for the native
//! path remain open, and correctness certificates are snapshot-specific.
use reinspiring::native::NativeSetup;

pub use reinspiring::native::NativeSecret;
pub use zakura_pir_native::{
    D, DITHERED_QUERY_BITS, KEY_BYTES, KEY_WORDS, MASK_BITS, Q, Q_BITS, QUERY_BITS, RESPONSE_BITS,
    decode_cols, params, prepare_dithered, prepare_with, public_len, public_query_masks,
    request_len, request_len_bits, response_len,
};

pub const COLS: usize = 12288;
/// Largest shard the native query shape supports.
pub const MAX_ROWS: usize = 32768;

/// Packing masks shared by every shard; seeded from the crate's public setup seed.
pub fn packing_setup() -> NativeSetup {
    zakura_pir_native::packing_setup(crate::types::setup_seed_bytes())
}

/// First-dimension query masks for `shard`, over the maximal shard shape.
pub fn query_masks(shard: u64) -> Vec<Vec<u64>> {
    public_query_masks(crate::types::setup_seed(shard), MAX_ROWS, COLS)
}

/// Decode an Enhance row, truncated to its logical width.
pub fn decode(secret: &NativeSecret, public: &[u8], body: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = decode_cols(secret, public, body, COLS)?;
    out.truncate(crate::types::ROW_BYTES);
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
    /// A request selection dithered to [`DITHERED_QUERY_BITS`]; see
    /// [`prepare_dithered`].
    pub fn prepare(&self, target: usize) -> Result<(NativeSecret, Vec<u8>), String> {
        prepare_dithered(&self.setup, &self.masks, self.rows, target)
    }
    pub fn decode(&self, secret: &NativeSecret, body: &[u8]) -> Result<Vec<u8>, String> {
        decode(secret, &self.public, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enhance_shape_checks() {
        assert_eq!(public_len(COLS), 89_088);
        assert_eq!(KEY_BYTES, 27_648);
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
        assert_eq!(body.len(), request_len_bits(D, DITHERED_QUERY_BITS));
        assert!(session.decode(&secret, &[0; 1]).is_err());
        assert_eq!(
            session
                .decode(&secret, &vec![0; response_len(COLS)])
                .unwrap(),
            vec![0; crate::types::ROW_BYTES]
        );
    }
}
