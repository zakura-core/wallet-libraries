//! The native ReinspiRING two-mask m29 PIR profile Enhance, Status and
//! Transparent deploy: `d` = 2,048, `q` = 2^54, `p` = 2^16, two-limb Gaussian
//! `K_g` key packing with 19-bit limbs, and two public masks rounded to 29 bits.
//!
//! These are the helpers every product computes identically: parameters,
//! query masks, the public hint, two-mask preprocessing, published mask bytes,
//! request framing, packing and decoding. What differs between products — the
//! seeds for the query masks and packing setup, and how a database maps onto
//! rows and columns — stays with each product and is passed in.
//!
//! Per query the client uploads one `K_g` packing key (27,648 bytes) and a
//! selection vector, over every row or only over the leading rows that can hold
//! data (see below). Per 2,048-coefficient block the server publishes both
//! masks (14,848 bytes) and answers with a 22-bit body (5,632 bytes).
//! Correctness certificates for this mode are snapshot-specific.
//!
//! The selection is uploaded at one of two widths, and the server tells them
//! apart by the upload's exact length alone:
//!
//! - **49 bits, rounded to nearest** (`rows * 49 / 8` bytes): the original
//!   query, [`prepare_with`] and [`parse_with`]. Every client deployed before
//!   dithering sends it, and every server keeps accepting it unchanged.
//! - **44 bits, dithered** (`rows * 44 / 8` bytes): [`prepare_dithered`]
//!   rounds each coefficient up with probability equal to the fraction it
//!   drops, using fresh coins, so the rounding errors are independent and zero
//!   mean. The certificate then budgets them as a variance term rather than a
//!   worst case, which is what lets the narrower width certify at least as
//!   strongly as 49 nearest. The server's parse depends only on the width
//!   ([`parse_bits`], [`parse_accepted`]), not on how the client rounded.
//!
//! The selection covers every row of the table or, when the product's public
//! geometry says every later row is zero, only its first `query_rows` whole
//! blocks: those omitted coefficients multiply zero rows, so the scan and the
//! response are bit-identical. [`parse_selection`] takes either row count at
//! either width, again by exact length alone.
//!
//! `tests/golden.rs` pins the bytes. Its digests were produced by the Enhance
//! and Transparent copies this crate replaced, which agreed byte for byte.
//!
//! The free functions and constants are that profile, [`P16`]. [`Profile`]
//! carries the same helpers for another parameter set: [`P8`] is the 8-bit
//! profile Transparent's history tables serve, with one byte per coefficient,
//! a one-digit `K_g` key of half the size, masks rounded to 22 bits, 28-bit
//! dithered selections only and 10-bit responses.

use ipir_sp::bits::{contiguous_bytes_to_u64s, u64s_to_contiguous_bytes};
use ipir_sp::native::{NativeProfile, NativePublicSetup};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use reinspiring::native::{NativeParams, NativeTwoMaskCiphertext, SecretDistribution};
use std::borrow::Borrow;

pub use reinspiring::native::{NativeKeys, NativePreprocessed, NativeSecret, NativeSetup};

/// Ciphertext modulus.
pub const Q: u64 = 1 << 54;
pub const Q_BITS: usize = 54;
/// Ring degree, which is also the row and column quantum.
pub const D: usize = 2048;
/// Plaintext bits per coefficient.
pub const P_BITS: usize = 16;
/// Gadget limb width and count of the packing key.
pub const GADGET_BITS: usize = 19;
pub const ELL: usize = 2;
/// Bits each published mask coefficient is rounded to.
pub const MASK_BITS: usize = 29;
/// Bits each selection coefficient is uploaded at, rounded to nearest: the
/// original query, which every server keeps accepting.
pub const QUERY_BITS: usize = 49;
/// Bits each selection coefficient is uploaded at under dithered rounding.
pub const DITHERED_QUERY_BITS: usize = 44;
/// Bits each response body coefficient is returned at.
pub const RESPONSE_BITS: usize = 22;
/// Uploaded `K_g` packing key.
pub const KEY_BYTES: usize = ELL * D * Q_BITS / 8;
/// Plaintext bytes one block carries: one row width quantum.
pub const INSTANCE_BYTES: usize = D * P_BITS / 8;
/// Published bytes per block: both masks at `MASK_BITS`.
pub const BLOCK_PUBLIC_BYTES: usize = 2 * D * MASK_BITS / 8;
/// Response body bytes per block at `RESPONSE_BITS`.
pub const BLOCK_RESPONSE_BYTES: usize = D * RESPONSE_BITS / 8;

const _: () = assert!(KEY_BYTES == 27_648);
const _: () = assert!(INSTANCE_BYTES == 4_096);
const _: () = assert!(BLOCK_PUBLIC_BYTES == 14_848);
const _: () = assert!(BLOCK_RESPONSE_BYTES == 5_632);

/// One native parameter set and the widths it is served at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    /// Plaintext bits per coefficient: 16 or 8.
    pub p_bits: usize,
    /// Gadget limb width and count of the `K_g` packing key.
    pub gadget_bits: usize,
    pub ell: usize,
    /// Bits each published mask coefficient is rounded to.
    pub mask_bits: usize,
    /// The selection width rounded to nearest, if the profile accepts one.
    pub nearest_bits: Option<usize>,
    /// The selection width under dithered rounding.
    pub dithered_bits: usize,
    /// Bits each response body coefficient is returned at.
    pub response_bits: usize,
}

/// The profile Enhance, Status, Receiver and Transparent's txid tables serve:
/// every free function and constant of this crate.
pub const P16: Profile = Profile {
    p_bits: P_BITS,
    gadget_bits: GADGET_BITS,
    ell: ELL,
    mask_bits: MASK_BITS,
    nearest_bits: Some(QUERY_BITS),
    dithered_bits: DITHERED_QUERY_BITS,
    response_bits: RESPONSE_BITS,
};

/// The 8-bit profile: one byte per coefficient, one 27-bit `K_g` digit,
/// 22-bit masks, 28-bit dithered selections and 10-bit responses. These are
/// the floors ipir-sp rc.7 certified for two-mask output at p = 2^8; each
/// served snapshot still needs its own certificate.
pub const P8: Profile = Profile {
    p_bits: 8,
    gadget_bits: 27,
    ell: 1,
    mask_bits: 22,
    nearest_bits: None,
    dithered_bits: 28,
    response_bits: 10,
};

const _: () = assert!(P8.key_bytes() == 13_824);
const _: () = assert!(P8.instance_bytes() == 2_048);
const _: () = assert!(P8.block_public_bytes() == 11_264);
const _: () = assert!(P8.block_response_bytes() == 2_560);

impl Profile {
    /// The packing parameters.
    pub fn params(&self) -> NativeParams {
        NativeParams::new(
            D,
            Q_BITS as u32,
            self.p_bits as u32,
            self.gadget_bits as u32,
            self.ell,
            SecretDistribution::Gaussian,
        )
        .expect("fixed native profile")
    }

    /// Domain-separated first-dimension masks for a `rows` by `cols`
    /// database; see the free [`public_query_masks`]. The parameters enter the
    /// derivation, so each profile's masks differ for the same seed.
    pub fn public_query_masks(
        &self,
        seed: [u8; 32],
        rows: usize,
        cols: usize,
    ) -> Result<Vec<Vec<u64>>, String> {
        let profile = NativeProfile::new(self.params(), rows, cols).map_err(|e| e.to_string())?;
        Ok(NativePublicSetup::new(profile, seed, [0; 32])
            .query_masks()
            .to_vec())
    }

    /// Uploaded `K_g` packing key.
    pub const fn key_bytes(&self) -> usize {
        self.ell * D * Q_BITS / 8
    }

    /// Plaintext bytes one block carries: one row width quantum.
    pub const fn instance_bytes(&self) -> usize {
        D * self.p_bits / 8
    }

    /// Plaintext bytes each coefficient carries.
    pub const fn entry_bytes(&self) -> usize {
        self.p_bits / 8
    }

    /// Published bytes per block: both masks.
    pub const fn block_public_bytes(&self) -> usize {
        2 * D * self.mask_bits / 8
    }

    /// Response body bytes per block.
    pub const fn block_response_bytes(&self) -> usize {
        D * self.response_bits / 8
    }

    /// Canonical published bytes for `cols` coefficients of two-mask blocks.
    pub const fn public_len(&self, cols: usize) -> usize {
        (2 * cols * self.mask_bits).div_ceil(8)
    }

    /// Response body bytes for `cols` coefficients.
    pub const fn response_len(&self, cols: usize) -> usize {
        (cols * self.response_bits).div_ceil(8)
    }

    /// Upload bytes for a `rows`-row table whose selection is sent at `bits`.
    pub const fn request_len_bits(&self, rows: usize, bits: usize) -> usize {
        self.key_bytes() + (rows * bits).div_ceil(8)
    }

    /// The width of the profile's own query: nearest where it has one, else
    /// dithered.
    pub const fn primary_bits(&self) -> usize {
        match self.nearest_bits {
            Some(bits) => bits,
            None => self.dithered_bits,
        }
    }

    /// The selection width of an upload of `len` bytes to a `rows`-row table,
    /// or `None` for any other length.
    pub const fn accepted_query_bits(&self, rows: usize, len: usize) -> Option<usize> {
        if let Some(bits) = self.nearest_bits {
            if len == self.request_len_bits(rows, bits) {
                return Some(bits);
            }
        }
        if len == self.request_len_bits(rows, self.dithered_bits) {
            Some(self.dithered_bits)
        } else {
            None
        }
    }

    /// The rows and width an upload of `len` bytes selects over; see the free
    /// [`accepted_query_shape`].
    pub const fn accepted_query_shape(
        &self,
        rows: usize,
        query_rows: usize,
        len: usize,
    ) -> Option<(usize, usize)> {
        if let Some(bits) = self.accepted_query_bits(rows, len) {
            return Some((rows, bits));
        }
        if query_rows == 0 || query_rows > rows || !query_rows.is_multiple_of(D) {
            return None;
        }
        match self.accepted_query_bits(query_rows, len) {
            Some(bits) => Some((query_rows, bits)),
            None => None,
        }
    }

    /// Canonical published bytes for two-mask blocks: every first mask, then
    /// every second mask, each coefficient rounded to `mask_bits`.
    pub fn publish<B: Borrow<NativePreprocessed>>(&self, blocks: &[B]) -> Result<Vec<u8>, String> {
        let others = blocks
            .iter()
            .map(|b| {
                b.borrow()
                    .other_mask()
                    .ok_or("one-mask native preprocessing")
            })
            .collect::<Result<Vec<_>, _>>()?;
        let words: Vec<_> = blocks
            .iter()
            .flat_map(|b| b.borrow().mask().iter())
            .chain(others.into_iter().flatten())
            .map(|&x| round(x, self.mask_bits))
            .collect();
        Ok(u64s_to_contiguous_bytes(&words, self.mask_bits))
    }

    /// Fresh secret, one-key packing upload and the profile's own selection
    /// ([`Self::primary_bits`]): 49 bits to nearest for [`P16`], 28 dithered
    /// bits for [`P8`].
    pub fn prepare(
        &self,
        setup: &NativeSetup,
        masks: &[Vec<u64>],
        rows: usize,
        target: usize,
    ) -> Result<(NativeSecret, Vec<u8>), String> {
        let mut entropy = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut entropy);
        let rng = &mut ChaCha20Rng::from_seed(entropy);
        let (bits, dithered) = match self.nearest_bits {
            Some(bits) => (bits, false),
            None => (self.dithered_bits, true),
        };
        self.prepare_rounded(setup, masks, rows, target, (bits, dithered), rng)
    }

    /// Fresh secret, one-key packing upload and dithered selection.
    pub fn prepare_dithered(
        &self,
        setup: &NativeSetup,
        masks: &[Vec<u64>],
        rows: usize,
        target: usize,
    ) -> Result<(NativeSecret, Vec<u8>), String> {
        let mut entropy = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut entropy);
        self.prepare_dithered_with(
            setup,
            masks,
            rows,
            target,
            &mut ChaCha20Rng::from_seed(entropy),
        )
    }

    /// Fresh secret, one-key packing upload and dithered selection over a
    /// caller's generator; see the free [`prepare_dithered_with`].
    pub fn prepare_dithered_with(
        &self,
        setup: &NativeSetup,
        masks: &[Vec<u64>],
        rows: usize,
        target: usize,
        rng: &mut ChaCha20Rng,
    ) -> Result<(NativeSecret, Vec<u8>), String> {
        self.prepare_rounded(setup, masks, rows, target, (self.dithered_bits, true), rng)
    }

    /// Draws the secret, the packing key, the selection's errors and, when
    /// dithered, one rounding coin per row, in that order.
    pub(super) fn prepare_rounded(
        &self,
        setup: &NativeSetup,
        masks: &[Vec<u64>],
        rows: usize,
        target: usize,
        (bits, dithered): (usize, bool),
        rng: &mut ChaCha20Rng,
    ) -> Result<(NativeSecret, Vec<u8>), String> {
        if target >= rows || !rows.is_multiple_of(D) || masks.len() < rows / D {
            return Err("native query shape".into());
        }
        let secret = NativeSecret::sample(&self.params(), rng);
        let keys = NativeKeys::generate_one_key(setup, &secret, rng).map_err(|e| e.to_string())?;
        let query = secret
            .encrypt_selection(&masks[..rows / D], target, rng)
            .map_err(|e| e.to_string())?;
        let mut bytes = u64s_to_contiguous_bytes(&keys.kg_words(), Q_BITS);
        let switched: Vec<_> = if dithered {
            query
                .iter()
                .map(|&x| round_dithered(x, bits, rng.next_u64()))
                .collect()
        } else {
            query.iter().map(|&x| round(x, bits)).collect()
        };
        bytes.extend(u64s_to_contiguous_bytes(&switched, bits));
        Ok((secret, bytes))
    }

    /// Parses an upload whose selection was sent at `bits`, one of the
    /// profile's widths, into its packing key and the selection lifted back
    /// to `q`.
    ///
    /// The lift is the same for either rounding rule: a coefficient sent at
    /// `bits` stands for itself times `2^(Q_BITS - bits)`.
    pub fn parse_bits(
        &self,
        setup: &NativeSetup,
        bytes: &[u8],
        rows: usize,
        bits: usize,
    ) -> Result<(NativeKeys, Vec<u64>), String> {
        if !(Some(bits) == self.nearest_bits || bits == self.dithered_bits)
            || rows == 0
            || !rows.is_multiple_of(D)
            || bytes.len() != self.request_len_bits(rows, bits)
        {
            return Err("native query framing".into());
        }
        let key_bytes = self.key_bytes();
        let keys = NativeKeys::from_kg_words(
            setup,
            &contiguous_bytes_to_u64s(&bytes[..key_bytes], Q_BITS),
        )
        .map_err(|e| e.to_string())?;
        let mut query: Vec<u64> = contiguous_bytes_to_u64s(&bytes[key_bytes..], bits)
            .into_iter()
            .map(|x| x << (Q_BITS - bits))
            .collect();
        // The packing leaves up to seven padding bits, which decode as one
        // extra coefficient when they fill a whole word. They are never part
        // of the query.
        query.truncate(rows);
        if query.len() != rows {
            return Err("native query framing".into());
        }
        Ok((keys, query))
    }

    /// Parses an upload at whichever width its exact length names.
    pub fn parse_accepted(
        &self,
        setup: &NativeSetup,
        bytes: &[u8],
        rows: usize,
    ) -> Result<(NativeKeys, Vec<u64>), String> {
        let bits = self
            .accepted_query_bits(rows, bytes.len())
            .ok_or("native query framing")?;
        self.parse_bits(setup, bytes, rows, bits)
    }

    /// Parses a full or prefix upload and returns the selection over every
    /// row; see the free [`parse_selection`].
    pub fn parse_selection(
        &self,
        setup: &NativeSetup,
        bytes: &[u8],
        query_rows: usize,
        rows: usize,
    ) -> Result<(NativeKeys, Vec<u64>), String> {
        if rows == 0 || !rows.is_multiple_of(D) {
            return Err("native query framing".into());
        }
        let (sent, bits) = self
            .accepted_query_shape(rows, query_rows, bytes.len())
            .ok_or("native query framing")?;
        let (keys, mut query) = self.parse_bits(setup, bytes, sent, bits)?;
        query.resize(rows, 0);
        Ok((keys, query))
    }

    /// Decodes every plaintext coefficient of a two-mask response, each as
    /// `entry_bytes` little-endian bytes.
    pub fn decode_cols(
        &self,
        secret: &NativeSecret,
        public: &[u8],
        body: &[u8],
        cols: usize,
    ) -> Result<Vec<u8>, String> {
        if cols == 0
            || !cols.is_multiple_of(D)
            || public.len() != self.public_len(cols)
            || body.len() != self.response_len(cols)
        {
            return Err("native response shape".into());
        }
        let masks: Vec<_> = contiguous_bytes_to_u64s(public, self.mask_bits)
            .into_iter()
            .map(|x| x << (Q_BITS - self.mask_bits))
            .collect();
        let (a, a_other) = masks[..2 * cols].split_at(cols);
        let b: Vec<_> = contiguous_bytes_to_u64s(body, self.response_bits)
            .into_iter()
            .map(|x| x << (Q_BITS - self.response_bits))
            .collect();
        let params = self.params();
        let entry = self.entry_bytes();
        let mut out = Vec::with_capacity(cols * entry);
        for ((a, a_other), b) in a
            .chunks_exact(D)
            .zip(a_other.chunks_exact(D))
            .zip(b[..cols].chunks_exact(D))
        {
            let ct = NativeTwoMaskCiphertext::from_rows(
                &params,
                a.to_vec(),
                a_other.to_vec(),
                b.to_vec(),
            )
            .map_err(|e| e.to_string())?;
            for x in secret.decrypt_two_mask(&ct).map_err(|e| e.to_string())? {
                out.extend(&(x as u16).to_le_bytes()[..entry]);
            }
        }
        Ok(out)
    }

    /// Prepares one uploaded key for every block, then finishes each block
    /// with its scan result. Returns the switched response bodies.
    pub fn pack<B: Borrow<NativePreprocessed> + Sync>(
        &self,
        blocks: &[B],
        keys: &NativeKeys,
        intermediate: &[u64],
    ) -> Result<Vec<u8>, String> {
        if blocks.is_empty()
            || intermediate.len() != blocks.len() * D
            || intermediate.iter().any(|&x| x >= Q)
        {
            return Err("native intermediate shape".into());
        }
        let prepared = blocks[0]
            .borrow()
            .prepare_keys(keys)
            .map_err(|e| e.to_string())?;
        let packed = blocks
            .par_iter()
            .zip(intermediate.par_chunks_exact(D))
            .map(|(p, b)| p.borrow().prepare_pack(&prepared)?.finish_two_mask(b))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        let values = packed
            .iter()
            .flat_map(|ct| ct.rows().2.iter().copied())
            .collect::<Vec<_>>();
        Ok(self.response(&values))
    }

    /// Rounds response bodies to `response_bits` and bit-packs them.
    pub fn response(&self, bodies: &[u64]) -> Vec<u8> {
        let switched: Vec<_> = bodies
            .iter()
            .map(|&x| round(x, self.response_bits))
            .collect();
        u64s_to_contiguous_bytes(&switched, self.response_bits)
    }

    /// Upper bound on one block's `reinspiring::prepared_native` encoding:
    /// block id, both masks, a width word and the compiled matrix at
    /// eight-byte words.
    pub const fn prepared_block_max_bytes(&self) -> u64 {
        (32 + 2 * D * 8 + 8 + D * D * self.ell * 8) as u64
    }

    /// Lower bound, at the four-byte words the encoding uses whenever every
    /// entry fits an `i32`. That depends on the table's data, for either key.
    pub const fn prepared_block_min_bytes(&self) -> u64 {
        (32 + 2 * D * 8 + 8 + D * D * self.ell * 4) as u64
    }

    /// What one block plans to hold. A two-digit key's entries fit four-byte
    /// words; a one-digit key's need about 35 bits on a table with data, so
    /// it plans at eight-byte words, and only a nearly empty table's matrix
    /// may come out narrower.
    pub const fn prepared_block_planned_bytes(&self) -> u64 {
        if self.ell == 1 {
            self.prepared_block_max_bytes()
        } else {
            self.prepared_block_min_bytes()
        }
    }
}

/// The fixed packing parameters.
pub fn params() -> NativeParams {
    NativeParams::new(
        D,
        Q_BITS as u32,
        P_BITS as u32,
        GADGET_BITS as u32,
        ELL,
        SecretDistribution::Gaussian,
    )
    .expect("fixed native profile")
}

/// Domain-separated first-dimension masks for a `rows` by `cols` database.
///
/// Uses a zero snapshot id so the masks, and therefore every published hint
/// contribution, stay stable across publications of the same shape.
pub fn public_query_masks(
    seed: [u8; 32],
    rows: usize,
    cols: usize,
) -> Result<Vec<Vec<u64>>, String> {
    P16.public_query_masks(seed, rows, cols)
}

/// Canonical published bytes for `cols` coefficients of two-mask blocks.
pub const fn public_len(cols: usize) -> usize {
    P16.public_len(cols)
}

/// Response body bytes for `cols` coefficients.
pub const fn response_len(cols: usize) -> usize {
    P16.response_len(cols)
}

/// Upload bytes for a `rows`-row table: `K_g` then the selection.
pub const fn request_len(rows: usize) -> usize {
    KEY_BYTES + (rows * QUERY_BITS).div_ceil(8)
}

/// Upload bytes for a `rows`-row table whose selection is sent at `bits`.
pub const fn request_len_bits(rows: usize, bits: usize) -> usize {
    P16.request_len_bits(rows, bits)
}

/// The selection width of an upload of `len` bytes to a `rows`-row table:
/// [`QUERY_BITS`] or [`DITHERED_QUERY_BITS`], or `None` for any other length.
///
/// The two lengths differ by `rows * 5 / 8` bytes, so for any table of whole
/// `D`-row blocks exactly one width matches.
pub const fn accepted_query_bits(rows: usize, len: usize) -> Option<usize> {
    P16.accepted_query_bits(rows, len)
}

fn round(x: u64, bits: usize) -> u64 {
    (((x as u128 * (1u128 << bits) + (Q / 2) as u128) / Q as u128) as u64) & ((1 << bits) - 1)
}

/// Unbiased randomized rounding of `x < Q` to `bits`: up with probability
/// exactly `dropped / 2^(Q_BITS - bits)`, by comparing the dropped bits with
/// the low bits of a fresh uniform `coin`. Branch-free in the value. The same
/// rule as ipir-sp's `down_dithered`.
fn round_dithered(x: u64, bits: usize, coin: u64) -> u64 {
    let shift = Q_BITS - bits;
    let low = (1u64 << shift) - 1;
    let up = u64::from((coin & low) < (x & low));
    ((x >> shift) + up) & ((1 << bits) - 1)
}

/// Canonical published bytes for two-mask blocks: every first mask, then every
/// second mask, each coefficient rounded to `MASK_BITS`.
pub fn publish<B: Borrow<NativePreprocessed>>(blocks: &[B]) -> Result<Vec<u8>, String> {
    P16.publish(blocks)
}

/// Fresh secret, one-key packing upload and 49-bit selection query.
pub fn prepare_with(
    setup: &NativeSetup,
    masks: &[Vec<u64>],
    rows: usize,
    target: usize,
) -> Result<(NativeSecret, Vec<u8>), String> {
    P16.prepare(setup, masks, rows, target)
}

/// Fresh secret, one-key packing upload and 44-bit dithered selection query.
pub fn prepare_dithered(
    setup: &NativeSetup,
    masks: &[Vec<u64>],
    rows: usize,
    target: usize,
) -> Result<(NativeSecret, Vec<u8>), String> {
    let mut entropy = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut entropy);
    prepare_dithered_with(
        setup,
        masks,
        rows,
        target,
        &mut ChaCha20Rng::from_seed(entropy),
    )
}

/// [`prepare_dithered`] over a caller's generator, which must be freshly and
/// secretly seeded for every query: it draws the secret, the packing key, the
/// selection's errors and then one rounding coin per row, in that order.
///
/// The coins are what makes the rounding errors independent and zero mean.
/// Coins an observer could predict would let it bias the errors, and coins
/// reused across queries would correlate them, so they come from the same
/// per-query generator as the secret.
pub fn prepare_dithered_with(
    setup: &NativeSetup,
    masks: &[Vec<u64>],
    rows: usize,
    target: usize,
    rng: &mut ChaCha20Rng,
) -> Result<(NativeSecret, Vec<u8>), String> {
    P16.prepare_dithered_with(setup, masks, rows, target, rng)
}

/// Parses a 49-bit upload into its packing key and the selection lifted back
/// to `q`.
pub fn parse_with(
    setup: &NativeSetup,
    bytes: &[u8],
    rows: usize,
) -> Result<(NativeKeys, Vec<u64>), String> {
    parse_bits(setup, bytes, rows, QUERY_BITS)
}

/// Parses an upload at whichever accepted width its exact length names; see
/// [`accepted_query_bits`]. Any other length is refused.
pub fn parse_accepted(
    setup: &NativeSetup,
    bytes: &[u8],
    rows: usize,
) -> Result<(NativeKeys, Vec<u64>), String> {
    P16.parse_accepted(setup, bytes, rows)
}

/// Parses an upload whose selection was sent at `bits`, which must be
/// [`QUERY_BITS`] or [`DITHERED_QUERY_BITS`], into its packing key and the
/// selection lifted back to `q`.
///
/// The lift is the same for either rounding rule: a coefficient sent at
/// `bits` stands for itself times `2^(Q_BITS - bits)`.
pub fn parse_bits(
    setup: &NativeSetup,
    bytes: &[u8],
    rows: usize,
    bits: usize,
) -> Result<(NativeKeys, Vec<u64>), String> {
    P16.parse_bits(setup, bytes, rows, bits)
}

/// The rows and width an upload of `len` bytes selects over, for a `rows`-row
/// table whose public geometry lets queries omit every row from `query_rows`
/// on: every row or only the first `query_rows`, at either accepted width.
/// `None` for any other length.
///
/// Every row is tried first. The four lengths are distinct whenever
/// `query_rows < rows` for tables of whole `D`-row blocks up to 65,536 rows,
/// which `tests/golden.rs` checks.
pub const fn accepted_query_shape(
    rows: usize,
    query_rows: usize,
    len: usize,
) -> Option<(usize, usize)> {
    P16.accepted_query_shape(rows, query_rows, len)
}

/// Parses an upload over every one of `rows`, or over only the first
/// `query_rows`, at either accepted width ([`accepted_query_shape`]), and
/// returns the selection over every row, zero past what was sent.
///
/// A client may send the shorter upload when every row from `query_rows` on is
/// zero: those selection coefficients multiply zero rows, so the scan, and
/// therefore the response, is bit-identical to the full upload's. Encrypted
/// under a prefix of the full-shape masks and rounded to nearest, the shorter
/// upload is byte for byte the full one's prefix. `query_rows` must come from public,
/// session-bound geometry that every client of the table shares, never from
/// the target.
pub fn parse_selection(
    setup: &NativeSetup,
    bytes: &[u8],
    query_rows: usize,
    rows: usize,
) -> Result<(NativeKeys, Vec<u64>), String> {
    P16.parse_selection(setup, bytes, query_rows, rows)
}

/// Decodes every little-endian u16 plaintext coefficient of a two-mask response.
pub fn decode_cols(
    secret: &NativeSecret,
    public: &[u8],
    body: &[u8],
    cols: usize,
) -> Result<Vec<u8>, String> {
    P16.decode_cols(secret, public, body, cols)
}

/// Prepares one uploaded key for every block, then finishes each block with
/// its scan result. Returns the switched response bodies.
pub fn pack<B: Borrow<NativePreprocessed> + Sync>(
    blocks: &[B],
    keys: &NativeKeys,
    intermediate: &[u64],
) -> Result<Vec<u8>, String> {
    P16.pack(blocks, keys, intermediate)
}

/// Rounds response bodies to `RESPONSE_BITS` and bit-packs them.
pub fn response(bodies: &[u64]) -> Vec<u8> {
    P16.response(bodies)
}

/// A stored plaintext coefficient: u16 under [`P16`], u8 under [`P8`].
pub trait Entry: Copy + Into<u64> + Send + Sync {
    /// The largest value, which bounds the hint's lifted products.
    const MAX: u64;
}

impl Entry for u16 {
    const MAX: u64 = u16::MAX as u64;
}

impl Entry for u8 {
    const MAX: u64 = u8::MAX as u64;
}

/// The public hint `H = A * D` for one segment, one block of `D` rows per
/// packing block, using exact lifted native-ring products.
///
/// `column(c)` is column `c` of the database: `rows` plaintext coefficients,
/// u16 under [`P16`] and u8 under [`P8`].
pub fn hint<'a, T: Entry + 'a>(
    masks: &[Vec<u64>],
    rows: usize,
    cols: usize,
    column: impl Fn(usize) -> &'a [T] + Sync,
) -> Result<Vec<Vec<Vec<u64>>>, String> {
    if rows == 0 || !rows.is_multiple_of(D) || !cols.is_multiple_of(D) || masks.len() != rows / D {
        return Err("native hint shape".into());
    }
    let lift = reinspiring::lift_ntt::LiftContext::new(D, Q).map_err(|e| e.to_string())?;
    let public = lift
        .prepare_public_dot(masks, T::MAX)
        .map_err(|e| e.to_string())?;
    (0..cols)
        .step_by(D)
        .map(|start| {
            (start..start + D)
                .into_par_iter()
                .map(|col| {
                    let data = column(col);
                    if data.len() != rows {
                        return Err("native hint column length".to_string());
                    }
                    let polys = data
                        .chunks_exact(D)
                        .map(|p| p.iter().map(|&x| x.into()).collect::<Vec<_>>())
                        .collect::<Vec<_>>();
                    lift.public_dot(&public, &polys).map_err(|e| e.to_string())
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .collect()
}

/// Two-mask preprocessing for every block of a hint.
pub fn preprocess(
    setup: &NativeSetup,
    hint: &[Vec<Vec<u64>>],
) -> Result<Vec<NativePreprocessed>, String> {
    hint.par_iter()
        .map(|block| NativePreprocessed::build_two_mask(setup, block))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}

/// Upper bound on one block's `reinspiring::prepared_native` encoding: block id,
/// both masks, a width word and the compiled matrix at eight-byte words.
pub const PREPARED_BLOCK_MAX_BYTES: u64 = P16.prepared_block_max_bytes();
/// Lower bound, at the four-byte words used when every entry fits an `i32`.
pub const PREPARED_BLOCK_MIN_BYTES: u64 = P16.prepared_block_min_bytes();
/// The encoding's magic and block count.
pub const PREPARED_HEADER_BYTES: u64 = 16;

#[cfg(test)]
mod tests {
    use super::*;

    /// Dithered rounding moves only to the floor or the ceiling, never moves an
    /// exact multiple, and rounds up as often as the dropped fraction says:
    /// the errors have zero mean. Six binomial standard deviations at p = 1/2.
    #[test]
    fn dithered_rounding_is_an_unbiased_floor_or_ceiling() {
        let mut rng = ChaCha20Rng::from_seed([21; 32]);
        for bits in [DITHERED_QUERY_BITS, QUERY_BITS] {
            let shift = Q_BITS - bits;
            let unit = 1u64 << shift;
            let mask = (1u64 << bits) - 1;
            for x in [0, unit, Q - unit] {
                for _ in 0..64 {
                    assert_eq!(round_dithered(x, bits, rng.next_u64()), x >> shift);
                }
            }
            for x in [
                1,
                unit / 4,
                unit / 2,
                unit - 1,
                Q - 1,
                Q - unit / 3,
                0x2a5f_0123_4567,
            ] {
                let trials = 1u32 << 16;
                let floor = x >> shift;
                let ups = (0..trials)
                    .filter(|_| {
                        let y = round_dithered(x, bits, rng.next_u64());
                        // The ceiling of the top coefficient wraps to zero, mod q.
                        assert!(y == floor || y == (floor + 1) & mask, "bits={bits} x={x}");
                        y != floor
                    })
                    .count() as f64;
                let expected = trials as f64 * (x & (unit - 1)) as f64 / unit as f64;
                let sd = (trials as f64 / 4.0).sqrt();
                assert!(
                    (ups - expected).abs() <= 6.0 * sd,
                    "bits={bits} x={x}: {ups} round-ups, expected {expected}"
                );
            }
        }
    }

    /// Exactly one width matches any length, and the 49-bit length is the
    /// legacy `request_len`.
    #[test]
    fn each_accepted_length_names_one_width() {
        for rows in [D, 2 * D, 4 * D, 16 * D, 32 * D] {
            let legacy = request_len(rows);
            let dithered = request_len_bits(rows, DITHERED_QUERY_BITS);
            assert_eq!(legacy, request_len_bits(rows, QUERY_BITS));
            assert_eq!(accepted_query_bits(rows, legacy), Some(QUERY_BITS));
            assert_eq!(
                accepted_query_bits(rows, dithered),
                Some(DITHERED_QUERY_BITS)
            );
            assert_eq!(legacy - dithered, rows * 5 / 8);
            for len in [
                dithered - 1,
                dithered + 1,
                legacy - 1,
                legacy + 1,
                KEY_BYTES,
                0,
            ] {
                assert_eq!(
                    accepted_query_bits(rows, len),
                    None,
                    "{rows} rows, {len} bytes"
                );
            }
        }
    }
}
