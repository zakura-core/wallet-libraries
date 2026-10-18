//! Fixed native profiles, shared setup derivation and byte lengths.
use ipir_native_client::{NativeProfile, NativePublicSetup};
pub use reinspiring::native::NativeSetup;
use reinspiring::native::{NativeParams, SecretDistribution};
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
/// Words of the uploaded `K_g` packing key.
pub const KEY_WORDS: usize = ELL * D;
/// Uploaded `K_g` packing key.
pub const KEY_BYTES: usize = KEY_WORDS * Q_BITS / 8;
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
        if let Some(bits) = self.nearest_bits
            && len == self.request_len_bits(rows, bits)
        {
            return Some(bits);
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

/// Packing key-switching setup derived from a protocol's packing seed.
pub fn packing_setup(seed: [u8; 32]) -> NativeSetup {
    NativeSetup::new(params(), seed)
}

/// Domain-separated first-dimension masks for a `rows` by `cols` database.
///
/// Uses a zero snapshot id so the masks, and therefore every published hint
/// contribution, stay stable across publications of the same shape. Panics on
/// a shape the profile refuses; [`Profile::public_query_masks`] on [`P16`]
/// returns the refusal instead.
pub fn public_query_masks(seed: [u8; 32], rows: usize, cols: usize) -> Vec<Vec<u64>> {
    P16.public_query_masks(seed, rows, cols)
        .expect("fixed experimental profile")
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

pub fn round(x: u64, bits: usize) -> u64 {
    (((x as u128 * (1u128 << bits) + (Q / 2) as u128) / Q as u128) as u64) & ((1 << bits) - 1)
}

/// Unbiased randomized rounding of `x < Q` to `bits`: up with probability
/// exactly `dropped / 2^(Q_BITS - bits)`, by comparing the dropped bits with
/// the low bits of a fresh uniform `coin`. Branch-free in the value. The same
/// rule as ipir-sp's `down_dithered`.
pub fn round_dithered(x: u64, bits: usize, coin: u64) -> u64 {
    let shift = Q_BITS - bits;
    let low = (1u64 << shift) - 1;
    let up = u64::from((coin & low) < (x & low));
    ((x >> shift) + up) & ((1 << bits) - 1)
}

/// Upper bound on one block's `reinspiring::prepared_native` encoding: block id,
/// both masks, a width word and the compiled matrix at eight-byte words.
pub const PREPARED_BLOCK_MAX_BYTES: u64 = P16.prepared_block_max_bytes();
/// Lower bound, at the four-byte words used when every entry fits an `i32`.
pub const PREPARED_BLOCK_MIN_BYTES: u64 = P16.prepared_block_min_bytes();
/// The encoding's magic and block count.
pub const PREPARED_HEADER_BYTES: u64 = 16;
