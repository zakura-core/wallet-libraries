//! Which of a script's two candidate directory rows holds it.
//!
//! Two-choice placement leaves a script in one of two rows, and without more
//! information a wallet must query both, because querying one and stopping on a
//! hit makes the query count a function of where the script landed. A
//! [`ChoiceTable`] publishes that one bit per placed script as a static function,
//! so the wallet evaluates it locally and sends exactly one directory query per
//! matched script, whatever the script.
//!
//! The structure is an xor retrieval table: three positions per key, drawn from
//! three equal segments of a bit array, whose xor is the key's bit. It stores
//! about 1.23 bits per key and nothing else: no key, no fingerprint, no row. It
//! is not a membership test. A script that was never placed evaluates to an
//! arbitrary bit, and the exact script comparison against the returned row is
//! what settles absence, as it does for the two-query lookup.
//!
//! The table is a deterministic function of the shard id and the set of
//! `(script, bit)` pairs, so two operators with the same journal publish the
//! same bytes.

use sha2::{Digest, Sha256};

/// Hash domain for choice positions. Distinct from the bucket salt's, so the
/// positions carry no relation to the candidate rows they select between.
const DOMAIN: &[u8] = b"zcash-transparent-range-v1/directory-choice\0";

/// The only encoding version this build reads or writes.
pub const CHOICE_VERSION: u8 = 1;

/// Version, seed, key count and segment length.
pub const CHOICE_HEADER_BYTES: usize = 1 + 4 + 4 + 4;

/// Seeds tried before construction is called a failure.
///
/// Peeling succeeds with high probability at this array size, so a retry is
/// rare and a run of failures means the input is not a set of distinct keys.
pub const MAX_SEEDS: u32 = 64;

/// Keys a table may index. Far above any shard; a bound on what a decoder will
/// allocate for, not a capacity target.
pub const MAX_KEYS: u32 = 1 << 24;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChoiceError {
    #[error("script {0} appears twice")]
    Duplicate(String),
    #[error("{keys} keys exceed the {MAX_KEYS}-key bound")]
    TooManyKeys { keys: usize },
    #[error("no seed below {MAX_SEEDS} peels {keys} keys")]
    Unpeelable { keys: usize },
    #[error("malformed choice table: {0}")]
    Malformed(String),
}

/// A published choice table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChoiceTable {
    seed: u32,
    keys: u32,
    segment: u32,
    bits: Vec<u8>,
}

/// Segment length for `keys` keys: three segments over `1.23 * keys + 32`
/// positions, the xor-filter sizing, and at least one position each so that an
/// empty table still evaluates.
pub fn segment_length(keys: u32) -> u32 {
    let capacity = (u64::from(keys) * 123).div_ceil(100) + 32;
    capacity.div_ceil(3).max(1) as u32
}

/// Bytes of the bit array for segments of length `segment`.
pub fn bit_bytes(segment: u32) -> usize {
    (3 * segment as usize).div_ceil(8)
}

/// The three positions a script takes under `seed`, one per segment.
pub fn positions(shard_id: u64, seed: u32, segment: u32, script: &[u8]) -> [usize; 3] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(shard_id.to_le_bytes());
    hasher.update(seed.to_le_bytes());
    hasher.update((script.len() as u32).to_le_bytes());
    hasher.update(script);
    let digest = hasher.finalize();
    std::array::from_fn(|i| {
        let word = u64::from_le_bytes(digest[i * 8..i * 8 + 8].try_into().expect("8 bytes"));
        i * segment as usize + (word % u64::from(segment)) as usize
    })
}

impl ChoiceTable {
    /// The candidate index for `script`: 0 or 1.
    ///
    /// Defined for every script. For a script the table was not built over the
    /// answer is arbitrary but in range, so a caller can always form exactly
    /// one query.
    pub fn choice(&self, shard_id: u64, script: &[u8]) -> usize {
        positions(shard_id, self.seed, self.segment, script)
            .iter()
            .fold(0u8, |acc, &at| acc ^ ((self.bits[at / 8] >> (at % 8)) & 1)) as usize
    }

    /// Keys the table was built over.
    pub fn keys(&self) -> u32 {
        self.keys
    }

    /// The seed construction settled on.
    pub fn seed(&self) -> u32 {
        self.seed
    }

    /// The published bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CHOICE_HEADER_BYTES + self.bits.len());
        out.push(CHOICE_VERSION);
        out.extend_from_slice(&self.seed.to_le_bytes());
        out.extend_from_slice(&self.keys.to_le_bytes());
        out.extend_from_slice(&self.segment.to_le_bytes());
        out.extend_from_slice(&self.bits);
        out
    }

    /// Reads published bytes, refusing anything [`encode`](Self::encode) would
    /// not have produced.
    ///
    /// Every field is checked before any position is computed from it: the
    /// segment length must be the one the key count implies, the length must be
    /// exact, and padding bits must be zero. Nothing is indexed until this
    /// returns.
    pub fn decode(bytes: &[u8]) -> Result<Self, ChoiceError> {
        let malformed = |why: String| ChoiceError::Malformed(why);
        if bytes.len() < CHOICE_HEADER_BYTES {
            return Err(malformed(format!(
                "{} bytes is shorter than a header",
                bytes.len()
            )));
        }
        if bytes[0] != CHOICE_VERSION {
            return Err(malformed(format!("version {}", bytes[0])));
        }
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes"));
        let (seed, keys, segment) = (word(1), word(5), word(9));
        if seed >= MAX_SEEDS {
            return Err(malformed(format!("seed {seed}")));
        }
        if keys > MAX_KEYS {
            return Err(malformed(format!("{keys} keys")));
        }
        if segment != segment_length(keys) {
            return Err(malformed(format!(
                "segment {segment} where {keys} keys imply {}",
                segment_length(keys)
            )));
        }
        let expected = CHOICE_HEADER_BYTES + bit_bytes(segment);
        if bytes.len() != expected {
            return Err(malformed(format!(
                "{} bytes where the header implies {expected}",
                bytes.len()
            )));
        }
        let bits = bytes[CHOICE_HEADER_BYTES..].to_vec();
        let used = 3 * segment as usize;
        if !used.is_multiple_of(8) && bits[bits.len() - 1] >> (used % 8) != 0 {
            return Err(malformed("nonzero padding bits".into()));
        }
        Ok(Self {
            seed,
            keys,
            segment,
            bits,
        })
    }
}
