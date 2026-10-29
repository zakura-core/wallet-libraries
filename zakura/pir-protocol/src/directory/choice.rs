//! Which of a key's two candidate directory rows holds it.
//!
//! The structure is an xor retrieval table: three positions per key, drawn from
//! three equal segments of a bit array, whose xor is the key's bit. It stores
//! about 1.23 bits per key and nothing else: no key, no fingerprint, no row. It
//! is not a membership test. A key that was never placed evaluates to an
//! arbitrary bit, and comparing the key against the returned row is what
//! settles absence.
//!
//! Positions are keyed by a format's hash domain, a fixed-length context (such
//! as a shard id), the seed and the key. The table is a deterministic function
//! of those and the set of `(key, bit)` pairs, so two operators with the same
//! input publish the same bytes.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// The only encoding version this build reads or writes.
pub const CHOICE_VERSION: u8 = 1;

/// Version, seed, key count and segment length.
pub const CHOICE_HEADER_BYTES: usize = 1 + 4 + 4 + 4;

/// Keys a table may index. Far above any shard; a bound on what a decoder will
/// allocate for, not a capacity target.
pub const MAX_KEYS: u32 = 1 << 24;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChoiceError {
    #[error("key {0} appears twice")]
    Duplicate(String),
    #[error("{keys} keys exceed the {MAX_KEYS}-key bound")]
    TooManyKeys { keys: usize },
    #[error("no candidate seed peels {keys} keys")]
    Unpeelable { keys: usize },
    #[error("malformed choice table: {0}")]
    Malformed(String),
}

/// Which stored seeds a decoder accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeedPolicy {
    /// Seeds below the bound, for a format whose builder tries `0..bound`.
    Below(u32),
    /// Any seed, for a format whose builder draws seeds from a hash. The seed
    /// is public, so accepting any value gives the reader nothing to trust.
    Any,
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

fn bit_bytes(segment: u32) -> usize {
    (3 * segment as usize).div_ceil(8)
}

/// The three positions `key` takes under `seed`, one per segment.
fn positions(domain: &[u8], context: &[u8], seed: u32, segment: u32, key: &[u8]) -> [usize; 3] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(context);
    hasher.update(seed.to_le_bytes());
    hasher.update((key.len() as u32).to_le_bytes());
    hasher.update(key);
    let digest = hasher.finalize();
    std::array::from_fn(|i| {
        let word = u64::from_le_bytes(digest[i * 8..i * 8 + 8].try_into().expect("8 bytes"));
        i * segment as usize + (word % u64::from(segment)) as usize
    })
}

impl ChoiceTable {
    /// Builds the table for `entries`, each a key and the candidate index
    /// (0 or 1) that holds it, under the first of `seeds` that peels.
    ///
    /// Keys must be distinct. Input order does not matter: entries are sorted
    /// first, so the peeling order and therefore the bytes depend only on the
    /// set, the seeds and the keying.
    pub fn build(
        domain: &[u8],
        context: &[u8],
        seeds: impl IntoIterator<Item = u32>,
        entries: &[(&[u8], u8)],
    ) -> Result<Self, ChoiceError> {
        if entries.len() > MAX_KEYS as usize {
            return Err(ChoiceError::TooManyKeys {
                keys: entries.len(),
            });
        }
        let mut sorted: BTreeMap<&[u8], u8> = BTreeMap::new();
        for (key, bit) in entries {
            if sorted.insert(key, bit & 1).is_some() {
                let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
                return Err(ChoiceError::Duplicate(hex));
            }
        }
        let keys = sorted.len() as u32;
        let segment = segment_length(keys);
        let slots = 3 * segment as usize;
        let sorted: Vec<(&[u8], u8)> = sorted.into_iter().collect();

        for seed in seeds {
            let hashed: Vec<[usize; 3]> = sorted
                .iter()
                .map(|(key, _)| positions(domain, context, seed, segment, key))
                .collect();
            let Some(order) = peel(&hashed, slots) else {
                continue;
            };
            // Assign in reverse peeling order: each key's free position is set
            // last among the keys touching it, so its xor comes out right.
            let mut array = vec![0u8; slots];
            for &(key, free) in order.iter().rev() {
                let [a, b, c] = hashed[key];
                array[free] = 0;
                array[free] = sorted[key].1 ^ array[a] ^ array[b] ^ array[c];
            }
            let mut bits = vec![0u8; bit_bytes(segment)];
            for (i, bit) in array.iter().enumerate() {
                bits[i / 8] |= bit << (i % 8);
            }
            return Ok(Self {
                seed,
                keys,
                segment,
                bits,
            });
        }
        Err(ChoiceError::Unpeelable {
            keys: keys as usize,
        })
    }

    /// The candidate index for `key` under the keying the table was built
    /// with: 0 or 1.
    ///
    /// Defined for every key. For a key the table was not built over the
    /// answer is arbitrary but in range, so a caller can always form exactly
    /// one query.
    pub fn choice(&self, domain: &[u8], context: &[u8], key: &[u8]) -> usize {
        positions(domain, context, self.seed, self.segment, key)
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
    /// not have produced or `seeds` does not accept.
    ///
    /// Every field is checked before any position is computed from it: the
    /// segment length must be the one the key count implies, the length must be
    /// exact, and padding bits must be zero. Nothing is indexed until this
    /// returns.
    pub fn decode(bytes: &[u8], seeds: SeedPolicy) -> Result<Self, ChoiceError> {
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
        if matches!(seeds, SeedPolicy::Below(bound) if seed >= bound) {
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

/// Peels the 3-hypergraph of `hashed` over `slots` positions.
///
/// Returns each key with the position it was peeled from, in peeling order, or
/// `None` if a core remains. Deterministic: positions are scanned in index order
/// and the stack is processed last in, first out.
fn peel(hashed: &[[usize; 3]], slots: usize) -> Option<Vec<(usize, usize)>> {
    let mut count = vec![0u32; slots];
    let mut xor = vec![0usize; slots];
    for (key, positions) in hashed.iter().enumerate() {
        for &at in positions {
            count[at] += 1;
            xor[at] ^= key;
        }
    }
    let mut stack: Vec<usize> = (0..slots).filter(|&at| count[at] == 1).collect();
    let mut order = Vec::with_capacity(hashed.len());
    while let Some(at) = stack.pop() {
        if count[at] != 1 {
            continue;
        }
        let key = xor[at];
        order.push((key, at));
        for &other in &hashed[key] {
            count[other] -= 1;
            xor[other] ^= key;
            if count[other] == 1 {
                stack.push(other);
            }
        }
    }
    (order.len() == hashed.len()).then_some(order)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAIN: &[u8] = b"directory-choice-test\0";
    const CONTEXT: &[u8] = &[7; 14];
    const SEED: u32 = 0x1234_5678;

    fn tags(count: u32) -> Vec<([u8; 14], u8)> {
        (0..count)
            .map(|i| {
                let mut tag = [0u8; 14];
                tag[..4].copy_from_slice(&i.to_le_bytes());
                (tag, (i.wrapping_mul(2_654_435_761) >> 7) as u8 & 1)
            })
            .collect()
    }

    fn build(seeds: &[u32], tags: &[([u8; 14], u8)]) -> Result<ChoiceTable, ChoiceError> {
        let entries: Vec<(&[u8], u8)> = tags.iter().map(|(t, b)| (&t[..], *b)).collect();
        ChoiceTable::build(DOMAIN, CONTEXT, seeds.iter().copied(), &entries)
    }

    /// A caller's own domain, context and seed list build a table that
    /// routes every key and round-trips under the any-seed policy.
    #[test]
    fn a_drawn_seed_list_builds_and_round_trips() {
        let tags = tags(2_000);
        let built = build(&[SEED, 3], &tags).expect("peels");
        assert_eq!(built.seed(), SEED);
        for (tag, bit) in &tags {
            assert_eq!(built.choice(DOMAIN, CONTEXT, tag), *bit as usize);
        }
        assert_eq!(
            ChoiceTable::decode(&built.encode(), SeedPolicy::Any),
            Ok(built)
        );
    }

    /// The bounded policy refuses its bound and a drawn seed; the any-seed
    /// policy accepts both.
    #[test]
    fn the_seed_policy_decides_which_seeds_decode() {
        for seed in [64, SEED] {
            let bytes = build(&[seed], &tags(100)).expect("peels").encode();
            assert!(ChoiceTable::decode(&bytes, SeedPolicy::Any).is_ok());
            assert!(matches!(
                ChoiceTable::decode(&bytes, SeedPolicy::Below(64)),
                Err(ChoiceError::Malformed(_))
            ));
        }
        let bytes = build(&[63], &tags(100)).expect("peels").encode();
        assert!(ChoiceTable::decode(&bytes, SeedPolicy::Below(64)).is_ok());
    }

    /// Only the listed seeds are tried.
    #[test]
    fn an_exhausted_seed_list_fails() {
        assert_eq!(
            build(&[], &tags(10)),
            Err(ChoiceError::Unpeelable { keys: 10 })
        );
    }
}
