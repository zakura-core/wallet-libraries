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
use std::collections::BTreeMap;

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

fn bit_bytes(segment: u32) -> usize {
    (3 * segment as usize).div_ceil(8)
}

/// The three positions a script takes under `seed`, one per segment.
fn positions(shard_id: u64, seed: u32, segment: u32, script: &[u8]) -> [usize; 3] {
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
    /// Builds the table for `entries`, each a script and the candidate index
    /// (0 or 1) that holds it.
    ///
    /// Scripts must be distinct. Input order does not matter: entries are
    /// sorted first, so the peeling order and therefore the bytes depend only
    /// on the set.
    pub fn build(shard_id: u64, entries: &[(&[u8], u8)]) -> Result<Self, ChoiceError> {
        if entries.len() > MAX_KEYS as usize {
            return Err(ChoiceError::TooManyKeys {
                keys: entries.len(),
            });
        }
        let mut sorted: BTreeMap<&[u8], u8> = BTreeMap::new();
        for (script, bit) in entries {
            if sorted.insert(script, bit & 1).is_some() {
                return Err(ChoiceError::Duplicate(hex::encode(script)));
            }
        }
        let keys = sorted.len() as u32;
        let segment = segment_length(keys);
        let slots = 3 * segment as usize;
        let sorted: Vec<(&[u8], u8)> = sorted.into_iter().collect();

        for seed in 0..MAX_SEEDS {
            let hashed: Vec<[usize; 3]> = sorted
                .iter()
                .map(|(script, _)| positions(shard_id, seed, segment, script))
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

    fn script(tag: u32) -> Vec<u8> {
        let mut bytes = vec![0x76, 0xa9, 0x14];
        bytes.extend_from_slice(&tag.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 16]);
        bytes.extend_from_slice(&[0x88, 0xac]);
        bytes
    }

    fn bit(tag: u32) -> u8 {
        (tag.wrapping_mul(2_654_435_761) >> 7) as u8 & 1
    }

    fn fixture(count: u32) -> Vec<(Vec<u8>, u8)> {
        (0..count).map(|tag| (script(tag), bit(tag))).collect()
    }

    fn table(shard_id: u64, fixture: &[(Vec<u8>, u8)]) -> ChoiceTable {
        let entries: Vec<(&[u8], u8)> = fixture.iter().map(|(s, b)| (s.as_slice(), *b)).collect();
        ChoiceTable::build(shard_id, &entries).expect("builds")
    }

    #[test]
    fn every_indexed_script_returns_its_bit() {
        for count in [0, 1, 2, 14, 1_000, 45_454] {
            let fixture = fixture(count);
            let built = table(7, &fixture);
            assert_eq!(built.keys(), count);
            for (script, bit) in &fixture {
                assert_eq!(built.choice(7, script), *bit as usize, "{count} keys");
            }
        }
    }

    #[test]
    fn the_bytes_depend_on_the_set_not_the_order() {
        let fixture = fixture(5_000);
        let mut reversed = fixture.clone();
        reversed.reverse();
        assert_eq!(table(3, &fixture).encode(), table(3, &reversed).encode());
    }

    #[test]
    fn the_shard_id_keys_the_positions() {
        let fixture = fixture(5_000);
        assert_ne!(table(3, &fixture).encode(), table(4, &fixture).encode());
    }

    #[test]
    fn it_costs_about_one_and_a_quarter_bits_per_key() {
        let built = table(0, &fixture(45_454));
        let bytes = built.encode().len();
        // 45,454 keys at 1.23 bits plus the fixed 32 positions and header.
        assert!(bytes < 7_100, "{bytes} bytes");
        assert!(bytes > 6_900, "{bytes} bytes");
    }

    #[test]
    fn an_unindexed_script_still_names_one_candidate() {
        let built = table(1, &fixture(1_000));
        let mut seen = [0usize; 2];
        for tag in 1_000..3_000 {
            seen[built.choice(1, &script(tag))] += 1;
        }
        // Both answers occur: an absent script is not steered to either row.
        assert!(seen[0] > 800 && seen[1] > 800, "{seen:?}");
    }

    #[test]
    fn duplicates_are_refused() {
        let a = script(1);
        let entries: Vec<(&[u8], u8)> = vec![(&a, 0), (&a, 1)];
        assert!(matches!(
            ChoiceTable::build(0, &entries),
            Err(ChoiceError::Duplicate(_))
        ));
    }

    #[test]
    fn encoding_round_trips() {
        for count in [0, 1, 13, 4_000] {
            let built = table(9, &fixture(count));
            assert_eq!(ChoiceTable::decode(&built.encode()), Ok(built));
        }
    }

    #[test]
    fn malformed_bytes_are_refused_before_use() {
        let good = table(9, &fixture(1_001)).encode();
        let reject = |bytes: &[u8]| {
            assert!(
                matches!(ChoiceTable::decode(bytes), Err(ChoiceError::Malformed(_))),
                "accepted {} bytes",
                bytes.len()
            )
        };
        reject(&[]);
        reject(&good[..CHOICE_HEADER_BYTES - 1]);
        reject(&good[..good.len() - 1]);
        let mut long = good.clone();
        long.push(0);
        reject(&long);

        let mut version = good.clone();
        version[0] = 2;
        reject(&version);

        let mut seed = good.clone();
        seed[1..5].copy_from_slice(&MAX_SEEDS.to_le_bytes());
        reject(&seed);

        // A key count the segment does not match, including zero keys over a
        // nonzero array.
        let mut keys = good.clone();
        keys[5..9].copy_from_slice(&0u32.to_le_bytes());
        reject(&keys);

        let mut huge = good.clone();
        huge[5..9].copy_from_slice(&(MAX_KEYS + 1).to_le_bytes());
        reject(&huge);

        let mut segment = good.clone();
        let wrong = segment_length(1_001) + 1;
        segment[9..13].copy_from_slice(&wrong.to_le_bytes());
        reject(&segment);

        // Padding exists only when the array does not end on a byte boundary.
        let odd = table(9, &fixture(3)).encode();
        assert!(!(3 * segment_length(3)).is_multiple_of(8));
        let mut padding = odd.clone();
        *padding.last_mut().expect("bits") |= 0x80;
        reject(&padding);
    }
}
