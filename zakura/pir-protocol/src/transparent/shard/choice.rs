//! Which of a script's two candidate directory rows holds it.
//!
//! Two-choice placement leaves a script in one of two rows, and without more
//! information a wallet must query both, because querying one and stopping on a
//! hit makes the query count a function of where the script landed. A
//! [`ChoiceTable`] publishes that one bit per placed script as a static function,
//! so the wallet evaluates it locally and sends exactly one directory query per
//! matched script, whatever the script.
//!
//! This is the shared [`crate::directory::choice`] table keyed by the shard id
//! and the raw script, under seeds `0..MAX_SEEDS`.

pub const DIRECTORY_CHOICES: usize = 2;

use crate::directory::choice::{self as shared, SeedPolicy};
pub use crate::directory::choice::{
    CHOICE_HEADER_BYTES, CHOICE_VERSION, ChoiceError, MAX_KEYS, segment_length,
};
use sha2::{Digest, Sha256};

/// Hash domain for choice positions. Distinct from the bucket salt's, so the
/// positions carry no relation to the candidate rows they select between.
const DOMAIN: &[u8] = b"zcash-transparent-range-v1/directory-choice\0";

/// Seeds tried before construction is called a failure.
///
/// Peeling succeeds with high probability at this array size, so a retry is
/// rare and a run of failures means the input is not a set of distinct keys.
pub const MAX_SEEDS: u32 = 64;

/// A published choice table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChoiceTable(shared::ChoiceTable);

impl ChoiceTable {
    /// Builds the table for `entries`, each a script and the candidate index
    /// (0 or 1) that holds it.
    ///
    /// Scripts must be distinct. Input order does not matter: entries are
    /// sorted first, so the peeling order and therefore the bytes depend only
    /// on the set.
    pub fn build(shard_id: u64, entries: &[(&[u8], u8)]) -> Result<Self, ChoiceError> {
        shared::ChoiceTable::build(DOMAIN, &shard_id.to_le_bytes(), 0..MAX_SEEDS, entries).map(Self)
    }

    /// The candidate index for `script`: 0 or 1. See
    /// [`shared::ChoiceTable::choice`].
    pub fn choice(&self, shard_id: u64, script: &[u8]) -> usize {
        self.0.choice(DOMAIN, &shard_id.to_le_bytes(), script)
    }

    /// Keys the table was built over.
    pub fn keys(&self) -> u32 {
        self.0.keys()
    }

    /// The seed construction settled on.
    pub fn seed(&self) -> u32 {
        self.0.seed()
    }

    /// The published bytes.
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode()
    }

    /// Reads published bytes, refusing anything [`encode`](Self::encode) would
    /// not have produced, including a seed of [`MAX_SEEDS`] or more.
    pub fn decode(bytes: &[u8]) -> Result<Self, ChoiceError> {
        shared::ChoiceTable::decode(bytes, SeedPolicy::Below(MAX_SEEDS)).map(Self)
    }
}

/// Both candidate rows for a script in this shard.
pub fn candidate_rows(shard_id: u64, script: &[u8], rows: u64) -> [u64; DIRECTORY_CHOICES] {
    candidates(&bucket_salts(shard_id), script, rows)
}
/// Derives one of a shard's independently salted bucket keys.
///
/// Salting per shard means the same script lands in different rows in different
/// shards, so an observer who learns one shard's row for a script learns
/// nothing about where it sits in any other.
fn bucket_salt(shard_id: u64, choice: usize) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"zcash-transparent-range-v1/directory-bucket\0");
    hasher.update(shard_id.to_le_bytes());
    hasher.update((choice as u32).to_le_bytes());
    hasher.finalize().into()
}
/// A shard's bucket salts, for deriving many scripts' candidate rows.
pub fn bucket_salts(shard_id: u64) -> [[u8; 32]; DIRECTORY_CHOICES] {
    std::array::from_fn(|choice| bucket_salt(shard_id, choice))
}
/// [`candidate_rows`] under salts already derived for the shard.
pub fn candidates(
    salts: &[[u8; 32]; DIRECTORY_CHOICES],
    script: &[u8],
    rows: u64,
) -> [u64; DIRECTORY_CHOICES] {
    std::array::from_fn(|choice| bucket_for(&salts[choice], script, rows))
}
/// The row a script hashes to under one salt.
pub fn bucket_for(salt: &[u8; 32], script: &[u8], rows: u64) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update((script.len() as u32).to_le_bytes());
    hasher.update(script);
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("8 bytes")) % rows
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
