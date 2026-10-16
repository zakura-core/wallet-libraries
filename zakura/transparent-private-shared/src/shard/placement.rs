//! Where a script may sit in a shard's directory: its candidate rows, which
//! the publisher places it in and the wallet queries.

use sha2::{Digest, Sha256};

/// Independently salted candidate rows per script.
///
/// Two choices, as the mainnet study selected: it packs far better than one and
/// costs one more query than one, where four costs two more queries for less
/// improvement. A script that fits in neither candidate is not resolved by a
/// public lookup, which would reveal the script it was trying to place; it is
/// resolved by giving the shard another segment and placing again.
pub const DIRECTORY_CHOICES: usize = 2;

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

/// The row a script hashes to under one salt.
pub fn bucket_for(salt: &[u8; 32], script: &[u8], rows: u64) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update((script.len() as u32).to_le_bytes());
    hasher.update(script);
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("8 bytes")) % rows
}

/// Both candidate rows for a script in this shard.
pub fn candidate_rows(shard_id: u64, script: &[u8], rows: u64) -> [u64; DIRECTORY_CHOICES] {
    candidates(&bucket_salts(shard_id), script, rows)
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
