//! A key's independently salted candidate rows.

use sha2::{Digest, Sha256};

/// Candidate rows per key.
pub const DIRECTORY_CHOICES: usize = 2;

/// A directory's bucket salts, one per choice: SHA-256 of `domain`, a
/// fixed-length `context` and the choice index.
pub fn bucket_salts(domain: &[u8], context: &[u8]) -> [[u8; 32]; DIRECTORY_CHOICES] {
    std::array::from_fn(|choice| {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(context);
        hasher.update((choice as u32).to_le_bytes());
        hasher.finalize().into()
    })
}

/// Both candidate rows for `key` out of `rows`, under salts from
/// [`bucket_salts`].
pub fn candidates(
    salts: &[[u8; 32]; DIRECTORY_CHOICES],
    key: &[u8],
    rows: u64,
) -> [u64; DIRECTORY_CHOICES] {
    std::array::from_fn(|choice| bucket_for(&salts[choice], key, rows))
}

/// The row `key` hashes to under one salt.
pub fn bucket_for(salt: &[u8; 32], key: &[u8], rows: u64) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update((key.len() as u32).to_le_bytes());
    hasher.update(key);
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("8 bytes")) % rows
}
