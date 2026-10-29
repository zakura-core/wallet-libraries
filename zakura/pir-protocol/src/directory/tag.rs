//! Salted key tags, and the salt counter that keeps a directory's tags
//! distinct.

use sha2::{Digest, Sha256};

/// Bytes a tag keeps of its digest.
pub const TAG_BYTES: usize = 14;

/// SHA-256 of `domain` followed by `parts` in order: a format's tag salt over
/// its own fixed-length inputs.
pub fn salt(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// A tag under `salt`: SHA-256 of `domain`, the salt and `key` in order,
/// truncated to [`TAG_BYTES`]. `key` carries the format's own framing, such
/// as a length prefix, so a fixed-length key can be hashed bare.
pub fn tag(domain: &[u8], salt: &[u8; 32], key: &[&[u8]]) -> [u8; TAG_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(salt);
    for part in key {
        hasher.update(part);
    }
    let digest = hasher.finalize();
    digest[..TAG_BYTES].try_into().expect("14 bytes")
}

/// The first of `counters` whose salt, `salt_at(counter)`, gives `keys`
/// distinct tags under `tag_of`, with that salt. `None` if none does.
///
/// On a collision every tag is recomputed under the next counter; no key is
/// dropped.
pub fn resolve_salt(
    counters: impl IntoIterator<Item = u32>,
    salt_at: impl Fn(u32) -> [u8; 32],
    keys: &[&[u8]],
    mut tag_of: impl FnMut(&[u8; 32], &[u8]) -> [u8; TAG_BYTES],
) -> Option<(u32, [u8; 32])> {
    counters.into_iter().find_map(|counter| {
        let salt = salt_at(counter);
        let mut seen = std::collections::HashSet::with_capacity(keys.len());
        keys.iter()
            .all(|key| seen.insert(tag_of(&salt, key)))
            .then_some((counter, salt))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAIN: &[u8] = b"directory-tag-test\0";

    /// A caller's own counter range and salt inputs: a salt that collides
    /// moves to the next counter, and a range of only colliding salts fails.
    #[test]
    fn resolution_walks_the_callers_counters() {
        let committed = [5u8; 32];
        let salt_at = |counter: u32| match counter {
            0 => committed,
            r => salt(DOMAIN, &[&committed, &r.to_le_bytes(), &[9; 32]]),
        };
        let keys: [&[u8]; 2] = [&[1; 43], &[2; 43]];
        let colliding = |salt: &[u8; 32], key: &[u8]| {
            if *salt == committed || *salt == salt_at(1) {
                [0; TAG_BYTES]
            } else {
                tag(DOMAIN, salt, &[key])
            }
        };
        assert_eq!(
            resolve_salt(0..=8, salt_at, &keys, colliding),
            Some((2, salt_at(2)))
        );
        assert_eq!(resolve_salt(0..=1, salt_at, &keys, colliding), None);
    }

    /// Both framings against vectors computed independently with Python's
    /// `hashlib`: a bare 43-byte key, and the same key after a `u16` length.
    #[test]
    fn tags_hash_the_callers_framing() {
        let key: Vec<u8> = (0..43).collect();
        let salt = [5; 32];
        let bare = tag(DOMAIN, &salt, &[&key]);
        let framed = tag(DOMAIN, &salt, &[&43u16.to_le_bytes(), &key]);
        assert_eq!(hex::encode(bare), "a312a2f53895dbfaeabeb897a91d");
        assert_eq!(hex::encode(framed), "acd7e1477d23e9103cceaa1aa9e7");
    }
}
