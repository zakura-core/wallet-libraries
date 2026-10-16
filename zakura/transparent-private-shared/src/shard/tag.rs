//! Salted script tags for private directory and page records.
//!
//! A tag is the first 14 bytes of a domain-separated SHA-256 of the complete
//! raw script, under a salt the revision's transactions cannot have predicted.
//! Placement and the choice table stay keyed on the raw script. The tag is
//! what a row stores and what a wallet compares.

use crate::filter::BlockHash;
use sha2::{Digest, Sha256};

/// Domain for the per-revision salt. The trailing NUL keeps this input from
/// being a prefix of another SHA-256 use.
pub const TAG_SALT_DOMAIN: &[u8] = b"transparent-shard-tag-salt-v1\0";

/// Domain for a page shard's salt.
pub const PAGE_TAG_SALT_DOMAIN: &[u8] = b"transparent-shard-page-tag-salt-v1\0";

/// Domain for the script tag itself.
pub const SCRIPT_TAG_DOMAIN: &[u8] = b"transparent-shard-script-tag-v2\0";

/// Bytes stored in place of a raw script.
pub const SCRIPT_TAG_BYTES: usize = 14;

/// Counters tried before publication fails.
///
/// An honest shard collides with probability far below anything this limit
/// can see. The counter exists so a collision rebuilds the tags instead of
/// failing the shard or dropping a script.
pub const MAX_TAG_SALT_COUNTER: u32 = 8;

/// The salt for one revision.
///
/// `terminal` is the block at the revision's end, in internal byte order.
/// The wallet recomputes this from the manifest and never accepts a salt
/// supplied separately.
pub fn tag_salt(shard_id: u64, terminal: &BlockHash, counter: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(TAG_SALT_DOMAIN);
    hasher.update(shard_id.to_le_bytes());
    hasher.update(terminal.internal_bytes());
    hasher.update(counter.to_le_bytes());
    hasher.finalize().into()
}

/// The salt for one page shard of a directory shard.
///
/// Keyed on the page shard's own end height and terminal block rather than
/// the directory shard's: while the directory shard is open its terminal moves
/// every block, and salting children with it would re-tag page shards that
/// have already sealed and must never change. The wallet recomputes this from
/// the manifest's child entry.
pub fn page_tag_salt(
    shard_id: u64,
    child: u32,
    end_height: u64,
    terminal: &BlockHash,
    counter: u32,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PAGE_TAG_SALT_DOMAIN);
    hasher.update(shard_id.to_le_bytes());
    hasher.update(child.to_le_bytes());
    hasher.update(end_height.to_le_bytes());
    hasher.update(terminal.internal_bytes());
    hasher.update(counter.to_le_bytes());
    hasher.finalize().into()
}

/// The 14-byte tag of one raw script under `salt`.
pub fn script_tag(salt: &[u8; 32], script: &[u8]) -> [u8; SCRIPT_TAG_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(SCRIPT_TAG_DOMAIN);
    hasher.update(salt);
    let length = u16::try_from(script.len()).expect("a tagged script is at most MAX_SCRIPT_BYTES");
    hasher.update(length.to_le_bytes());
    hasher.update(script);
    let digest = hasher.finalize();
    digest[..SCRIPT_TAG_BYTES].try_into().expect("14 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terminal(byte: u8) -> BlockHash {
        BlockHash::from_internal_bytes([byte; 32])
    }

    #[test]
    fn the_salt_moves_with_the_terminal_block_and_the_counter() {
        let base = tag_salt(3, &terminal(1), 0);
        assert_ne!(tag_salt(3, &terminal(2), 0), base);
        assert_ne!(tag_salt(3, &terminal(1), 1), base);
        assert_ne!(tag_salt(4, &terminal(1), 0), base);
        assert_eq!(tag_salt(3, &terminal(1), 0), base);
    }

    /// A page shard's salt depends on its own identity, not its directory
    /// shard's terminal, and is distinct from the directory's salt.
    #[test]
    fn a_page_shard_salt_moves_with_the_page_shard_alone() {
        let base = page_tag_salt(3, 1, 500, &terminal(1), 0);
        assert_ne!(page_tag_salt(3, 2, 500, &terminal(1), 0), base);
        assert_ne!(page_tag_salt(3, 1, 501, &terminal(1), 0), base);
        assert_ne!(page_tag_salt(3, 1, 500, &terminal(2), 0), base);
        assert_ne!(page_tag_salt(3, 1, 500, &terminal(1), 1), base);
        assert_ne!(page_tag_salt(4, 1, 500, &terminal(1), 0), base);
        assert_ne!(tag_salt(3, &terminal(1), 0), base);
    }

    #[test]
    fn a_tag_is_not_a_prefix_of_the_script() {
        let script = b"\x76\xa9identical-prefix-bytes!!";
        let tag = script_tag(&tag_salt(1, &terminal(9), 0), script);
        assert_ne!(&tag[..], &script[..SCRIPT_TAG_BYTES]);
        assert_eq!(tag.len(), SCRIPT_TAG_BYTES);
    }

    #[test]
    fn a_tag_from_another_salt_is_not_the_one_the_wallet_derives() {
        let script = b"\x76\xa9wallet-script";
        let hash = terminal(7);
        let wallet = script_tag(&tag_salt(9, &hash, 0), script);
        let foreign = script_tag(&tag_salt(9, &hash, 1), script);
        assert_ne!(wallet, foreign);
    }
}
