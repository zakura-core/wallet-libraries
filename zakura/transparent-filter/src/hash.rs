//! Block hashes, in the two byte orders that matter, kept apart by type, and
//! the filter keyings derived from them.
//!
//! Zcash RPC and block explorers display a block hash as the hex of its
//! *reversed* serialized bytes. The BIP 158 SipHash keys are derived from the
//! serialized ("internal") order. Confusing the two produces a filter that is
//! self-consistent and wrong, which no round-trip test through a single
//! implementation would catch, so the conversion is named and tested against
//! pinned vectors rather than being spelled inline at each call site.
//!
//! Every keying this crate supports is defined here, so that a reviewer can see
//! all of them at once and check that they cannot collide. There are two: the
//! per-block keying of the `zcash-transparent-basic-v1` profile, taken directly
//! from the block hash, and the per-shard keying of
//! `zcash-transparent-range-v1`, derived by hashing the shard's identity under
//! its own profile string.

use crate::error::FilterError;
use sha2::{Digest, Sha256};

/// The two little-endian 64-bit SipHash-2-4 keys a filter is encoded under.
///
/// A newtype rather than a bare `(u64, u64)` so that the encoder and the
/// matcher cannot be handed keys from some unrelated source. Producing a value
/// of this type is the only way to key a filter, and every producer is in this
/// module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilterKeys {
    pub k0: u64,
    pub k1: u64,
}

impl FilterKeys {
    /// Splits sixteen bytes into the two little-endian keys.
    fn from_prefix(bytes: &[u8; 16]) -> Self {
        Self {
            k0: u64::from_le_bytes(bytes[0..8].try_into().expect("8 bytes")),
            k1: u64::from_le_bytes(bytes[8..16].try_into().expect("8 bytes")),
        }
    }
}

/// A block hash in canonical internal (serialized, little-endian) byte order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockHash(pub [u8; 32]);

impl BlockHash {
    /// Wraps bytes that are already in internal order.
    pub fn from_internal_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parses RPC/display hex, reversing into internal order.
    pub fn from_display_hex(text: &str) -> Result<Self, FilterError> {
        let mut bytes = <[u8; 32]>::try_from(
            hex::decode(text)
                .map_err(|_| FilterError::BlockHash("block hash is not hexadecimal".into()))?
                .as_slice(),
        )
        .map_err(|_| FilterError::BlockHash("block hash is not 32 bytes".into()))?;
        bytes.reverse();
        Ok(Self(bytes))
    }

    /// Renders RPC/display hex. Never use this in binary serialization.
    pub fn to_display_hex(self) -> String {
        let mut bytes = self.0;
        bytes.reverse();
        hex::encode(bytes)
    }

    pub fn internal_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The two little-endian 64-bit SipHash-2-4 keys, taken from the first
    /// sixteen bytes of the internal representation.
    ///
    /// This is the `zcash-transparent-basic-v1` keying, and it is BIP 158's:
    /// the keys are the block hash itself, not a hash of it.
    pub fn filter_keys(&self) -> FilterKeys {
        FilterKeys::from_prefix(self.0[..16].try_into().expect("16 bytes"))
    }
}

/// The identity a `zcash-transparent-range-v1` filter is keyed under.
///
/// A range covers many blocks, so there is no single block hash to key it with.
/// The keys are instead derived by hashing the shard's full public identity
/// under the range profile's own string. Two properties are being bought here:
///
/// - **Profile separation.** The profile string is part of the preimage, so a
///   range filter's keys can never coincide with a block filter's. A range
///   filter presented as a block filter fails to match anything rather than
///   matching under the wrong rules.
/// - **Identity binding.** The shard id, both heights and the terminal block
///   hash are all in the preimage, so a filter cannot be replayed under a
///   different shard identity — not even one covering the same heights on the
///   same chain, because the shard id still differs.
///
/// The genesis hash is included for the same reason it identifies a chain
/// everywhere else in this crate: the network name alone would let a filter
/// built on one chain be accepted on another that happens to share it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShardKey([u8; 16]);

impl ShardKey {
    /// Derives the keying for one shard.
    ///
    /// The profile string is followed by a NUL byte; everything after it is
    /// fixed-width, so the preimage parses unambiguously and no two distinct
    /// shard identities can produce the same byte string.
    pub fn derive(
        profile: &str,
        genesis: BlockHash,
        shard_id: u64,
        start_height: u64,
        end_height: u64,
        terminal_block_hash: BlockHash,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(profile.as_bytes());
        hasher.update([0u8]);
        hasher.update(genesis.internal_bytes());
        hasher.update(shard_id.to_le_bytes());
        hasher.update(start_height.to_le_bytes());
        hasher.update(end_height.to_le_bytes());
        hasher.update(terminal_block_hash.internal_bytes());
        let digest = hasher.finalize();
        Self(digest[..16].try_into().expect("16 bytes"))
    }

    pub fn filter_keys(&self) -> FilterKeys {
        FilterKeys::from_prefix(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{MAINNET_GENESIS_DISPLAY, RANGE_PROFILE};

    #[test]
    fn display_hex_round_trips_through_internal_order() {
        let hash = BlockHash::from_display_hex(MAINNET_GENESIS_DISPLAY).unwrap();
        assert_eq!(hash.to_display_hex(), MAINNET_GENESIS_DISPLAY);
    }

    #[test]
    fn internal_order_is_the_reverse_of_display_order() {
        let hash = BlockHash::from_display_hex(MAINNET_GENESIS_DISPLAY).unwrap();
        // Display order ends in ...dce08, so internal order begins 08 ce 03 97.
        assert_eq!(&hash.internal_bytes()[..4], &[0x08, 0xce, 0x3d, 0x97]);
        // And the leading display zeros land at the end of internal order.
        assert_eq!(&hash.internal_bytes()[28..], &[0xe8, 0x0f, 0x04, 0x00]);
    }

    #[test]
    fn keys_come_from_the_first_sixteen_internal_bytes() {
        let mut bytes = [0u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let keys = BlockHash::from_internal_bytes(bytes).filter_keys();
        assert_eq!(keys.k0, 0x0706_0504_0302_0100);
        assert_eq!(keys.k1, 0x0f0e_0d0c_0b0a_0908);
    }

    fn genesis() -> BlockHash {
        BlockHash::from_display_hex(MAINNET_GENESIS_DISPLAY).unwrap()
    }

    fn terminal() -> BlockHash {
        BlockHash::from_internal_bytes([0x5a; 32])
    }

    fn shard_key(
        profile: &str,
        shard_id: u64,
        start_height: u64,
        end_height: u64,
        terminal_block_hash: BlockHash,
    ) -> ShardKey {
        ShardKey::derive(
            profile,
            genesis(),
            shard_id,
            start_height,
            end_height,
            terminal_block_hash,
        )
    }

    /// Every field of the shard identity has to reach the keys. A field that
    /// silently fell out of the preimage would let one shard's filter be
    /// accepted as another's, which the wallet has no other way to detect.
    #[test]
    fn each_part_of_the_shard_identity_changes_the_keying() {
        let base = shard_key(RANGE_PROFILE, 7, 100, 199, terminal());
        let variants = [
            shard_key("zcash-transparent-basic-v1", 7, 100, 199, terminal()),
            shard_key(RANGE_PROFILE, 8, 100, 199, terminal()),
            shard_key(RANGE_PROFILE, 7, 101, 199, terminal()),
            shard_key(RANGE_PROFILE, 7, 100, 200, terminal()),
            shard_key(
                RANGE_PROFILE,
                7,
                100,
                199,
                BlockHash::from_internal_bytes([0x5b; 32]),
            ),
            ShardKey::derive(
                RANGE_PROFILE,
                BlockHash::from_internal_bytes([0x01; 32]),
                7,
                100,
                199,
                terminal(),
            ),
        ];
        for variant in variants {
            assert_ne!(base, variant);
            assert_ne!(base.filter_keys(), variant.filter_keys());
        }
    }

    #[test]
    fn the_shard_keying_is_deterministic() {
        assert_eq!(
            shard_key(RANGE_PROFILE, 7, 100, 199, terminal()).filter_keys(),
            shard_key(RANGE_PROFILE, 7, 100, 199, terminal()).filter_keys()
        );
    }

    /// A shard's terminal block hash is a real block hash, so the derivation
    /// must not be a pass-through of it: that would make a range filter over a
    /// single block byte-identical to that block's own filter, and the profile
    /// separation would be lost exactly where it matters most.
    #[test]
    fn a_shard_keying_is_not_its_terminal_block_hash_keying() {
        let terminal = terminal();
        assert_ne!(
            shard_key(RANGE_PROFILE, 0, 100, 100, terminal).filter_keys(),
            terminal.filter_keys()
        );
    }

    /// The NUL after the profile string is what makes the preimage parse
    /// unambiguously. Without it a profile ending in extra bytes could collide
    /// with a longer profile whose name absorbed them.
    #[test]
    fn the_profile_string_is_terminated_rather_than_run_into_the_genesis_hash() {
        let genesis = genesis();
        let mut shifted = *genesis.internal_bytes();
        let stolen = shifted[0];
        shifted[0] = 0;
        assert_ne!(
            ShardKey::derive(RANGE_PROFILE, genesis, 0, 0, 0, terminal()),
            ShardKey::derive(
                &format!("{RANGE_PROFILE}{}", stolen as char),
                BlockHash::from_internal_bytes(shifted),
                0,
                0,
                0,
                terminal()
            )
        );
    }

    #[test]
    fn malformed_display_hashes_are_rejected() {
        assert!(BlockHash::from_display_hex("nothex").is_err());
        assert!(BlockHash::from_display_hex("00ff").is_err());
        assert!(BlockHash::from_display_hex(&"ab".repeat(33)).is_err());
    }
}
