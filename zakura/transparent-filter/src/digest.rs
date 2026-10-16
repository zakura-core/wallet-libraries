//! Filter digests and the optional BIP 157 style header chain.

use crate::hash::BlockHash;
use sha2::{Digest, Sha256};

/// Double-SHA-256 of the serialized filter bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilterHash(pub [u8; 32]);

/// Double-SHA-256 of `filter_hash || previous_header`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilterHeader(pub [u8; 32]);

fn double_sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut first = Sha256::new();
    for part in parts {
        first.update(part);
    }
    let once = first.finalize();
    Sha256::digest(once).into()
}

/// The standard filter digest.
///
/// This detects corruption of content the wallet previously accepted. It is not
/// evidence that the filter is honestly or completely constructed: a digest
/// supplied alongside a false filter simply commits to the false filter.
pub fn filter_hash(bytes: &[u8]) -> FilterHash {
    FilterHash(double_sha256(&[bytes]))
}

/// Chains one filter header onto its predecessor.
///
/// The all-zero predecessor is correct only at genesis. For a bounded
/// historical sample the caller must supply an explicitly labelled fixture
/// anchor or an externally sourced predecessor; a zero anchor part-way up the
/// chain is not a genesis-derived header chain and must not be described as
/// one.
///
/// Chaining headers is not by itself proof from Zcash consensus that a filter's
/// scripts are complete. This crate implements the digest construction only; it
/// does not implement BIP 157 peer verification or service signalling.
pub fn filter_header(filter: FilterHash, previous: FilterHeader) -> FilterHeader {
    FilterHeader(double_sha256(&[&filter.0, &previous.0]))
}

/// The all-zero predecessor, valid only as the genesis anchor.
pub const GENESIS_PREDECESSOR: FilterHeader = FilterHeader([0u8; 32]);

impl FilterHash {
    pub fn to_display_hex(self) -> String {
        BlockHash(self.0).to_display_hex()
    }
}

impl FilterHeader {
    pub fn to_display_hex(self) -> String {
        BlockHash(self.0).to_display_hex()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_digest_is_double_sha256_of_the_bytes() {
        // Independently: SHA256(SHA256(0x00)).
        let once = Sha256::digest([0x00u8]);
        let twice: [u8; 32] = Sha256::digest(once).into();
        assert_eq!(filter_hash(&[0x00]).0, twice);
    }

    #[test]
    fn different_filters_have_different_digests() {
        assert_ne!(filter_hash(&[0x00]), filter_hash(&[0x01]));
    }

    #[test]
    fn headers_chain_and_depend_on_the_predecessor() {
        let filter = filter_hash(&[0x00]);
        let first = filter_header(filter, GENESIS_PREDECESSOR);
        let second = filter_header(filter, first);
        assert_ne!(first, second);
        // The chain is a function of both inputs, so replaying the same
        // predecessor reproduces the same header.
        assert_eq!(first, filter_header(filter, GENESIS_PREDECESSOR));
    }
}
