//! Shared BIP 158 Golomb-coded set encoding and low-level reading.
//!
//! This crate supplies bytes and bit operations, with SipHash-2-4 from
//! [`siphasher::sip::SipHasher24`].
//! Callers own filter contents, key derivation, parameters, and strict whole-filter
//! validation. Reading a count or bits does not validate a filter or its completeness.
//!
//! The codec is extracted from rust-bitcoin 0.32.102. Application vectors and an
//! exactly pinned upstream test oracle keep the encoded bytes stable.

mod bits;
mod compact_size;
mod filter;

pub use bits::BitStreamReader;
pub use compact_size::{read_compact_size, write_compact_size};
pub use filter::GcsFilterWriter;

/// Hashes `element` into `[0, range)` with the BIP 158 SipHash-2-4 mapping.
///
/// Uses the high 64 bits of the product of the keyed hash and `range`. A zero
/// range returns zero. Callers derive the keys and validate their set's range;
/// this function does not validate a filter or establish membership.
#[inline]
pub fn hash_to_range(k0: u64, k1: u64, range: u64, element: &[u8]) -> u64 {
    let hash = siphasher::sip::SipHasher24::new_with_keys(k0, k1).hash(element);
    ((u128::from(hash) * u128::from(range)) >> 64) as u64
}

// Keep the previous codec's partial-consumption semantics on truncated reads.
// In particular, the standard library's slice read_exact specialization may
// leave a short slice untouched, while the previous reader consumed it.
fn read_exact<R: std::io::Read + ?Sized>(
    reader: &mut R,
    mut bytes: &mut [u8],
) -> std::io::Result<()> {
    while !bytes.is_empty() {
        match reader.read(bytes) {
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(len) => bytes = &mut bytes[len..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

// Retain UnexpectedEof for a zero-length write, as the previous codec did.
fn write_all<W: std::io::Write + ?Sized>(writer: &mut W, mut bytes: &[u8]) -> std::io::Result<()> {
    while !bytes.is_empty() {
        match writer.write(bytes) {
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(len) => bytes = &bytes[len..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
