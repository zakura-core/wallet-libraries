//! Shared BIP 158 Golomb-coded set encoding and low-level reading.
//!
//! This crate supplies bytes and bit operations, with SipHash from `bitcoin_hashes`.
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
pub use filter::{GcsFilterWriter, write_rice_deltas};
