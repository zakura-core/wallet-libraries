//! Private receiver lookups over caller-owned transports.
//!
//! Encrypted row retrieval returns candidates for wallet validation, not chain proofs:
//! records from `InventoryClient::page` and payloads from `InventoryClient::witness` are
//! untrusted bytes, which the wallet checks cryptographically before use. Rolling block
//! GCS hints and sealed shard filters are optional bandwidth optimizations. Matches
//! trigger PIR rather than compact scanning. PIR hides the queried address, but query
//! timing is visible. All returned payments require wallet authentication, inclusion
//! and spend checks.
pub use zakura_pir_protocol::receiver::*;
mod client;
mod descriptor_cache;
pub mod transport;

pub use client::{Client, Query, WitnessClient, WitnessQuery};

/// Zcash mainnet's genesis block hash, in internal byte order, which its directory
/// publications commit to.
pub const MAINNET_GENESIS: [u8; 32] = [
    0x08, 0xce, 0x3d, 0x97, 0x31, 0xb0, 0x00, 0xc0, 0x83, 0x38, 0x45, 0x5c, 0x8a, 0x4a, 0x6b, 0xd0,
    0x5d, 0xa1, 0x6e, 0x26, 0xb1, 0x1d, 0xaa, 0x1b, 0x91, 0x71, 0x84, 0xec, 0xe8, 0x0f, 0x04, 0x00,
];
