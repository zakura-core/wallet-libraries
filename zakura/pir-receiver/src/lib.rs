//! Restore sweeps of dynamic keys through a receiver directory over PIR.
//!
//! A restored wallet cannot rescan public history for every key its seed may have
//! used, so each dynamic key recovered from the seed is looked up once in a receiver
//! directory: a public index of Ironwood payments sent with the zero outgoing viewing
//! key, keyed by receiver. Lookups use PIR, so the directory does not learn which
//! receivers the wallet holds. A publication is used only at a block the wallet
//! scanned, and the wallet authenticates every payment with its derived key and its
//! own chain before crediting it.
//!
//! `fetch_seen` downloads the swap provider seen sets that a wallet checks before
//! issuing a swap address. The `wallet` feature adds `sweep`, which runs these lookups
//! for any wallet store that implements the backend's `DynamicIvkWrite`. The caller
//! supplies transports, which carry its route policy, cancellation and timeouts, and a
//! `WriteLock` that serializes wallet writes with its other writers. Dropping a `sweep`
//! future at any await is safe: each wallet step commits on its own, and every begun
//! attempt is already backed off.

mod seen;
#[cfg(feature = "wallet")]
mod sweep;
pub use seen::{Seen, fetch_seen};
#[cfg(feature = "wallet")]
pub use sweep::{EnhanceNotes, Error, NoteSource, Swept, WriteLock, sweep};

pub use receiver_pir::{Error as DirectoryError, transport::Transport};
/// The directory format and client underneath, for callers that need them directly.
pub use {receiver_directory, receiver_pir};

/// Zcash mainnet's genesis block hash, in internal byte order, which its directory
/// publications commit to.
pub const MAINNET_GENESIS: [u8; 32] = [
    0x08, 0xce, 0x3d, 0x97, 0x31, 0xb0, 0x00, 0xc0, 0x83, 0x38, 0x45, 0x5c, 0x8a, 0x4a, 0x6b, 0xd0,
    0x5d, 0xa1, 0x6e, 0x26, 0xb1, 0x1d, 0xaa, 0x1b, 0x91, 0x71, 0x84, 0xec, 0xe8, 0x0f, 0x04, 0x00,
];
