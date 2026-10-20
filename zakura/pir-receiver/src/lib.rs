//! Private receiver lookups over caller-owned transports.
//!
//! Rolling block GCS hints and sealed shard filters are optional bandwidth optimizations.
//! Matches trigger PIR rather than compact scanning. PIR hides the queried address, but query timing is visible.
//! All returned payments require wallet authentication, inclusion and spend checks.
//! Network futures hold no database handle. The caller commits results through the
//! wallet's recovery queue, which fences stale callbacks and enforces the feature toggle.

#[cfg(feature = "wallet")]
mod discovery;
#[cfg(feature = "wallet")]
pub use discovery::{FILTER_STEP_LIMIT, lookup, publication, witness};

pub use receiver_pir::{Error as DirectoryError, transport::Transport};
/// The directory format and client underneath, for callers that need them directly.
/// They parse records and witness payloads structurally only: records from
/// `InventoryClient::page` and payloads from `InventoryClient::witness` are
/// unchecked. Commit them through the wallet recovery queue before crediting funds.
pub use {receiver_directory, receiver_pir};

/// The directory error for data a receiver check refuses: the same error the
/// directory's own decoding gave when it checked receivers, payments and witnesses.
#[cfg(feature = "wallet")]
pub(crate) fn checked(error: zakura_receiver_crypto::Error) -> DirectoryError {
    use zakura_receiver_crypto::Error;
    DirectoryError::Directory(match error {
        Error::Malformed => receiver_directory::Error::Malformed,
        Error::Coverage => receiver_directory::Error::Coverage,
        Error::Capacity => receiver_directory::Error::Capacity,
    })
}

/// Zcash mainnet's genesis block hash, in internal byte order, which its directory
/// publications commit to.
pub const MAINNET_GENESIS: [u8; 32] = [
    0x08, 0xce, 0x3d, 0x97, 0x31, 0xb0, 0x00, 0xc0, 0x83, 0x38, 0x45, 0x5c, 0x8a, 0x4a, 0x6b, 0xd0,
    0x5d, 0xa1, 0x6e, 0x26, 0xb1, 0x1d, 0xaa, 0x1b, 0x91, 0x71, 0x84, 0xec, 0xe8, 0x0f, 0x04, 0x00,
];
