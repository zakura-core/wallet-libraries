//! Recovery of a seed's one-time keys through a receiver directory over PIR.
//!
//! A wallet cannot rescan public history for every key its seed may have used, so it tests
//! its receivers against a receiver directory's public paid sets and looks up the paid
//! ones: the directory is a public index of Ironwood payments sent with the zero outgoing
//! viewing key, keyed by receiver. Lookups use PIR, so a lookup does not reveal which
//! receiver it reads. Whether and when the wallet looks up is not hidden: it follows the
//! paid sets and retries failed lookups, so a dishonest directory that changes what it
//! serves can test whether the wallet holds a receiver it chose. The wallet judges each
//! publication against its own chain and authenticates every payment with its derived key
//! before crediting it.
//!
//! Recovery tests receivers locally against objects every wallet downloads alike on a
//! common schedule: the catalog head, closed paid buckets, cumulative paid snapshots and
//! the seen set. Those downloads reveal no membership, though one triggered by a window's
//! growth reveals activity. A lookup after a bucket hit points to the receivers paid in
//! that bucket, so repeated payments allow intersection.
//!
//! Once the wallet holds a payment recovery found, it is an ordinary note: its
//! enhancement, scan priority and any rebroadcast follow as for any note. So when a
//! directory's answer is wrong, traffic to the wallet's other services can differ from an
//! honest answer's, another route to the test above.
//!
//! `fetch_seen` downloads the seen set that a wallet checks before issuing a swap address.
//! The `wallet` feature adds `recover` and `check_history`, which run recovery for any
//! wallet store that implements the backend's `OneTimeIvkCoverageWrite` and
//! `OneTimeIvkRestoreWrite`. The caller supplies transports, which carry its route policy,
//! cancellation and timeouts, and a `WriteLock` that serializes wallet writes with its
//! other writers. Dropping either future at any await is safe: each wallet step commits on
//! its own.

#[cfg(feature = "wallet")]
mod recovery;
mod seen;
#[cfg(feature = "wallet")]
mod session;
#[cfg(feature = "wallet")]
pub use recovery::{
    DERIVE_PER_RUN, Delay, OBJECTS_PER_RUN, Recovered, SEEN_REFRESH_SECS, check_history, recover,
};
pub use seen::{Seen, fetch_seen};
#[cfg(feature = "wallet")]
pub use session::{Error, WriteLock};

pub use receiver_pir::{Error as DirectoryError, transport::Transport};
/// The directory format and client underneath, for callers that need them directly.
/// They parse records and witness files structurally only: records from
/// `DirectoryClient::page` and the bytes from `DirectoryClient::witnesses` are
/// unchecked. Validate them with `zakura-receiver-crypto`, as `recover` does, before use.
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
