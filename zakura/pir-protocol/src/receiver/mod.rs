//! Receiver directory formats, PIR sessions and inventories shared by every role.
//!
//! A match is a candidate, never proof of ownership or spendability. Everything here
//! except [`crypto`] parses structure only and checks no cryptography: callers validate
//! receivers, Action fields and inclusion proofs at their trust boundaries.
pub mod blocks;
#[cfg(feature = "receiver-crypto")]
pub mod crypto;
mod gcs;
pub mod inventory;
#[cfg(feature = "native")]
pub mod native;
pub mod record;
pub mod session;
pub mod shards;
pub mod snapshot;
pub mod v2;
pub mod wire;
pub mod witness;

pub use record::{Payment, RECORD_BYTES, RawRecord, ReceiverBytes};
/// A 32-byte hash in protocol byte order.
pub type Hash = [u8; 32];

/// Why directory data or coverage was rejected.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("malformed receiver directory data")]
    Malformed,
    #[error("receiver directory coverage is incomplete or uses a different anchor")]
    Coverage,
    #[error("receiver directory table or commitment history limit exceeded")]
    Capacity,
    /// No candidate seed built a v2 segment's choice table.
    #[error("receiver choice table could not be built")]
    Choice,
    #[error("missing continuation page")]
    MissingPage,
    /// A payment or witness profile, or a record version, that a newer client supports.
    #[error("receiver directory format needs a newer client")]
    Unsupported,
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
