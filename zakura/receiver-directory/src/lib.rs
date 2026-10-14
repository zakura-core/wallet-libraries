//! Receiver discovery records. A match is a candidate, never proof of ownership or spendability.
pub mod extract;
pub mod filter;
pub mod record;
pub mod snapshot;
#[cfg(feature = "test-support")]
pub mod test_support;
pub mod witness;

pub use record::{Payment, RECORD_BYTES, Receiver, Record};
/// A 32-byte hash in protocol byte order.
pub type Hash = [u8; 32];

/// Why directory data or coverage was rejected.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("malformed receiver directory data")]
    Malformed,
    #[error("receiver directory coverage is incomplete or uses a different anchor")]
    Coverage,
    #[error("receiver directory table or witness limit exceeded")]
    Capacity,
    #[error("missing continuation page")]
    MissingPage,
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
