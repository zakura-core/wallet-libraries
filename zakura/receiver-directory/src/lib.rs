//! Receiver discovery records. A match is a candidate, never proof of ownership or spendability.
//!
//! This crate places, stores and parses records structurally; it checks no
//! cryptography. Callers validate receivers, Action fields and inclusion proofs at
//! their trust boundaries.
pub mod blocks;
pub mod filter;
mod gcs;
mod object;
pub mod record;
pub mod seen;
pub mod snapshot;

pub use record::{Payment, RawRecord, ReceiverBytes, RECORD_BYTES};
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
    #[error("missing continuation page")]
    MissingPage,
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
