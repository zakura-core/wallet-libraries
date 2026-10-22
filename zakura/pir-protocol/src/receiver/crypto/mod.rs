//! Receiver cryptographic validation over the [`wire`](super::wire) codec.
//!
//! Validated `Receiver`, `Record` and `Payment` APIs, authenticated zero-OVK receiver
//! recovery, and checked note-tree hashing for companion witness tables. These checks
//! must finish before a caller accepts a payment; a path must additionally reach the
//! caller's independently accepted root.
mod address;
mod record;
pub mod recovery;
pub mod witness;

use super::Hash;
pub use super::wire::RECORD_BYTES;
pub use address::Network;
pub use record::{Payment, Receiver, Record};

/// Why receiver data was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Bytes that are not a valid encoding, address, field element or proof.
    #[error("malformed receiver directory data")]
    Malformed,
    /// A position outside the commitments a path is built from.
    #[error("receiver directory coverage is incomplete or uses a different anchor")]
    Coverage,
    /// More commitments than one Ironwood shard holds.
    #[error("receiver directory witness limit exceeded")]
    Capacity,
}
