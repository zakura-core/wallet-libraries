//! Receiver record encoding and cryptographic validation.
//!
//! [`wire`] owns the fixed record format. Its raw records contain untrusted bytes:
//! structural parsing does not check addresses, field elements or ephemeral keys.
//! The codec has no dependencies and is available with default features disabled.
//!
//! The default `crypto` feature adds validated `Receiver`, `Record` and `Payment`
//! APIs, authenticated zero-OVK receiver recovery, and inclusion proof construction
//! and verification. These checks must finish before a caller accepts a payment;
//! a proof root must additionally match the caller's independently accepted chain.
#![forbid(unsafe_code)]

#[cfg(feature = "crypto")]
mod address;
#[cfg(feature = "crypto")]
mod record;
#[cfg(feature = "crypto")]
pub mod recovery;
pub mod wire;
#[cfg(feature = "crypto")]
pub mod witness;

#[cfg(feature = "crypto")]
pub use address::Network;
#[cfg(feature = "crypto")]
pub use record::{Payment, Receiver, Record};
pub use wire::RECORD_BYTES;

/// A 32-byte hash in protocol byte order.
pub type Hash = [u8; 32];

/// Why receiver data was refused.
#[cfg(feature = "crypto")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Bytes that are not a valid encoding, address, field element or proof.
    #[error("malformed receiver directory data")]
    Malformed,
    /// A proof that does not cover the requested publication, position or records.
    #[error("receiver directory coverage is incomplete or uses a different anchor")]
    Coverage,
    /// A proof file over [`witness::MAX_WITNESS_BYTES`].
    #[error("receiver directory witness limit exceeded")]
    Capacity,
}
