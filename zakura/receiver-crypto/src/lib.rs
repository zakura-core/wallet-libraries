//! Cryptographic validation for receiver directory data.
//!
//! A receiver directory publishes, per Ironwood receiver, the compact payments that
//! were sent to it with the public all-zero outgoing viewing key, together with one
//! common file of Merkle siblings that proves those payments' note commitments are in
//! the pool's commitment tree. The PIR layer (`receiver-wire` and the serving crates
//! in wallet-pir) moves these bytes without interpreting them; this crate is where
//! they are trusted or refused:
//!
//! - [`Receiver`] accepts only bytes that decode to an Ironwood address, and reads
//!   and writes the Ironwood receiver of a unified address.
//! - [`Record`] decodes and encodes one row slot through `receiver-wire`'s codec, and
//!   additionally refuses noncanonical note commitments and nullifiers and invalid
//!   ephemeral keys.
//! - [`recovery::Action`] recovers a payment's receiver with the zero outgoing viewing
//!   key, authenticating the note plaintext.
//! - [`witness`] builds and checks the common inclusion-proof file.
//!
//! The types here are owned by this crate. Callers holding their own copy of the
//! receiver protocol structs map fields, or decode the fixed canonical bytes, rather
//! than share struct identities across crate sources.
#![forbid(unsafe_code)]

mod address;
mod record;
pub mod recovery;
pub mod witness;

pub use address::Network;
pub use record::{Payment, RECORD_BYTES, Receiver, Record};

/// A 32-byte hash in protocol byte order.
pub type Hash = [u8; 32];

/// Why receiver data was refused.
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
