//! Experimental one-time IVKs: Ironwood receiving keys that share an account's
//! spending authority, each with its own incoming viewing key.
//!
//! The crate root derives keys ([`KeyId`]), and [`swap`] holds the swap conventions
//! built on them: the refund memo that lets a restore find refund keys and the
//! completion policy.
//!
//! This implements a draft wallet convention, not a consensus key derivation.
//! It must not be used to issue live addresses before review.
//! Wallets own durable index reservation, authenticated funding-note provenance,
//! scanning coverage, and ordinary note accounting. This crate owns derivation,
//! byte formats, and completion policy so wallets can share those rules.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod swap;

mod keys;

pub use keys::{DerivationError, KeyId, Purpose};
