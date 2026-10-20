//! Experimental one-time IVKs: Ironwood receiving keys that share an account's
//! spending authority, each with its own incoming viewing key.
//!
//! The crate root derives keys ([`KeyId`]), and [`swap`] holds the swap conventions
//! built on them: the refund memo that lets a restore find refund keys and the
//! provider-neutral operation observations.
//!
//! This implements a draft wallet convention, not a consensus key derivation.
//! It must not be used to issue live addresses before review.
//! Wallets find payments to these keys through PIR rather than ordinary scanning.
//! They own durable index reservation, authenticated funding-note provenance, PIR
//! payment authentication and ordinary note accounting. This crate owns derivation,
//! memo formats and normalized observations so wallets can share those rules.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod swap;

mod keys;

pub use keys::{DerivationError, KeyId, Purpose};
