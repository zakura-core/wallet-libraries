//! Experimental dynamic IVKs: Ironwood receiving keys that share an account's
//! spending authority, each with its own incoming viewing key, and the refund memo
//! that lets a restore find refund keys.
//!
//! This implements a draft wallet convention, not a consensus key derivation.
//! It is unpublished and must not be used to issue live addresses before review.
//! Wallets own durable index reservation, authenticated funding-note provenance,
//! scanning coverage, and ordinary note accounting. This crate owns derivation,
//! byte formats, and completion policy so wallets can share those rules.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod lifecycle;
pub mod recovery;

mod keys;
mod memo;

pub use keys::{DerivationError, KeyId, Purpose, has_same_spending_authority};
pub use memo::{REFUND_MEMO_MAGIC, RefundMemo};
