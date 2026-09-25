//! Experimental v1 swap receiving keys and refund recovery memos.
//!
//! This implements a draft wallet convention, not a consensus key derivation.
//! It is unpublished and must not be used to issue live addresses before review.
//! Wallets own durable index reservation, authenticated funding-note provenance,
//! scanning coverage, and ordinary note accounting. This crate owns the shared
//! byte formats and derivation so those rules need not be reimplemented in a UI.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod keys;
mod memo;

pub use keys::{
    DerivationError, KeyId, Purpose, derive_full_viewing_key, has_same_spending_authority,
};
pub use memo::{MemoError, RefundMemo};
