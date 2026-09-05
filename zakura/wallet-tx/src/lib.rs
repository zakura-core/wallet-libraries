//! Building transactions.
//!
//! This crate turns notes the wallet holds into a proven, verifiable bundle. It
//! is kept apart from the rest of the core because it is the only part that
//! needs the proving stack: keeping it out means a watch-only build, and the
//! scanner's own test suite, never pay for halo2.
//!
//! What it does *not* do is decide policy. Which notes to spend, what to pay
//! and what the fee is are settled in [`Proposal`] before any proving starts,
//! so the expensive step runs once against a plan that is already known to
//! balance.

#![deny(missing_docs)]
#![deny(unsafe_code)]

mod build;
pub mod crossing;
mod error;
pub mod fee;
mod select;
pub mod transaction;
mod witness;

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing;

pub use build::{Keys, SpendRequest, action_counts, bundles, transaction as payment, verify_proofs};
pub use error::Error;
pub use select::{Proposal, SpendableNote, select};
pub use witness::{Anchors, anchors, spendable_notes};
