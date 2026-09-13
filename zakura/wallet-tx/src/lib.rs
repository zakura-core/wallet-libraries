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
pub mod circuit;
pub mod crossing;
mod error;
pub mod fee;
mod shield;
mod select;
pub mod transaction;
mod witness;

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing;

/// The memo field of an output carrying no memo.
///
/// Per ZIP 302 the lead byte says how a memo is read: `0xF6` followed by zeros
/// means "no memo", while a lead byte below `0xF5` makes it UTF-8 text. An
/// all-zero field is therefore not an absent memo but an empty *text* one, and
/// a recipient's wallet renders it as a message rather than skipping it. The
/// difference is visible to whoever is paid, so it is worth getting right.
pub const NO_MEMO: [u8; 512] = {
    let mut memo = [0u8; 512];
    memo[0] = 0xF6;
    memo
};

pub use build::{
    Keys, SpendRequest, action_counts, bundles, transaction as payment, transparent_bundle,
    verify_proofs,
};
pub use error::Error;
pub use shield::{default_policy, max_inputs, plan_shielding};
pub use select::{Proposal, SpendableNote, plan_transparent_payment, select};
pub use witness::{Anchors, anchors, crossing_anchors, spendable_notes};
