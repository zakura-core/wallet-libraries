//! Compact-block detection for the Zakura wallet.
//!
//! This crate answers one question: given some viewing keys and a run of
//! compact blocks, what did those blocks contain that this wallet cares about?
//!
//! [`detect_batch`] is a pure function of its arguments. It has no database
//! handle, performs no I/O, and is deterministic. That is what makes the rest of
//! the wallet tractable: detection can be exercised against a synthetic chain
//! with no storage in the dependency graph, its output compared as a value, and
//! its results re-derived identically after a reorg.
//!
//! Both shielded pools go through one code path, parameterised by
//! [`zakura_wallet_core::ShieldedPool`]. Transparent detection is deliberately
//! separate: it is set membership over scripts and outpoints, with no trial
//! decryption, no tree and no nullifiers.

#![deny(missing_docs)]
#![deny(unsafe_code)]

mod detect;
mod error;
mod keys;
mod position;
mod transparent;

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing;

pub use detect::detect_batch;
pub use error::ScanError;
pub use keys::ScanKeys;

// Re-exported so a consumer of the scanner does not have to name `core` as
// well; these types are the scanner's output, but the vocabulary is shared.
pub use zakura_wallet_core::{
    AccountId, BlockAnchor, DetectedBatch, DetectedBlock, DetectedNote, DetectedSpend,
    DetectedTransparentOutput, DetectedTx, EnhanceCandidate, KeyScope, NullifierSnapshot,
    PoolCommitments,
};
pub use transparent::TransparentWatch;
