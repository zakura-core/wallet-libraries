//! Candidate transparent recovery records, independent of wallet storage and proving.
//!
//! Records describe observations; accepting them never establishes financial authority.
//! Hash-bearing records are generic so existing wallet APIs can retain their hash type.

use zcash_protocol::consensus::BlockHeight;

mod block_hash;
pub use block_hash::RecoveryBlockHash;
#[cfg(feature = "transparent-inputs")]
mod mapping;
mod metadata;
pub use metadata::{TransactionMetadata, WholeTransactionFee};
#[cfg(feature = "transparent-inputs")]
mod records;
#[cfg(feature = "transparent-inputs")]
pub use records::*;

/// A locally accepted block: its height and the hash the wallet holds for that height.
///
/// Coverage through `H` can support a transaction targeting `H + 1`; the future block has
/// no accepted hash to check. A publisher's asserted hash never substitutes for a local one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChainPoint<Hash = RecoveryBlockHash> {
    /// Height of the accepted block.
    pub height: BlockHeight,
    /// The wallet's hash for the block at `height`.
    pub hash: Hash,
}

/// Why candidate recovery for an account is not yet complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CandidateBlocker {
    /// No local target exists.
    ChainUnknown,
    /// Some watched address lacks continuous coverage from its required start to the target.
    IncompleteCoverage,
    /// Pages remain open.
    PendingPages,
    /// A mined spend consumes an output that has not been recovered.
    UnresolvedSpends,
    /// A range recorded as unsupported is not covered by any source.
    UnsupportedRanges,
    /// Activity near the end of a derived window needs addresses that this account's keys
    /// cannot derive, or reaches the last non-hardened index, which the wallet cannot store.
    WindowUnderivable,
}
