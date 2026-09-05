//! Errors detection can return.

use std::fmt;

use zakura_wallet_core::{PoolId, scanning::ScanRange};
use zcash_protocol::consensus::BlockHeight;

/// A failure encountered while detecting wallet activity in a batch of blocks.
///
/// Every variant aborts the whole batch. Detection never returns partial
/// results: a batch that cannot be interpreted end to end tells us nothing
/// trustworthy about any block in it, because positions in the later blocks are
/// derived from the earlier ones.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScanError {
    /// A block's `prev_hash` does not match the hash of the block before it.
    ///
    /// Either the chain reorganised under us, or the source is inconsistent.
    PrevHashMismatch {
        /// The height of the block whose parent did not match.
        at_height: BlockHeight,
    },

    /// A block's height is not one more than its predecessor's.
    BlockHeightDiscontinuity {
        /// The height of the preceding block.
        prev_height: BlockHeight,
        /// The height claimed by the block that broke the sequence.
        new_height: BlockHeight,
    },

    /// A block's stated tree size for a pool disagrees with the size computed
    /// by counting that pool's actions in the block.
    ///
    /// This is the check that catches a source which omits an action: doing so
    /// shifts every later note's position by one, which silently invalidates
    /// every witness derived from this point on. Nothing downstream would
    /// notice until a spend proof failed to verify.
    TreeSizeMismatch {
        /// The pool whose tree size disagreed.
        pool: PoolId,
        /// The height of the offending block.
        at_height: BlockHeight,
        /// The size the block claimed.
        given: u32,
        /// The size implied by the actions the block actually contained.
        computed: u32,
    },

    /// Applying a block's actions would take a pool's tree size beyond `u32`.
    TreeSizeOverflow {
        /// The pool whose tree overflowed.
        pool: PoolId,
        /// The height of the offending block.
        at_height: BlockHeight,
    },

    /// A block below a pool's activation height contained actions for it.
    ///
    /// Consensus forbids this, so a source that produces it is faulty or
    /// hostile. Accepting it would mean deriving positions in a tree that does
    /// not yet exist.
    ActionsBeforeActivation {
        /// The pool whose actions appeared too early.
        pool: PoolId,
        /// The height of the offending block.
        at_height: BlockHeight,
        /// The height at which that pool activates.
        activation_height: BlockHeight,
    },
}

impl ScanError {
    /// Returns whether this error indicates the chain moved under us, rather
    /// than that the data was malformed.
    ///
    /// A continuity error is handled by rewinding and rescanning; the others
    /// mean the source cannot be trusted for this range and retrying the same
    /// data will fail the same way.
    pub fn is_continuity_error(&self) -> bool {
        match self {
            ScanError::PrevHashMismatch { .. } | ScanError::BlockHeightDiscontinuity { .. } => true,
            ScanError::TreeSizeMismatch { .. } => true,
            ScanError::TreeSizeOverflow { .. } | ScanError::ActionsBeforeActivation { .. } => false,
        }
    }

    /// Returns the height of the block at which detection failed.
    pub fn at_height(&self) -> BlockHeight {
        match self {
            ScanError::PrevHashMismatch { at_height }
            | ScanError::TreeSizeMismatch { at_height, .. }
            | ScanError::TreeSizeOverflow { at_height, .. }
            | ScanError::ActionsBeforeActivation { at_height, .. } => *at_height,
            ScanError::BlockHeightDiscontinuity { new_height, .. } => *new_height,
        }
    }

    /// Returns the range that must be rescanned to recover from this error, if
    /// rescanning can recover from it at all.
    ///
    /// Only continuity errors are recoverable this way, and the caller decides
    /// how far below the failure to rewind; this returns the failing block
    /// alone, which is the smallest range that must be redone.
    pub fn rescan_range(&self, priority: zakura_wallet_core::scanning::ScanPriority) -> Option<ScanRange> {
        self.is_continuity_error().then(|| {
            let h = self.at_height();
            ScanRange::from_parts(h..(h + 1), priority)
        })
    }
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::PrevHashMismatch { at_height } => write!(
                f,
                "the parent hash of the block at height {at_height} does not match its predecessor"
            ),
            ScanError::BlockHeightDiscontinuity {
                prev_height,
                new_height,
            } => write!(
                f,
                "block height discontinuity at {new_height}; the previous block was {prev_height}"
            ),
            ScanError::TreeSizeMismatch {
                pool,
                at_height,
                given,
                computed,
            } => write!(
                f,
                "the block at height {at_height} claims a {pool:?} tree size of {given}, \
                 but its actions imply {computed}"
            ),
            ScanError::TreeSizeOverflow { pool, at_height } => write!(
                f,
                "the {pool:?} tree size overflows a u32 at height {at_height}"
            ),
            ScanError::ActionsBeforeActivation {
                pool,
                at_height,
                activation_height,
            } => write!(
                f,
                "the block at height {at_height} contains {pool:?} actions, but {pool:?} \
                 does not activate until height {activation_height}"
            ),
        }
    }
}

impl std::error::Error for ScanError {}
