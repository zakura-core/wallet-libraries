//! Note commitment tree position tracking.
//!
//! A note's position is the number of commitments that preceded it in its
//! pool's tree. Detection derives that by starting from the tree size at the
//! previous block and counting actions forward, then checks the result against
//! the size the block itself claims.
//!
//! That final check is the load-bearing part. If a source omits one action, the
//! derived positions of every later note are one too low, and every witness
//! built from them is wrong. Nothing downstream notices: the notes decrypt, the
//! balances look right, and the failure only surfaces when a spend proof is
//! rejected by consensus, potentially months later. Comparing the derived count
//! against the block's own tree size is what turns that into an error here.

use std::marker::PhantomData;

use incrementalmerkletree::Position;
use zakura_wallet_core::{
    CompactBlock, CompactTx,
    pool::{ShieldedPool, TreeSizes},
};
use zcash_protocol::consensus::{BlockHeight, Parameters};

use crate::error::ScanError;

/// Tracks one pool's position within its commitment tree across a block.
#[derive(Debug)]
pub(crate) struct PositionTracker<P> {
    /// The number of commitments before the next action to be processed.
    position: u32,
    /// The tree size this block must end at.
    final_size: u32,
    at_height: BlockHeight,
    pool: PhantomData<P>,
}

impl<P: ShieldedPool> PositionTracker<P> {
    /// Starts tracking `block`, given the tree sizes at the end of its
    /// predecessor.
    ///
    /// Returns an error if the block contains actions for a pool that has not
    /// activated, or if applying its actions would overflow the tree size.
    pub(crate) fn start<Params: Parameters>(
        params: &Params,
        prior: &TreeSizes,
        block: &CompactBlock,
    ) -> Result<Self, ScanError> {
        let at_height = block.height;
        let start = P::tree_size(prior);

        let action_count: u32 = block
            .txs
            .iter()
            .map(|tx| P::actions(tx).len())
            .try_fold(0u32, |acc, n| {
                u32::try_from(n)
                    .ok()
                    .and_then(|n| acc.checked_add(n))
                    .ok_or(ScanError::TreeSizeOverflow {
                        pool: P::ID,
                        at_height,
                    })
            })?;

        // Consensus forbids actions for a pool below its activation height.
        // Accepting them would mean deriving positions in a tree that does not
        // yet exist, so this is rejected rather than tolerated.
        if action_count > 0
            && let Some(activation) = P::activation_height(params)
            && at_height < activation
        {
            return Err(ScanError::ActionsBeforeActivation {
                pool: P::ID,
                at_height,
                activation_height: activation,
            });
        }

        let final_size = start
            .checked_add(action_count)
            .ok_or(ScanError::TreeSizeOverflow {
                pool: P::ID,
                at_height,
            })?;

        Ok(Self {
            position: start,
            final_size,
            at_height,
            pool: PhantomData,
        })
    }

    /// Returns the tree position of the action at `action_index` in the
    /// transaction currently being processed.
    pub(crate) fn note_position(&self, action_index: usize) -> Position {
        Position::from(u64::from(self.position) + action_index as u64)
    }

    /// Returns whether `tx` contains this block's final commitment for the pool.
    ///
    /// The last commitment in a block carries the tree checkpoint for that
    /// height, which is what a rewind to this height later rolls back to.
    pub(crate) fn contains_final_action(&self, tx: &CompactTx) -> bool {
        let n = P::actions(tx).len() as u32;
        n > 0 && self.position + n == self.final_size
    }

    /// Advances past `tx`.
    pub(crate) fn advance_over(&mut self, tx: &CompactTx) {
        self.position += P::actions(tx).len() as u32;
    }

    /// Returns the tree size this block ends at.
    pub(crate) fn final_size(&self) -> u32 {
        self.final_size
    }

    /// Checks the derived tree size against the size the block claims.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::advance_over`] was not called for every transaction in
    /// the block, which would be a bug in this crate rather than bad input.
    pub(crate) fn finish(self, claimed: &TreeSizes) -> Result<(), ScanError> {
        assert_eq!(
            self.position, self.final_size,
            "every transaction in the block must be advanced over before finishing",
        );

        let given = P::tree_size(claimed);
        if given == self.final_size {
            Ok(())
        } else {
            Err(ScanError::TreeSizeMismatch {
                pool: P::ID,
                at_height: self.at_height,
                given,
                computed: self.final_size,
            })
        }
    }
}
