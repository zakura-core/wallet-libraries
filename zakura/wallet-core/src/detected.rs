//! What a detection pass produces, and the state it needs to run.
//!
//! Everything here is a plain owned value with no lifetimes, no database handle
//! and no interior mutability. That is deliberate: it makes a
//! [`DetectedBatch`] something a test can construct, compare and store as a
//! fixture, and it means the boundary between detection and storage is a data
//! boundary rather than a trait boundary.

use std::collections::HashMap;

use incrementalmerkletree::{Position, Retention};
use orchard::note::{ExtractedNoteCommitment, Note, Nullifier};
use transparent::bundle::{OutPoint, TxOut};
use crate::{
    account::{AccountId, KeyScope},
    block::BlockHash,
    pool::{PoolId, TreeSizes},
};
use zcash_protocol::{TxId, consensus::BlockHeight};


/// The state of the chain immediately before a batch of blocks.
///
/// Detection cannot start from nothing: note positions are offsets into trees
/// whose size at the previous block must already be known, and the continuity
/// check needs the previous block's hash. For a range starting at the wallet's
/// birthday this comes from the server's tree state at `birthday - 1`;
/// otherwise it comes from the wallet's own record of the preceding block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockAnchor {
    /// The height of the block preceding the batch.
    pub height: BlockHeight,
    /// The hash of the block preceding the batch.
    pub hash: BlockHash,
    /// Each pool's tree size as of the end of that block.
    pub tree_sizes: TreeSizes,
}

/// The wallet's unspent nullifiers, as of some point in time.
///
/// This is an immutable snapshot rather than a live view, which is what lets
/// detection be a pure function. It carries an `epoch` so the writer can tell
/// whether the wallet moved on while the batch was in flight; if it did, the
/// writer re-runs the cheap nullifier-to-note linking step against current data
/// inside the same transaction that applies the batch.
#[derive(Debug, Clone, Default)]
pub struct NullifierSnapshot {
    // `Nullifier` is `Eq` but not `Hash`, and its byte encoding is canonical,
    // so that is what keys the map.
    orchard: HashMap<[u8; 32], AccountId>,
    ironwood: HashMap<[u8; 32], AccountId>,
    epoch: u64,
}

impl NullifierSnapshot {
    /// Builds a snapshot from the wallet's unspent notes.
    pub fn new(
        epoch: u64,
        entries: impl IntoIterator<Item = (PoolId, Nullifier, AccountId)>,
    ) -> Self {
        let mut snapshot = Self {
            epoch,
            ..Default::default()
        };
        for (pool, nf, account) in entries {
            snapshot.insert(pool, nf, account);
        }
        snapshot
    }

    /// Returns the epoch at which this snapshot was taken.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Records a nullifier discovered mid-batch.
    ///
    /// Detection keeps a local overlay over the caller's snapshot so that a note
    /// received in one block can be seen spent in a later block of the same
    /// batch.
    pub fn insert(&mut self, pool: PoolId, nf: Nullifier, account: AccountId) {
        self.map_mut(pool).insert(nf.to_bytes(), account);
    }

    /// Returns the account owning the note with this nullifier, if the wallet
    /// knows of one.
    pub fn get(&self, pool: PoolId, nf: &Nullifier) -> Option<AccountId> {
        self.map(pool).get(&nf.to_bytes()).copied()
    }

    /// Returns the number of tracked nullifiers for a pool.
    pub fn len(&self, pool: PoolId) -> usize {
        self.map(pool).len()
    }

    /// Returns whether a pool has no tracked nullifiers.
    pub fn is_empty(&self, pool: PoolId) -> bool {
        self.map(pool).is_empty()
    }

    fn map(&self, pool: PoolId) -> &HashMap<[u8; 32], AccountId> {
        match pool {
            PoolId::Orchard => &self.orchard,
            PoolId::Ironwood => &self.ironwood,
        }
    }

    fn map_mut(&mut self, pool: PoolId) -> &mut HashMap<[u8; 32], AccountId> {
        match pool {
            PoolId::Orchard => &mut self.orchard,
            PoolId::Ironwood => &mut self.ironwood,
        }
    }
}

/// Everything a batch of blocks told us.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectedBatch {
    /// The chain state the batch was scanned against.
    ///
    /// Storage needs this as well as the results: a batch is inserted into the
    /// commitment trees at an explicit position, and this is where that position
    /// starts. Appending would only work for a batch that continues from the
    /// tree's current tip, which under descending recovery it usually does not.
    pub start_anchor: BlockAnchor,
    /// One entry per block scanned, in ascending height order.
    pub blocks: Vec<DetectedBlock>,
    /// The chain state after the last block, ready to anchor the next batch.
    pub end_anchor: BlockAnchor,
    /// The epoch of the nullifier snapshot detection ran against.
    ///
    /// The writer compares this with the wallet's current epoch to decide
    /// whether spend linking must be redone against fresher data.
    pub snapshot_epoch: u64,
}

impl DetectedBatch {
    /// Returns every note received across the batch.
    pub fn received_notes(&self) -> impl Iterator<Item = &DetectedNote> {
        self.blocks
            .iter()
            .flat_map(|b| b.transactions.iter())
            .flat_map(|tx| tx.received.iter())
    }

    /// Returns every wallet note spend detected across the batch.
    pub fn spends(&self) -> impl Iterator<Item = &DetectedSpend> {
        self.blocks
            .iter()
            .flat_map(|b| b.transactions.iter())
            .flat_map(|tx| tx.spends.iter())
    }
}

/// One block's worth of detection results.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectedBlock {
    /// The block's height.
    pub height: BlockHeight,
    /// The block's hash.
    pub hash: BlockHash,
    /// The block's timestamp.
    pub time: u32,
    /// Each pool's tree size as of the end of this block.
    pub tree_sizes: TreeSizes,
    /// Transactions in which this wallet had activity, in block order.
    ///
    /// Transactions with no wallet relevance are dropped; their commitments
    /// are still recorded, because the trees must track the chain regardless
    /// of whose notes they contain.
    pub transactions: Vec<DetectedTx>,
    /// Orchard note commitments created by this block, in tree order.
    pub orchard: PoolCommitments,
    /// Ironwood note commitments created by this block, in tree order.
    pub ironwood: PoolCommitments,
}

impl DetectedBlock {
    /// Returns the commitments for the given pool.
    pub fn commitments(&self, pool: PoolId) -> &PoolCommitments {
        match pool {
            PoolId::Orchard => &self.orchard,
            PoolId::Ironwood => &self.ironwood,
        }
    }
}

/// A pool's commitment and nullifier output for one block.
#[derive(Debug, Clone, PartialEq)]
pub struct PoolCommitments {
    /// Every note commitment the block appended to this pool's tree, in order,
    /// each with the retention the tree should give it.
    ///
    /// Commitments for notes this wallet owns are [`Retention::Marked`] so a
    /// witness can be produced later; the final commitment in the block also
    /// carries a checkpoint at the block height, which is what makes a precise
    /// rewind to this height possible.
    pub commitments: Vec<(ExtractedNoteCommitment, Retention<BlockHeight>)>,
    /// This pool's tree size as of the end of the block.
    pub final_tree_size: u32,
    /// Nullifiers revealed by the block that matched none of the wallet's
    /// known notes, keyed by the transaction that revealed them.
    ///
    /// These are not noise. A wallet recovering descending sees a note's spend
    /// before it sees the note; storing these is what lets the spend be linked
    /// when the note is finally found.
    pub unlinked_nullifiers: Vec<(u64, TxId, Vec<Nullifier>)>,
}

/// One transaction in which the wallet had activity.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectedTx {
    /// The transaction's index within its block.
    pub index: u64,
    /// The transaction's identifier.
    pub txid: TxId,
    /// Notes this wallet received.
    pub received: Vec<DetectedNote>,
    /// Wallet notes this transaction spent.
    pub spends: Vec<DetectedSpend>,
    /// Transparent outputs paid to addresses the wallet is watching.
    pub transparent_received: Vec<DetectedTransparentOutput>,
    /// Transparent outputs of the wallet's that this transaction spent.
    pub transparent_spends: Vec<OutPoint>,
    /// Ironwood actions that may hide outgoing data this wallet can recover.
    ///
    /// Captured during scanning because they cannot be reconstructed later
    /// without the raw transaction — which is precisely what private
    /// enhancement exists to avoid fetching. See `docs/zakura_pir_enhance.md`.
    pub enhance_candidates: Vec<EnhanceCandidate>,
}

impl DetectedTx {
    fn is_empty(&self) -> bool {
        self.received.is_empty()
            && self.spends.is_empty()
            && self.transparent_received.is_empty()
            && self.transparent_spends.is_empty()
            && self.enhance_candidates.is_empty()
    }

    /// Returns `None` if this transaction turned out to hold nothing of the
    /// wallet's, so that it can be dropped from the results.
    pub fn into_option(self) -> Option<Self> {
        (!self.is_empty()).then_some(self)
    }
}

/// A note this wallet received.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectedNote {
    /// The pool the note belongs to.
    pub pool: PoolId,
    /// The account that received it.
    pub account: AccountId,
    /// Whether it arrived on the account's external or internal address.
    pub scope: KeyScope,
    /// The note's index within its pool's actions in the transaction.
    ///
    /// An Orchard action and an Ironwood action in the same transaction can
    /// share an index, so this is only unique together with `pool`.
    pub action_index: usize,
    /// The note's position in its pool's commitment tree.
    pub position: Position,
    /// The note itself.
    pub note: Note,
    /// The note's nullifier, derived with the receiving account's key.
    pub nullifier: Nullifier,
    /// Whether the note is change.
    ///
    /// True when the receiving account also spent notes in this transaction,
    /// or when the note arrived on the account's internal address.
    pub is_change: bool,
}

/// A wallet note spent by a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectedSpend {
    /// The pool the spent note belonged to.
    pub pool: PoolId,
    /// The account that owned it.
    pub account: AccountId,
    /// The index of the spending action within its pool's actions.
    pub action_index: usize,
    /// The nullifier revealed by the spend.
    pub nullifier: Nullifier,
}

/// A transparent output paid to an address the wallet watches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedTransparentOutput {
    /// The output's index in the transaction's `vout`.
    pub output_index: u32,
    /// The account whose address was paid.
    ///
    /// Carried from the watch set that matched the script. Without it the store
    /// cannot say whose funds these are, and a multi-account wallet would
    /// attribute every transparent receipt to the same place.
    pub account: AccountId,
    /// Which of that account's addresses was used, if the watch set knew.
    ///
    /// This is what gap-limit maintenance runs on: an address being used is
    /// what obliges the wallet to look further ahead.
    pub address_index: Option<u32>,
    /// The output itself.
    pub txout: TxOut,
}

/// An Ironwood action whose outgoing data this wallet may be able to recover.
///
/// Compact scanning cannot tell a padding dummy from a real output, so every
/// action of a wallet-funded transaction that the wallet did not itself receive
/// becomes a candidate. The fields recorded here are exactly those needed to
/// authenticate a later response against what was scanned.
#[derive(Debug, Clone, PartialEq)]
pub struct EnhanceCandidate {
    /// The action's position in the Ironwood commitment tree.
    ///
    /// This, not the transaction identifier, is what a private lookup sends.
    pub position: Position,
    /// The action's index within the transaction's Ironwood actions.
    pub action_index: usize,
    /// The nullifier the action revealed.
    pub nullifier: Nullifier,
    /// The commitment to the action's output note.
    pub cmx: ExtractedNoteCommitment,
    /// The action's ephemeral public key.
    pub ephemeral_key: [u8; 32],
    /// The 52-byte prefix of the action's note ciphertext.
    ///
    /// Together with the ephemeral key this is what a later response is matched
    /// against: it authenticates the note data, though not the rest of the
    /// record. See `docs/zakura_pir_enhance.md`.
    pub compact_ciphertext: [u8; 52],
    /// The accounts that funded the transaction, whose outgoing viewing keys
    /// are the ones worth trying.
    pub funding_accounts: Vec<AccountId>,
}
