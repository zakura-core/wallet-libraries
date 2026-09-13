//! Compact block types.
//!
//! These are the wallet's own representation of a compact block, not the
//! protobuf wire types. The network crate parses the wire format into these;
//! everything above the network layer speaks only this vocabulary. Keeping the
//! two apart means a change to the protocol definition cannot ripple into the
//! scanner or the store, and that scanning can be driven from a synthetic chain
//! in tests without a gRPC dependency.

use std::fmt;

use orchard::note_encryption::CompactAction;
use transparent::bundle::{OutPoint, TxOut};
use zcash_protocol::{TxId, consensus::BlockHeight};

use crate::pool::TreeSizes;

/// The hash of a block.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockHash(pub [u8; 32]);

impl fmt::Debug for BlockHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Block hashes are conventionally displayed byte-reversed.
        for b in self.0.iter().rev() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl BlockHash {
    /// Constructs a block hash from bytes in protocol (not display) order.
    ///
    /// Returns `None` if `bytes` is not 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        <[u8; 32]>::try_from(bytes).ok().map(BlockHash)
    }
}

/// A compact block: the subset of a block a wallet needs in order to detect its
/// own activity and to track the note commitment trees.
#[derive(Debug, Clone)]
pub struct CompactBlock {
    /// The height of this block.
    pub height: BlockHeight,
    /// The hash of this block.
    pub hash: BlockHash,
    /// The hash of this block's predecessor.
    ///
    /// Checking this against the previous block is the cheapest reorg detector
    /// available, and it is the reason blocks must be scanned in a contiguous
    /// run rather than independently.
    pub prev_hash: BlockHash,
    /// The block's timestamp, as seconds since the Unix epoch.
    pub time: u32,
    /// The size of each pool's note commitment tree as of the end of this block.
    ///
    /// The scanner derives each note's tree position from the previous block's
    /// sizes and cross-checks the result against these, which is what catches a
    /// server that omits an action and shifts every later position by one.
    pub tree_sizes: TreeSizes,
    /// The wallet-relevant transactions in this block, in block order.
    pub txs: Vec<CompactTx>,
}

/// A compact transaction.
///
/// Both shielded pools appear here, and always together: a stream filtered to
/// one pool cannot establish that a transaction touches no other, which is a
/// prerequisite for the private-enhancement routing decision. See
/// `docs/zakura_pir_enhance.md`.
#[derive(Debug, Clone)]
pub struct CompactTx {
    /// The index of this transaction within its block.
    ///
    /// Index 0 is the coinbase transaction.
    pub index: u64,
    /// The transaction's identifier.
    pub txid: TxId,
    /// The transaction's Orchard actions, in bundle order.
    pub orchard_actions: Vec<CompactAction>,
    /// The transaction's Ironwood actions, in bundle order.
    ///
    /// An Orchard action and an Ironwood action in the same transaction can
    /// share an index, which is why stored notes are keyed by pool as well as
    /// by action index.
    pub ironwood_actions: Vec<CompactAction>,
    /// The outpoints this transaction spends.
    ///
    /// The null outpoint of a coinbase transaction is omitted; test
    /// `index == 0` to recognise a coinbase.
    pub vin: Vec<OutPoint>,
    /// The transparent outputs this transaction creates.
    pub vout: Vec<TxOut>,
}
