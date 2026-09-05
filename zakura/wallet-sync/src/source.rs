//! The chain source: where compact blocks come from.
//!
//! This is one of only two traits in the wallet core, and it earns that because
//! there are genuinely several implementations: the gRPC client, the in-memory
//! chain the engine is tested against, and later a Tor-wrapped transport.
//!
//! Flow control lives here rather than in the engine. A real implementation
//! reads a server stream and can stop pulling from it once the caller's byte
//! budget is spent; expressing that as "fetch this range, but stop when you
//! have this many bytes" keeps the back-pressure at the boundary that actually
//! has it, and lets the engine bound its memory without knowing how the
//! transport works.

use std::{fmt, ops::Range};

use zakura_wallet_core::{BlockAnchor, BlockHash, CompactBlock};
use zcash_protocol::consensus::BlockHeight;

/// The tip of the chain, as the source sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainTip {
    /// The height of the tip block.
    pub height: BlockHeight,
    /// The hash of the tip block.
    pub hash: BlockHash,
}

/// How much block data the caller is willing to hold at once.
///
/// A count of blocks would not do. Mainnet compact blocks vary in size by four
/// orders of magnitude, so a fixed block count is either pointlessly small on
/// the empty stretches or an out-of-memory kill on the busy ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteBudget(usize);

impl ByteBudget {
    /// A budget suitable for a phone.
    pub const MOBILE: Self = Self(16 * 1024 * 1024);
    /// A budget suitable for a desktop or server.
    pub const DESKTOP: Self = Self(128 * 1024 * 1024);

    /// Constructs a budget of `bytes`, which must be positive.
    ///
    /// # Panics
    ///
    /// Panics if `bytes` is zero: a zero budget can never make progress, and
    /// failing loudly at construction is better than looping forever.
    pub fn new(bytes: usize) -> Self {
        assert!(bytes > 0, "a byte budget must allow at least one block");
        Self(bytes)
    }

    /// Returns the budget in bytes.
    pub fn bytes(self) -> usize {
        self.0
    }
}

/// Which end of a range to fetch from.
///
/// Recovery works backwards, from the tip towards the birthday, because
/// spendable value concentrates near the tip and Ironwood exists only there: a
/// user restoring a wallet sees their current balance long before the whole
/// history has been downloaded. Following the tip works forwards, because there
/// the next block is the one that matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Lowest height first.
    Ascending,
    /// Highest height first.
    Descending,
}

/// A subtree root the server holds for a shard.
#[derive(Debug, Clone, Copy)]
pub struct SubtreeRoot {
    /// The shard's index.
    pub index: u64,
    /// The height at which its last commitment was mined.
    pub end_height: BlockHeight,
    /// The shard's root hash.
    pub root: orchard::tree::MerkleHashOrchard,
}

/// A source of compact blocks and chain metadata.
pub trait ChainSource {
    /// What can go wrong talking to this source.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Returns the current chain tip.
    fn tip(&self) -> impl Future<Output = Result<ChainTip, Self::Error>> + Send;

    /// Returns the chain state as of the end of `height`.
    ///
    /// This is what anchors a scan range that does not continue from a block
    /// the wallet has already scanned — which, under descending recovery, is
    /// most of them.
    fn anchor(
        &self,
        height: BlockHeight,
    ) -> impl Future<Output = Result<BlockAnchor, Self::Error>> + Send;

    /// Returns blocks from one end of `range`, stopping at `budget`.
    ///
    /// The blocks returned must be contiguous and in ascending height order
    /// whichever direction was asked for; `Descending` changes *which* end of
    /// the range is covered, not the order they come back in. Returning fewer
    /// than the whole range is expected and is how the budget is honoured.
    fn fetch(
        &self,
        range: Range<BlockHeight>,
        budget: ByteBudget,
        direction: Direction,
    ) -> impl Future<Output = Result<Vec<CompactBlock>, Self::Error>> + Send;

    /// Returns subtree roots for `pool`, starting at `start_index`.
    ///
    /// A root summarises a whole shard, so this is what lets a wallet witness a
    /// note near the tip without first downloading the history beneath it.
    fn subtree_roots(
        &self,
        pool: zakura_wallet_core::pool::PoolId,
        start_index: u64,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<SubtreeRoot>, Self::Error>> + Send;
}

/// Returns an estimate of a block's in-memory size.
///
/// Used to charge a block against the byte budget. It counts the parts that
/// dominate — the compact actions and transparent outputs — rather than trying
/// to be exact, because the budget is a bound, not an accounting record.
pub fn estimated_size(block: &CompactBlock) -> usize {
    /// Nullifier, commitment, ephemeral key and the 52-byte ciphertext prefix.
    const ACTION_BYTES: usize = 32 + 32 + 32 + 52;
    const BLOCK_OVERHEAD: usize = 32 + 32 + 16;
    const TX_OVERHEAD: usize = 32 + 8;

    BLOCK_OVERHEAD
        + block
            .txs
            .iter()
            .map(|tx| {
                TX_OVERHEAD
                    + (tx.orchard_actions.len() + tx.ironwood_actions.len()) * ACTION_BYTES
                    + tx.vin.len() * 36
                    + tx.vout.iter().map(|o| 8 + o.script_pubkey().0.0.len()).sum::<usize>()
            })
            .sum::<usize>()
}

/// A source failure, boxed so the engine's error type does not have to be
/// generic over every transport.
#[derive(Debug)]
pub struct SourceError(Box<dyn std::error::Error + Send + Sync>);

impl SourceError {
    /// Wraps a transport's error.
    pub fn new<E: std::error::Error + Send + Sync + 'static>(err: E) -> Self {
        Self(Box::new(err))
    }
}

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the chain source failed: {}", self.0)
    }
}

impl std::error::Error for SourceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}
