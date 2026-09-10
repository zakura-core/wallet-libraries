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

pub use zakura_wallet_core::enhanced::TransactionStatus;
use zcash_protocol::{TxId, consensus::BlockHeight};

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

    /// Whether a block of `size` may still be added to a batch that has already
    /// spent `spent` bytes on `count` blocks.
    ///
    /// The decision has to be made *before* the block is added, not after:
    /// stopping once the budget is already spent overshoots by the whole size
    /// of the last block, and since a batch is usually many blocks that makes
    /// the overshoot the normal case rather than the exception. The engine
    /// asserts the bound, so a source that overshoots takes the wallet down
    /// with it.
    ///
    /// An empty batch always admits, however large the block: one larger than
    /// the entire budget must still be scannable, or a wallet stalls on it
    /// forever.
    ///
    /// Shared rather than written out at each source, because there were two
    /// and they disagreed — which is the whole defect.
    pub fn admits(self, spent: usize, size: usize, count: usize) -> bool {
        count == 0 || spent + size <= self.0
    }
}

#[cfg(test)]
mod budget_tests {
    use super::ByteBudget;

    #[test]
    fn an_empty_batch_admits_a_block_larger_than_the_whole_budget() {
        assert!(ByteBudget::new(100).admits(0, 10_000, 0));
    }

    #[test]
    fn a_block_that_fits_is_admitted() {
        assert!(ByteBudget::new(100).admits(40, 50, 1));
    }

    #[test]
    fn a_block_that_exactly_fills_the_budget_is_admitted() {
        assert!(ByteBudget::new(100).admits(40, 60, 1));
    }

    /// The defect: deciding after adding let the batch exceed the budget by a
    /// whole block, which the engine asserts against.
    #[test]
    fn a_block_that_would_overshoot_is_refused() {
        assert!(!ByteBudget::new(100).admits(40, 61, 1));
    }

    #[test]
    fn a_full_batch_refuses_even_a_tiny_block() {
        assert!(!ByteBudget::new(100).admits(100, 1, 3));
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

    /// Returns a whole transaction by identifier, or a definite negative.
    ///
    /// This is what enhancement runs on, and it answers both questions the
    /// wallet asks about a transaction — what it contains, and whether it is
    /// mined — because over this protocol they are one request.
    ///
    /// `Ok(None)` means the source *positively asserts* it cannot supply this
    /// transaction. A transport failure is `Err` and must never be reported as
    /// `Ok(None)`: the negative is what starts a transaction's expiry clock, so
    /// mistaking a timeout for one expires transactions that are still live and
    /// releases the notes they spend.
    fn transaction(
        &self,
        txid: TxId,
    ) -> impl Future<Output = Result<Option<FetchedTransaction>, Self::Error>> + Send;
}

/// A transaction as a source returned it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedTransaction {
    /// The transaction's bytes.
    pub raw: Vec<u8>,
    /// Where the source says it stands.
    pub status: TransactionStatus,
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
                    + tx.vout
                        .iter()
                        .map(|o| 8 + o.script_pubkey().0.0.len())
                        .sum::<usize>()
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
