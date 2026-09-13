//! Progress reporting.
//!
//! Progress is reported as note-commitment coverage, not as blocks scanned.
//! Blocks are a poor proxy: the empty stretches of the chain scan orders of
//! magnitude faster than the busy ones, so a block-count bar moves in lurches
//! and consistently lies about how much time is left. Coverage of the
//! commitment trees is what the remaining work is actually proportional to.

use zakura_wallet_core::pool::PoolId;
use zcash_protocol::consensus::BlockHeight;

/// What the engine is currently doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncPhase {
    /// Nothing has been scanned yet.
    Bootstrapping,
    /// Working backwards through history.
    Recovering,
    /// Following the chain tip.
    Tracking,
    /// Nothing left to scan.
    Idle,
}

/// A fraction, kept as its two parts so a caller can render it either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ratio {
    /// How much is done.
    pub numerator: u64,
    /// How much there is in total.
    pub denominator: u64,
}

impl Ratio {
    /// Returns the ratio as a fraction between 0 and 1, or `None` if there is
    /// nothing to measure yet.
    pub fn fraction(&self) -> Option<f64> {
        (self.denominator > 0).then(|| self.numerator as f64 / self.denominator as f64)
    }
}

/// A snapshot of how far synchronisation has got.
///
/// Published through a watch channel: lossy by design, cheap to read, and
/// expressible across an FFI boundary as a poll rather than a callback that has
/// to be marshalled back into another language's runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncStatus {
    /// What the engine is doing.
    pub phase: SyncPhase,
    /// Commitment coverage of each pool.
    pub per_pool: [(PoolId, Ratio); 2],
    /// The highest block the source reported.
    pub tip: Option<BlockHeight>,
    /// The highest block the wallet has scanned.
    pub scanned_to: Option<BlockHeight>,
    /// How many blocks remain queued.
    pub blocks_remaining: u64,
}

impl Default for SyncStatus {
    fn default() -> Self {
        Self {
            phase: SyncPhase::Bootstrapping,
            per_pool: [
                (
                    PoolId::Orchard,
                    Ratio {
                        numerator: 0,
                        denominator: 0,
                    },
                ),
                (
                    PoolId::Ironwood,
                    Ratio {
                        numerator: 0,
                        denominator: 0,
                    },
                ),
            ],
            tip: None,
            scanned_to: None,
            blocks_remaining: 0,
        }
    }
}
