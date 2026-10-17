//! Where display shards seal, and where the recent shard starts.
//!
//! Archives are contiguous from the display start. The unsealed range
//! `[U, tip]` seals its oldest prefix `[U, h]` as an archive at the smallest
//! `h` where every archive bucket holds at least `archive_target` real txids,
//! once `h` is at least `reorg_margin` blocks below the tip.
//!
//! Boundaries depend only on the start, the target and the chain: the margin
//! only becomes easier as the tip advances, so sealing incrementally block by
//! block and sealing once over a long range give the same shards. That is
//! what lets an archive be rebuilt later, from the journal, to the same
//! digest.
//!
//! The recent shard is a sliding window over `[R, tip]`: `R` is the latest
//! height at which every recent bucket of `[R, tip]` still holds
//! `recent_window` txids, but never above `U`, so every unsealed height is
//! covered, and never below the display start. It overlaps the newest
//! archive or archives. Its start is not part of any archive's identity.

use super::MAX_BUCKETS;
use serde::{Deserialize, Serialize};

/// The seal rule's parameters, published in the display map.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DisplaySealParams {
    pub n_archive: u32,
    pub n_recent: u32,
    /// Real txids every archive bucket must hold.
    pub archive_target: u64,
    /// Real txids every recent bucket holds once the chain from the display
    /// start does.
    pub recent_window: u64,
    /// Blocks a sealed range must lie below the tip.
    pub reorg_margin: u64,
}

impl DisplaySealParams {
    /// Checks both bucket counts lie in `1..=MAX_BUCKETS`, so every bucket
    /// computation has a divisor and every table label is valid.
    pub fn check(&self) -> Result<(), String> {
        for (tier, buckets) in [("archive", self.n_archive), ("recent", self.n_recent)] {
            if !(1..=MAX_BUCKETS).contains(&buckets) {
                return Err(format!("{buckets} {tier} display buckets"));
            }
        }
        Ok(())
    }
}

impl Default for DisplaySealParams {
    fn default() -> Self {
        Self {
            n_archive: 1,
            n_recent: 1,
            archive_target: 90_000,
            recent_window: 90_000,
            reorg_margin: 100,
        }
    }
}
