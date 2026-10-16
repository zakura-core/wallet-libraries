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

use super::{bucket, MAX_BUCKETS};
use crate::txid::DisplayEntry;
use serde::{Deserialize, Serialize};
use std::ops::RangeInclusive;

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

/// One block's records, counted per archive bucket and per recent bucket.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeightCounts {
    pub archive: Vec<u32>,
    pub recent: Vec<u32>,
}

pub fn height_counts(
    params: &DisplaySealParams,
    entries: &[impl AsRef<DisplayEntry>],
) -> HeightCounts {
    let mut counts = HeightCounts {
        archive: vec![0; params.n_archive as usize],
        recent: vec![0; params.n_recent as usize],
    };
    for entry in entries.iter().map(AsRef::as_ref) {
        counts.archive[bucket(&entry.tag, params.n_archive) as usize] += 1;
        counts.recent[bucket(&entry.tag, params.n_recent) as usize] += 1;
    }
    counts
}

/// The smallest `h ≥ start` at which every archive bucket of `[start, h]`
/// reaches the target, where `counts[i]` is height `start + i`.
pub fn archive_boundary(
    params: &DisplaySealParams,
    start: u64,
    counts: &[HeightCounts],
) -> Option<u64> {
    let mut sums = vec![0u64; params.n_archive as usize];
    for (i, block) in counts.iter().enumerate() {
        for (sum, count) in sums.iter_mut().zip(&block.archive) {
            *sum += u64::from(*count);
        }
        if sums.iter().all(|s| *s >= params.archive_target) {
            return Some(start + i as u64);
        }
    }
    None
}

/// Every seal the rule makes over `[start, start + counts.len() - 1]`, in order.
pub fn plan_seals(
    params: &DisplaySealParams,
    start: u64,
    counts: &[HeightCounts],
) -> Vec<RangeInclusive<u64>> {
    let Some(last) = counts.len().checked_sub(1) else {
        return Vec::new();
    };
    let tip = start + last as u64;
    let mut seals = Vec::new();
    let mut from = 0usize;
    while from < counts.len() {
        let Some(h) = archive_boundary(params, start + from as u64, &counts[from..]) else {
            break;
        };
        if h + params.reorg_margin > tip {
            break;
        }
        seals.push(start + from as u64..=h);
        from = (h - start) as usize + 1;
    }
    seals
}

/// The latest `w ≥ floor` at which every recent bucket of `[w, end]` holds
/// `recent_window` txids, or `floor` when none does, where `counts[i]` is
/// height `floor + i` and `end` the last of them.
pub fn window_start(params: &DisplaySealParams, floor: u64, counts: &[HeightCounts]) -> u64 {
    let mut sums = vec![0u64; params.n_recent as usize];
    for (i, block) in counts.iter().enumerate().rev() {
        for (sum, count) in sums.iter_mut().zip(&block.recent) {
            *sum += u64::from(*count);
        }
        if sums.iter().all(|s| *s >= params.recent_window) {
            return floor + i as u64;
        }
    }
    floor
}

/// The recent shard's start at the tip `counts` ends at: [`window_start`],
/// but never above `unsealed`, the first height no archive holds.
pub fn recent_start(
    params: &DisplaySealParams,
    floor: u64,
    unsealed: u64,
    counts: &[HeightCounts],
) -> u64 {
    window_start(params, floor, counts).min(unsealed).max(floor)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> DisplaySealParams {
        DisplaySealParams {
            n_archive: 2,
            n_recent: 1,
            archive_target: 10,
            recent_window: 6,
            reorg_margin: 3,
        }
    }

    fn block(a: [u32; 2]) -> HeightCounts {
        HeightCounts {
            archive: a.to_vec(),
            recent: vec![a[0] + a[1]],
        }
    }

    #[test]
    fn boundary_waits_for_the_slowest_bucket() {
        let p = params();
        let mut counts = vec![block([5, 1]); 2];
        counts.extend(vec![block([0, 1]); 8]);
        // Bucket 0 reaches 10 at index 1; bucket 1 reaches 10 at index 9.
        assert_eq!(archive_boundary(&p, 100, &counts), Some(109));
        assert_eq!(archive_boundary(&p, 100, &counts[..9]), None);
    }

    #[test]
    fn only_the_reorg_margin_gates_a_seal() {
        let p = params();
        // Boundary at height 101 (two blocks of 5+5); the margin needs a tip
        // of at least 104, however few txids lie above the boundary.
        let mut sparse = vec![block([5, 5]); 2];
        sparse.push(block([3, 3]));
        assert!(plan_seals(&p, 100, &sparse).is_empty(), "101 + 3 > 102");
        sparse.push(block([0, 0]));
        assert!(plan_seals(&p, 100, &sparse).is_empty(), "101 + 3 > 103");
        sparse.push(block([0, 0]));
        assert_eq!(plan_seals(&p, 100, &sparse), vec![100..=101]);
    }

    #[test]
    fn the_recent_window_slides_and_covers_every_unsealed_height() {
        let p = params();
        // Heights 100..=105 hold 4, 4, 4, 1, 1, 1 recent txids.
        let mut counts = vec![block([2, 2]); 3];
        counts.extend(vec![block([1, 0]); 3]);
        // [102, 105] holds 7 >= 6; [103, 105] only 3.
        assert_eq!(window_start(&p, 100, &counts), 102);
        assert_eq!(recent_start(&p, 100, 106, &counts), 102);
        // Never above the first unsealed height.
        assert_eq!(recent_start(&p, 100, 101, &counts), 101);
        // A chain shorter than the window starts at the floor.
        assert_eq!(window_start(&p, 100, &counts[4..]), 100);
        assert_eq!(recent_start(&p, 100, 106, &[]), 100);
        // The window ends at the tip, so it moves up as blocks arrive.
        counts.push(block([3, 3]));
        assert_eq!(window_start(&p, 100, &counts), 106);
    }

    fn pseudo_chain(len: usize, seed: u64) -> Vec<HeightCounts> {
        let mut x = seed;
        (0..len)
            .map(|_| {
                x = x
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let a = ((x >> 33) % 4) as u32;
                let b = ((x >> 45) % 4) as u32;
                block([a, b])
            })
            .collect()
    }

    /// Sealing as the tip advances, in any step size, gives the shards one
    /// pass over the whole range gives.
    #[test]
    fn incremental_sealing_equals_bootstrap() {
        let p = params();
        for seed in 0..20 {
            let counts = pseudo_chain(400, seed);
            let whole = plan_seals(&p, 1_000, &counts);
            assert!(whole.len() > 5, "the fixture exercises several seals");
            for step in [1usize, 7, 100, 13 + seed as usize] {
                let mut sealed = Vec::new();
                let mut from = 0usize;
                let mut tip = 0usize;
                while tip < counts.len() {
                    tip = (tip + step).min(counts.len());
                    for range in plan_seals(&p, 1_000 + from as u64, &counts[from..tip]) {
                        from = (*range.end() - 1_000) as usize + 1;
                        sealed.push(range);
                    }
                }
                assert_eq!(sealed, whole, "seed {seed} step {step}");
            }
            // Shards are contiguous, gapless and each meets the target.
            let mut next = 1_000;
            for range in &whole {
                assert_eq!(*range.start(), next);
                next = range.end() + 1;
                let slice =
                    &counts[(*range.start() - 1_000) as usize..=(*range.end() - 1_000) as usize];
                for b in 0..2 {
                    let sum: u32 = slice.iter().map(|c| c.archive[b]).sum();
                    assert!(u64::from(sum) >= p.archive_target);
                }
            }
        }
    }

    #[test]
    fn counts_follow_buckets_and_empty_input_is_inert() {
        let p = DisplaySealParams {
            n_archive: 4,
            ..params()
        };
        assert!(plan_seals(&p, 0, &[]).is_empty());
        let counts = height_counts(&p, &[] as &[DisplayEntry]);
        assert_eq!(counts.archive, vec![0; 4]);
        assert_eq!(counts.recent, vec![0]);
    }
}
