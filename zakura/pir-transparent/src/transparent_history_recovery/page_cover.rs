//! Page cover, not built yet: the walk's page queries pass through unchanged,
//! and these functions draw no cover. The tests beside it state what page cover
//! must do; `docs/pir-page-cover.md` states the rules.

#![cfg_attr(not(test), allow(dead_code))]

use std::collections::BTreeSet;

#[cfg(test)]
use rand::SeedableRng;
use rand::rngs::StdRng;

/// The cover size drawn most often.
const BASE_SIZE: u32 = 3;

/// The cover set: only the tables already known to be needed.
pub(crate) fn draw(_rng: &mut StdRng, _tables: &[u32], known: &BTreeSet<u32>) -> BTreeSet<u32> {
    known.clone()
}

/// A sweep's order: the cover in table order.
pub(crate) fn sweep_order(_rng: &mut StdRng, cover: &BTreeSet<u32>) -> Vec<u32> {
    cover.iter().copied().collect()
}

/// A shard's sweeps, unpadded.
pub(crate) fn padded(sweeps: u64) -> u64 {
    sweeps
}

#[cfg(test)]
mod tests;
