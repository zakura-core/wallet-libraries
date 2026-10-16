//! Progress retained by the store, independent of a newly offered publication.
use super::store::{CoverageKind, StoreError, WalletStore, uncovered};
use super::sync::ProvisionalCoverage;
use std::collections::BTreeMap;

pub(crate) struct DurableProgress {
    pub(crate) covered_through: u64,
    pub(crate) settled_through: u64,
    pub(crate) provisional: Vec<ProvisionalCoverage>,
}

pub(crate) fn summary(store: &(impl WalletStore + ?Sized)) -> Result<DurableProgress, StoreError> {
    let (covered_through, settled_through) = coverage(store, None)?;
    Ok(DurableProgress {
        covered_through,
        settled_through,
        provisional: provisional(store)?,
    })
}

/// Recompute from current scripts and contiguous saved ranges. The anchor is
/// only an upper bound, never evidence that a newly added script was covered.
/// A normal sync supplies its accepted target; status uses retained endpoints.
pub(crate) fn coverage(
    store: &(impl WalletStore + ?Sized),
    through: Option<u64>,
) -> Result<(u64, u64), StoreError> {
    let start = store.set_identity()?.map_or(0, |set| set.start_height);
    let floor = start.saturating_sub(1);
    let entries = store.scripts()?;
    let mut saved = Vec::with_capacity(entries.len());
    let mut retained = store.anchor()?.map_or(floor, |anchor| anchor.height);
    for entry in entries {
        let ranges = store.coverage(&entry.script)?;
        retained = ranges
            .iter()
            .fold(retained, |height, range| height.max(range.end_height));
        saved.push((entry, ranges));
    }
    let through = through.unwrap_or(retained);
    let floor = floor.min(through);
    if saved.is_empty() {
        return Ok((floor, floor));
    }
    let mut covered = through;
    let mut settled = through;
    for (entry, ranges) in saved {
        let from = entry.required_from.max(start);
        let first_gap = uncovered(&ranges, from, through)
            .first()
            .map(|(start, _)| *start);
        covered = covered.min(first_gap.map_or(through, |start| start.saturating_sub(1)));
        let sealed = ranges
            .into_iter()
            .filter(|range| range.kind == CoverageKind::Settled)
            .collect::<Vec<_>>();
        let first_gap = uncovered(&sealed, from, through)
            .first()
            .map(|(start, _)| *start);
        settled = settled.min(first_gap.map_or(through, |start| start.saturating_sub(1)));
    }
    Ok((covered.max(floor), settled.max(floor)))
}

pub(crate) fn provisional(
    store: &(impl WalletStore + ?Sized),
) -> Result<Vec<ProvisionalCoverage>, StoreError> {
    let mut seen: BTreeMap<(u64, String), u64> = BTreeMap::new();
    for range in store.provisional()? {
        let end = seen
            .entry((range.shard_id, range.revision_digest))
            .or_insert(range.end_height);
        *end = (*end).max(range.end_height);
    }
    Ok(seen
        .into_iter()
        .map(
            |((shard_id, manifest_digest), end_height)| ProvisionalCoverage {
                shard_id,
                // The store retains the identifying digest, but not a numeric revision.
                revision: 0,
                manifest_digest,
                end_height,
            },
        )
        .collect())
}
