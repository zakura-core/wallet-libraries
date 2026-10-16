//! What a wallet keeps between syncs, and the one boundary it changes at.
//!
//! A sync that starts from nothing every time cannot be a returning wallet: it
//! forgets the receive it found last month, so the spend it finds today is
//! unresolved, and moving the birthday forward to save work throws the receive
//! away for good. The store is the wallet's memory of what it has recovered,
//! which scripts it is responsible for and over which ranges each is covered,
//! what it accepted as the chain's anchor, and what private work it still owes.
//!
//! # One commit per shard
//!
//! Everything a shard yields is committed together — its events, the coverage
//! it establishes for each script, and the page work still owed — or not at
//! all. A crash between two commits loses at most one shard's retrieval, which
//! the next sync repeats; it never records coverage for events it did not keep
//! or events under coverage it did not record. Retrying a commit is idempotent
//! by construction: events are keyed by their stable identities, coverage by
//! script and range, and a repeat that *differs* in any field is a
//! contradiction, refused rather than merged.
//!
//! # Provisional and settled
//!
//! Coverage taken from an unsealed tail carries that revision's digest. When
//! the tail is superseded, that coverage and the events under it are truncated
//! and the range re-derived; when the same digest is later sealed, it is
//! promoted in place. Settled coverage is never rewritten except by a reorg,
//! which rolls everything above the accepted ancestor back at once.
//!
//! # What the wallet owns
//!
//! This is a trait so the wallet that embeds the library supplies the storage:
//! its own database, its own transaction, its own encryption. The reference
//! implementations — in memory here, SQLite in [`crate::engine_store`] —
//! are what the tests run against and what a first integration can use as-is.

use crate::engine::client::Table;
use crate::engine::ledger::{Ledger, LedgerError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use transparent_events::TransparentEvent;
use transparent_filter::{SealParameters, ShardMap};

/// The publication lineage a store is bound to.
///
/// Everything in the map that does not change as the set grows: chain,
/// profile, envelope version, first height, and the seal thresholds each
/// geometry was sealed under. The map digest itself changes with every tail
/// republication and is deliberately not part of this.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetIdentity {
    pub shard_schema: String,
    pub network: String,
    pub genesis_hash: String,
    pub profile: String,
    pub range_envelope_version: u16,
    pub start_height: u64,
    pub seal: BTreeMap<String, SealParameters>,
}

impl SetIdentity {
    pub fn of(map: &ShardMap) -> Self {
        Self::of_schema(map, transparent_shard::SCHEMA)
    }

    pub fn of_schema(map: &ShardMap, schema: &str) -> Self {
        Self {
            shard_schema: schema.to_string(),
            network: map.network.clone(),
            genesis_hash: map.genesis_hash.clone(),
            profile: map.profile.clone(),
            range_envelope_version: map.range_envelope_version,
            start_height: map.start_height,
            seal: map.seal.clone(),
        }
    }

    /// Extends a compatible identity without forgetting previously bound seals.
    pub(crate) fn retain_seals(&mut self, stored: &Self) {
        for (name, seal) in &stored.seal {
            self.seal.entry(name.clone()).or_insert(*seal);
        }
    }

    /// SHA-256 of the canonical serialization.
    pub fn digest(&self) -> String {
        hex::encode(Sha256::digest(
            serde_json::to_vec(self).expect("a set identity serializes"),
        ))
    }

    /// Whether `other` is the same lineage, allowing a geometry the store had
    /// not seen to appear (a set growing into another tier) but never a
    /// changed seal for one already in use.
    pub fn continues(&self, other: &Self) -> bool {
        self.shard_schema == other.shard_schema
            && self.network == other.network
            && self.genesis_hash == other.genesis_hash
            && self.profile == other.profile
            && self.range_envelope_version == other.range_envelope_version
            && self.start_height == other.start_height
            && self
                .seal
                .iter()
                .all(|(name, seal)| other.seal.get(name).is_none_or(|theirs| theirs == seal))
    }
}

/// The chain block a wallet has accepted as the end of its coverage.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    pub height: u64,
    /// Display hex.
    pub hash: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScriptOrigin {
    /// From the wallet's own derivation rules.
    Derived,
    /// Imported by the user; its history may begin anywhere.
    Imported,
}

/// One script the wallet is responsible for, and the height its required
/// coverage begins at.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptEntry {
    pub script: Vec<u8>,
    pub origin: ScriptOrigin,
    /// First height the wallet needs covered for this script. The wallet's
    /// own rule decides it; a derived script's is typically the birthday,
    /// an imported script's is the set's first height.
    pub required_from: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoverageKind {
    /// From a sealed shard. Immutable short of a reorg.
    Settled,
    /// From an unsealed tail revision. Replaced when the tail is republished.
    Provisional,
}

/// One script's coverage over one shard's range.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageRange {
    pub script: Vec<u8>,
    pub start_height: u64,
    pub end_height: u64,
    pub kind: CoverageKind,
    pub shard_id: u64,
    pub revision_digest: String,
    pub terminal_block_hash: String,
    /// Full published endpoint, distinct from the covered endpoint.
    pub source_anchor: Option<Anchor>,
}

/// One event the wallet keeps, with where it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredEvent {
    pub script: Vec<u8>,
    pub event: TransparentEvent,
    pub shard_id: u64,
    pub revision_digest: String,
}

/// Last committed fragment's boundary, needed to validate greedy packing after resume.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageBoundary {
    pub event_bytes: u32,
    pub last_event: TransparentEvent,
}

/// Where a chain walk resumes: the run it reads next.
///
/// A script's history in a directory shard is a chain of runs, newest first,
/// each in an earlier page shard than the one before. The directory entry
/// names the newest; every run's first fragment names the next older one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunCursor {
    /// The page shard `j` holding the run; its table is `pages-<j>`.
    pub child: u8,
    /// Zero-based row of the run's first fragment in that table.
    pub row: u32,
    /// How many runs the run's first fragment must report as older than it:
    /// one fewer than the newer run reported. `None` for the newest run,
    /// which the directory entry names without a count.
    pub older_runs: Option<u8>,
}

/// Indistinguishable page queries still owed after an entry's content failed.
/// Kept with the pending cursor so a budget, outage or restart cannot omit them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DummyQueries {
    pub child: u8,
    pub remaining: u32,
}

/// Page retrieval a wallet still owes for one script in one directory shard
/// revision: the rest of its chain of runs.
///
/// Every run newer than the cursor has been read, checked and committed. Kept
/// durably so an exhausted budget or an outage leaves resumable work, not a
/// synchronized balance. Keyed by the directory shard revision alone, whose
/// digest commits to every page shard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingPages {
    /// Assigned by the store; `None` until first committed.
    pub id: Option<u64>,
    pub shard_id: u64,
    pub revision_digest: String,
    pub script: Vec<u8>,
    /// The run the walk reads next.
    pub cursor: RunCursor,
    /// The two oldest events already read, oldest first: the newer runs' or,
    /// before any run was read, the directory entry's inline events. The run
    /// at the cursor must be older than both, and each of its events was
    /// pushed out by the event two places after it, which these supply for
    /// its last two.
    pub carried: Vec<TransparentEvent>,
    /// Checked fragments of the current run, each encoded as a page row holding
    /// only this script. They are revalidated on resume and cleared at the next run.
    pub fragments: Vec<Vec<u8>>,
    pub attempts: u32,
    /// Cover traffic must finish before this failed entry can be suppressed.
    pub dummy_queries: Option<DummyQueries>,
    pub target_anchor: Option<Anchor>,
}

/// One script's run in a sealed page shard, as a wallet verified it, and the
/// name of the cached run below it.
///
/// Keyed by the page shard's chained identity
/// ([`ShardManifest::child_digests`](transparent_shard::ShardManifest::child_digests)),
/// which covers that page shard and every older one in its directory shard, so
/// nothing the run or the runs below it depend on can change under the key.
/// Following `older` back to the start of the directory shard gives the
/// script's history there, and a walk that reaches a cached run stops at it.
///
/// A store drops a directory shard's cached runs for a script once it covers
/// that script over the shard sealed: no later walk of the shard is expected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedRun {
    /// The page shard's chained identity, in hex.
    pub child_digest: String,
    pub script: Vec<u8>,
    /// The directory shard the run belongs to.
    pub shard_id: u64,
    /// The run's own events, oldest first.
    pub events: Vec<TransparentEvent>,
    /// The chained identity of the page shard holding the script's previous
    /// run, or `None` when this is its oldest run in the directory shard.
    pub older: Option<String>,
}

/// What one shard's retrieval commits, all at once.
#[derive(Clone, Debug, Default)]
pub struct ShardCommit {
    /// Original publication endpoint when coverage is clipped to a wallet anchor.
    pub source_anchor: Option<Anchor>,
    pub shard_id: u64,
    pub revision_digest: String,
    pub sealed: bool,
    pub start_height: u64,
    pub end_height: u64,
    pub terminal_block_hash: String,
    pub events: Vec<StoredEvent>,
    /// Scripts whose coverage this commit extends over the shard's range.
    pub covered_scripts: Vec<Vec<u8>>,
    /// Pending page work created or advanced by this commit.
    pub pending_upsert: Vec<PendingPages>,
    /// Pending ids this commit finishes.
    pub pending_complete: Vec<u64>,
    /// Verified runs to keep for later walks.
    pub cached_runs: Vec<CachedRun>,
    /// Scripts whose directory entry in this shard failed on content in this
    /// commit's retrieval: a reply that did not decode or verify, or a record
    /// that contradicts what the store holds. Each adds one to the entry's
    /// [`WalletStore::entry_failures`]; unlike everything else here, that is
    /// not idempotent, so a commit carrying failures is made once.
    pub failed_entries: Vec<Vec<u8>>,
}

/// Ledger-event bytes, framed pending-event lists, then framed cached-run lists.
pub(crate) type EncodedCommitEvents = (Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>);

impl ShardCommit {
    /// Check every staged event before either store changes its state. SQLite
    /// reuses these exact bytes; the memory store discards them after checking.
    /// This includes unfinished work that has not entered the ledger yet.
    pub(crate) fn encode_events(&self) -> Result<EncodedCommitEvents, StoreError> {
        let events = self
            .events
            .iter()
            .map(|stored| encode_event(stored.event))
            .collect::<Result<Vec<_>, _>>()?;
        let pending = self
            .pending_upsert
            .iter()
            .map(|pending| {
                if pending
                    .dummy_queries
                    .is_some_and(|cover| cover.remaining == 0)
                    || pending.dummy_queries.is_some() && pending.target_anchor.is_none()
                {
                    return Err(StoreError::Corrupt(
                        "invalid pending cover obligation".into(),
                    ));
                }
                encode_events(&pending.carried)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let runs = self
            .cached_runs
            .iter()
            .map(|run| encode_events(&run.events))
            .collect::<Result<Vec<_>, _>>()?;
        Ok((events, pending, runs))
    }

    /// Whether this commit covers its `covered_scripts` over the whole of a
    /// sealed shard, so no later walk of the shard is expected for them and
    /// the store drops their cached runs in it. Coverage clipped to a wallet
    /// anchor inside the shard does not: the next sync carries on through it.
    pub fn finishes_shard(&self) -> bool {
        self.sealed
            && self
                .source_anchor
                .as_ref()
                .is_none_or(|source| source.height == self.end_height)
    }
}

fn encode_event(event: TransparentEvent) -> Result<Vec<u8>, StoreError> {
    event
        .to_bytes()
        .map_err(|error| StoreError::Corrupt(error.to_string()))
}

/// Events, each framed by its length, after a version tag.
fn encode_events(events: &[TransparentEvent]) -> Result<Vec<u8>, StoreError> {
    let mut out = b"EV3\0".to_vec();
    for event in events {
        let raw = encode_event(*event)?;
        out.extend_from_slice(&(raw.len() as u16).to_le_bytes());
        out.extend_from_slice(&raw);
    }
    Ok(out)
}

/// Published setup for one table segment, kept for reuse.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupBlob {
    pub public_params_base64: String,
    pub public_params_sha256: String,
}

/// What a setup is keyed by: the set lineage, the exact revision, the table
/// and the segment. Anything less would reuse parameters against bytes they
/// were not derived from.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SetupKey {
    pub set_digest: String,
    pub revision_digest: String,
    pub table: Table,
    pub segment: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("store I/O: {0}")]
    Io(String),
    #[error("store is corrupt: {0}")]
    Corrupt(String),
    /// A repeat that differs. Nothing is written.
    #[error("contradiction: {0}")]
    Contradiction(#[from] LedgerError),
    #[error("the store is bound to set {stored}, this map is {offered}")]
    SetMismatch { stored: String, offered: String },
    #[error("the store's anchor is {stored}, which the offered map at {offered} does not reach")]
    AnchorRegressed { stored: u64, offered: u64 },
    #[error("the commit would leave more than {limit} pending page retrievals")]
    PendingLimit { limit: usize },
}

/// The wallet's durable memory. See the module documentation.
pub trait WalletStore {
    /// The lineage this store is bound to, with its digest, if any.
    fn set_identity(&self) -> Result<Option<SetIdentity>, StoreError>;
    /// Binds a fresh store to a lineage, or confirms a bound one continues it.
    fn bind_set(&mut self, identity: &SetIdentity) -> Result<(), StoreError>;

    fn anchor(&self) -> Result<Option<Anchor>, StoreError>;

    fn scripts(&self) -> Result<Vec<ScriptEntry>, StoreError>;
    /// Adds scripts. An existing script's `required_from` is never raised:
    /// coverage once required stays required.
    fn add_scripts(&mut self, entries: &[ScriptEntry]) -> Result<usize, StoreError>;

    fn coverage(&self, script: &[u8]) -> Result<Vec<CoverageRange>, StoreError>;
    /// Every provisional range across every script.
    fn provisional(&self) -> Result<Vec<CoverageRange>, StoreError>;

    /// Every kept event in canonical order.
    fn events(&self) -> Result<Vec<StoredEvent>, StoreError>;
    /// The ledger replayed from `events`.
    fn ledger(&self) -> Result<Ledger, StoreError> {
        let mut events: Vec<(Vec<u8>, TransparentEvent)> = self
            .events()?
            .into_iter()
            .map(|stored| (stored.script, stored.event))
            .collect();
        let mut ledger = Ledger::new();
        ledger.replay(&mut events)?;
        Ok(ledger)
    }

    /// The one mutating boundary for retrieval. Atomic and idempotent; a
    /// repeat that differs is refused whole.
    fn commit_shard(&mut self, commit: ShardCommit) -> Result<u64, StoreError>;
    /// Records the accepted anchor and derived coverage summaries.
    fn commit_anchor(
        &mut self,
        anchor: &Anchor,
        settled_through: u64,
        covered_through: u64,
    ) -> Result<u64, StoreError>;
    /// Removes every event, coverage range and pending item above `height`
    /// and lowers the anchor to it. A reorg or a replaced provisional tail.
    fn rollback_above(&mut self, anchor: &Anchor, reason: &str) -> Result<u64, StoreError>;
    /// Provisional coverage under `revision_digest` becomes settled: the same
    /// bytes were sealed.
    fn promote_provisional(
        &mut self,
        shard_id: u64,
        revision_digest: &str,
    ) -> Result<(), StoreError>;

    fn pending(&self) -> Result<Vec<PendingPages>, StoreError>;
    /// The run cached for `script` in the page shard with chained identity
    /// `child_digest`, if any. See [`CachedRun`].
    fn cached_run(
        &self,
        child_digest: &str,
        script: &[u8],
    ) -> Result<Option<CachedRun>, StoreError>;
    /// The most pending page retrievals a commit may leave behind.
    fn pending_limit(&self) -> usize;

    fn setup(&self, key: &SetupKey) -> Result<Option<SetupBlob>, StoreError>;
    fn put_setup(&mut self, key: &SetupKey, blob: &SetupBlob) -> Result<(), StoreError>;
    /// Forgets a setup a reply showed to be stale, so the next sync fetches
    /// the published one again. Forgetting one not held is not an error.
    fn drop_setup(&mut self, key: &SetupKey) -> Result<(), StoreError>;
    fn filter(
        &self,
        revision_digest: &str,
        filter_hash: &str,
    ) -> Result<Option<Vec<u8>>, StoreError>;
    fn put_filter(
        &mut self,
        revision_digest: &str,
        filter_hash: &str,
        sealed: bool,
        bytes: &[u8],
    ) -> Result<(), StoreError>;
    /// Forgets the filters and setups cached under any revision but those in
    /// `queryable`, the revisions a validated map publishes. A sync reads them
    /// only under those, so the rest are never read again. Cached runs and
    /// content failure counts are not keyed by a map revision and are kept.
    fn prune_caches(&mut self, queryable: &[&str]) -> Result<(), StoreError>;

    /// The id of the last commit, zero before any.
    fn last_commit(&self) -> Result<u64, StoreError>;

    /// Content failures recorded for `script`'s directory entry in shard
    /// `shard_id` under `revision`, across syncs and restarts. A success or
    /// rollback under that revision preserves the count. A different manifest
    /// starts a fresh count: a re-cut may reuse the id for unrelated content.
    /// Historic counters without a proven revision binding do not hold a
    /// revision; a later revision-bearing commit establishes the binding.
    fn entry_failures(
        &self,
        shard_id: u64,
        revision: &str,
        script: &[u8],
    ) -> Result<u32, StoreError>;
}

impl<T: WalletStore + ?Sized> WalletStore for Box<T> {
    fn set_identity(&self) -> Result<Option<SetIdentity>, StoreError> {
        (**self).set_identity()
    }
    fn bind_set(&mut self, identity: &SetIdentity) -> Result<(), StoreError> {
        (**self).bind_set(identity)
    }
    fn anchor(&self) -> Result<Option<Anchor>, StoreError> {
        (**self).anchor()
    }
    fn scripts(&self) -> Result<Vec<ScriptEntry>, StoreError> {
        (**self).scripts()
    }
    fn add_scripts(&mut self, entries: &[ScriptEntry]) -> Result<usize, StoreError> {
        (**self).add_scripts(entries)
    }
    fn coverage(&self, script: &[u8]) -> Result<Vec<CoverageRange>, StoreError> {
        (**self).coverage(script)
    }
    fn provisional(&self) -> Result<Vec<CoverageRange>, StoreError> {
        (**self).provisional()
    }
    fn events(&self) -> Result<Vec<StoredEvent>, StoreError> {
        (**self).events()
    }
    fn commit_shard(&mut self, commit: ShardCommit) -> Result<u64, StoreError> {
        (**self).commit_shard(commit)
    }
    fn commit_anchor(
        &mut self,
        anchor: &Anchor,
        settled_through: u64,
        covered_through: u64,
    ) -> Result<u64, StoreError> {
        (**self).commit_anchor(anchor, settled_through, covered_through)
    }
    fn rollback_above(&mut self, anchor: &Anchor, reason: &str) -> Result<u64, StoreError> {
        (**self).rollback_above(anchor, reason)
    }
    fn promote_provisional(
        &mut self,
        shard_id: u64,
        revision_digest: &str,
    ) -> Result<(), StoreError> {
        (**self).promote_provisional(shard_id, revision_digest)
    }
    fn pending(&self) -> Result<Vec<PendingPages>, StoreError> {
        (**self).pending()
    }
    fn pending_limit(&self) -> usize {
        (**self).pending_limit()
    }
    fn cached_run(
        &self,
        child_digest: &str,
        script: &[u8],
    ) -> Result<Option<CachedRun>, StoreError> {
        (**self).cached_run(child_digest, script)
    }
    fn setup(&self, key: &SetupKey) -> Result<Option<SetupBlob>, StoreError> {
        (**self).setup(key)
    }
    fn put_setup(&mut self, key: &SetupKey, blob: &SetupBlob) -> Result<(), StoreError> {
        (**self).put_setup(key, blob)
    }
    fn drop_setup(&mut self, key: &SetupKey) -> Result<(), StoreError> {
        (**self).drop_setup(key)
    }
    fn filter(
        &self,
        revision_digest: &str,
        filter_hash: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        (**self).filter(revision_digest, filter_hash)
    }
    fn put_filter(
        &mut self,
        revision_digest: &str,
        filter_hash: &str,
        sealed: bool,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        (**self).put_filter(revision_digest, filter_hash, sealed, bytes)
    }
    fn prune_caches(&mut self, queryable: &[&str]) -> Result<(), StoreError> {
        (**self).prune_caches(queryable)
    }
    fn last_commit(&self) -> Result<u64, StoreError> {
        (**self).last_commit()
    }
    fn entry_failures(
        &self,
        shard_id: u64,
        revision: &str,
        script: &[u8],
    ) -> Result<u32, StoreError> {
        (**self).entry_failures(shard_id, revision, script)
    }
}

/// The identity a receive is keyed by.
pub fn receive_key(event: &transparent_events::ReceiveEvent) -> (transparent_events::Txid, u32) {
    (event.txid, event.output_index)
}

/// The identity a spend is keyed by.
pub fn spend_key(
    event: &transparent_events::SpendEvent,
) -> (transparent_events::Txid, u32, transparent_events::Txid, u32) {
    (
        event.spending_txid,
        event.input_index,
        event.spent_txid,
        event.spent_output_index,
    )
}

/// Sorts one script's ranges and drops exact repeats.
///
/// Ranges are kept per shard rather than merged into runs, deliberately: each
/// carries the block hash its coverage rests on, and a reorg is found by
/// asking the wallet's chain about those hashes newest first. Merging shards
/// 0-2 into one range would keep only shard 2's hash, and a reorg inside
/// shard 1 would then roll back to the set's start instead of to shard 0.
pub fn merge_coverage(mut ranges: Vec<CoverageRange>) -> Vec<CoverageRange> {
    ranges.sort_by_key(|range| (range.start_height, range.end_height));
    ranges.dedup();
    ranges
}

/// The heights in `[from, through]` that `ranges` do not cover, as inclusive
/// gaps in ascending order.
pub fn uncovered(ranges: &[CoverageRange], from: u64, through: u64) -> Vec<(u64, u64)> {
    if from > through {
        return Vec::new();
    }
    let mut sorted: Vec<&CoverageRange> = ranges.iter().collect();
    sorted.sort_by_key(|range| range.start_height);
    let mut gaps = Vec::new();
    let mut next = from;
    for range in sorted {
        if range.end_height < next || range.start_height > range.end_height {
            continue;
        }
        if range.start_height > through {
            break;
        }
        if range.start_height > next {
            gaps.push((next, range.start_height - 1));
        }
        // Reaching the inclusive target completes the walk, including MAX:
        // there need not be a representable height after the covered suffix.
        if range.end_height >= through {
            return gaps;
        }
        next = next.max(range.end_height + 1);
    }
    gaps.push((next, through));
    gaps
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(start: u64, end: u64, kind: CoverageKind) -> CoverageRange {
        CoverageRange {
            source_anchor: None,
            script: vec![1],
            start_height: start,
            end_height: end,
            kind,
            shard_id: 0,
            revision_digest: "d".into(),
            terminal_block_hash: "h".into(),
        }
    }

    #[test]
    fn coverage_at_the_largest_height_does_not_wrap() {
        let max = u64::MAX;
        assert_eq!(uncovered(&[], max, max), vec![(max, max)]);
        assert!(uncovered(&[], max, max - 1).is_empty());
        assert!(uncovered(&[range(0, max, CoverageKind::Settled)], 0, max).is_empty());
        assert_eq!(
            uncovered(&[range(1, max, CoverageKind::Settled)], 0, max),
            vec![(0, 0)]
        );
        assert_eq!(
            uncovered(&[range(1, max - 1, CoverageKind::Settled)], 0, max),
            vec![(0, 0), (max, max)]
        );
        assert_eq!(
            uncovered(&[range(max, max, CoverageKind::Settled)], 3, 5),
            vec![(3, 5)]
        );
        assert!(uncovered(&[range(max, max, CoverageKind::Settled)], max, max).is_empty());
    }

    #[test]
    fn ranges_are_kept_per_shard_in_order_without_repeats() {
        let merged = merge_coverage(vec![
            range(200, 299, CoverageKind::Settled),
            range(0, 199, CoverageKind::Settled),
            range(0, 199, CoverageKind::Settled),
            range(300, 349, CoverageKind::Provisional),
        ]);
        assert_eq!(merged.len(), 3);
        assert_eq!((merged[0].start_height, merged[0].end_height), (0, 199));
        assert_eq!((merged[1].start_height, merged[1].end_height), (200, 299));
        assert_eq!(merged[2].kind, CoverageKind::Provisional);
    }

    #[test]
    fn uncovered_reports_the_gaps_and_nothing_else() {
        let ranges = vec![
            range(100, 199, CoverageKind::Settled),
            range(300, 399, CoverageKind::Settled),
        ];
        assert_eq!(
            uncovered(&ranges, 0, 499),
            vec![(0, 99), (200, 299), (400, 499)]
        );
        assert_eq!(uncovered(&ranges, 150, 350), vec![(200, 299)]);
        assert_eq!(uncovered(&ranges, 100, 199), vec![]);
        assert_eq!(uncovered(&[], 5, 5), vec![(5, 5)]);
    }
}
