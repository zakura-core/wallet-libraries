//! The store, in memory: the reference semantics every other implementation
//! has to match, and what the one-shot `sync` uses.

use crate::engine::ledger::LedgerError;
use crate::engine::store::{
    Anchor, CachedRun, CoverageKind, CoverageRange, PendingPages, ScriptEntry, SetIdentity,
    SetupBlob, SetupKey, ShardCommit, StoreError, StoredEvent, WalletStore, merge_coverage,
    receive_key, spend_key,
};
use std::collections::BTreeMap;
use transparent_events::{TransparentEvent, Txid};

/// Default bound on pending page retrievals a commit may leave.
pub const DEFAULT_PENDING_LIMIT: usize = 4_096;

type ReceiveKey = (Txid, u32);
type SpendKey = (Txid, u32, Txid, u32);

#[derive(Clone, Debug, Default)]
struct State {
    identity: Option<SetIdentity>,
    anchor: Option<Anchor>,
    settled_through: Option<u64>,
    covered_through: Option<u64>,
    scripts: BTreeMap<Vec<u8>, ScriptEntry>,
    coverage: BTreeMap<Vec<u8>, Vec<CoverageRange>>,
    receives: BTreeMap<ReceiveKey, StoredEvent>,
    spends: BTreeMap<SpendKey, StoredEvent>,
    /// Which spend consumes each outpoint, for the double-spend rule.
    spent_by: BTreeMap<ReceiveKey, SpendKey>,
    pending: BTreeMap<u64, PendingPages>,
    next_pending: u64,
    setups: BTreeMap<SetupKey, SetupBlob>,
    /// Run histories by page shard identity and script.
    runs: BTreeMap<(String, Vec<u8>), CachedRun>,
    filters: BTreeMap<String, (String, bool, Vec<u8>)>,
    /// Content failures by shard id and script.
    failures: BTreeMap<(u64, Vec<u8>), u32>,
    commits: u64,
}

/// An in-memory [`WalletStore`] with snapshot and restore for crash tests.
#[derive(Clone, Debug, Default)]
pub struct MemoryStore {
    state: State,
    pending_limit: Option<usize>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_pending_limit(limit: usize) -> Self {
        Self {
            state: State::default(),
            pending_limit: Some(limit),
        }
    }

    /// A copy of the whole store, to restore after a simulated crash.
    pub fn snapshot(&self) -> Self {
        self.clone()
    }

    pub fn restore(&mut self, snapshot: Self) {
        *self = snapshot;
    }

    fn height_of(event: &TransparentEvent) -> u64 {
        match event {
            TransparentEvent::Receive(receive) => u64::from(receive.height),
            TransparentEvent::Spend(spend) => u64::from(spend.height),
        }
    }
}

impl WalletStore for MemoryStore {
    fn set_identity(&self) -> Result<Option<SetIdentity>, StoreError> {
        Ok(self.state.identity.clone())
    }

    fn bind_set(&mut self, identity: &SetIdentity) -> Result<(), StoreError> {
        match &self.state.identity {
            None => {
                self.state.identity = Some(identity.clone());
                Ok(())
            }
            Some(stored) if stored.continues(identity) => {
                // A geometry the store had not seen may appear; record it.
                self.state.identity = Some(identity.clone());
                Ok(())
            }
            Some(stored) => Err(StoreError::SetMismatch {
                stored: stored.digest(),
                offered: identity.digest(),
            }),
        }
    }

    fn anchor(&self) -> Result<Option<Anchor>, StoreError> {
        Ok(self.state.anchor.clone())
    }

    fn scripts(&self) -> Result<Vec<ScriptEntry>, StoreError> {
        Ok(self.state.scripts.values().cloned().collect())
    }

    fn add_scripts(&mut self, entries: &[ScriptEntry]) -> Result<usize, StoreError> {
        let mut added = 0;
        for entry in entries {
            match self.state.scripts.get_mut(&entry.script) {
                Some(existing) => {
                    // Coverage once required stays required.
                    existing.required_from = existing.required_from.min(entry.required_from);
                }
                None => {
                    self.state
                        .scripts
                        .insert(entry.script.clone(), entry.clone());
                    added += 1;
                }
            }
        }
        Ok(added)
    }

    fn coverage(&self, script: &[u8]) -> Result<Vec<CoverageRange>, StoreError> {
        Ok(self.state.coverage.get(script).cloned().unwrap_or_default())
    }

    fn provisional(&self) -> Result<Vec<CoverageRange>, StoreError> {
        Ok(self
            .state
            .coverage
            .values()
            .flatten()
            .filter(|range| range.kind == CoverageKind::Provisional)
            .cloned()
            .collect())
    }

    fn events(&self) -> Result<Vec<StoredEvent>, StoreError> {
        let mut events: Vec<StoredEvent> = self
            .state
            .receives
            .values()
            .chain(self.state.spends.values())
            .cloned()
            .collect();
        events.sort_by_key(|entry| entry.event.sort_key());
        Ok(events)
    }

    fn commit_shard(&mut self, commit: ShardCommit) -> Result<u64, StoreError> {
        transparent_events::check_transaction_consistency(
            self.state
                .receives
                .values()
                .chain(self.state.spends.values())
                .chain(commit.events.iter())
                .map(|stored| &stored.event),
        )
        .map_err(|e| StoreError::Corrupt(e.to_string()))?;
        // Validate everything against the current state first; only then
        // write, so a refused commit leaves the store exactly as it was.
        let mut new_receives: Vec<(ReceiveKey, StoredEvent)> = Vec::new();
        let mut new_spends: Vec<(SpendKey, StoredEvent)> = Vec::new();
        for stored in &commit.events {
            match &stored.event {
                TransparentEvent::Receive(receive) => {
                    let key = receive_key(receive);
                    if let Some(existing) = self.state.receives.get(&key) {
                        if existing.event != stored.event || existing.script != stored.script {
                            return Err(LedgerError::ConflictingReceive(
                                receive.txid.to_display_hex(),
                                receive.output_index,
                            )
                            .into());
                        }
                        continue;
                    }
                    new_receives.push((key, stored.clone()));
                }
                TransparentEvent::Spend(spend) => {
                    let key = spend_key(spend);
                    let outpoint = (spend.spent_txid, spend.spent_output_index);
                    if let Some(existing) = self.state.spends.get(&key) {
                        if existing.event != stored.event || existing.script != stored.script {
                            return Err(LedgerError::DoubleSpend(
                                spend.spent_txid.to_display_hex(),
                                spend.spent_output_index,
                            )
                            .into());
                        }
                        continue;
                    }
                    if let Some(other) = self.state.spent_by.get(&outpoint) {
                        if *other != key {
                            return Err(LedgerError::DoubleSpend(
                                spend.spent_txid.to_display_hex(),
                                spend.spent_output_index,
                            )
                            .into());
                        }
                    }
                    new_spends.push((key, stored.clone()));
                }
            }
        }
        let limit = self.pending_limit();
        let pending_after = self.state.pending.len()
            + commit
                .pending_upsert
                .iter()
                .filter(|p| p.id.is_none())
                .count()
            - commit.pending_complete.len().min(self.state.pending.len());
        if pending_after > limit {
            return Err(StoreError::PendingLimit { limit });
        }
        for run in &commit.cached_runs {
            if self
                .state
                .runs
                .get(&(run.child_digest.clone(), run.script.clone()))
                .is_some_and(|held| held != run)
            {
                return Err(StoreError::Corrupt(format!(
                    "page shard {} holds two histories for one script",
                    run.child_digest
                )));
            }
        }

        for (key, event) in new_receives {
            self.state.receives.insert(key, event);
        }
        for (key, event) in new_spends {
            let outpoint = (key.2, key.3);
            self.state.spent_by.insert(outpoint, key);
            self.state.spends.insert(key, event);
        }
        let kind = if commit.sealed {
            CoverageKind::Settled
        } else {
            CoverageKind::Provisional
        };
        for script in &commit.covered_scripts {
            let ranges = self.state.coverage.entry(script.clone()).or_default();
            let range = CoverageRange {
                source_anchor: commit.source_anchor.clone(),
                script: script.clone(),
                start_height: commit.start_height,
                end_height: commit.end_height,
                kind,
                shard_id: commit.shard_id,
                revision_digest: commit.revision_digest.clone(),
                terminal_block_hash: commit.terminal_block_hash.clone(),
            };
            // A range strictly inside the one starting nearest at or below it
            // is already covered: nothing changes. Otherwise it replaces every
            // range of this script it contains, whatever shard they came
            // from: a repeat, a longer revision at the same start, and the
            // narrower shards a re-cut merged into this one. The SQLite store
            // keeps the same rule.
            let holder = ranges
                .iter()
                .filter(|old| old.start_height <= range.start_height)
                .max_by_key(|old| (old.start_height, old.end_height));
            if holder.is_some_and(|old| {
                old.end_height >= range.end_height
                    && (old.start_height, old.end_height) != (range.start_height, range.end_height)
            }) {
                continue;
            }
            ranges.retain(|old| {
                !(old.start_height >= range.start_height && old.end_height <= range.end_height)
            });
            if !ranges.contains(&range) {
                ranges.push(range);
            }
            let merged = merge_coverage(std::mem::take(ranges));
            *ranges = merged;
        }
        for id in &commit.pending_complete {
            self.state.pending.remove(id);
        }
        let finishes_shard = commit.finishes_shard();
        for run in commit.cached_runs {
            self.state
                .runs
                .insert((run.child_digest.clone(), run.script.clone()), run);
        }
        if finishes_shard {
            self.state.runs.retain(|(_, script), run| {
                run.shard_id != commit.shard_id || !commit.covered_scripts.contains(script)
            });
        }
        for script in commit.failed_entries {
            *self
                .state
                .failures
                .entry((commit.shard_id, script))
                .or_default() += 1;
        }
        for mut pending in commit.pending_upsert {
            let id = match pending.id {
                Some(id) => id,
                None => {
                    self.state.next_pending += 1;
                    self.state.next_pending
                }
            };
            pending.id = Some(id);
            self.state.pending.insert(id, pending);
        }
        self.state.commits += 1;
        Ok(self.state.commits)
    }

    fn commit_anchor(
        &mut self,
        anchor: &Anchor,
        settled_through: u64,
        covered_through: u64,
    ) -> Result<u64, StoreError> {
        self.state.anchor = Some(anchor.clone());
        self.state.settled_through = Some(settled_through);
        self.state.covered_through = Some(covered_through);
        self.state.commits += 1;
        Ok(self.state.commits)
    }

    fn rollback_above(&mut self, accepted: &Anchor, _reason: &str) -> Result<u64, StoreError> {
        let height = accepted.height;
        self.state
            .receives
            .retain(|_, stored| Self::height_of(&stored.event) <= height);
        let mut removed_spends: Vec<SpendKey> = Vec::new();
        self.state.spends.retain(|key, stored| {
            let keep = Self::height_of(&stored.event) <= height;
            if !keep {
                removed_spends.push(*key);
            }
            keep
        });
        for key in removed_spends {
            self.state.spent_by.remove(&(key.2, key.3));
        }
        for ranges in self.state.coverage.values_mut() {
            ranges.retain_mut(|range| {
                if range.start_height > height {
                    return false;
                }
                if range.end_height > height {
                    // A range straddling the rollback keeps its covered part;
                    // the identity it carried no longer describes the whole
                    // range, but it still names the shard the part came from.
                    range.end_height = height;
                    range.terminal_block_hash = accepted.hash.clone();
                }
                true
            });
        }
        // Cached runs survive: each is keyed by its page shard's chained
        // identity, which commits to that page shard's terminal block and to
        // every earlier one, so a walk reaches it only through a manifest on
        // the accepted chain. A tail replaced by a later revision keeps the
        // runs its sealed page shards share, which is what lets the catch-up
        // stop at them.
        // All pending retrievals are inexpensive to re-plan and may contain old-branch data.
        self.state.pending.clear();
        if let Some(anchor) = &mut self.state.anchor {
            if anchor.height > height {
                anchor.height = height;
                anchor.hash = accepted.hash.clone();
            }
        }
        if let Some(settled) = &mut self.state.settled_through {
            *settled = (*settled).min(height);
        }
        if let Some(covered) = &mut self.state.covered_through {
            *covered = (*covered).min(height);
        }
        self.state.commits += 1;
        Ok(self.state.commits)
    }

    fn promote_provisional(
        &mut self,
        shard_id: u64,
        revision_digest: &str,
    ) -> Result<(), StoreError> {
        for ranges in self.state.coverage.values_mut() {
            for range in ranges.iter_mut() {
                if range.shard_id == shard_id
                    && range.revision_digest == revision_digest
                    && range.kind == CoverageKind::Provisional
                {
                    range.kind = CoverageKind::Settled;
                }
            }
            let merged = merge_coverage(std::mem::take(ranges));
            *ranges = merged;
        }
        Ok(())
    }

    fn pending(&self) -> Result<Vec<PendingPages>, StoreError> {
        Ok(self.state.pending.values().cloned().collect())
    }

    fn cached_run(
        &self,
        child_digest: &str,
        script: &[u8],
    ) -> Result<Option<CachedRun>, StoreError> {
        Ok(self
            .state
            .runs
            .get(&(child_digest.to_string(), script.to_vec()))
            .cloned())
    }

    fn pending_limit(&self) -> usize {
        self.pending_limit.unwrap_or(DEFAULT_PENDING_LIMIT)
    }

    fn setup(&self, key: &SetupKey) -> Result<Option<SetupBlob>, StoreError> {
        Ok(self.state.setups.get(key).cloned())
    }

    fn put_setup(&mut self, key: &SetupKey, blob: &SetupBlob) -> Result<(), StoreError> {
        self.state.setups.insert(key.clone(), blob.clone());
        Ok(())
    }

    fn drop_setup(&mut self, key: &SetupKey) -> Result<(), StoreError> {
        self.state.setups.remove(key);
        Ok(())
    }

    fn filter(
        &self,
        revision_digest: &str,
        filter_hash: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .state
            .filters
            .get(revision_digest)
            .filter(|(hash, _, _)| hash == filter_hash)
            .map(|(_, _, bytes)| bytes.clone()))
    }

    fn put_filter(
        &mut self,
        revision_digest: &str,
        filter_hash: &str,
        sealed: bool,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        self.state.filters.insert(
            revision_digest.to_string(),
            (filter_hash.to_string(), sealed, bytes.to_vec()),
        );
        Ok(())
    }

    fn last_commit(&self) -> Result<u64, StoreError> {
        Ok(self.state.commits)
    }

    fn entry_failures(&self, shard_id: u64, script: &[u8]) -> Result<u32, StoreError> {
        Ok(self
            .state
            .failures
            .get(&(shard_id, script.to_vec()))
            .copied()
            .unwrap_or(0))
    }
}
