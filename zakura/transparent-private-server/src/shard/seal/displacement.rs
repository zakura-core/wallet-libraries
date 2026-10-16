//! Sealing for the decoupled layout: a directory shard and its page shards.
//!
//! A directory shard D covers a block range and seals on script count,
//! directory bytes, a tier boundary, or its page-shard limit. Inside it, up to
//! [`MAX_PAGE_CHILDREN`] page shards cover consecutive block ranges and seal on
//! page rows alone, so the two tables are sized independently.
//!
//! Each script keeps its two newest events in D inline. When a third arrives,
//! the oldest inline event is *pushed out* into the script's run in whichever
//! page shard is open at that block, never into the one where the event
//! happened: that one may have sealed, and sealed tables never change. A
//! script therefore has at most one run per page shard, runs are in time
//! order, and a sealed page shard is final the moment it seals.
//!
//! Per block, deterministically, so a fresh build equals block-by-block
//! publishing:
//!
//! 1. project the block into (D, P);
//! 2. if P would overflow, close P and re-project into (D, new P); if D has no
//!    room for another page shard, close D as well;
//! 3. if D would overflow, close both and re-project into a fresh pair;
//! 4. after absorbing: if D is at a target, close D and P; else if P is at its
//!    target, close P, and D too if that was its last page shard;
//! 5. a block over a capacity on its own is absorbed into its own shard, which
//!    the builder gives more segments, and closes immediately.

use super::{Limit, SealError, SealPolicy, SealReason};
use crate::shard::build::Placement;
use crate::shard::packing::{HistoryLayout, PackedDemand};
use std::collections::{HashMap, HashSet};
use zakura_transparent_private_shared::events::TransparentEvent;
use zakura_transparent_private_shared::filter::ScriptBytes;
use zakura_transparent_private_shared::shard::compact;
pub use zakura_transparent_private_shared::shard::layout::MAX_PAGE_CHILDREN;
use zakura_transparent_private_shared::shard::layout::{Geometry, PAGE_ENTRY_HEADER_BYTES};
use zakura_transparent_private_shared::shard::packing::ROW_PAYLOAD;
use zakura_transparent_private_shared::shard::records::{
    DIRECTORY_ENTRY_HEADER_BYTES, DIRECTORY_ROW_HEADER_BYTES, MAX_SCRIPT_BYTES,
};

/// The limits a decoupled pair seals under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecoupledPolicy {
    pub scripts: Limit,
    pub directory_bytes: Limit,
    pub page_rows: Limit,
    pub max_children: u32,
    /// Page entry header bytes, which decide each fragment's payload.
    pub page_entry_header: usize,
}

impl DecoupledPolicy {
    /// The policy a published geometry implies: its directory dimensions size
    /// D, its page rows size every page shard, with the same reserves as
    /// [`SealPolicy`] (a seventh of scripts and directory bytes, a
    /// thirty-second of page rows), [`MAX_PAGE_CHILDREN`] page shards and the
    /// schema's page entry header.
    pub fn for_geometry(geometry: &Geometry) -> Self {
        Self::scoring(geometry, MAX_PAGE_CHILDREN, PAGE_ENTRY_HEADER_BYTES)
    }

    /// [`Self::for_geometry`] with another child limit or entry header, for a
    /// census scoring a shape that is not published.
    pub fn scoring(geometry: &Geometry, max_children: u32, page_entry_header: usize) -> Self {
        let coupled = SealPolicy::for_geometry(geometry);
        let bytes = geometry.directory_rows
            * (geometry.directory_row_bytes - DIRECTORY_ROW_HEADER_BYTES) as u64;
        Self {
            scripts: coupled.scripts,
            directory_bytes: Limit {
                target: bytes - bytes / 7,
                capacity: bytes,
            },
            page_rows: coupled.page_rows,
            max_children,
            page_entry_header,
        }
    }
}

/// What one page shard holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChildOccupancy {
    /// Packed page rows, which is what seals a page shard.
    pub page_rows: u64,
    pub fragments: u64,
    /// Scripts with a run here.
    pub runs: u64,
    pub paged_events: u64,
    pub blocks: u64,
    pub demand: PackedDemand,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedChild {
    /// Position j within the directory shard.
    pub index: u32,
    pub start_height: u64,
    pub end_height: u64,
    pub occupancy: ChildOccupancy,
    /// `None` for the page shard still open in the tail directory shard.
    pub reason: Option<SealReason>,
}

/// What one directory shard holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DirectoryOccupancy {
    pub scripts: u64,
    pub directory_bytes: u64,
    pub events: u64,
    pub inline_events: u64,
    pub blocks: u64,
    /// Scripts with at least one run.
    pub paged_scripts: u64,
    /// Scripts by run count: index r counts the scripts with r runs. A paged
    /// script's first recovery costs about r + 1 page round trips.
    pub chain_lengths: Vec<u64>,
}

/// One run of a watched script, in time order within its directory shard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WatchedRun {
    pub child: u32,
    pub fragments: u32,
    pub events: u32,
}

/// A watched script's place in one directory shard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WatchedChain {
    pub script: Vec<u8>,
    pub events: u32,
    pub runs: Vec<WatchedRun>,
}

/// A boundary the sealer decided, in the order it decided them.
///
/// A builder that follows the sealer consumes these as they happen, so it can
/// lay out each page shard as soon as it seals rather than holding a whole
/// directory shard's history: see [`DisplacementSealer::drain_closed`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Closed {
    /// A page shard sealed. Its directory shard may still be open.
    Child(SealedChild),
    /// A directory shard closed, after its last page shard's [`Closed::Child`].
    Directory(SealedDirectory),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedDirectory {
    pub shard_id: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub occupancy: DirectoryOccupancy,
    pub children: Vec<SealedChild>,
    /// `None` for the tail.
    pub reason: Option<SealReason>,
    pub placement: Option<Placement>,
    /// Watched scripts active in this shard, in script order.
    pub watched: Vec<WatchedChain>,
}

#[derive(Clone, Debug, Default)]
struct Entry {
    events: u32,
    inline: Vec<TransparentEvent>,
    runs: u32,
}

impl Entry {
    fn directory_bytes(&self) -> u64 {
        (DIRECTORY_ENTRY_HEADER_BYTES + compact::encoded_len(&self.inline)) as u64
    }
}

struct Update {
    script: Vec<u8>,
    entry: Entry,
    pushed: Vec<TransparentEvent>,
}

struct DirectoryProjection {
    scripts: u64,
    directory_bytes: u64,
    inline_events: u64,
}

/// Streams blocks in height order and emits closed directory shards with their
/// page shards. Feed every block, including empty ones.
pub struct DisplacementSealer {
    policy: DecoupledPolicy,
    geometry: Geometry,
    measure_placement: bool,
    watched: HashSet<Vec<u8>>,
    first_height: u64,
    next_expected: Option<u64>,
    next_shard_id: u64,

    scripts: HashMap<Vec<u8>, Entry>,
    directory_bytes: u64,
    inline_events: u64,
    events: u64,
    start_height: Option<u64>,
    last_height: Option<u64>,
    children: Vec<SealedChild>,
    watched_runs: HashMap<Vec<u8>, Vec<WatchedRun>>,

    runs: HashMap<Vec<u8>, HistoryLayout>,
    demand: PackedDemand,
    fragments: u64,
    paged_events: u64,
    child_start: Option<u64>,
    /// Boundaries not yet drained, oldest first.
    closed: Vec<Closed>,
}

impl DisplacementSealer {
    pub fn new(
        policy: DecoupledPolicy,
        geometry: Geometry,
        first_height: u64,
        next_shard_id: u64,
    ) -> Self {
        Self {
            policy,
            geometry,
            measure_placement: false,
            watched: HashSet::new(),
            first_height,
            next_expected: None,
            next_shard_id,
            scripts: HashMap::new(),
            directory_bytes: 0,
            inline_events: 0,
            events: 0,
            start_height: None,
            last_height: None,
            children: Vec::new(),
            watched_runs: HashMap::new(),
            runs: HashMap::new(),
            demand: PackedDemand::with_entry_header(policy.page_entry_header),
            fragments: 0,
            paged_events: 0,
            child_start: None,
            closed: Vec::new(),
        }
    }

    /// Every boundary decided since the last call, in order: each sealed page
    /// shard, then its directory shard when that closed too.
    pub fn drain_closed(&mut self) -> Vec<Closed> {
        std::mem::take(&mut self.closed)
    }

    /// The page shard index the next absorbed block joins.
    pub fn open_child(&self) -> u32 {
        self.children.len() as u32
    }

    /// Reports each directory shard's real two-choice placement.
    pub fn measure_placement(&mut self, on: bool) {
        self.measure_placement = on;
    }

    /// Scripts whose per-shard chains each closed directory shard reports.
    pub fn watch(&mut self, scripts: HashSet<Vec<u8>>) {
        self.watched = scripts;
    }

    pub fn next_shard_id(&self) -> u64 {
        self.next_shard_id
    }

    pub fn open_start(&self) -> Option<u64> {
        self.start_height
    }

    fn payload(&self) -> usize {
        ROW_PAYLOAD - self.policy.page_entry_header
    }

    /// The directory entries `events` produce, and what each pushes out.
    fn directory_updates(&self, events: &[(ScriptBytes, TransparentEvent)]) -> Vec<Update> {
        let mut added: HashMap<&[u8], Vec<TransparentEvent>> = HashMap::new();
        for (script, event) in events {
            added.entry(script.as_slice()).or_default().push(*event);
        }
        let inline = self.geometry.inline_events as usize;
        let mut updates: Vec<Update> = added
            .into_iter()
            .map(|(script, mut events)| {
                events.sort_by_key(TransparentEvent::sort_key);
                let mut entry = self.scripts.get(script).cloned().unwrap_or_default();
                let mut pushed = Vec::new();
                for event in events {
                    entry.events += 1;
                    entry.inline.push(event);
                    if entry.inline.len() > inline {
                        pushed.push(entry.inline.remove(0));
                    }
                }
                Update {
                    script: script.to_vec(),
                    entry,
                    pushed,
                }
            })
            .collect();
        // Map order is random; the projection's arithmetic is not, but the
        // runs it hands back are inserted in this order.
        updates.sort_by(|a, b| a.script.cmp(&b.script));
        updates
    }

    fn project_directory(&self, updates: &[Update]) -> DirectoryProjection {
        let mut projection = DirectoryProjection {
            scripts: self.scripts.len() as u64,
            directory_bytes: self.directory_bytes,
            inline_events: self.inline_events,
        };
        for update in updates {
            let old = self.scripts.get(&update.script);
            if old.is_none() {
                projection.scripts += 1;
            }
            let old_inline = old.map_or(0, |entry| entry.inline.len() as u64);
            projection.inline_events =
                projection.inline_events - old_inline + update.entry.inline.len() as u64;
            if update.script.len() <= MAX_SCRIPT_BYTES {
                projection.directory_bytes = projection.directory_bytes
                    - old.map_or(0, Entry::directory_bytes)
                    + update.entry.directory_bytes();
            }
        }
        projection
    }

    /// The runs `updates` produce in the open page shard. Shifts the packed
    /// demand in place; [`Self::unproject_child`] restores it.
    fn project_child(&mut self, updates: &[Update]) -> Vec<(Vec<u8>, HistoryLayout)> {
        let payload = self.payload();
        let mut runs = Vec::new();
        // A script too long for a directory entry is filtered publicly but
        // never indexed, so it has no runs either.
        for update in updates
            .iter()
            .filter(|update| !update.pushed.is_empty() && update.script.len() <= MAX_SCRIPT_BYTES)
        {
            let old = self.runs.get(&update.script).cloned().unwrap_or_default();
            let mut run = old.clone();
            for event in &update.pushed {
                run.push_with_payload(*event, 0, payload);
            }
            self.demand.shift(&old, &run);
            runs.push((update.script.clone(), run));
        }
        runs
    }

    fn unproject_child(&mut self, runs: &[(Vec<u8>, HistoryLayout)]) {
        for (script, run) in runs {
            let empty = HistoryLayout::default();
            let old = self.runs.get(script).unwrap_or(&empty);
            self.demand.shift(run, old);
        }
    }

    fn directory_over(&self, projection: &DirectoryProjection) -> Option<&'static str> {
        if projection.scripts > self.policy.scripts.capacity {
            Some("scripts")
        } else if projection.directory_bytes > self.policy.directory_bytes.capacity {
            Some("directory bytes")
        } else {
            None
        }
    }

    fn directory_at_target(&self) -> Option<&'static str> {
        if self.scripts.len() as u64 >= self.policy.scripts.target {
            Some("scripts")
        } else if self.directory_bytes >= self.policy.directory_bytes.target {
            Some("directory bytes")
        } else {
            None
        }
    }

    /// Whether the open page shard is the last one this directory may hold.
    fn last_child(&self) -> bool {
        self.children.len() as u32 + 1 >= self.policy.max_children
    }

    fn absorb(
        &mut self,
        height: u64,
        updates: Vec<Update>,
        projection: DirectoryProjection,
        runs: Vec<(Vec<u8>, HistoryLayout)>,
        events: u64,
    ) {
        self.start_height.get_or_insert(height);
        self.child_start.get_or_insert(height);
        self.last_height = Some(height);
        self.directory_bytes = projection.directory_bytes;
        self.inline_events = projection.inline_events;
        self.events += events;
        for (script, run) in runs {
            let old = self.runs.get(&script);
            self.fragments += u64::from(run.fragments - old.map_or(0, |r| r.fragments));
            self.paged_events += u64::from(run.events - old.map_or(0, |r| r.events));
            self.runs.insert(script, run);
        }
        for mut update in updates {
            if !update.pushed.is_empty()
                && update.script.len() <= MAX_SCRIPT_BYTES
                && self
                    .runs
                    .get(&update.script)
                    .is_some_and(|run| run.events as usize == update.pushed.len())
            {
                // This page shard just gained the script's run.
                update.entry.runs += 1;
            }
            self.scripts.insert(update.script, update.entry);
        }
        debug_assert_eq!(self.scripts.len() as u64, projection.scripts);
    }

    fn close_child(&mut self, reason: Option<SealReason>) {
        let Some(start_height) = self.child_start.take() else {
            return;
        };
        let index = self.children.len() as u32;
        if self.watched.len() < self.runs.len() {
            for script in &self.watched {
                if let Some(run) = self.runs.get(script) {
                    self.watched_runs
                        .entry(script.clone())
                        .or_default()
                        .push(WatchedRun {
                            child: index,
                            fragments: run.fragments,
                            events: run.events,
                        });
                }
            }
        } else {
            for (script, run) in &self.runs {
                if self.watched.contains(script) {
                    self.watched_runs
                        .entry(script.clone())
                        .or_default()
                        .push(WatchedRun {
                            child: index,
                            fragments: run.fragments,
                            events: run.events,
                        });
                }
            }
        }
        let demand = std::mem::replace(
            &mut self.demand,
            PackedDemand::with_entry_header(self.policy.page_entry_header),
        );
        let end_height = self.last_height.expect("an open page shard has an end");
        let child = SealedChild {
            index,
            start_height,
            end_height,
            occupancy: ChildOccupancy {
                page_rows: demand.rows(),
                fragments: self.fragments,
                runs: self.runs.len() as u64,
                paged_events: self.paged_events,
                blocks: end_height - start_height + 1,
                demand,
            },
            reason,
        };
        self.closed.push(Closed::Child(child.clone()));
        self.children.push(child);
        self.runs.clear();
        self.fragments = 0;
        self.paged_events = 0;
    }

    fn close_directory(
        &mut self,
        reason: Option<SealReason>,
        child_reason: Option<SealReason>,
    ) -> SealedDirectory {
        self.close_child(child_reason);
        let mut chain_lengths = vec![0u64; self.policy.max_children as usize + 1];
        let mut paged_scripts = 0;
        for entry in self.scripts.values() {
            chain_lengths[entry.runs as usize] += 1;
            if entry.runs > 0 {
                paged_scripts += 1;
            }
        }
        let placement = self.measure_placement.then(|| {
            let ordered = crate::shard::build::placement_order(
                self.scripts
                    .iter()
                    .filter(|(script, _)| script.len() <= MAX_SCRIPT_BYTES)
                    .map(|(script, entry)| (script.as_slice(), entry.directory_bytes() as usize)),
            );
            let scripts: Vec<&[u8]> = ordered.iter().map(|(script, _)| *script).collect();
            let sizes: Vec<usize> = ordered.iter().map(|(_, size)| *size).collect();
            crate::shard::build::place_scripts(
                self.next_shard_id,
                &scripts,
                &sizes,
                self.geometry.directory_rows,
                self.geometry.directory_row_bytes - DIRECTORY_ROW_HEADER_BYTES,
            )
            .unwrap_or_else(|script| panic!("placement gave up on script {script}"))
            .0
        });
        let mut watched: Vec<WatchedChain> = self
            .watched
            .iter()
            .filter_map(|script| {
                self.scripts.get(script).map(|entry| WatchedChain {
                    script: script.clone(),
                    events: entry.events,
                    runs: self.watched_runs.remove(script).unwrap_or_default(),
                })
            })
            .collect();
        watched.sort_by(|a, b| a.script.cmp(&b.script));
        let start_height = self
            .start_height
            .take()
            .expect("a closing shard has a start");
        let end_height = self.last_height.take().expect("a closing shard has an end");
        let shard = SealedDirectory {
            shard_id: self.next_shard_id,
            start_height,
            end_height,
            occupancy: DirectoryOccupancy {
                scripts: self.scripts.len() as u64,
                directory_bytes: self.directory_bytes,
                events: self.events,
                inline_events: self.inline_events,
                blocks: end_height - start_height + 1,
                paged_scripts,
                chain_lengths,
            },
            children: std::mem::take(&mut self.children),
            reason,
            placement,
            watched,
        };
        self.next_shard_id += 1;
        self.scripts.clear();
        self.watched_runs.clear();
        self.directory_bytes = 0;
        self.inline_events = 0;
        self.events = 0;
        self.closed.push(Closed::Directory(shard.clone()));
        shard
    }

    /// Offers one block, returning the directory shards it closed. Page shards
    /// closed inside a still-open directory shard are reported with it.
    pub fn push_block(
        &mut self,
        height: u64,
        events: &[(ScriptBytes, TransparentEvent)],
    ) -> Result<Vec<SealedDirectory>, SealError> {
        let expected = self.next_expected.unwrap_or(self.first_height);
        if height != expected {
            return Err(SealError::OutOfOrder { height, expected });
        }
        let mut sealed = Vec::new();
        let mut updates = self.directory_updates(events);
        let mut projection = self.project_directory(&updates);
        let mut runs = self.project_child(&updates);

        if self.child_start.is_some() && self.demand.rows() > self.policy.page_rows.capacity {
            self.unproject_child(&runs);
            let pages_full = Some(SealReason::WouldExceedCapacity("page rows"));
            if self.last_child() {
                sealed.push(self.close_directory(Some(SealReason::ChildLimit), pages_full));
                updates = self.directory_updates(events);
                projection = self.project_directory(&updates);
            } else {
                self.close_child(pages_full);
            }
            runs = self.project_child(&updates);
        }
        if self.start_height.is_some() {
            if let Some(quantity) = self.directory_over(&projection) {
                self.unproject_child(&runs);
                sealed.push(self.close_directory(
                    Some(SealReason::WouldExceedCapacity(quantity)),
                    Some(SealReason::DirectorySealed),
                ));
                updates = self.directory_updates(events);
                projection = self.project_directory(&updates);
                runs = self.project_child(&updates);
            }
        }
        let directory_oversized = self.directory_over(&projection);
        let pages_oversized = self.demand.rows() > self.policy.page_rows.capacity;
        self.absorb(height, updates, projection, runs, events.len() as u64);
        self.next_expected = Some(height + 1);

        if let Some(quantity) = directory_oversized {
            sealed.push(self.close_directory(
                Some(SealReason::BlockExceedsCapacity(quantity)),
                Some(SealReason::DirectorySealed),
            ));
        } else if let Some(quantity) = self.directory_at_target() {
            sealed.push(self.close_directory(
                Some(SealReason::ReachedTarget(quantity)),
                Some(SealReason::DirectorySealed),
            ));
        } else if pages_oversized || self.demand.rows() >= self.policy.page_rows.target {
            let reason = Some(if pages_oversized {
                SealReason::BlockExceedsCapacity("page rows")
            } else {
                SealReason::ReachedTarget("page rows")
            });
            if self.last_child() {
                sealed.push(self.close_directory(Some(SealReason::ChildLimit), reason));
            } else {
                self.close_child(reason);
            }
        }
        Ok(sealed)
    }

    /// Closes the directory shard and its open page shard at a tier boundary.
    pub fn seal_at_geometry_change(&mut self) -> Option<SealedDirectory> {
        self.start_height?;
        Some(self.close_directory(
            Some(SealReason::GeometryChanged),
            Some(SealReason::GeometryChanged),
        ))
    }

    /// Closes whatever is still accumulating: the tail pair.
    pub fn finish(&mut self) -> Option<SealedDirectory> {
        self.start_height?;
        Some(self.close_directory(None, None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zakura_transparent_private_shared::events::{ReceiveEvent, SpendEvent, Txid};
    use zakura_transparent_private_shared::shard::layout::DECOUPLED_2K_8K;

    fn script(tag: u32) -> ScriptBytes {
        let mut bytes = vec![0x76, 0xa9, 0x14];
        bytes.extend_from_slice(&tag.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 16]);
        bytes.extend_from_slice(&[0x88, 0xac]);
        ScriptBytes::new(bytes)
    }

    fn receive(height: u64, tag: u32, nonce: u32) -> (ScriptBytes, TransparentEvent) {
        let mut txid = [0u8; 32];
        txid[..4].copy_from_slice(&tag.to_le_bytes());
        txid[4..8].copy_from_slice(&nonce.to_le_bytes());
        txid[8..16].copy_from_slice(&height.to_le_bytes());
        (
            script(tag),
            TransparentEvent::Receive(ReceiveEvent {
                height: height as u32,
                txid: Txid(txid),
                transaction_index: 1,
                output_index: nonce,
                value: 1,
                coinbase: false,
                metadata: None,
            }),
        )
    }

    fn spend(height: u64, tag: u32, nonce: u32) -> (ScriptBytes, TransparentEvent) {
        let (script, TransparentEvent::Receive(r)) = receive(height, tag, nonce) else {
            unreachable!()
        };
        (
            script,
            TransparentEvent::Spend(SpendEvent {
                metadata: None,
                height: r.height,
                spending_txid: r.txid,
                transaction_index: r.transaction_index,
                input_index: nonce,
                spent_txid: Txid([9; 32]),
                spent_output_index: nonce,
            }),
        )
    }

    fn policy(page_rows: (u64, u64), max_children: u32) -> DecoupledPolicy {
        DecoupledPolicy {
            page_rows: Limit::new(page_rows.0, page_rows.1).unwrap(),
            max_children,
            ..DecoupledPolicy::for_geometry(&DECOUPLED_2K_8K)
        }
    }

    /// Children are forced by a page target of one row: the first page row in
    /// a page shard closes it after the block that made it.
    fn run(
        blocks: &[(u64, Vec<(ScriptBytes, TransparentEvent)>)],
        policy: DecoupledPolicy,
        watched: &[u32],
    ) -> Vec<SealedDirectory> {
        let first = blocks[0].0;
        let mut sealer = DisplacementSealer::new(policy, DECOUPLED_2K_8K, first, 0);
        sealer.watch(
            watched
                .iter()
                .map(|t| script(*t).as_slice().to_vec())
                .collect(),
        );
        let mut out = Vec::new();
        for (height, events) in blocks {
            out.extend(sealer.push_block(*height, events).unwrap());
        }
        out.extend(sealer.finish());
        out
    }

    fn blocks_with(
        from: u64,
        to: u64,
        events: &[(u64, (ScriptBytes, TransparentEvent))],
    ) -> Vec<(u64, Vec<(ScriptBytes, TransparentEvent)>)> {
        (from..=to)
            .map(|h| {
                (
                    h,
                    events
                        .iter()
                        .filter(|(at, _)| *at == h)
                        .map(|(_, e)| e.clone())
                        .collect(),
                )
            })
            .collect()
    }

    /// The design's worked example: e1@1010, e2@1020, e3@1100, e4@1400,
    /// e5@1700, e6@1710, with page shards forced at 1299 and 1649 by a busy
    /// filler script, gives runs P0 [e1], P1 [e2], P2 [e3, e4] and inline e5, e6.
    #[test]
    fn pushed_out_events_go_to_the_page_shard_open_when_they_are_pushed() {
        let mut events: Vec<(u64, (ScriptBytes, TransparentEvent))> =
            [1010, 1020, 1100, 1400, 1700, 1710]
                .iter()
                .enumerate()
                .map(|(i, h)| (*h, receive(*h, 1, i as u32)))
                .collect();
        // A filler whose page rows force P0 to close at 1299 and P1 at 1649.
        for (h, n) in [(1299u64, 0u32), (1649, 1)] {
            for k in 0..200u32 {
                events.push((h, receive(h, 1000 + n * 1000 + k, k)));
                events.push((h, receive(h, 1000 + n * 1000 + k, k + 10_000)));
                events.push((h, receive(h, 1000 + n * 1000 + k, k + 20_000)));
            }
        }
        // Each filler script pages one 51-byte receive: 200 entries of 91
        // bytes fill five rows. A target of four rows closes the shard there.
        let shards = run(
            &blocks_with(1000, 1999, &events),
            policy((4, 1_000), 32),
            &[1],
        );
        assert_eq!(shards.len(), 1);
        let d = &shards[0];
        assert_eq!(
            d.children
                .iter()
                .map(|c| (c.start_height, c.end_height))
                .collect::<Vec<_>>(),
            vec![(1000, 1299), (1300, 1649), (1650, 1999)]
        );
        let chain = &d.watched[0];
        assert_eq!(chain.events, 6);
        assert_eq!(
            chain
                .runs
                .iter()
                .map(|r| (r.child, r.events))
                .collect::<Vec<_>>(),
            vec![(0, 1), (1, 1), (2, 2)]
        );
        assert_eq!(d.occupancy.chain_lengths[3], 1);
        assert_eq!(d.occupancy.inline_events, 2 + 2 * 400);
    }

    #[test]
    fn a_directory_closes_after_its_last_page_shard() {
        // A paged event every block; a one-row page target closes a page
        // shard per block, so three children close the directory.
        let events: Vec<_> = (100..112u64)
            .flat_map(|h| {
                [
                    (h, receive(h, 1, 0)),
                    (h, spend(h, 1, 1)),
                    (h, receive(h, 2, 2)),
                ]
            })
            .collect();
        let shards = run(&blocks_with(100, 111, &events), policy((1, 10), 3), &[1]);
        assert!(shards.len() >= 2);
        for d in &shards[..shards.len() - 1] {
            assert_eq!(d.children.len(), 3);
            assert_eq!(d.reason, Some(SealReason::ChildLimit));
        }
        // Directory shards tile the range, and so do their children.
        let mut next = 100;
        for d in &shards {
            assert_eq!(d.start_height, next);
            let mut child_next = d.start_height;
            for c in &d.children {
                assert_eq!(c.start_height, child_next);
                child_next = c.end_height + 1;
            }
            assert_eq!(child_next, d.end_height + 1);
            next = d.end_height + 1;
        }
        assert_eq!(next, 112);
    }

    #[test]
    fn sealed_children_do_not_depend_on_later_blocks() {
        let events: Vec<_> = (0..300u64)
            .flat_map(|h| {
                let tag = (h % 7) as u32;
                [
                    (1000 + h, receive(1000 + h, tag, h as u32)),
                    (1000 + h, receive(1000 + h, tag + 50, h as u32 + 1)),
                ]
            })
            .collect();
        let short = run(
            &blocks_with(1000, 1199, &events),
            policy((1, 4), 32),
            &[1, 2],
        );
        let long = run(
            &blocks_with(1000, 1299, &events),
            policy((1, 4), 32),
            &[1, 2],
        );
        let sealed: Vec<_> = short[0]
            .children
            .iter()
            .filter(|c| c.reason.is_some())
            .collect();
        assert!(sealed.len() >= 2);
        for child in sealed {
            assert_eq!(&long[0].children[child.index as usize], child);
        }
    }
}
