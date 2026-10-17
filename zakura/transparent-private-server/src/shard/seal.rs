//! Deciding where one shard ends and the next begins.
//!
//! Shards are sealed on what they *contain*, not on how many blocks they span.
//! Nothing bounds what a height range holds — transparent density on mainnet
//! varies several-fold across the chain, and a spam burst varies it further —
//! so a fixed-width shard would either waste most of a pinned table on a quiet
//! range or overflow it on a busy one. Sealing on content makes that variation
//! a difference in block span instead, which costs nothing.
//!
//! # Why three thresholds and not one
//!
//! Distinct script count bounds the filter, actual compact directory bytes
//! bound directory storage, and packed page rows bound page storage. Each
//! block's projection applies the same per-history encoding and packing rule
//! as the builder. Variable packing is not monotone: a later event can change
//! inline compression or the mix of shared entries. Decisions use the exact
//! projected state; they never assume that a history which does not fit now
//! cannot fit later.
//!
//! Distinct transaction ids are counted and reported but do not seal:
//! they size the optional transaction-detail table, which this POC does not
//! build. Over the Ironwood-to-tip journal that limit never bound in any
//! candidate policy, so dropping it moves no boundary.
//!
//! # Why capacity and target are separate numbers
//!
//! A threshold alone is not enough. Blocks arrive whole, and one block can add
//! thousands of scripts, so a shard that was just under a threshold could land
//! far past it — past what the pinned geometry actually holds. So each quantity
//! has two numbers: the `capacity` the tables really hold, and the `target` at
//! which sealing is preferred. A block that would breach capacity seals the
//! shard *before* it is added; reaching a target seals *after*. Targets should
//! sit below capacity by at least the largest block worth accommodating.
//!
//! # The block that fits nowhere
//!
//! Sealing cannot help a block whose own content exceeds a capacity: there is
//! nothing to seal before it. Refusing to publish it would let one purchased
//! block halt the service, so such a block is absorbed into a shard of its own,
//! and the builder gives that shard as many segments of the pinned geometry as
//! its content needs. The seal thresholds are per segment, so this changes
//! nothing for ordinary shards — the block that overran a capacity is above
//! every target too, so the shard closes immediately after it.
//!
//! # Which sealer publishes
//!
//! Published sets are sealed by [`DisplacementSealer`]: a directory shard
//! with its own page shards, each table sized independently. [`Sealer`] seals
//! a shard whose directory and pages close together, which no published
//! schema uses any more; it remains as the census's model of coupled layouts,
//! scored at the current page entry header.

use crate::shard::build::Placement;
use crate::shard::packing::{HistoryLayout, PackedDemand};
use std::collections::{HashMap, HashSet};
use zakura_transparent_private_shared::events::{TransparentEvent, Txid};
use zakura_transparent_private_shared::filter::ScriptBytes;
use zakura_transparent_private_shared::shard::layout::Geometry;
use zakura_transparent_private_shared::shard::records::MAX_SCRIPT_BYTES;

mod displacement;
pub use displacement::{
    ChildOccupancy, Closed, DecoupledPolicy, DirectoryOccupancy, DisplacementSealer, SealedChild,
    SealedDirectory, WatchedChain, WatchedRun, MAX_PAGE_CHILDREN,
};

/// How full a shard is allowed to get.
///
/// `capacity` is what the pinned tables hold and is a hard limit. `target` is
/// where sealing is preferred, and must leave room for one more block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limit {
    pub target: u64,
    pub capacity: u64,
}

impl Limit {
    pub fn new(target: u64, capacity: u64) -> Result<Self, SealError> {
        if target == 0 || target > capacity {
            return Err(SealError::Limits(format!(
                "target {target} must be positive and at most capacity {capacity}"
            )));
        }
        Ok(Self { target, capacity })
    }
}

/// The seal parameters a shard set is built under.
///
/// These are schema, not tuning. Two shard sets built under different
/// thresholds are different partitions of the same chain, and a wallet holding
/// both would be holding incompatible coverage. Changing any of them re-shards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealPolicy {
    /// Distinct script count. Actual directory bytes have an additional
    /// geometry-derived limit with the same one-seventh reserve.
    pub scripts: Limit,
    /// Page rows, which size the pages table.
    pub page_rows: Limit,
}

impl SealPolicy {
    /// The policy a geometry implies.
    ///
    /// Capacity is what the tables hold; the targets are the headroom each one
    /// needs, and both fractions are load-bearing rather than round numbers.
    ///
    /// Script count and actual directory bytes keep a seventh in reserve for
    /// block growth and weighted two-choice placement. This is headroom, not
    /// a proof that placement always fits one segment; the placer may add one.
    ///
    /// The page table keeps a **thirty-second**, far less, because its demand
    /// is projected exactly before absorbing each block:
    /// the reserve only has to absorb one block, not a placement failure.
    ///
    /// Deriving both here rather than at each call site is what keeps a
    /// geometry from acquiring a second, disagreeing policy. Before this, the
    /// publisher and the census each spelled the fractions out, against the
    /// compiled constants, and a new row count would have had to be applied to
    /// both.
    pub fn for_geometry(geometry: &Geometry) -> Self {
        let scripts_capacity = geometry.directory_capacity();
        let page_rows_capacity = geometry.page_rows;
        Self {
            scripts: Limit {
                target: scripts_capacity - scripts_capacity / 7,
                capacity: scripts_capacity,
            },
            page_rows: Limit {
                target: page_rows_capacity - page_rows_capacity / 32,
                capacity: page_rows_capacity,
            },
        }
    }
}

/// Which page figure closes a shard.
///
/// Not part of [`SealPolicy`], which is schema: this selects between two ways
/// of counting the same content, and only one of them can be right for a given
/// builder. Other bases remain diagnostic alternatives only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PageBasis {
    /// Short histories sharing rows, which is what the builder emits.
    #[default]
    Packed,
    /// A row per fragment, as the layout stored them before packing. Kept so a
    /// census can report what the same content would have cost, and so the two
    /// can be compared over one journal; a set must not be built this way,
    /// because the table would be sized for more than the builder writes.
    Fragments,
    /// Packed rows of short histories only, as if long histories lived in a
    /// separate bulk table that does not decide boundaries. A census option for
    /// the bulk-isolation design in the architecture update; no builder lays
    /// out tables this way.
    PackedOrdinary,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SealError {
    #[error("invalid seal limits: {0}")]
    Limits(String),
    #[error("block {height} does not follow {expected}")]
    OutOfOrder { height: u64, expected: u64 },
}

/// What a shard holds, as it accumulates.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Occupancy {
    pub scripts: u64,
    /// The figure that closes the shard, under the sealer's [`PageBasis`].
    pub page_rows: u64,
    /// Fragment count before sharing rows.
    pub fragments: u64,
    pub txids: u64,
    pub events: u64,
    /// Events that fit in directory entries and cost no page row.
    ///
    /// Tracked so `events - inline_events` gives the paged events exactly, and
    /// a caller can report how full the page rows actually are. Deriving it as
    /// `2 * scripts` would be wrong for every script holding a single event,
    /// which the measured distribution says is common.
    pub inline_events: u64,
    /// Actual compact directory-entry bytes, excluding row headers.
    pub directory_bytes: u64,
    pub blocks: u64,
    /// Page rows the same content needs with short histories packed into shared
    /// rows.
    ///
    /// Equal to `page_rows` under [`PageBasis::Packed`]. Under
    /// [`PageBasis::Fragments`] it is a projection at boundaries chosen by the
    /// unpacked figure, and no packed table was built to match it.
    pub packed_page_rows: u64,
    /// The class counts behind `packed_page_rows`, for reporting.
    ///
    /// Excludes scripts too long for a directory entry, which the builder never
    /// pages. `page_rows` still counts them, which is why the two can disagree
    /// by more than packing alone explains.
    pub demand: PackedDemand,
}

impl Occupancy {
    /// Events that had to go into page rows.
    pub fn paged_events(&self) -> u64 {
        self.events.saturating_sub(self.inline_events)
    }
}

/// What [`Sealer::project`] reports about a block before it is absorbed.
struct Projection {
    scripts: u64,
    fragments: u64,
    inline_events: u64,
    directory_bytes: u64,
    page_rows: u64,
    txids: u64,
    events: u64,
}

/// A sealed shard's extent and contents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedShard {
    pub shard_id: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub occupancy: Occupancy,
    /// Which limit caused the seal. `None` for a shard closed by the end of the
    /// journal rather than by reaching a limit — that is the unsealed tail.
    pub reason: Option<SealReason>,
    /// What two-choice placement actually costs this shard's script set.
    ///
    /// `None` unless the sealer was asked for it, because it is the one figure
    /// here that is not free: it runs the placement rule over every script the
    /// shard holds. It is computed at close and only the result is kept, so a
    /// census gets the real segment count without holding a chain's worth of
    /// scripts — which is the reason it is produced here rather than by a
    /// caller that would have to retain them.
    pub placement: Option<Placement>,
    /// The indexable scripts this shard holds, each with the page fragments its
    /// history in this shard costs to retrieve.
    ///
    /// Fragments rather than events, because fragments are what a wallet pays:
    /// a history inside the inline allowance costs none, and one above it costs
    /// a query per fragment. Carried per shard because that is where the
    /// allowance is granted — the same script in two shards gets two of them,
    /// which is the whole reason shard width changes what retrieval costs.
    ///
    /// `None` unless the sealer was asked for them. A caller that asks **must
    /// drain this as each shard is sealed**: it is one shard's scripts, which is
    /// bounded, but a caller that keeps every sealed shard and never takes them
    /// is holding the journal's whole script set, which over a genesis-to-tip
    /// journal is not bounded by anything useful.
    pub scripts: Option<Vec<(Vec<u8>, u32)>>,
    /// The choice table this shard's placement would publish, if asked for.
    ///
    /// `Err` carries why construction failed. `None` unless the sealer was
    /// asked with [`Sealer::measure_choice`].
    pub choice: Option<Result<ChoiceMeasure, String>>,
}

/// What a shard's choice table costs, measured by building it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChoiceMeasure {
    /// Encoded bytes, header included.
    pub bytes: u64,
    /// Scripts indexed.
    pub keys: u32,
    /// The seed construction settled on; above zero means retries.
    pub seed: u32,
    /// Wall time to build, in microseconds.
    pub micros: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealReason {
    /// A target was reached after a block was added.
    ReachedTarget(&'static str),
    /// The next block would have breached a capacity, so the shard closed
    /// before it.
    WouldExceedCapacity(&'static str),
    /// The shard holds a single block that exceeds a capacity on its own, so it
    /// closed immediately after it. Its tables need more than one segment.
    BlockExceedsCapacity(&'static str),
    /// The geometry changed at the next height, so the shard closed before it.
    ///
    /// The one reason that is not about how full the shard got. A shard's rows
    /// are addressed at one row count, so a shard cannot span a geometry
    /// change: the boundary is forced, and the shard on the near side is sealed
    /// wherever it happened to be. Published as a reason of its own so a census
    /// does not read a half-empty shard at the cutoff as evidence about the
    /// seal thresholds.
    GeometryChanged,
    /// Decoupled layout: the directory shard holds as many page shards as it
    /// may, so it closes with its last one.
    ChildLimit,
    /// Decoupled layout: a page shard closed because its directory shard did.
    DirectorySealed,
}

/// Streams blocks in height order and emits shard boundaries.
///
/// Feed every block, in order, including empty ones — a height with no
/// supported activity is still part of a shard's span, and skipping it would
/// leave a gap that no consumer could distinguish from missing coverage.
pub struct Sealer {
    policy: SealPolicy,
    basis: PageBasis,
    /// The geometry occupancy is counted against.
    ///
    /// Inline allowance determines the paged prefix; directory dimensions
    /// determine the independent byte limit. Defaults match the publisher.
    geometry: Geometry,
    /// Whether each closed shard reports its real directory placement.
    measure_placement: bool,
    /// Whether each closed shard reports the choice table its placement implies.
    measure_choice: bool,
    /// Whether each closed shard carries its script set out with it.
    retain_scripts: bool,
    next_shard_id: u64,
    /// Compact history summaries within the shard being accumulated.
    scripts: HashMap<Vec<u8>, HistoryLayout>,
    txids: HashSet<Txid>,
    fragments: u64,
    /// Maintained rather than recomputed: `occupancy()` is reached up to five
    /// times per block, and a full scan of the script map each time is the
    /// difference between a runnable and an unrunnable full-journal census.
    inline_events: u64,
    directory_bytes: u64,
    /// Packed row demand, carried as a passenger. See [`Occupancy::packed_page_rows`].
    demand: PackedDemand,
    events: u64,
    start_height: Option<u64>,
    last_height: Option<u64>,
    /// The height the next block must have. Tracked separately from the shard
    /// being accumulated because it has to survive a seal: after a shard
    /// closes, the accumulator is empty but the journal has not restarted.
    next_expected: Option<u64>,
    first_height: u64,
}

impl Sealer {
    pub fn new(policy: SealPolicy, first_height: u64) -> Self {
        Self::with_basis(policy, first_height, PageBasis::default())
    }

    /// A sealer that closes on `basis` rather than on the default.
    pub fn with_basis(policy: SealPolicy, first_height: u64, basis: PageBasis) -> Self {
        Self::with_geometry(policy, first_height, basis, Geometry::default())
    }

    /// A sealer continuing an existing shard-id sequence.
    ///
    /// For the second half of a mixed publication: shard ids are the wallet's
    /// stable handle on a range, and restarting them at zero after a geometry
    /// change would publish two shards under one id.
    pub fn resume(
        policy: SealPolicy,
        first_height: u64,
        basis: PageBasis,
        geometry: Geometry,
        next_shard_id: u64,
    ) -> Self {
        let mut sealer = Self::with_geometry(policy, first_height, basis, geometry);
        sealer.next_shard_id = next_shard_id;
        sealer
    }

    /// A sealer that counts occupancy against a geometry other than the
    /// compiled one.
    ///
    /// For scoring a candidate. A published set must not be sealed this way
    /// unless the builder was compiled to match, or the tables would be sized
    /// for content they do not hold.
    pub fn with_geometry(
        policy: SealPolicy,
        first_height: u64,
        basis: PageBasis,
        geometry: Geometry,
    ) -> Self {
        Self {
            policy,
            basis,
            geometry,
            measure_placement: false,
            measure_choice: false,
            retain_scripts: false,
            next_shard_id: 0,
            scripts: HashMap::new(),
            txids: HashSet::new(),
            fragments: 0,
            inline_events: 0,
            directory_bytes: 0,
            demand: PackedDemand::default(),
            events: 0,
            start_height: None,
            last_height: None,
            next_expected: None,
            first_height,
        }
    }

    /// Asks each closed shard to report its real directory placement.
    ///
    /// Off by default. It costs a sort and a placement pass over the shard's
    /// scripts, which is worth paying to answer how much headroom a seal target
    /// really has and not worth paying to publish, where the builder places
    /// them anyway.
    pub fn measure_placement(&mut self, on: bool) {
        self.measure_placement = on;
    }

    /// Asks each closed shard to build the choice table its placement implies,
    /// and report its size and construction cost. Implies placement.
    pub fn measure_choice(&mut self, on: bool) {
        self.measure_choice = on;
    }

    /// Asks each closed shard to carry its indexable script set out with it.
    ///
    /// For a caller counting how many shards each script appears in, which
    /// cannot be derived from occupancy counts. See [`SealedShard::scripts`] for
    /// the draining obligation this creates.
    pub fn retain_scripts(&mut self, on: bool) {
        self.retain_scripts = on;
    }

    /// The page figure a limit is compared against.
    fn page_rows(basis: PageBasis, fragments: u64, demand: &PackedDemand) -> u64 {
        match basis {
            PageBasis::Fragments => fragments,
            PageBasis::Packed => demand.rows(),
            PageBasis::PackedOrdinary => demand.ordinary_rows(),
        }
    }

    fn occupancy(&self) -> Occupancy {
        let packed = self.demand.rows();
        Occupancy {
            scripts: self.scripts.len() as u64,
            page_rows: Self::page_rows(self.basis, self.fragments, &self.demand),
            fragments: self.fragments,
            txids: self.txids.len() as u64,
            events: self.events,
            inline_events: self.inline_events,
            directory_bytes: self.directory_bytes,
            blocks: match (self.start_height, self.last_height) {
                (Some(start), Some(last)) => last - start + 1,
                _ => 0,
            },
            packed_page_rows: packed,
            demand: self.demand.clone(),
        }
    }

    fn reset(&mut self) {
        self.scripts.clear();
        self.txids.clear();
        self.fragments = 0;
        self.inline_events = 0;
        self.directory_bytes = 0;
        self.demand = PackedDemand::default();
        self.events = 0;
        self.start_height = None;
        self.last_height = None;
    }

    /// Runs the builder's placement rule over the scripts this shard holds.
    ///
    /// Only the scripts a directory entry can hold, in the builder's placement
    /// order — the two things the builder does, and both of them matter. A
    /// script too long to index is filtered publicly but never placed, and
    /// placement in any other order is a different placement.
    fn placeable(&self) -> Vec<(&[u8], usize)> {
        crate::shard::build::placement_order(
            self.scripts
                .iter()
                .filter(|(script, _)| script.len() <= MAX_SCRIPT_BYTES)
                .map(|(script, history)| (script.as_slice(), history.directory_bytes())),
        )
    }

    fn placement(&self) -> (Placement, Option<Result<ChoiceMeasure, String>>) {
        let ordered = self.placeable();
        let placeable: Vec<_> = ordered.iter().map(|(script, _)| *script).collect();
        let sizes: Vec<_> = ordered.iter().map(|(_, size)| *size).collect();
        let (placement, assignment) = crate::shard::build::place_scripts(
            self.next_shard_id,
            &placeable,
            &sizes,
            self.geometry.directory_rows,
            self.geometry.directory_row_bytes
                - zakura_transparent_private_shared::shard::records::DIRECTORY_ROW_HEADER_BYTES,
        )
        // The rule adds a segment until everything fits and the cap is a
        // bug-catcher far above any reachable load, so a census reaching it is
        // a defect in the rule rather than a property of the journal.
        .unwrap_or_else(|script| panic!("placement gave up on script {script}"));
        let choice = self.measure_choice.then(|| {
            let started = std::time::Instant::now();
            let rows = self.geometry.directory_rows * u64::from(placement.segments);
            crate::shard::build::choice_table(self.next_shard_id, &placeable, &assignment, rows)
                .map(|table| ChoiceMeasure {
                    bytes: table.encode().len() as u64,
                    keys: table.keys(),
                    seed: table.seed(),
                    micros: started.elapsed().as_micros() as u64,
                })
                .map_err(|error| error.to_string())
        });
        (placement, choice)
    }

    fn close(&mut self, reason: Option<SealReason>) -> SealedShard {
        let (placement, choice) = if self.measure_placement || self.measure_choice {
            let (placement, choice) = self.placement();
            (Some(placement), choice)
        } else {
            (None, None)
        };
        let shard = SealedShard {
            placement,
            choice,
            scripts: self.retain_scripts.then(|| {
                self.placeable()
                    .into_iter()
                    .map(|(script, _)| {
                        let fragments = self
                            .scripts
                            .get(script)
                            .map_or(0, |history| history.fragments);
                        (script.to_vec(), fragments)
                    })
                    .collect()
            }),
            shard_id: self.next_shard_id,
            start_height: self.start_height.expect("a shard being closed has a start"),
            end_height: self.last_height.expect("a shard being closed has an end"),
            occupancy: self.occupancy(),
            reason,
        };
        self.next_shard_id += 1;
        self.reset();
        shard
    }

    /// What this shard's occupancy would become if `events` were added.
    ///
    /// Computed without mutating, because the answer decides whether the block
    /// belongs to this shard at all.
    fn updated_histories(
        &self,
        events: &[(ScriptBytes, TransparentEvent)],
    ) -> Vec<(Vec<u8>, HistoryLayout)> {
        let mut added: HashMap<&[u8], Vec<TransparentEvent>> = HashMap::new();
        for (script, event) in events {
            added.entry(script.as_slice()).or_default().push(*event);
        }
        added
            .into_iter()
            .map(|(script, mut events)| {
                events.sort_by_key(TransparentEvent::sort_key);
                let mut history = self.scripts.get(script).cloned().unwrap_or_default();
                for event in events {
                    history.push(event, self.geometry.inline_events);
                }
                (script.to_vec(), history)
            })
            .collect()
    }

    /// The occupancy adding `events` would produce, computed on a copy. The
    /// reference [`Self::project`] is tested against.
    #[cfg(test)]
    fn projected(&self, events: &[(ScriptBytes, TransparentEvent)]) -> Occupancy {
        let histories = self.updated_histories(events);
        let mut scripts = self.scripts.len() as u64;
        let mut fragments = self.fragments;
        let mut inline_events = self.inline_events;
        let mut directory_bytes = self.directory_bytes;
        let mut demand = self.demand.clone();
        for (script, updated) in &histories {
            let empty = HistoryLayout::default();
            let old = self.scripts.get(script).unwrap_or(&empty);
            if old.events == 0 {
                scripts += 1;
            }
            fragments += u64::from(updated.fragments - old.fragments);
            inline_events += (updated.inline.len() - old.inline.len()) as u64;
            if script.len() <= MAX_SCRIPT_BYTES {
                directory_bytes = directory_bytes
                    - if old.events == 0 {
                        0
                    } else {
                        old.directory_bytes() as u64
                    }
                    + updated.directory_bytes() as u64;
                demand.shift(old, updated);
            }
        }
        let added_txids: HashSet<_> = events.iter().map(|(_, event)| event.txid()).collect();
        let txids = self.txids.len() as u64
            + added_txids
                .iter()
                .filter(|id| !self.txids.contains(*id))
                .count() as u64;
        Occupancy {
            scripts,
            page_rows: Self::page_rows(self.basis, fragments, &demand),
            fragments,
            txids,
            events: self.events + events.len() as u64,
            inline_events,
            directory_bytes,
            blocks: match (self.start_height, self.last_height) {
                (Some(start), Some(last)) => last - start + 2,
                _ => 1,
            },
            packed_page_rows: demand.rows(),
            demand,
        }
    }

    /// The figures a capacity decision reads if `events`, with their
    /// [`Self::updated_histories`], were added.
    ///
    /// The packed demand is shifted in place rather than on a copy: the
    /// sealer runs this for every block of the tail at every publication, and
    /// the block is almost always absorbed. [`Self::unproject`] restores it
    /// when the shard closes first. The row count computed here stays cached
    /// for [`Self::reached_target`].
    fn project(
        &mut self,
        histories: &[(Vec<u8>, HistoryLayout)],
        events: &[(ScriptBytes, TransparentEvent)],
    ) -> Projection {
        let mut projection = Projection {
            scripts: self.scripts.len() as u64,
            fragments: self.fragments,
            inline_events: self.inline_events,
            directory_bytes: self.directory_bytes,
            page_rows: 0,
            txids: 0,
            events: self.events + events.len() as u64,
        };
        for (script, updated) in histories {
            let empty = HistoryLayout::default();
            let old = self.scripts.get(script).unwrap_or(&empty);
            if old.events == 0 {
                projection.scripts += 1;
            }
            projection.fragments += u64::from(updated.fragments - old.fragments);
            projection.inline_events += (updated.inline.len() - old.inline.len()) as u64;
            if script.len() <= MAX_SCRIPT_BYTES {
                projection.directory_bytes = projection.directory_bytes
                    - if old.events == 0 {
                        0
                    } else {
                        old.directory_bytes() as u64
                    }
                    + updated.directory_bytes() as u64;
                self.demand.shift(old, updated);
            }
        }
        let added_txids: HashSet<_> = events.iter().map(|(_, event)| event.txid()).collect();
        projection.txids = self.txids.len() as u64
            + added_txids
                .iter()
                .filter(|id| !self.txids.contains(*id))
                .count() as u64;
        projection.page_rows = Self::page_rows(self.basis, projection.fragments, &self.demand);
        projection
    }

    /// Undoes [`Self::project`]'s shift of the packed demand.
    fn unproject(&mut self, histories: &[(Vec<u8>, HistoryLayout)]) {
        for (script, updated) in histories {
            if script.len() <= MAX_SCRIPT_BYTES {
                let empty = HistoryLayout::default();
                let old = self.scripts.get(script).unwrap_or(&empty);
                self.demand.shift(updated, old);
            }
        }
    }

    fn directory_limit(&self) -> Limit {
        let capacity = self.geometry.directory_rows
            * (self.geometry.directory_row_bytes
                - zakura_transparent_private_shared::shard::records::DIRECTORY_ROW_HEADER_BYTES)
                as u64;
        Limit {
            target: capacity - capacity / 7,
            capacity,
        }
    }

    fn over_capacity(&self, projected: &Projection) -> Option<(&'static str, u64, u64)> {
        for (name, value, limit) in [
            ("scripts", projected.scripts, self.policy.scripts),
            (
                "directory bytes",
                projected.directory_bytes,
                self.directory_limit(),
            ),
            ("page rows", projected.page_rows, self.policy.page_rows),
        ] {
            if value > limit.capacity {
                return Some((name, value, limit.capacity));
            }
        }
        None
    }

    fn reached_target(&self) -> Option<&'static str> {
        // The three figures `occupancy()` would report, without cloning the
        // packed demand it carries: this runs after every block.
        for (name, value, limit) in [
            ("scripts", self.scripts.len() as u64, self.policy.scripts),
            (
                "directory bytes",
                self.directory_bytes,
                self.directory_limit(),
            ),
            (
                "page rows",
                Self::page_rows(self.basis, self.fragments, &self.demand),
                self.policy.page_rows,
            ),
        ] {
            if value >= limit.target {
                return Some(name);
            }
        }
        None
    }

    /// Adds a block, given the projection [`Self::project`] took for it
    /// against the current state and the histories that projection used.
    ///
    /// The projection already computed every counter absorbing changes and
    /// shifted the packed demand, so neither is applied a second time.
    fn absorb(
        &mut self,
        height: u64,
        events: &[(ScriptBytes, TransparentEvent)],
        histories: Vec<(Vec<u8>, HistoryLayout)>,
        projected: Projection,
    ) {
        if self.start_height.is_none() {
            self.start_height = Some(height);
        }
        self.last_height = Some(height);
        self.fragments = projected.fragments;
        self.inline_events = projected.inline_events;
        self.directory_bytes = projected.directory_bytes;
        self.events = projected.events;
        for (script, updated) in histories {
            self.scripts.insert(script, updated);
        }
        for (_, event) in events {
            self.txids.insert(event.txid());
        }
        debug_assert_eq!(self.scripts.len() as u64, projected.scripts);
        debug_assert_eq!(self.txids.len() as u64, projected.txids);
    }

    /// Offers one block to the sealer, returning the shards it sealed.
    ///
    /// Usually none or one. A shard returned *before* this block was closed
    /// because adding the block would have breached a capacity, and does not
    /// contain it; a shard closed by reaching a target does contain it.
    ///
    /// Two shards come back only for a block that breaches a capacity on its
    /// own: the shard that ended before it, and the single-block shard holding
    /// it. That shard needs more than one segment per table, and the builder
    /// gives it those — no valid block is ever refused, because a service that
    /// stops publishing on one adversarial block is not available.
    pub fn push_block(
        &mut self,
        height: u64,
        events: &[(ScriptBytes, TransparentEvent)],
    ) -> Result<Vec<SealedShard>, SealError> {
        let expected = self.next_expected.unwrap_or(self.first_height);
        if height != expected {
            return Err(SealError::OutOfOrder { height, expected });
        }

        let mut sealed = Vec::new();
        let mut oversized = None;
        let mut histories = self.updated_histories(events);
        let mut projected = self.project(&histories, events);
        if let Some((quantity, _, _)) = self.over_capacity(&projected) {
            if self.start_height.is_some() {
                // The shard closes without this block.
                self.unproject(&histories);
                sealed.push(self.close(Some(SealReason::WouldExceedCapacity(quantity))));
                histories = self.updated_histories(events);
                projected = self.project(&histories, events);
            }
            // Re-check against the now-empty shard. Still over means the block
            // exceeds a capacity by itself, so it becomes a shard of its own
            // and is sealed as soon as it is absorbed.
            if let Some((quantity, _, _)) = self.over_capacity(&projected) {
                oversized = Some(quantity);
            }
        }

        self.absorb(height, events, histories, projected);
        self.next_expected = Some(height + 1);

        if let Some(quantity) = oversized {
            sealed.push(self.close(Some(SealReason::BlockExceedsCapacity(quantity))));
        } else if let Some(quantity) = self.reached_target() {
            sealed.push(self.close(Some(SealReason::ReachedTarget(quantity))));
        }
        Ok(sealed)
    }

    /// Closes the current shard at a forced boundary, and reopens numbering for
    /// a different geometry.
    ///
    /// A shard's row indices are taken against one row count, so a shard cannot
    /// span two geometries: the transition has to be a boundary, and the shard
    /// before it is *sealed* rather than left as a growing tail. It is final —
    /// nothing after the cutoff can be added to it — so publishing it as
    /// provisional would tell a wallet to expect a revision that will never
    /// come.
    ///
    /// Returns `None` if nothing has been accumulated, which is the case when
    /// the cutoff falls exactly on a boundary the thresholds already produced.
    ///
    /// The caller then continues with a sealer built for the new geometry and
    /// policy, resumed at the next shard id — see [`Sealer::resume`].
    pub fn seal_at_geometry_change(&mut self) -> Option<SealedShard> {
        self.start_height?;
        Some(self.close(Some(SealReason::GeometryChanged)))
    }

    /// The shard id the next shard would take.
    ///
    /// What a successor sealer resumes from, so ids stay a single ascending
    /// sequence across a geometry change rather than restarting at zero.
    pub fn next_shard_id(&self) -> u64 {
        self.next_shard_id
    }

    /// The first height of the shard still accumulating, if any.
    ///
    /// `None` means the last block offered closed a shard by itself, so the
    /// next height is a boundary the thresholds produced. A tier boundary
    /// placed at this height, rather than at the height the sealer has
    /// reached, leaves no shard to close at a geometry change.
    pub fn open_start(&self) -> Option<u64> {
        self.start_height
    }

    /// Closes whatever is still accumulating.
    ///
    /// The result is the tail: a shard that reached no limit and is therefore
    /// still growing as the chain does. It is published as a provisional
    /// revision, immutable under its own digest but expected to be superseded,
    /// and a consumer must not treat the range it covers as settled.
    pub fn finish(&mut self) -> Option<SealedShard> {
        self.start_height?;
        Some(self.close(None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The census targets: a seventh of scripts and directory bytes in
    /// reserve, a thirty-second of page rows.
    #[test]
    fn the_decoupled_tiers_imply_the_census_targets() {
        let recent = DecoupledPolicy::for_geometry(
            &zakura_transparent_private_shared::shard::layout::DECOUPLED_2K_8K,
        );
        assert_eq!(recent.scripts.capacity, 118_784);
        assert_eq!(recent.scripts.target, 101_815);
        assert_eq!(recent.directory_bytes.capacity, 2_048 * 4_092);
        assert_eq!(
            recent.directory_bytes.target,
            2_048 * 4_092 - 2_048 * 4_092 / 7
        );
        assert_eq!(recent.page_rows.capacity, 8_192);
        assert_eq!(recent.page_rows.target, 7_936);
        assert_eq!(recent.max_children, 32);
        assert_eq!(recent.page_entry_header, 40);
        let archive = DecoupledPolicy::for_geometry(
            &zakura_transparent_private_shared::shard::layout::DECOUPLED_32K_32K,
        );
        assert_eq!(archive.scripts.capacity, 1_900_544);
        assert_eq!(archive.directory_bytes.capacity, 32_768 * 4_092);
        assert_eq!(archive.page_rows.capacity, 32_768);
        assert_eq!(archive.page_rows.target, 31_744);
        assert_eq!(archive.max_children, 32);
    }

    /// Every registry entry must imply a policy that is actually sealable:
    /// positive targets, targets under capacity, and enough headroom that one
    /// more block cannot jump the gap between them.
    #[test]
    fn every_geometry_implies_a_usable_policy() {
        for geometry in zakura_transparent_private_shared::shard::layout::PROFILES {
            let policy = SealPolicy::for_geometry(geometry);
            Limit::new(policy.scripts.target, policy.scripts.capacity)
                .unwrap_or_else(|error| panic!("{}: {error}", geometry.name));
            Limit::new(policy.page_rows.target, policy.page_rows.capacity)
                .unwrap_or_else(|error| panic!("{}: {error}", geometry.name));
            assert!(
                policy.scripts.target < policy.scripts.capacity,
                "{}: the directory needs placement headroom",
                geometry.name
            );
            assert!(
                policy.page_rows.target < policy.page_rows.capacity,
                "{}: the page table needs a block of headroom",
                geometry.name
            );
        }
    }

    /// A wider archive geometry must buy proportionally more of both, so the
    /// two tables still close a shard at about the same occupancy. One that
    /// scaled only the pages would fill its directory first and waste them.
    #[test]
    fn a_wider_geometry_seals_later_in_both_tables() {
        let recent = SealPolicy::for_geometry(
            &zakura_transparent_private_shared::shard::layout::DECOUPLED_2K_8K,
        );
        let archive = SealPolicy::for_geometry(
            &zakura_transparent_private_shared::shard::layout::DECOUPLED_32K_32K,
        );
        assert!(archive.scripts.target > recent.scripts.target);
        assert!(archive.page_rows.target > recent.page_rows.target);
    }
    use zakura_transparent_private_shared::events::ReceiveEvent;
    use zakura_transparent_private_shared::shard::layout::{EVENTS_PER_PAGE, INLINE_EVENTS};

    fn policy(scripts: (u64, u64), page_rows: (u64, u64)) -> SealPolicy {
        SealPolicy {
            scripts: Limit::new(scripts.0, scripts.1).unwrap(),
            page_rows: Limit::new(page_rows.0, page_rows.1).unwrap(),
        }
    }

    fn generous() -> SealPolicy {
        policy((1_000_000, 2_000_000), (1_000_000, 2_000_000))
    }

    fn script(tag: u32) -> ScriptBytes {
        let mut bytes = vec![0x76, 0xa9, 0x14];
        bytes.extend_from_slice(&tag.to_le_bytes());
        ScriptBytes::new(bytes)
    }

    fn event(height: u64, tag: u32, nonce: u32) -> (ScriptBytes, TransparentEvent) {
        let mut txid = [0u8; 32];
        txid[..4].copy_from_slice(&tag.to_le_bytes());
        txid[4..8].copy_from_slice(&nonce.to_le_bytes());
        (
            script(tag),
            TransparentEvent::Receive(ReceiveEvent {
                metadata: None,
                height: height as u32,
                txid: Txid(txid),
                transaction_index: 0,
                output_index: 0,
                value: 1,
                coinbase: false,
            }),
        )
    }

    /// A sealer told a different inline allowance counts a different table.
    ///
    /// This is the whole point of a scoring geometry: the allowance decides
    /// whether a history reaches the page table at all, so two sealers fed the
    /// identical journal disagree about page demand — and, once a limit binds,
    /// about where the boundary falls. A sealer that ignored its geometry would
    /// pass every other test in this file.
    #[test]
    fn the_inline_allowance_changes_what_a_shard_is_counted_to_hold() {
        // Three events per script: one page row each at the compiled allowance
        // of two, none at three, and three paged events each at zero.
        let block: Vec<_> = (0..10u32)
            .flat_map(|tag| (0..3u32).map(move |nonce| event(1, tag, nonce)))
            .collect();

        let mut counted = Vec::new();
        for inline in [0u32, 2, 3] {
            let geometry = Geometry {
                inline_events: inline,
                ..Default::default()
            };
            let mut sealer = Sealer::with_geometry(generous(), 1, PageBasis::Packed, geometry);
            sealer.push_block(1, &block).expect("valid block");
            let occupancy = sealer.finish().expect("a tail").occupancy;
            assert_eq!(occupancy.scripts, 10, "the script set does not move");
            assert_eq!(occupancy.events, 30);
            counted.push((
                occupancy.inline_events,
                occupancy.fragments,
                occupancy.packed_page_rows,
            ));
        }

        // Zero inline: every event is paged, ten class-3 histories, ten of
        // which share a row at 10 per row.
        assert_eq!(counted[0], (0, 10, 1));
        // Two inline: twenty events stay inline, ten class-1 histories, all of
        // which fit one row at 22 per row.
        assert_eq!(counted[1], (20, 10, 1));
        // Three inline: nothing is paged at all, which is the case the
        // allowance exists to buy.
        assert_eq!(counted[2], (30, 0, 0));
    }

    /// Real placement is worse than `scripts / slots`, and that gap is the
    /// point of measuring it.
    ///
    /// The modelled figure assumes every row fills evenly. Two choices per
    /// script make the load far more even than one would, but not even: the
    /// fullest row still runs well ahead of the mean, and it is the fullest row,
    /// not the mean, that decides when a second segment appears and doubles what
    /// every wallet pays for that shard.
    #[test]
    fn placement_costs_more_than_dividing_scripts_by_slots() {
        let geometry = Geometry::default();
        let slots = geometry.directory_slots();
        // A tenth of a segment's capacity, which the model would place in a
        // tenth of its rows at exactly `slots` each.
        let scripts = geometry.directory_capacity() / 10;

        let mut sealer = Sealer::with_geometry(generous(), 1, PageBasis::default(), geometry);
        sealer.measure_placement(true);
        let block: Vec<_> = (0..scripts as u32).map(|tag| event(1, tag, 0)).collect();
        sealer.push_block(1, &block).expect("valid block");
        let sealed = sealer.finish().expect("a tail");

        let placement = sealed.placement.expect("placement was asked for");
        assert_eq!(sealed.occupancy.scripts, scripts);
        assert_eq!(placement.segments, 1, "a tenth of a segment fits in one");
        let mean = scripts as f64 / geometry.directory_rows as f64;
        assert!(
            placement.max_row_load as f64 > mean,
            "fullest row {} should exceed the mean {mean:.2}",
            placement.max_row_load
        );
        assert!(
            placement.max_row_load <= slots,
            "a placement that fit cannot have overrun a row"
        );
    }

    /// More scripts than a directory segment holds takes another, and the
    /// sealer's count is the builder's count.
    #[test]
    fn a_script_set_past_one_segment_places_into_two() {
        // A geometry small enough to overrun cheaply: one inline event gives 58
        // minimum entries per row.
        let geometry = Geometry {
            inline_events: 1,
            ..Default::default()
        };
        let scripts = geometry.directory_capacity() + 1;

        let mut sealer = Sealer::with_geometry(generous(), 1, PageBasis::default(), geometry);
        sealer.measure_placement(true);
        let block: Vec<_> = (0..scripts as u32).map(|tag| event(1, tag, 0)).collect();
        let mut sealed = sealer.push_block(1, &block).expect("valid block");
        sealed.extend(sealer.finish());
        let placement = sealed
            .pop()
            .expect("one shard")
            .placement
            .expect("placement was asked for");
        assert!(
            placement.segments >= 2,
            "{scripts} scripts cannot fit {} slots",
            geometry.directory_capacity()
        );
    }

    /// Placement is off unless asked for, so publishing pays nothing for it.
    #[test]
    fn placement_is_not_measured_unless_it_is_asked_for() {
        let mut sealer = Sealer::new(generous(), 1);
        sealer
            .push_block(1, &[event(1, 0, 0)])
            .expect("valid block");
        assert_eq!(sealer.finish().expect("a tail").placement, None);
    }

    /// The single shard a push was expected to seal.
    fn one(sealed: Result<Vec<SealedShard>, SealError>) -> SealedShard {
        let mut sealed = sealed.expect("no valid block is ever refused");
        assert_eq!(sealed.len(), 1, "expected exactly one sealed shard");
        sealed.pop().expect("one shard")
    }

    /// Distinct scripts, each with one event, so only the script limit bites.
    fn block_of_new_scripts(
        height: u64,
        first_tag: u32,
        count: u32,
    ) -> Vec<(ScriptBytes, TransparentEvent)> {
        (0..count)
            .map(|i| event(height, first_tag + i, 0))
            .collect()
    }

    #[test]
    fn an_empty_journal_seals_nothing() {
        let mut sealer = Sealer::new(generous(), 100);
        assert_eq!(sealer.finish(), None);
    }

    /// A shard that never reaches a limit is the tail: it must come out
    /// unsealed, so a consumer does not treat a still-growing range as
    /// immutable.
    /// A geometry change forces a boundary, and the shard before it is sealed
    /// rather than left as a growing tail.
    ///
    /// A shard's rows are addressed at one row count, so nothing after the
    /// cutoff can join the shard before it. Leaving it provisional would tell a
    /// wallet to expect a revision that will never be published.
    #[test]
    fn a_geometry_change_seals_the_shard_before_it() {
        let mut sealer = Sealer::new(generous(), 100);
        for height in 100..105 {
            assert_eq!(
                sealer.push_block(height, &block_of_new_scripts(height, 0, 3)),
                Ok(Vec::new())
            );
        }
        let closed = sealer
            .seal_at_geometry_change()
            .expect("five blocks are accumulated");
        assert_eq!((closed.start_height, closed.end_height), (100, 104));
        assert_eq!(closed.reason, Some(SealReason::GeometryChanged));
        assert_eq!(closed.shard_id, 0);
        // Nowhere near a limit: the boundary is forced, which is exactly why it
        // needs a reason of its own rather than being reported as a full shard.
        assert_eq!(closed.occupancy.scripts, 3);
    }

    /// A cutoff landing on a boundary the thresholds already produced adds no
    /// empty shard.
    ///
    /// An empty shard is not harmless: a wallet queries every shard whose
    /// filter matches, and one covering no blocks is a range that cannot be
    /// addressed to a height at all.
    #[test]
    fn a_geometry_change_on_an_existing_boundary_seals_nothing() {
        let mut sealer = Sealer::new(generous(), 100);
        assert_eq!(sealer.seal_at_geometry_change(), None);
    }

    /// Shard ids continue across a geometry change.
    ///
    /// The id is the wallet's stable handle on a range and the map is indexed by
    /// it, so a successor that restarted at zero would publish two shards under
    /// one id and the map would not load at all.
    #[test]
    fn ids_continue_across_a_geometry_change() {
        let mut archive = Sealer::new(policy((10, 1_000), (1_000, 10_000)), 100);
        let mut sealed = Vec::new();
        let mut tag = 0u32;
        for offset in 0..6u64 {
            let block = block_of_new_scripts(100 + offset, tag, 4);
            tag += 4;
            sealed.extend(archive.push_block(100 + offset, &block).unwrap());
        }
        sealed.extend(archive.seal_at_geometry_change());
        let next_id = archive.next_shard_id();
        assert_eq!(next_id, sealed.len() as u64);

        let mut recent = Sealer::resume(
            SealPolicy::for_geometry(
                &zakura_transparent_private_shared::shard::layout::DECOUPLED_2K_8K,
            ),
            106,
            PageBasis::default(),
            zakura_transparent_private_shared::shard::layout::DECOUPLED_2K_8K,
            next_id,
        );
        for offset in 0..3u64 {
            let block = block_of_new_scripts(106 + offset, tag, 4);
            tag += 4;
            sealed.extend(recent.push_block(106 + offset, &block).unwrap());
        }
        sealed.extend(recent.finish());

        // One ascending, gapless sequence across the change, and the ranges
        // tile the journal without a hole at the boundary.
        for (index, shard) in sealed.iter().enumerate() {
            assert_eq!(shard.shard_id, index as u64, "ids must not restart");
        }
        for pair in sealed.windows(2) {
            assert_eq!(
                pair[1].start_height,
                pair[0].end_height + 1,
                "the boundary must not drop a height"
            );
        }
        assert_eq!(sealed.first().unwrap().start_height, 100);
        assert_eq!(sealed.last().unwrap().end_height, 108);
    }

    /// A tier boundary moved back to the open shard's start closes nothing.
    ///
    /// The boundary `shard-cutoff` records: replayed up to that height, the
    /// archive sealer has sealed every shard by a threshold, so the geometry
    /// change has no part-filled shard to force.
    #[test]
    fn a_boundary_at_the_open_start_forces_no_seal() {
        let blocks: Vec<_> = (0..8u64)
            .map(|offset| block_of_new_scripts(100 + offset, offset as u32 * 4, 4))
            .collect();
        let replay = |through: u64| {
            let mut sealer = Sealer::new(policy((10, 1_000), (1_000, 10_000)), 100);
            let mut sealed = Vec::new();
            for (offset, block) in blocks.iter().enumerate() {
                let height = 100 + offset as u64;
                if height >= through {
                    break;
                }
                sealed.extend(sealer.push_block(height, block).unwrap());
            }
            (sealer, sealed)
        };

        let calendar = 107;
        let (mut at_calendar, _) = replay(calendar);
        let boundary = at_calendar.open_start().unwrap_or(calendar);
        assert!(boundary < calendar, "the example must leave a shard open");
        let forced = at_calendar.seal_at_geometry_change().expect("open shard");
        assert_eq!(forced.reason, Some(SealReason::GeometryChanged));

        let (mut at_boundary, sealed) = replay(boundary);
        assert_eq!(at_boundary.seal_at_geometry_change(), None);
        assert_eq!(sealed.last().unwrap().end_height, boundary - 1);
        assert!(sealed
            .iter()
            .all(|shard| matches!(shard.reason, Some(SealReason::ReachedTarget(_)))));
    }

    #[test]
    fn a_journal_below_every_limit_yields_one_unsealed_tail() {
        let mut sealer = Sealer::new(generous(), 100);
        for height in 100..110 {
            assert_eq!(
                sealer.push_block(height, &block_of_new_scripts(height, 0, 3)),
                Ok(Vec::new())
            );
        }
        let tail = sealer.finish().expect("a tail");
        assert_eq!(tail.shard_id, 0);
        assert_eq!((tail.start_height, tail.end_height), (100, 109));
        assert_eq!(tail.reason, None);
        assert_eq!(tail.occupancy.blocks, 10);
        // Ten blocks of the same three scripts: three distinct scripts, thirty
        // events.
        assert_eq!(tail.occupancy.scripts, 3);
        assert_eq!(tail.occupancy.events, 30);
    }

    #[test]
    fn reaching_the_script_target_seals_the_block_that_reached_it() {
        let mut sealer = Sealer::new(policy((10, 1_000), (1_000, 10_000)), 100);
        assert_eq!(
            sealer.push_block(100, &block_of_new_scripts(100, 0, 4)),
            Ok(Vec::new())
        );
        let sealed = one(sealer.push_block(101, &block_of_new_scripts(101, 4, 6)));
        assert_eq!(sealed.reason, Some(SealReason::ReachedTarget("scripts")));
        assert_eq!((sealed.start_height, sealed.end_height), (100, 101));
        assert_eq!(sealed.occupancy.scripts, 10);
    }

    /// The case a single threshold cannot handle: a block large enough to carry
    /// the shard past what its tables hold. It must be sealed *before* the
    /// block, not after.
    #[test]
    fn a_block_that_would_breach_capacity_seals_the_shard_before_it() {
        let mut sealer = Sealer::new(policy((100, 120), (10_000, 20_000)), 100);
        assert_eq!(
            sealer.push_block(100, &block_of_new_scripts(100, 0, 90)),
            Ok(Vec::new())
        );
        // 90 + 50 = 140, past the capacity of 120, so this block starts a new
        // shard instead of overflowing the current one.
        let sealed = one(sealer.push_block(101, &block_of_new_scripts(101, 1_000, 50)));
        assert_eq!(
            sealed.reason,
            Some(SealReason::WouldExceedCapacity("scripts"))
        );
        assert_eq!((sealed.start_height, sealed.end_height), (100, 100));
        assert_eq!(sealed.occupancy.scripts, 90);

        let tail = sealer.finish().expect("the block that did not fit");
        assert_eq!((tail.start_height, tail.end_height), (101, 101));
        assert_eq!(tail.occupancy.scripts, 50);
    }

    /// No shard may exceed its capacity, whatever the block sizes. This is the
    /// property the shared parameter set depends on.
    #[test]
    fn no_sealed_shard_ever_exceeds_capacity() {
        let policy = policy((60, 100), (10_000, 20_000));
        let mut sealer = Sealer::new(policy, 100);
        let mut shards = Vec::new();
        let mut tag = 0u32;
        // Deliberately irregular block sizes, including several that alone are
        // a large fraction of capacity.
        for (offset, size) in [7u32, 40, 3, 55, 1, 90, 12, 30, 0, 45]
            .into_iter()
            .enumerate()
        {
            let height = 100 + offset as u64;
            let block = block_of_new_scripts(height, tag, size);
            tag += size;
            shards.extend(sealer.push_block(height, &block).unwrap());
        }
        shards.extend(sealer.finish());
        assert!(
            shards.len() > 1,
            "the fixture should produce several shards"
        );
        for shard in &shards {
            assert!(
                shard.occupancy.scripts <= policy.scripts.capacity,
                "shard {} holds {} scripts, capacity {}",
                shard.shard_id,
                shard.occupancy.scripts,
                policy.scripts.capacity
            );
        }
    }

    /// Boundaries must tile the journal exactly: gapless, non-overlapping, and
    /// ascending in shard id. A gap would be indistinguishable from a range the
    /// operator chose not to publish.
    #[test]
    fn shards_tile_the_journal_without_gaps_or_overlaps() {
        let mut sealer = Sealer::new(policy((25, 60), (10_000, 20_000)), 100);
        let mut shards = Vec::new();
        let mut tag = 0u32;
        for offset in 0..20u64 {
            let height = 100 + offset;
            let block = block_of_new_scripts(height, tag, 7);
            tag += 7;
            shards.extend(sealer.push_block(height, &block).unwrap());
        }
        shards.extend(sealer.finish());

        assert_eq!(shards[0].start_height, 100);
        assert_eq!(shards.last().unwrap().end_height, 119);
        for (index, shard) in shards.iter().enumerate() {
            assert_eq!(shard.shard_id, index as u64);
            assert!(shard.end_height >= shard.start_height);
            if index > 0 {
                assert_eq!(shard.start_height, shards[index - 1].end_height + 1);
            }
        }
        // Only the last shard may be unsealed. This fixture happens to end
        // exactly on a boundary, so it has no partial tail at all — which is a
        // legitimate outcome, not a missing one.
        assert!(shards[..shards.len() - 1]
            .iter()
            .all(|s| s.reason.is_some()));
    }

    /// A block larger than any single segment is still published. It becomes a
    /// shard of its own, which the builder gives the segments it needs; failing
    /// instead would let one purchased block stop the service.
    #[test]
    fn a_block_larger_than_a_segment_becomes_a_shard_of_its_own() {
        let mut sealer = Sealer::new(policy((10, 20), (10_000, 20_000)), 100);
        let sealed = one(sealer.push_block(100, &block_of_new_scripts(100, 0, 50)));
        assert_eq!(
            sealed.reason,
            Some(SealReason::BlockExceedsCapacity("scripts"))
        );
        assert_eq!((sealed.start_height, sealed.end_height), (100, 100));
        assert_eq!(sealed.occupancy.scripts, 50);
        assert_eq!(sealer.finish(), None, "the oversized block took the shard");
    }

    /// An oversized block arriving mid-shard closes the shard before it and
    /// then seals as its own, so the accumulating shard is never overrun and
    /// the block is never carried into a fresh one that could not hold it.
    #[test]
    fn an_oversized_block_after_a_seal_closes_two_shards() {
        let mut sealer = Sealer::new(policy((10, 20), (10_000, 20_000)), 100);
        assert_eq!(
            sealer.push_block(100, &block_of_new_scripts(100, 0, 8)),
            Ok(Vec::new())
        );
        let sealed = sealer
            .push_block(101, &block_of_new_scripts(101, 100, 50))
            .expect("no valid block is ever refused");
        assert_eq!(sealed.len(), 2);
        assert_eq!(
            sealed[0].reason,
            Some(SealReason::WouldExceedCapacity("scripts"))
        );
        assert_eq!((sealed[0].start_height, sealed[0].end_height), (100, 100));
        assert_eq!(
            sealed[1].reason,
            Some(SealReason::BlockExceedsCapacity("scripts"))
        );
        assert_eq!((sealed[1].start_height, sealed[1].end_height), (101, 101));
        assert_eq!(sealed[1].occupancy.scripts, 50);
    }

    /// The availability property, over irregular blocks including several that
    /// exceed a capacity on their own: every block is placed, every shard is
    /// non-empty, and the boundaries still tile the journal.
    #[test]
    fn no_valid_block_is_ever_refused() {
        let policy = policy((60, 100), (10_000, 20_000));
        let mut sealer = Sealer::new(policy, 100);
        let mut shards = Vec::new();
        let mut tag = 0u32;
        for (offset, size) in [7u32, 400, 3, 55, 1, 250, 12, 30, 0, 45]
            .into_iter()
            .enumerate()
        {
            let height = 100 + offset as u64;
            let block = block_of_new_scripts(height, tag, size);
            tag += size;
            shards.extend(
                sealer
                    .push_block(height, &block)
                    .expect("no valid block is ever refused"),
            );
        }
        shards.extend(sealer.finish());

        assert_eq!(shards[0].start_height, 100);
        assert_eq!(shards.last().unwrap().end_height, 109);
        for (index, shard) in shards.iter().enumerate() {
            assert_eq!(shard.shard_id, index as u64);
            if index > 0 {
                assert_eq!(shard.start_height, shards[index - 1].end_height + 1);
            }
        }
        // The shards that exceed capacity are exactly the single-block ones,
        // and they are the ones the builder must give extra segments.
        for shard in &shards {
            if shard.occupancy.scripts > policy.scripts.capacity {
                assert_eq!(shard.start_height, shard.end_height);
                assert_eq!(
                    shard.reason,
                    Some(SealReason::BlockExceedsCapacity("scripts"))
                );
            }
        }
    }

    /// Pages, not events, drive the pages table. A shard full of long histories
    /// should seal on page rows even though its script count stays small.
    #[test]
    fn a_shard_can_seal_on_page_rows_with_few_scripts() {
        let mut sealer = Sealer::new(policy((10_000, 20_000), (4, 10)), 100);
        // One script accumulating a long history: each full page is one row.
        let per_block = (INLINE_EVENTS + EVENTS_PER_PAGE) as usize;
        let mut sealed = None;
        for offset in 0..10u64 {
            let height = 100 + offset;
            let block: Vec<_> = (0..per_block)
                .map(|nonce| event(height, 0, offset as u32 * 1_000 + nonce as u32))
                .collect();
            let closed = sealer.push_block(height, &block).unwrap();
            if let Some(shard) = closed.into_iter().next() {
                sealed = Some(shard);
                break;
            }
        }
        let sealed = sealed.expect("page rows should seal a shard");
        assert_eq!(sealed.reason, Some(SealReason::ReachedTarget("page rows")));
        assert_eq!(sealed.occupancy.scripts, 1, "only one script was involved");
        assert!(sealed.occupancy.page_rows >= 4);
    }

    #[test]
    fn blocks_must_arrive_in_order() {
        let mut sealer = Sealer::new(generous(), 100);
        assert_eq!(
            sealer.push_block(101, &[]),
            Err(SealError::OutOfOrder {
                height: 101,
                expected: 100
            })
        );
        sealer.push_block(100, &[]).unwrap();
        assert_eq!(
            sealer.push_block(102, &[]),
            Err(SealError::OutOfOrder {
                height: 102,
                expected: 101
            })
        );
    }

    /// Empty blocks are part of a shard's span. Dropping them would make the
    /// span disagree with the chain it claims to cover.
    #[test]
    fn empty_blocks_extend_the_span_without_adding_occupancy() {
        let mut sealer = Sealer::new(generous(), 100);
        sealer
            .push_block(100, &block_of_new_scripts(100, 0, 2))
            .unwrap();
        for height in 101..105 {
            sealer.push_block(height, &[]).unwrap();
        }
        let tail = sealer.finish().unwrap();
        assert_eq!((tail.start_height, tail.end_height), (100, 104));
        assert_eq!(tail.occupancy.blocks, 5);
        assert_eq!(tail.occupancy.scripts, 2);
        assert_eq!(tail.occupancy.events, 2);
    }

    /// Sealing must be a function of the journal alone, so two operators
    /// reproduce the same boundaries and their digests stay comparable.
    #[test]
    fn the_same_journal_seals_identically_every_time() {
        let policy = policy((25, 60), (10_000, 20_000));
        let run = || {
            let mut sealer = Sealer::new(policy, 100);
            let mut shards = Vec::new();
            let mut tag = 0u32;
            for offset in 0..20u64 {
                let height = 100 + offset;
                let block = block_of_new_scripts(height, tag, 7);
                tag += 7;
                shards.extend(sealer.push_block(height, &block).unwrap());
            }
            shards.extend(sealer.finish());
            shards
        };
        assert_eq!(run(), run());
    }

    /// A journal that ends exactly where a shard sealed has no partial tail.
    /// Emitting an empty one would publish a shard covering no blocks.
    #[test]
    fn a_journal_ending_on_a_boundary_leaves_no_tail() {
        let mut sealer = Sealer::new(policy((7, 100), (10_000, 20_000)), 100);
        let sealed = one(sealer.push_block(100, &block_of_new_scripts(100, 0, 7)));
        assert_eq!(sealed.occupancy.scripts, 7);
        assert_eq!(sealer.finish(), None);
    }

    /// Sealing must survive across shards: the height check is about the
    /// journal, not about the shard currently accumulating.
    #[test]
    fn ordering_is_enforced_across_a_seal() {
        let mut sealer = Sealer::new(policy((7, 100), (10_000, 20_000)), 100);
        sealer
            .push_block(100, &block_of_new_scripts(100, 0, 7))
            .unwrap();
        assert_eq!(
            sealer.push_block(102, &[]),
            Err(SealError::OutOfOrder {
                height: 102,
                expected: 101
            })
        );
        assert_eq!(sealer.push_block(101, &[]), Ok(Vec::new()));
    }

    #[test]
    fn limits_must_be_positive_and_ordered() {
        assert!(Limit::new(0, 10).is_err());
        assert!(Limit::new(11, 10).is_err());
        assert!(Limit::new(10, 10).is_ok());
    }

    /// Absorbing takes its counters and packed demand from the projection
    /// rather than reapplying the block. Boundaries and occupancy must equal a
    /// reference that recounts every candidate shard from its blocks alone,
    /// across target seals, capacity seals, a block over capacity on its own,
    /// long paged histories and scripts too long to index.
    #[test]
    fn boundaries_equal_a_from_scratch_recount() {
        type Block = Vec<(ScriptBytes, TransparentEvent)>;
        let geometry = Geometry::default();
        let directory = {
            let capacity = geometry.directory_rows
                * (geometry.directory_row_bytes
                    - zakura_transparent_private_shared::shard::records::DIRECTORY_ROW_HEADER_BYTES)
                    as u64;
            Limit {
                target: capacity - capacity / 7,
                capacity,
            }
        };
        // Scripts, directory bytes and packed page rows of `blocks` as one shard.
        let recount = |blocks: &[&Block]| -> (u64, u64, u64) {
            let mut histories: HashMap<Vec<u8>, HistoryLayout> = HashMap::new();
            for block in blocks {
                let mut added: std::collections::BTreeMap<&[u8], Vec<TransparentEvent>> =
                    std::collections::BTreeMap::new();
                for (script, event) in block.iter() {
                    added.entry(script.as_slice()).or_default().push(*event);
                }
                for (script, mut events) in added {
                    events.sort_by_key(TransparentEvent::sort_key);
                    let history = histories.entry(script.to_vec()).or_default();
                    for event in events {
                        history.push(event, geometry.inline_events);
                    }
                }
            }
            let mut demand = PackedDemand::default();
            let mut bytes = 0;
            for (script, history) in &histories {
                if script.len() <= MAX_SCRIPT_BYTES {
                    demand.shift(&HistoryLayout::default(), history);
                    bytes += history.directory_bytes() as u64;
                }
            }
            (histories.len() as u64, bytes, demand.rows())
        };
        let policy = policy((60, 90), (6, 9));
        let over = |(scripts, bytes, rows): (u64, u64, u64)| {
            scripts > policy.scripts.capacity
                || bytes > directory.capacity
                || rows > policy.page_rows.capacity
        };
        let reached = |(scripts, bytes, rows): (u64, u64, u64)| {
            scripts >= policy.scripts.target
                || bytes >= directory.target
                || rows >= policy.page_rows.target
        };

        let mut blocks: Vec<(u64, Block)> = Vec::new();
        for height in 100..400u64 {
            let mut block = Vec::new();
            let width = match height % 37 {
                0 => 120, // over the script capacity on its own
                n if n % 5 == 0 => 0,
                n => n as u32 % 9,
            };
            for i in 0..width {
                // The block over capacity also pages every one of its
                // histories, so closing before it must leave its demand out.
                let (tag, per) = match width {
                    w if w > 100 => (i * 1000 + 50, 4),
                    _ => ((height as u32 * 11 + i * 7) % 50, 1),
                };
                for k in 0..per {
                    let (script, mut event) = event(height, tag, i * 8 + k);
                    if let TransparentEvent::Receive(receive) = &mut event {
                        receive.value = u64::from(i) << (height % 40);
                    }
                    block.push((script, event));
                }
            }
            // One history grows across many blocks and pages repeatedly.
            for nonce in 0..(height % 4) as u32 {
                for event in crate::shard::test_events::pair(height as u32, nonce) {
                    block.push((script(7_777), event));
                }
            }
            if height % 23 == 0 {
                let (_, event) = event(height, 9, 99);
                block.push((ScriptBytes::new(vec![0x51; MAX_SCRIPT_BYTES + 1]), event));
            }
            blocks.push((height, block));
        }

        let mut sealer = Sealer::new(policy, 100);
        let mut sealed = Vec::new();
        for (height, block) in &blocks {
            sealed.extend(sealer.push_block(*height, block).unwrap());
        }
        sealed.extend(sealer.finish());

        let mut expected = Vec::new();
        let mut current: Vec<&(u64, Block)> = Vec::new();
        let counts = |shard: &[&(u64, Block)]| {
            recount(&shard.iter().map(|(_, block)| block).collect::<Vec<_>>())
        };
        for entry in &blocks {
            let mut candidate = current.clone();
            candidate.push(entry);
            let mut oversized = false;
            if over(counts(&candidate)) {
                if !current.is_empty() {
                    expected.push((counts(&current), current.clone()));
                    current.clear();
                }
                oversized = over(counts(&[entry]));
            }
            current.push(entry);
            if oversized || reached(counts(&current)) {
                expected.push((counts(&current), std::mem::take(&mut current)));
            }
        }
        if !current.is_empty() {
            expected.push((counts(&current), current));
        }

        assert!(expected.len() > 10, "the fixture seals often");
        assert_eq!(sealed.len(), expected.len());
        for (shard, (counts, blocks)) in sealed.iter().zip(&expected) {
            assert_eq!(
                (shard.start_height, shard.end_height),
                (blocks[0].0, blocks.last().unwrap().0)
            );
            let occupancy = &shard.occupancy;
            assert_eq!(
                (
                    occupancy.scripts,
                    occupancy.directory_bytes,
                    occupancy.page_rows
                ),
                *counts,
                "shard {}",
                shard.shard_id
            );
            assert_eq!(occupancy.packed_page_rows, occupancy.demand.rows());
        }
    }

    /// `inline_events` is maintained rather than recomputed, so it has to be
    /// checked against the scan it replaced. Nothing else would notice a drift.
    #[test]
    fn maintained_counters_match_a_full_recount() {
        let mut sealer = Sealer::new(generous(), 100);
        for height in 100..160u64 {
            // Reuse tags across blocks so histories grow, and mix in fresh ones.
            let mut block = Vec::new();
            for i in 0..12u32 {
                block.push(event(height, (height as u32 * 3 + i) % 40, i));
            }
            sealer.push_block(height, &block).unwrap();

            let occupancy = sealer.occupancy();
            let recounted: u64 = sealer
                .scripts
                .values()
                .map(|history| history.inline.len() as u64)
                .sum();
            assert_eq!(occupancy.inline_events, recounted, "at height {height}");

            let fragments: u64 = sealer
                .scripts
                .values()
                .map(|h| u64::from(h.fragments))
                .sum();
            assert_eq!(occupancy.fragments, fragments, "at height {height}");
        }
    }

    /// Sharing rows never needs more rows than one per fragment.
    #[test]
    fn packing_is_bounded_by_the_fragment_count() {
        let mut sealer = Sealer::new(generous(), 100);
        for height in 100..200u64 {
            let block: Vec<_> = (0..height as u32 % 17)
                .map(|i| event(height, (height as u32 * 5 + i) % 60, i))
                .collect();
            sealer.push_block(height, &block).unwrap();
            let occupancy = sealer.occupancy();
            assert!(occupancy.packed_page_rows <= occupancy.fragments);
        }
    }

    /// The projection a capacity decision is made on must equal what absorbing
    /// actually produces, for the packed figure as much as the unpacked one.
    /// If those drift, the builder's row count and the sealer's stop agreeing.
    #[test]
    fn the_projection_equals_what_absorbing_produces() {
        let mut sealer = Sealer::new(generous(), 100);
        for height in 100..180u64 {
            let block: Vec<_> = (0..(height as u32 % 9))
                .map(|i| event(height, (height as u32 * 7 + i) % 30, i))
                .collect();
            let projected = sealer.projected(&block);
            sealer.push_block(height, &block).unwrap();
            assert_eq!(sealer.occupancy(), projected, "at height {height}");
        }
    }

    /// Sealing on packed demand is what makes a smaller page table possible:
    /// the same journal, the same page limit, and far fewer shards, because the
    /// limit stops being reached by padding.
    ///
    /// The two bases must not be mixed. A sealer closing on packed rows against
    /// a builder that still emits one row per fragment would size the table for
    /// less than the builder writes, and the difference would come back as
    /// extra segments — which every wallet querying that generation pays for,
    /// because it must query all of them.
    #[test]
    fn the_basis_decides_where_a_shard_ends() {
        let policy = policy((1_000_000, 2_000_000), (40, 50));
        let mut counts = Vec::new();
        for basis in [PageBasis::Fragments, PageBasis::Packed] {
            let mut sealer = Sealer::with_basis(policy, 100, basis);
            let mut shards = Vec::new();
            for height in 100..200u64 {
                // Three events per script puts every one of them in class 1,
                // where 22 share a row.
                let block: Vec<_> = (0..3u32)
                    .flat_map(|nonce| {
                        (0..4u32).map(move |i| event(height, height as u32 * 4 + i, nonce))
                    })
                    .collect();
                shards.extend(sealer.push_block(height, &block).unwrap());
            }
            shards.extend(sealer.finish());
            counts.push(shards.len());
        }
        assert!(
            counts[1] < counts[0],
            "packed sealing should need fewer shards: {counts:?}"
        );
    }

    /// A script too long for a directory entry is filtered publicly and never
    /// paged, so it must not appear in packed demand. It still counts toward
    /// the unpacked figure, which is the v4 behaviour this projection rides on.
    #[test]
    fn an_unindexable_script_contributes_no_packed_rows() {
        let mut sealer = Sealer::new(generous(), 100);
        let long = ScriptBytes::new(vec![0x51; MAX_SCRIPT_BYTES + 1]);
        let (_, sample) = event(100, 0, 0);
        let block: Vec<_> = (0..10)
            .map(|i| {
                let (_, e) = event(100, 0, i);
                (long.clone(), e)
            })
            .collect();
        let _ = sample;
        sealer.push_block(100, &block).unwrap();

        let occupancy = sealer.occupancy();
        assert_eq!(occupancy.scripts, 1);
        assert!(
            occupancy.fragments > 0,
            "the unpacked figure still counts it"
        );
        assert_eq!(occupancy.packed_page_rows, 0);
        assert_eq!(occupancy.demand.paged_scripts(), 0);
    }
}
