//! Assembling a directory shard's published objects.
//!
//! A directory shard publishes a public activity filter, a private script
//! directory, and up to [`MAX_PAGE_CHILDREN`] page shards, each its own private
//! table. Everything here is a deterministic function of the events, the
//! boundaries the sealer chose and the shard's identity. Two operators with the
//! same journal must produce byte-identical tables, or the published digests
//! stop being comparable and the only cross-operator check the design has stops
//! working. That is why scripts are processed in sorted order, events in their
//! own total order, and bucket placement resolved by a rule rather than by
//! iteration order.
//!
//! # Streaming
//!
//! [`DirectoryBuilder`] follows the sealer block by block. It keeps, per
//! script, only what the directory entry needs (the two newest events and a
//! pointer to the newest run), plus the blocks of the page shard still open.
//! When a page shard seals its runs are laid out at once and its table handed
//! back, so a directory shard spanning many page shards never holds more than
//! one page shard's history. [`ShardStream`] drives a [`DisplacementSealer`]
//! and the builders together and checks that every page shard and directory
//! holds exactly what the sealer sized it for.
//!
//! # Pushing out
//!
//! A script keeps its two newest events in the directory shard inline. When a
//! third arrives the oldest inline event is pushed into the script's run in the
//! page shard open at that block. Each run's first fragment links to the
//! script's previous run, whose row is fixed because its page shard has
//! already sealed; the directory entry points at the newest run.

pub use zakura_pir_protocol::transparent::shard::choice::candidate_rows;

pub use crate::directory::Placement;
use crate::directory::{AssignmentError, Overflow};
pub use zakura_pir_protocol::transparent::shard::choice::bucket_for;
use zakura_pir_protocol::transparent::shard::choice::bucket_salts;

use crate::transparent::events::TransparentEvent;
use crate::transparent::filter::{
    BlockHash, FilterBytes, FilterError, ScriptBytes, ShardKey, build_range_filter_for,
};
use crate::transparent::layout::{
    Geometry, INLINE_EVENTS, MAX_PAGE_CHILDREN, PackedDemand, segments_for,
};
use crate::transparent::packing::{self, FRAGMENT_PAYLOAD, HistoryLayout, ROW_PAYLOAD};
use crate::transparent::page_row::{PageEntry, RunLink, encode_page_row};
use crate::transparent::records::{
    DirectoryEntry, MAX_SCRIPT_BYTES, RecordError, encode_directory_row,
};
use crate::transparent::seal::{
    Closed, DecoupledPolicy, DisplacementSealer, SealError, SealedDirectory,
};
use crate::transparent::tag::{resolve_page_tag_salt, resolve_tag_salt, script_tag};
use sha2::{Digest, Sha256};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};

/// Independently salted candidate rows per script.
///
/// Two choices, as the mainnet study selected: it packs far better than one and
/// costs one more query than one, where four costs two more queries for less
/// improvement. A script that fits in neither candidate is not resolved by a
/// public lookup, which would reveal the script it was trying to place; it is
/// resolved by giving the shard another segment and placing again.
pub use zakura_pir_protocol::transparent::shard::choice::DIRECTORY_CHOICES;

/// Segments a shard's directory may be given before placement is called
/// pathological.
///
/// This is not the availability bound. Adding a segment re-hashes every script
/// over a larger row space, so the load falls with each attempt and one or two
/// attempts settle any real shard — the largest block ever produced is many
/// orders of magnitude below what this many segments hold. It exists so a bug
/// in the placement rule fails loudly instead of allocating forever.
const MAX_DIRECTORY_SEGMENTS: u32 = 1_024;

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("record: {0}")]
    Record(#[from] RecordError),
    #[error("filter: {0}")]
    Filter(#[from] FilterError),
    #[error("seal: {0}")]
    Seal(#[from] SealError),
    #[error("script {script} fits in neither candidate row at {MAX_DIRECTORY_SEGMENTS} segments")]
    DirectoryFull { script: String },
    #[error("{0}")]
    Invalid(String),
}

/// One block's events, as the journal yields them.
pub type Block = (u64, Vec<(ScriptBytes, TransparentEvent)>);

/// One page shard's published table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltChild {
    pub shard_id: u64,
    /// Position `j` within the directory shard.
    pub index: u32,
    pub start_height: u64,
    pub end_height: u64,
    /// The block at `end_height`; part of the page shard's tag salt.
    pub terminal_block_hash: BlockHash,
    pub tag_salt_counter: u32,
    /// False only for the page shard still open in a tail.
    pub sealed: bool,
    /// The occupied rows, `page_rows` of them, written from row zero. Every
    /// later row of every segment is zero, so the zeros are not held: an
    /// archive directory shard's page shards would otherwise pin gigabytes of
    /// padding. [`BuiltChild::segment`] materialises a whole segment.
    pub pages: Vec<u8>,
    /// Segments the table is published in. Zero when no run was pushed here.
    pub segments: u32,
    pub page_rows: u64,
    pub fragments: u64,
    /// Scripts with a run here.
    pub runs: u64,
    /// Events pushed here.
    pub events: u64,
}

impl BuiltChild {
    /// One row of the page shard's logical row space, which is its segments
    /// concatenated. Panics outside the space, which is a programming error.
    pub fn page_row(&self, geometry: &Geometry, row: u64) -> &[u8] {
        static ZERO_ROW: [u8; crate::transparent::layout::PAGE_ROW_BYTES] =
            [0; crate::transparent::layout::PAGE_ROW_BYTES];
        assert!(
            row < u64::from(self.segments) * geometry.page_rows,
            "row {row} is outside the table"
        );
        let width = geometry.page_row_bytes;
        let at = row as usize * width;
        self.pages.get(at..at + width).unwrap_or(&ZERO_ROW[..width])
    }

    /// Segment `segment` of the published table, zero padded to the
    /// geometry's full segment size.
    pub fn segment(&self, geometry: &Geometry, segment: u32) -> Vec<u8> {
        assert!(
            segment < self.segments,
            "segment {segment} is outside the table"
        );
        let size = geometry.page_rows as usize * geometry.page_row_bytes;
        let from = (segment as usize * size).min(self.pages.len());
        let to = (from + size).min(self.pages.len());
        let mut bytes = Vec::with_capacity(size);
        bytes.extend_from_slice(&self.pages[from..to]);
        bytes.resize(size, 0);
        bytes
    }

    /// The manifest entry describing this page shard, at `geometry`.
    pub fn describe(&self, geometry: &Geometry) -> crate::transparent::manifest::PageChild {
        crate::transparent::manifest::PageChild {
            index: self.index,
            start_height: self.start_height,
            end_height: self.end_height,
            terminal_block_hash: self.terminal_block_hash.to_display_hex(),
            tag_salt_counter: self.tag_salt_counter,
            sealed: self.sealed,
            page_segments: self
                .segment_digests(geometry)
                .iter()
                .map(|digest| crate::transparent::manifest::TableGeometry {
                    rows: geometry.page_rows,
                    row_bytes: geometry.page_row_bytes as u32,
                    sha256: hex::encode(digest),
                })
                .collect(),
            occupancy: crate::transparent::manifest::PageChildOccupancy {
                page_rows: self.page_rows,
                fragments: self.fragments,
                runs: self.runs,
                events: self.events,
            },
        }
    }

    /// SHA-256 of each published segment, computed over the zero padding
    /// without materialising it.
    pub fn segment_digests(&self, geometry: &Geometry) -> Vec<[u8; 32]> {
        static ZEROS: [u8; 1 << 16] = [0; 1 << 16];
        let size = geometry.page_rows as usize * geometry.page_row_bytes;
        (0..self.segments as usize)
            .map(|segment| {
                let from = (segment * size).min(self.pages.len());
                let to = (from + size).min(self.pages.len());
                let mut hasher = Sha256::new();
                hasher.update(&self.pages[from..to]);
                let mut padding = size - (to - from);
                while padding > 0 {
                    let take = padding.min(ZEROS.len());
                    hasher.update(&ZEROS[..take]);
                    padding -= take;
                }
                hasher.finalize().into()
            })
            .collect()
    }
}

/// Builds one directory shard over `blocks` with page shards ending at the
/// heights in `child_ends`, without a sealer deciding where they close.
///
/// For tools and tests that lay shards out by hand. `blocks` must be
/// consecutive, empty ones included; `child_ends` ascends and ends on the
/// last block. Every page shard but the last is sealed; the last, and the
/// directory shard, are sealed when `sealed` is.
#[allow(clippy::too_many_arguments)]
pub fn build_directory_shard(
    shard_id: u64,
    geometry: &'static Geometry,
    genesis: BlockHash,
    profile: &str,
    blocks: Vec<Block>,
    child_ends: &[u64],
    terminal: &dyn Fn(u64) -> BlockHash,
    sealed: bool,
) -> Result<(BuiltDirectory, Vec<BuiltChild>), BuildError> {
    let end = blocks
        .last()
        .map(|(height, _)| *height)
        .ok_or_else(|| BuildError::Invalid("a directory shard holds no block".into()))?;
    if child_ends.last() != Some(&end) || child_ends.windows(2).any(|w| w[0] >= w[1]) {
        return Err(BuildError::Invalid(format!(
            "page shards ending at {child_ends:?} do not tile a shard ending at {end}"
        )));
    }
    let mut builder = DirectoryBuilder::new(shard_id, geometry, genesis, profile)?;
    for block in blocks {
        builder.push_block(block)?;
    }
    let mut children = Vec::with_capacity(child_ends.len());
    for (index, child_end) in child_ends.iter().enumerate() {
        let last = index + 1 == child_ends.len();
        children.push(builder.close_child(*child_end, terminal(*child_end), !last || sealed)?);
    }
    let (built, _) = builder.finish(end, terminal(end), sealed)?;
    Ok((built, children))
}

/// A directory shard's directory and filter, once its page shards are built.
pub struct BuiltDirectory {
    pub shard_id: u64,
    /// The geometry this shard was built at. Carried rather than assumed,
    /// because a set may mix geometries across its tiers.
    pub geometry: &'static Geometry,
    pub start_height: u64,
    pub end_height: u64,
    /// The public filter. Contains every element the range yields, including
    /// scripts too long to index privately.
    pub filter: FilterBytes,
    /// The directory table, one entry per segment.
    ///
    /// One segment is the ordinary case. More means this shard's content did
    /// not fit one, which happens when a single block exceeds a seal capacity
    /// on its own. Every segment has the same pinned geometry, so the shared
    /// parameter set is unaffected.
    pub directory: Vec<Vec<u8>>,
    /// Page shards, in order.
    pub children: u32,
    /// Scripts placed in the directory.
    pub scripts: u64,
    pub events: u64,
    /// Distinct transaction ids among the shard's events.
    pub txids: u64,
    /// Which candidate row holds each placed script, for a single-lookup
    /// directory. See [`crate::transparent::choice`]. `None` only if no seed peeled, which
    /// leaves the shard on two queries rather than failing the build.
    pub choice: Option<crate::transparent::choice::ChoiceTable>,
    /// Scripts in the filter but not the directory, because they exceed
    /// [`MAX_SCRIPT_BYTES`]. Published so the coverage gap is measured rather
    /// than silent.
    pub excluded_scripts: u64,
    /// The directory's tag-salt counter. Zero unless a collision forced a
    /// rebuild.
    pub tag_salt_counter: u32,
    /// Whether the directory shard is sealed rather than a tail.
    pub sealed: bool,
}

impl BuiltDirectory {
    /// Segments in this shard's directory table. One in the ordinary case.
    pub fn directory_segments(&self) -> u32 {
        self.directory.len() as u32
    }

    /// One row of the shard's logical directory space, which is its segments
    /// concatenated. Panics outside the space, which is a programming error.
    pub fn directory_row(&self, row: u64) -> &[u8] {
        let (segment, within) =
            crate::transparent::layout::split_row(row, self.geometry.directory_rows);
        let width = self.geometry.directory_row_bytes;
        let at = within as usize * width;
        &self.directory[segment as usize][at..at + width]
    }
}

/// A script's place in an open directory shard.
#[derive(Clone, Debug, Default)]
struct ScriptState {
    events: u32,
    /// The newest events, oldest first, at most [`INLINE_EVENTS`].
    inline: Vec<TransparentEvent>,
    /// The newest run's page shard and 1-based first row.
    head: Option<(u8, u32)>,
    /// Runs so far.
    runs: u8,
}

/// Builds one directory shard, block by block, as the sealer closes its page
/// shards. See the module documentation.
pub struct DirectoryBuilder {
    shard_id: u64,
    geometry: &'static Geometry,
    genesis: BlockHash,
    profile: String,
    start_height: Option<u64>,
    last_height: Option<u64>,
    /// Blocks not yet assigned to a sealed page shard.
    pending: VecDeque<Block>,
    /// Indexable scripts.
    scripts: BTreeMap<Vec<u8>, ScriptState>,
    /// Scripts too long for a directory entry: filtered, never indexed.
    excluded: BTreeSet<Vec<u8>>,
    events: u64,
    /// The first eight bytes of each distinct transaction id. Transaction ids
    /// are hashes, so this counts them without holding them whole.
    txids: HashSet<u64>,
    children: u32,
}

impl DirectoryBuilder {
    pub fn new(
        shard_id: u64,
        geometry: &'static Geometry,
        genesis: BlockHash,
        profile: &str,
    ) -> Result<Self, BuildError> {
        // A geometry this build cannot encode would produce tables no wallet
        // could read, so it is refused before any bytes are written.
        geometry
            .validate_publishable()
            .map_err(BuildError::Invalid)?;
        if crate::transparent::filter::range_profile(profile).is_none() {
            return Err(BuildError::Invalid(format!(
                "unknown range profile {profile:?}"
            )));
        }
        Ok(Self {
            shard_id,
            geometry,
            genesis,
            profile: profile.to_string(),
            start_height: None,
            last_height: None,
            pending: VecDeque::new(),
            scripts: BTreeMap::new(),
            excluded: BTreeSet::new(),
            events: 0,
            txids: HashSet::new(),
            children: 0,
        })
    }

    pub fn shard_id(&self) -> u64 {
        self.shard_id
    }

    /// Takes the next block. Blocks must be consecutive, empty ones included.
    pub fn push_block(&mut self, block: Block) -> Result<(), BuildError> {
        let (height, events) = &block;
        if let Some(last) = self.last_height {
            if *height != last + 1 {
                return Err(BuildError::Invalid(format!(
                    "block {height} does not follow {last}"
                )));
            }
        }
        if let Some((_, event)) = events
            .iter()
            .find(|(_, event)| u64::from(event.height()) != *height)
        {
            return Err(BuildError::Invalid(format!(
                "an event at height {} is in block {height}",
                event.height()
            )));
        }
        self.start_height.get_or_insert(*height);
        self.last_height = Some(*height);
        self.pending.push_back(block);
        Ok(())
    }

    /// Absorbs one block: inline events advance, and each event pushed out
    /// joins its script's run in the open page shard.
    fn absorb(&mut self, (_, events): Block, runs: &mut BTreeMap<Vec<u8>, Vec<TransparentEvent>>) {
        let mut by_script: BTreeMap<Vec<u8>, Vec<TransparentEvent>> = BTreeMap::new();
        for (script, event) in events {
            self.events += 1;
            let txid = event.txid().0;
            self.txids
                .insert(u64::from_le_bytes(txid[..8].try_into().expect("8 bytes")));
            by_script
                .entry(script.as_slice().to_vec())
                .or_default()
                .push(event);
        }
        for (script, mut events) in by_script {
            if script.len() > MAX_SCRIPT_BYTES {
                self.excluded.insert(script);
                continue;
            }
            events.sort_by_key(TransparentEvent::sort_key);
            let state = self.scripts.entry(script.clone()).or_default();
            for event in events {
                state.events += 1;
                state.inline.push(event);
                if state.inline.len() > INLINE_EVENTS as usize {
                    let pushed = state.inline.remove(0);
                    runs.entry(script.clone()).or_default().push(pushed);
                }
            }
        }
    }

    /// Seals the open page shard at `end_height` and lays out its table.
    ///
    /// Every pending block at or below `end_height` belongs to it; later ones
    /// stay for the next page shard. `terminal` is the block at `end_height`.
    pub fn close_child(
        &mut self,
        end_height: u64,
        terminal: BlockHash,
        sealed: bool,
    ) -> Result<BuiltChild, BuildError> {
        let index = self.children;
        if index >= MAX_PAGE_CHILDREN {
            return Err(BuildError::Invalid(format!(
                "shard {} would hold more than {MAX_PAGE_CHILDREN} page shards",
                self.shard_id
            )));
        }
        let start_height = match self.pending.front() {
            Some((height, _)) if *height <= end_height => *height,
            _ => {
                return Err(BuildError::Invalid(format!(
                    "page shard {index} of shard {} holds no block",
                    self.shard_id
                )));
            }
        };
        let mut runs: BTreeMap<Vec<u8>, Vec<TransparentEvent>> = BTreeMap::new();
        while self
            .pending
            .front()
            .is_some_and(|(height, _)| *height <= end_height)
        {
            let block = self.pending.pop_front().expect("checked");
            self.absorb(block, &mut runs);
        }
        if self.last_height.is_some_and(|last| last < end_height) {
            return Err(BuildError::Invalid(format!(
                "page shard {index} ends at {end_height}, past the last block"
            )));
        }

        let scripts: Vec<&[u8]> = runs.keys().map(Vec::as_slice).collect();
        let (tag_salt_counter, salt) = resolve_page_tag_salt(
            self.shard_id,
            index,
            end_height,
            &terminal,
            &scripts,
            script_tag,
        )
        .map_err(BuildError::Invalid)?;
        let laid = lay_out_runs(
            &runs,
            |script| script_tag(&salt, script),
            |script| {
                self.scripts
                    .get(script)
                    .and_then(|state| {
                        state.head.map(|(prev_child, prev_row)| RunLink {
                            prev_child,
                            prev_row,
                            older_runs: state.runs,
                        })
                    })
                    .unwrap_or_default()
            },
        )?;
        for (script, first_row) in &laid.first_rows {
            let state = self
                .scripts
                .get_mut(*script)
                .expect("a script with a run has a state");
            state.head = Some((index as u8, *first_row));
            state.runs += 1;
        }

        let page_rows = laid.rows.len() as u64;
        // Unused rows are zero and decode as empty; they are indistinguishable
        // in a response from occupied ones, and are padded on publication.
        let segments = if laid.rows.is_empty() {
            0
        } else {
            segments_for(page_rows, self.geometry.page_rows)
        };
        let mut pages = Vec::with_capacity(laid.rows.len() * self.geometry.page_row_bytes);
        for row in &laid.rows {
            pages.extend_from_slice(&encode_page_row(row)?);
        }
        self.children += 1;
        Ok(BuiltChild {
            shard_id: self.shard_id,
            index,
            start_height,
            end_height,
            terminal_block_hash: terminal,
            tag_salt_counter,
            sealed,
            pages,
            segments,
            page_rows,
            fragments: laid.fragments,
            runs: runs.len() as u64,
            events: runs.values().map(|run| run.len() as u64).sum(),
        })
    }

    /// Builds the directory and filter once the last page shard is closed.
    ///
    /// Returns the blocks offered past `end_height`, which belong to the next
    /// directory shard.
    pub fn finish(
        mut self,
        end_height: u64,
        terminal: BlockHash,
        sealed: bool,
    ) -> Result<(BuiltDirectory, Vec<Block>), BuildError> {
        if self
            .pending
            .front()
            .is_some_and(|(height, _)| *height <= end_height)
        {
            return Err(BuildError::Invalid(format!(
                "shard {} closes with blocks no page shard holds",
                self.shard_id
            )));
        }
        let start_height = self
            .start_height
            .ok_or_else(|| BuildError::Invalid("a directory shard holds no block".into()))?;
        if self.children == 0 {
            return Err(BuildError::Invalid(format!(
                "shard {} closes with no page shard",
                self.shard_id
            )));
        }
        let leftover: Vec<Block> = self.pending.drain(..).collect();

        // The filter covers every element, including scripts the private
        // tables cannot index. Excluding them would tell a wallet holding one
        // that its script had no activity, which is worse than telling it the
        // script is outside coverage.
        let filter_elements: Vec<ScriptBytes> = self
            .scripts
            .keys()
            .chain(self.excluded.iter())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|script| ScriptBytes::new(script.clone()))
            .collect();
        let key = ShardKey::derive(
            &self.profile,
            self.genesis,
            self.shard_id,
            start_height,
            end_height,
            terminal,
        );
        let range = crate::transparent::filter::range_profile(&self.profile).ok_or_else(|| {
            BuildError::Invalid(format!("unknown range profile {:?}", self.profile))
        })?;
        let filter = build_range_filter_for(range, key, &filter_elements)?;

        let indexed: Vec<&[u8]> = self.scripts.keys().map(Vec::as_slice).collect();
        let (tag_salt_counter, salt) =
            resolve_tag_salt(self.shard_id, &terminal, &indexed, script_tag)
                .map_err(BuildError::Invalid)?;
        let mut entries: Vec<DirectoryEntry> = self
            .scripts
            .iter()
            .map(|(script, state)| DirectoryEntry {
                script: script.clone(),
                tag: script_tag(&salt, script),
                event_count: state.events,
                inline: state.inline.clone(),
                head_child: state.head.map_or(0, |(child, _)| child),
                head_row: state.head.map_or(0, |(_, row)| row),
            })
            .collect();
        entries.sort_by(|a, b| {
            (Reverse(a.encoded_len()), &a.script).cmp(&(Reverse(b.encoded_len()), &b.script))
        });
        let (directory, scripts, choice) =
            place_directory(self.shard_id, entries, self.geometry, self.children)?;
        Ok((
            BuiltDirectory {
                shard_id: self.shard_id,
                geometry: self.geometry,
                start_height,
                end_height,
                filter,
                directory,
                children: self.children,
                scripts,
                events: self.events,
                txids: self.txids.len() as u64,
                choice,
                excluded_scripts: self.excluded.len() as u64,
                tag_salt_counter,
                sealed,
            },
            leftover,
        ))
    }
}

/// One page shard's rows, laid out.
struct LaidOut<'a> {
    rows: Vec<Vec<PageEntry>>,
    /// Each script's 1-based first row.
    first_rows: BTreeMap<&'a [u8], u32>,
    fragments: u64,
}

/// Lays out one page shard's runs: long runs in script order on contiguous
/// rows, then single-fragment runs by descending best fit, including spare
/// space in long runs' last rows, unless equal-size groups need fewer rows.
/// The same rule, step for step, as the sealer's [`PackedDemand`] count,
/// which the row count is checked against.
fn lay_out_runs<'a>(
    runs: &'a BTreeMap<Vec<u8>, Vec<TransparentEvent>>,
    tag_of: impl Fn(&[u8]) -> [u8; crate::transparent::tag::SCRIPT_TAG_BYTES],
    link_of: impl Fn(&[u8]) -> RunLink,
) -> Result<LaidOut<'a>, BuildError> {
    let mut demand = PackedDemand::default();
    let mut summaries = BTreeMap::new();
    for (script, run) in runs {
        let mut summary = HistoryLayout::default();
        for event in run {
            summary.push_with_payload(*event, 0, FRAGMENT_PAYLOAD);
        }
        demand.shift(&HistoryLayout::default(), &summary);
        summaries.insert(script.as_slice(), summary);
    }
    let mut rows: Vec<Vec<PageEntry>> = Vec::new();
    let mut first_rows: BTreeMap<&[u8], u32> = BTreeMap::new();
    let mut short = Vec::new();
    let mut free: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    let mixed = demand.use_mixed();
    let locator = |row: usize| {
        u32::try_from(row + 1).map_err(|_| BuildError::Invalid("page locator overflow".into()))
    };
    // Long runs are allocated in script order and remain contiguous. Only
    // their last row is offered to single-fragment runs.
    for (script, run) in runs {
        let script = script.as_slice();
        let fragments = packing::fragments(run);
        let count = summaries[script].fragments;
        let link = link_of(script);
        if fragments.len() == 1 {
            let entry = PageEntry::new(tag_of(script), 0, 1, run.clone())?.with_link(link)?;
            short.push((script, entry));
        } else {
            first_rows.insert(script, locator(rows.len())?);
            for (ordinal, events) in fragments.iter().enumerate() {
                let mut entry =
                    PageEntry::new(tag_of(script), ordinal as u32, count, events.to_vec())?;
                if ordinal == 0 {
                    entry = entry.with_link(link)?;
                }
                rows.push(vec![entry]);
            }
            if mixed {
                let row = rows.len() - 1;
                free.entry(ROW_PAYLOAD - rows[row][0].encoded_len())
                    .or_default()
                    .insert(row);
            }
        }
    }
    short.sort_by(|a, b| (Reverse(a.1.encoded_len()), a.0).cmp(&(Reverse(b.1.encoded_len()), b.0)));
    let mut last_size = None;
    for (script, entry) in short {
        let size = entry.encoded_len();
        if !mixed && last_size != Some(size) {
            free.clear();
        }
        last_size = Some(size);
        let (space, row) = if let Some((&space, indices)) = free.range(size..).next() {
            let row = *indices.first().expect("nonempty bin set");
            let indices = free.get_mut(&space).expect("existing bin set");
            indices.remove(&row);
            if indices.is_empty() {
                free.remove(&space);
            }
            (space, row)
        } else {
            rows.push(Vec::new());
            (ROW_PAYLOAD, rows.len() - 1)
        };
        first_rows.insert(script, locator(row)?);
        rows[row].push(entry);
        free.entry(space - size).or_default().insert(row);
    }
    if rows.len() as u64 != demand.rows() {
        return Err(BuildError::Invalid(format!(
            "emitted {} rows, predicted {}",
            rows.len(),
            demand.rows()
        )));
    }
    Ok(LaidOut {
        rows,
        first_rows,
        fragments: demand.fragments(),
    })
}

/// What a [`ShardStream`] built.
///
/// Moved once from the stream to the publisher per page shard or directory
/// shard, so the directory variant's size is not worth a box.
#[allow(clippy::large_enum_variant)]
pub enum Built {
    /// A page shard closed. Its directory shard may still be open.
    Child(BuiltChild),
    /// A directory shard closed, after its last page shard. `sealed` is what
    /// the sealer decided about it, including each page shard's occupancy.
    Directory {
        built: BuiltDirectory,
        sealed: SealedDirectory,
    },
}

/// Seals and builds a block stream: a [`DisplacementSealer`] deciding
/// boundaries and a [`DirectoryBuilder`] per directory shard following it.
///
/// `terminal(height)` is the hash of the block at `height`; it is asked only
/// for heights already offered.
pub struct ShardStream {
    geometry: &'static Geometry,
    policy: DecoupledPolicy,
    sealer: DisplacementSealer,
    builder: Option<DirectoryBuilder>,
    genesis: BlockHash,
    profile: String,
}

impl ShardStream {
    /// A stream starting a directory shard at `first_height` under shard id
    /// `next_shard_id`, sealing under the policy the geometry implies.
    pub fn new(
        geometry: &'static Geometry,
        first_height: u64,
        next_shard_id: u64,
        genesis: BlockHash,
        profile: &str,
    ) -> Result<Self, BuildError> {
        Self::with_policy(
            geometry,
            DecoupledPolicy::for_geometry(geometry),
            first_height,
            next_shard_id,
            genesis,
            profile,
        )
    }

    /// [`Self::new`] under another policy, for tests that need page shards
    /// and directory shards to close within a few blocks. A published set
    /// seals under the policy its geometry implies, which the manifest states.
    pub fn with_policy(
        geometry: &'static Geometry,
        policy: DecoupledPolicy,
        first_height: u64,
        next_shard_id: u64,
        genesis: BlockHash,
        profile: &str,
    ) -> Result<Self, BuildError> {
        geometry
            .validate_publishable()
            .map_err(BuildError::Invalid)?;
        Ok(Self {
            geometry,
            policy,
            sealer: DisplacementSealer::new(policy, *geometry, first_height, next_shard_id),
            builder: None,
            genesis,
            profile: profile.to_string(),
        })
    }

    pub fn geometry(&self) -> &'static Geometry {
        self.geometry
    }

    /// The policy this stream seals under.
    pub fn policy(&self) -> &DecoupledPolicy {
        &self.policy
    }

    /// The shard id the next directory shard takes.
    pub fn next_shard_id(&self) -> u64 {
        self.sealer.next_shard_id()
    }

    /// The first height of the directory shard still open, if any.
    pub fn open_start(&self) -> Option<u64> {
        self.sealer.open_start()
    }

    /// Offers one block and returns what it closed, in order.
    pub fn push_block(
        &mut self,
        block: Block,
        terminal: &dyn Fn(u64) -> Option<BlockHash>,
    ) -> Result<Vec<Built>, BuildError> {
        let (height, events) = &block;
        self.sealer.push_block(*height, events)?;
        let next = self.sealer.next_shard_id();
        let builder = match self.builder.as_mut() {
            Some(builder) => builder,
            None => self.builder.insert(DirectoryBuilder::new(
                next - u64::from(self.sealer.open_start().is_none()),
                self.geometry,
                self.genesis,
                &self.profile,
            )?),
        };
        builder.push_block(block)?;
        let closed = self.sealer.drain_closed();
        self.apply(closed, terminal)
    }

    /// Closes the open directory shard at a tier boundary; see
    /// [`DisplacementSealer::seal_at_geometry_change`]. The stream then
    /// continues under `geometry` at `next_height`.
    pub fn change_geometry(
        &mut self,
        geometry: &'static Geometry,
        next_height: u64,
        terminal: &dyn Fn(u64) -> Option<BlockHash>,
    ) -> Result<Vec<Built>, BuildError> {
        self.sealer.seal_at_geometry_change();
        let closed = self.sealer.drain_closed();
        let built = self.apply(closed, terminal)?;
        let next_shard_id = self.sealer.next_shard_id();
        let profile = self.profile.clone();
        *self = Self::new(geometry, next_height, next_shard_id, self.genesis, &profile)?;
        Ok(built)
    }

    /// [`Self::change_geometry`] under an explicit policy for the new tier.
    pub fn change_geometry_with_policy(
        &mut self,
        geometry: &'static Geometry,
        policy: DecoupledPolicy,
        next_height: u64,
        terminal: &dyn Fn(u64) -> Option<BlockHash>,
    ) -> Result<Vec<Built>, BuildError> {
        self.sealer.seal_at_geometry_change();
        let closed = self.sealer.drain_closed();
        let built = self.apply(closed, terminal)?;
        let next_shard_id = self.sealer.next_shard_id();
        let profile = self.profile.clone();
        *self = Self::with_policy(
            geometry,
            policy,
            next_height,
            next_shard_id,
            self.genesis,
            &profile,
        )?;
        Ok(built)
    }

    /// Closes whatever is still open: the tail directory shard and its open
    /// page shard, both unsealed.
    pub fn finish(
        &mut self,
        terminal: &dyn Fn(u64) -> Option<BlockHash>,
    ) -> Result<Vec<Built>, BuildError> {
        self.sealer.finish();
        let closed = self.sealer.drain_closed();
        self.apply(closed, terminal)
    }

    fn apply(
        &mut self,
        closed: Vec<Closed>,
        terminal: &dyn Fn(u64) -> Option<BlockHash>,
    ) -> Result<Vec<Built>, BuildError> {
        let hash = |height: u64| {
            terminal(height)
                .ok_or_else(|| BuildError::Invalid(format!("no block hash is known at {height}")))
        };
        let mut out = Vec::new();
        for closure in closed {
            let builder = self.builder.as_mut().ok_or_else(|| {
                BuildError::Invalid("the sealer closed a shard no builder followed".into())
            })?;
            match closure {
                Closed::Child(child) => {
                    let built = builder.close_child(
                        child.end_height,
                        hash(child.end_height)?,
                        child.reason.is_some(),
                    )?;
                    // The sealer sized this page shard from the packing rule;
                    // the builder laid it out under the same rule. A
                    // divergence would publish a table sized for something
                    // other than what it holds.
                    if built.index != child.index
                        || built.start_height != child.start_height
                        || built.page_rows != child.occupancy.page_rows
                        || built.fragments != child.occupancy.fragments
                        || built.runs != child.occupancy.runs
                    {
                        return Err(BuildError::Invalid(format!(
                            "page shard {} of shard {} over {}-{} emitted {} rows, {} fragments \
                             and {} runs, but was sealed for {}, {} and {}",
                            child.index,
                            builder.shard_id(),
                            child.start_height,
                            child.end_height,
                            built.page_rows,
                            built.fragments,
                            built.runs,
                            child.occupancy.page_rows,
                            child.occupancy.fragments,
                            child.occupancy.runs,
                        )));
                    }
                    out.push(Built::Child(built));
                }
                Closed::Directory(sealed) => {
                    let builder = self.builder.take().expect("checked above");
                    if builder.shard_id() != sealed.shard_id {
                        return Err(BuildError::Invalid(format!(
                            "the builder followed shard {} but the sealer closed {}",
                            builder.shard_id(),
                            sealed.shard_id
                        )));
                    }
                    let (built, leftover) = builder.finish(
                        sealed.end_height,
                        hash(sealed.end_height)?,
                        sealed.reason.is_some(),
                    )?;
                    if built.children as usize != sealed.children.len()
                        || built.start_height != sealed.start_height
                    {
                        return Err(BuildError::Invalid(format!(
                            "shard {} was built with {} page shards from {}, sealed with {} from {}",
                            sealed.shard_id,
                            built.children,
                            built.start_height,
                            sealed.children.len(),
                            sealed.start_height
                        )));
                    }
                    let next_id = sealed.shard_id + 1;
                    out.push(Built::Directory { built, sealed });
                    if !leftover.is_empty() {
                        let mut next = DirectoryBuilder::new(
                            next_id,
                            self.geometry,
                            self.genesis,
                            &self.profile,
                        )?;
                        for block in leftover {
                            next.push_block(block)?;
                        }
                        self.builder = Some(next);
                    }
                }
            }
        }
        Ok(out)
    }
}

/// Descending encoded directory size, with raw script bytes breaking ties.
/// Both the builder and census feed this order to byte-based placement.
pub fn placement_order<'a>(
    scripts: impl IntoIterator<Item = (&'a [u8], usize)>,
) -> Vec<(&'a [u8], usize)> {
    let mut entries: Vec<_> = scripts.into_iter().collect();
    entries.sort_by(|a, b| (Reverse(a.1), a.0).cmp(&(Reverse(b.1), b.0)));
    entries
}

/// Runs the placement rule over a script set without building anything.
///
/// The same rule, in the same order, as [`place_directory`] — which calls it,
/// so there is one implementation and a census cannot report a placement the
/// builder would not produce. A script that fits in neither candidate gives the
/// shard another segment, up to [`MAX_DIRECTORY_SEGMENTS`]. Returns the
/// offending script, hex encoded, if that cap is reached.
pub fn place_scripts(
    shard_id: u64,
    scripts: &[&[u8]],
    sizes: &[usize],
    rows_per_segment: u64,
    capacity: usize,
) -> Result<(Placement, Vec<u32>), String> {
    crate::directory::place(
        &bucket_salts(shard_id),
        scripts,
        sizes,
        rows_per_segment,
        capacity,
        Overflow::Grow(MAX_DIRECTORY_SEGMENTS),
    )
    .map_err(|index| hex::encode(scripts[index]))
}

/// The choice table for a placement: which candidate row each script took.
///
/// `scripts` and `assignment` are what [`place_scripts`] was given and
/// returned, and `rows` is the logical row space it settled on.
pub fn choice_table(
    shard_id: u64,
    scripts: &[&[u8]],
    assignment: &[u32],
    rows: u64,
) -> Result<crate::transparent::choice::ChoiceTable, crate::transparent::choice::ChoiceError> {
    let entries = crate::directory::choice_bits(&bucket_salts(shard_id), scripts, assignment, rows);
    crate::transparent::choice::ChoiceTable::build(shard_id, &entries)
}

/// Checks that `table` names the row each script is held in.
///
/// `row_of(i)` is the logical row holding `scripts[i]`, over `rows` rows.
/// Returns the index of the first script it misroutes, or `None` if it routes
/// every one.
pub fn verify_choice(
    shard_id: u64,
    table: &crate::transparent::choice::ChoiceTable,
    scripts: &[&[u8]],
    rows: u64,
    row_of: impl Fn(usize) -> u64,
) -> Option<usize> {
    crate::directory::misrouted(
        &bucket_salts(shard_id),
        scripts,
        rows,
        |script| table.choice(shard_id, script),
        row_of,
    )
}

/// A placed directory: one encoded table per segment, the number of scripts
/// placed, and the choice table for the placement.
type PlacedDirectory = (
    Vec<Vec<u8>>,
    u64,
    Option<crate::transparent::choice::ChoiceTable>,
);

/// Checks the encoded bytes, not the placer's intent.
///
/// Rows carry tags, so a server cannot recompute a script's route; this is
/// the last point where the scripts are known. See
/// [`crate::directory::verify_assignment`] for the checks. A miss here would
/// reach a wallet as absence, which it cannot tell from an empty history.
fn verify_encoded_rows(
    tables: &[Vec<u8>],
    entries: &[DirectoryEntry],
    assignment: &[u32],
    geometry: &Geometry,
    children: u32,
) -> Result<(), BuildError> {
    let tags: Vec<_> = entries.iter().map(|entry| entry.tag).collect();
    crate::directory::verify_assignment(
        tables
            .iter()
            .flat_map(|table| table.chunks_exact(geometry.directory_row_bytes)),
        |raw| {
            crate::transparent::records::decode_directory_row(raw, children)
                .map(|row| row.into_iter().map(|entry| entry.tag).collect())
        },
        &tags,
        assignment,
    )
    .map_err(|error| match error {
        AssignmentError::Decode(error) => BuildError::Record(error),
        AssignmentError::Lengths { tags, assignment } => {
            BuildError::Invalid(format!("{tags} entries were placed with {assignment} rows"))
        }
        AssignmentError::Duplicate => {
            BuildError::Invalid("a script tag appears twice in the directory".into())
        }
        AssignmentError::Count { held, placed } => BuildError::Invalid(format!(
            "the directory holds {held} entries, {placed} were placed"
        )),
        AssignmentError::Misplaced { index, row } => BuildError::Invalid(format!(
            "script {} is not in its assigned row {row}",
            hex::encode(&entries[index].script)
        )),
    })
}

/// Returns the encoded directory and its choice table.
fn place_directory(
    shard_id: u64,
    entries: Vec<DirectoryEntry>,
    geometry: &Geometry,
    children: u32,
) -> Result<PlacedDirectory, BuildError> {
    let scripts_only: Vec<&[u8]> = entries
        .iter()
        .map(|entry| entry.script.as_slice())
        .collect();
    let (placed, assignment) = place_scripts(
        shard_id,
        &scripts_only,
        &entries
            .iter()
            .map(DirectoryEntry::encoded_len)
            .collect::<Vec<_>>(),
        geometry.directory_rows,
        geometry.directory_row_bytes - crate::transparent::records::DIRECTORY_ROW_HEADER_BYTES,
    )
    .map_err(|script| BuildError::DirectoryFull { script })?;
    let segments = placed.segments;
    let rows = geometry.directory_rows * segments as u64;
    // The placer's own assignment, not a second rule applied to the same
    // input. Relocation means a script's row is a function of every script
    // placed before it, so a greedy replay here would put entries in rows the
    // segment count was not decided for — and only some of them, which is the
    // kind of disagreement that produces a table a wallet cannot read.
    let mut buckets: Vec<Vec<&DirectoryEntry>> = vec![Vec::new(); rows as usize];
    for (entry, row) in entries.iter().zip(&assignment) {
        buckets[*row as usize].push(entry);
    }

    let mut scripts = 0u64;
    let mut tables = Vec::with_capacity(segments as usize);
    for segment in buckets.chunks_mut(geometry.directory_rows as usize) {
        let mut table =
            Vec::with_capacity(geometry.directory_rows as usize * geometry.directory_row_bytes);
        for bucket in segment.iter_mut() {
            // Within a row, entries are ordered by script, so the row's
            // bytes do not depend on placement order.
            bucket.sort_by(|a, b| a.script.cmp(&b.script));
            scripts += bucket.len() as u64;
            let owned: Vec<DirectoryEntry> = bucket.iter().map(|e| (*e).clone()).collect();
            table.extend_from_slice(&encode_directory_row(&owned)?);
        }
        tables.push(table);
    }
    verify_encoded_rows(&tables, &entries, &assignment, geometry, children)?;
    let choice = choice_table(shard_id, &scripts_only, &assignment, rows).ok();
    if let Some(table) = &choice {
        // A wrong bit is not an error a wallet can see: it queries the other
        // row, finds no entry, and reads the script as absent. So every placed
        // script is checked before the table can be published.
        if let Some(index) = verify_choice(shard_id, table, &scripts_only, rows, |i| {
            u64::from(assignment[i])
        }) {
            return Err(BuildError::Invalid(format!(
                "choice table sends script {} to the wrong row",
                hex::encode(scripts_only[index])
            )));
        }
    }
    Ok((tables, scripts, choice))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transparent::events::{ReceiveEvent, SpendEvent, Txid};
    use crate::transparent::filter::{FilterLimits, RANGE_PROFILE, validate_filter};
    use crate::transparent::layout::{DECOUPLED_2K_8K, DIRECTORY_ROWS};
    use crate::transparent::page_row::decode_page_row;
    use crate::transparent::records::decode_directory_row;
    use crate::transparent::seal::Limit;

    fn genesis() -> BlockHash {
        BlockHash::from_display_hex(crate::transparent::filter::MAINNET_GENESIS_DISPLAY).unwrap()
    }

    /// The hash of the block at `height` on fork `fork`.
    fn hash_at(fork: u8, height: u64) -> BlockHash {
        let mut bytes = [fork; 32];
        bytes[..8].copy_from_slice(&height.to_le_bytes());
        BlockHash::from_internal_bytes(bytes)
    }

    fn script(tag: u32) -> ScriptBytes {
        let mut bytes = vec![0x76, 0xa9, 0x14];
        bytes.extend_from_slice(&tag.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 16]);
        bytes.extend_from_slice(&[0x88, 0xac]);
        ScriptBytes::new(bytes)
    }

    fn event(height: u32, nonce: u32) -> TransparentEvent {
        let mut txid = [0u8; 32];
        txid[..4].copy_from_slice(&nonce.to_le_bytes());
        txid[4..8].copy_from_slice(&height.to_le_bytes());
        TransparentEvent::Receive(ReceiveEvent {
            metadata: None,
            height,
            txid: Txid(txid),
            transaction_index: 0,
            output_index: nonce,
            value: 1_000,
            coinbase: false,
        })
    }

    fn spend(height: u32, nonce: u32) -> TransparentEvent {
        let TransparentEvent::Receive(receive) = event(height, nonce) else {
            unreachable!()
        };
        TransparentEvent::Spend(SpendEvent {
            metadata: None,
            height,
            spending_txid: receive.txid,
            transaction_index: 1,
            input_index: nonce,
            spent_txid: Txid([7; 32]),
            spent_output_index: nonce,
        })
    }

    /// A seeded generator, so a failing case reproduces exactly without a
    /// property-testing dependency the workspace does not have.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self, bound: u64) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            (z ^ (z >> 31)) % bound
        }
    }

    /// `count` blocks from `first`: a few busy scripts, many quiet ones, and
    /// now and then a burst of new scripts, so page shards and directory
    /// shards both close under a small policy.
    fn chain(seed: u64, first: u64, count: u64) -> Vec<Block> {
        let mut rng = Rng(seed);
        let mut nonce = 0u32;
        (first..first + count)
            .map(|height| {
                let mut events = Vec::new();
                for _ in 0..rng.next(6) {
                    let tag = match rng.next(10) {
                        0..=4 => rng.next(4) as u32,
                        5..=8 => 100 + rng.next(60) as u32,
                        _ => 10_000 + rng.next(1_000_000) as u32,
                    };
                    nonce += 1;
                    let at = height as u32;
                    events.push((
                        script(tag),
                        if rng.next(3) == 0 {
                            spend(at, nonce)
                        } else {
                            event(at, nonce)
                        },
                    ));
                }
                (height, events)
            })
            .collect()
    }

    /// A policy small enough that a few hundred blocks close many page shards
    /// and several directory shards, by page rows, by child limit and by
    /// directory bytes.
    fn small_policy(max_children: u32) -> DecoupledPolicy {
        DecoupledPolicy {
            scripts: Limit::new(120, 400).unwrap(),
            directory_bytes: Limit::new(12_000, 40_000).unwrap(),
            page_rows: Limit::new(1, 2).unwrap(),
            max_children,
            ..DecoupledPolicy::for_geometry(&DECOUPLED_2K_8K)
        }
    }

    fn stream(policy: DecoupledPolicy, first: u64) -> ShardStream {
        ShardStream::with_policy(&DECOUPLED_2K_8K, policy, first, 0, genesis(), RANGE_PROFILE)
            .unwrap()
    }

    /// Everything a run over `blocks` builds, ending with the tail.
    struct Run {
        children: Vec<BuiltChild>,
        directories: Vec<(BuiltDirectory, SealedDirectory)>,
    }

    fn run(policy: DecoupledPolicy, blocks: &[Block], fork: impl Fn(u64) -> u8) -> Run {
        let mut stream = stream(policy, blocks[0].0);
        let terminal = |height: u64| Some(hash_at(fork(height), height));
        let mut out = Vec::new();
        for block in blocks {
            out.extend(stream.push_block(block.clone(), &terminal).unwrap());
        }
        out.extend(stream.finish(&terminal).unwrap());
        let mut run = Run {
            children: Vec::new(),
            directories: Vec::new(),
        };
        for built in out {
            match built {
                Built::Child(child) => run.children.push(child),
                Built::Directory { built, sealed } => run.directories.push((built, sealed)),
            }
        }
        run
    }

    /// The history a wallet recovers for `script` from one directory shard,
    /// walking from the directory entry back along each run's link, with the
    /// walk's checks. `None` when the script has no entry.
    fn walk(
        directory: &BuiltDirectory,
        children: &[&BuiltChild],
        script: &[u8],
    ) -> Option<Vec<TransparentEvent>> {
        let geometry = directory.geometry;
        let salt = crate::transparent::tag_salt(
            directory.shard_id,
            &hash_at(0, directory.end_height),
            directory.tag_salt_counter,
        );
        let wanted = script_tag(&salt, script);
        let rows = geometry.directory_rows * u64::from(directory.directory_segments());
        let mut found = None;
        for row in candidate_rows(directory.shard_id, script, rows) {
            for entry in
                decode_directory_row(directory.directory_row(row), directory.children).unwrap()
            {
                if entry.tag == wanted {
                    found = Some(entry);
                }
            }
        }
        let entry = found?;
        let mut newer: Vec<TransparentEvent> = entry.inline.clone();
        let mut next = entry.head();
        let mut expected_older: Option<u8> = None;
        let mut last_child = u8::MAX;
        while let Some((child, row)) = next {
            assert!(child < last_child, "page shard numbers strictly decrease");
            last_child = child;
            let page = children[child as usize];
            let page_salt = crate::transparent::tag::page_tag_salt(
                directory.shard_id,
                page.index,
                page.end_height,
                &page.terminal_block_hash,
                page.tag_salt_counter,
            );
            let tag = script_tag(&page_salt, script);
            let mut run = Vec::new();
            let mut count = None;
            let mut link = RunLink::default();
            let mut ordinal = 0;
            loop {
                let raw = page.page_row(geometry, u64::from(row) + u64::from(ordinal));
                let fragment = decode_page_row(raw)
                    .unwrap()
                    .into_iter()
                    .find(|e| e.tag == tag && e.ordinal == ordinal)
                    .expect("the run's fragment is where the chain says");
                if ordinal == 0 {
                    count = Some(fragment.fragment_count);
                    link = fragment.link;
                }
                run.extend(fragment.events);
                ordinal += 1;
                if ordinal == count.unwrap() {
                    break;
                }
            }
            if let Some(older) = expected_older {
                assert_eq!(link.older_runs, older, "older_runs drops by one per hop");
            }
            assert_eq!(link.older_runs == 0, link.prev_row == 0);
            expected_older = link.older_runs.checked_sub(1);
            // Push-out placement: each paged event's successor-but-one lies in
            // this run's page shard.
            let mut following = run.clone();
            following.extend(newer.iter().copied());
            for (i, _) in run.iter().enumerate() {
                let height = u64::from(following[i + 2].height());
                assert!(
                    (page.start_height..=page.end_height).contains(&height),
                    "an event was pushed into a page shard that was not open"
                );
            }
            run.extend(newer);
            newer = run;
            next = link.previous();
        }
        assert!(expected_older.is_none(), "the chain is not cut short");
        Some(newer)
    }

    fn histories(blocks: &[Block]) -> BTreeMap<Vec<u8>, Vec<TransparentEvent>> {
        let mut all: BTreeMap<Vec<u8>, Vec<TransparentEvent>> = BTreeMap::new();
        for (_, events) in blocks {
            for (script, event) in events {
                all.entry(script.as_slice().to_vec())
                    .or_default()
                    .push(*event);
            }
        }
        for events in all.values_mut() {
            events.sort_by_key(TransparentEvent::sort_key);
        }
        all
    }

    /// The design's worked example: e1@1010, e2@1020, e3@1100, e4@1400,
    /// e5@1700, e6@1710 with page shards 1000-1299, 1300-1649, 1650-1999 gives
    /// runs P0 [e1], P1 [e2], P2 [e3, e4] and e5, e6 inline.
    #[test]
    fn pushed_out_events_go_to_the_page_shard_open_when_they_are_pushed() {
        let watched = script(1);
        let heights = [1010u64, 1020, 1100, 1400, 1700, 1710];
        let mut blocks: Vec<Block> = (1000..2000).map(|h| (h, Vec::new())).collect();
        for (i, h) in heights.iter().enumerate() {
            blocks[(*h - 1000) as usize]
                .1
                .push((watched.clone(), event(*h as u32, i as u32)));
        }
        // Fillers whose pushed-out events fill two rows and close a page
        // shard at 1299 and at 1649.
        for (h, base) in [(1299u64, 1_000u32), (1649, 2_000)] {
            for k in 0..200u32 {
                for n in 0..3 {
                    blocks[(h - 1000) as usize]
                        .1
                        .push((script(base + k), event(h as u32, k * 10 + n)));
                }
            }
        }
        let policy = DecoupledPolicy {
            page_rows: Limit::new(4, 1_000).unwrap(),
            ..small_policy(32)
        };
        let policy = DecoupledPolicy {
            scripts: Limit::new(10_000, 20_000).unwrap(),
            directory_bytes: Limit::new(1_000_000, 2_000_000).unwrap(),
            ..policy
        };
        let built = run(policy, &blocks, |_| 0);
        assert_eq!(built.directories.len(), 1);
        let (directory, _) = &built.directories[0];
        assert_eq!(
            built
                .children
                .iter()
                .map(|c| (c.start_height, c.end_height))
                .collect::<Vec<_>>(),
            vec![(1000, 1299), (1300, 1649), (1650, 1999)]
        );
        let children: Vec<&BuiltChild> = built.children.iter().collect();
        let history = walk(directory, &children, watched.as_slice()).unwrap();
        assert_eq!(history.len(), 6);
        assert_eq!(
            history
                .iter()
                .map(|e| u64::from(e.height()))
                .collect::<Vec<_>>(),
            heights
        );
    }

    /// Every script's history comes back exactly by walking its chain, across
    /// many page shards and directory shards, with every check on the way.
    #[test]
    fn walking_each_chain_recovers_every_history_exactly() {
        for seed in 0..6u64 {
            let blocks = chain(seed, 500, 400);
            let max_children = [2u32, 3, 32][seed as usize % 3];
            let built = run(small_policy(max_children), &blocks, |_| 0);
            assert!(built.directories.len() > 1, "seed {seed}");
            assert!(
                built.children.len() > built.directories.len(),
                "seed {seed}"
            );
            let mut recovered: BTreeMap<Vec<u8>, Vec<TransparentEvent>> = BTreeMap::new();
            let mut child_at = 0;
            for (directory, sealed) in &built.directories {
                let children: Vec<&BuiltChild> = built.children
                    [child_at..child_at + directory.children as usize]
                    .iter()
                    .collect();
                child_at += directory.children as usize;
                assert_eq!(children.len(), sealed.children.len());
                assert!(children.len() as u32 <= max_children);
                let span = &blocks[(directory.start_height - 500) as usize
                    ..=(directory.end_height - 500) as usize];
                for (script, events) in histories(span) {
                    let walked = walk(directory, &children, &script).expect("an entry");
                    assert_eq!(walked, events, "seed {seed}");
                    recovered.entry(script).or_default().extend(walked);
                }
            }
            assert_eq!(child_at, built.children.len());
            assert_eq!(recovered, histories(&blocks), "seed {seed}");
        }
    }

    /// Publishing block by block equals a fresh build: every page shard and
    /// directory shard a prefix seals is byte-identical to the one the whole
    /// chain seals, and the prefix's tail is what a fresh build of the prefix
    /// produces.
    #[test]
    fn sealed_shards_are_byte_stable_under_tail_growth() {
        for seed in 0..3u64 {
            let blocks = chain(100 + seed, 0, 160);
            let policy = small_policy(3);
            let full = run(policy, &blocks, |_| 0);
            for end in (1..blocks.len()).step_by(7) {
                let prefix = run(policy, &blocks[..end], |_| 0);
                for child in prefix.children.iter().filter(|c| c.sealed) {
                    assert!(
                        full.children.contains(child),
                        "seed {seed} prefix {end}: page shard {} of {} changed",
                        child.index,
                        child.shard_id
                    );
                }
                for (directory, sealed) in prefix.directories.iter().filter(|(d, _)| d.sealed) {
                    let (same, same_sealed) = full
                        .directories
                        .iter()
                        .find(|(d, _)| d.shard_id == directory.shard_id)
                        .expect("the same shard");
                    assert_eq!(same.directory, directory.directory, "seed {seed}");
                    assert_eq!(same.filter, directory.filter);
                    assert_eq!(same_sealed, sealed);
                }
                // Only the tail may be open, and only its last page shard. A
                // prefix whose last block sealed a directory shard has no
                // tail; one whose last block sealed a page shard has a tail
                // whose page shards are all sealed.
                let (tail, _) = prefix.directories.last().unwrap();
                assert!(
                    prefix.directories[..prefix.directories.len() - 1]
                        .iter()
                        .all(|(d, _)| d.sealed)
                );
                let open: Vec<_> = prefix.children.iter().filter(|c| !c.sealed).collect();
                assert!(open.len() <= usize::from(!tail.sealed));
                if let Some(open) = open.first() {
                    assert_eq!(*open, prefix.children.last().unwrap());
                }
            }
        }
    }

    /// A reorg at height h rebuilds only what holds a block at or above h:
    /// every page shard and directory shard ending below h is reproduced
    /// exactly, including reorgs exactly at a page-shard boundary and at a
    /// directory-shard boundary.
    #[test]
    fn a_reorg_reproduces_everything_sealed_below_it() {
        let blocks = chain(7, 0, 200);
        let policy = small_policy(3);
        let original = run(policy, &blocks, |_| 0);
        let child_boundaries: Vec<u64> = original
            .children
            .iter()
            .filter(|c| c.sealed && c.end_height + 1 < 200)
            .map(|c| c.end_height + 1)
            .collect();
        let directory_boundaries: Vec<u64> = original
            .directories
            .iter()
            .filter(|(d, _)| d.sealed)
            .map(|(d, _)| d.end_height + 1)
            .collect();
        assert!(!child_boundaries.is_empty() && !directory_boundaries.is_empty());
        let inside = original.children[1].start_height + 1;
        for reorg in child_boundaries
            .iter()
            .chain(&directory_boundaries)
            .copied()
            .chain([inside])
        {
            // The fork replaces every block from `reorg` with different events.
            let mut forked = blocks[..reorg as usize].to_vec();
            forked.extend(chain(99, reorg, 200 - reorg));
            let replayed = run(policy, &forked, |h| u8::from(h >= reorg));
            for child in original.children.iter().filter(|c| c.end_height < reorg) {
                assert!(
                    replayed.children.contains(child),
                    "reorg at {reorg}: page shard {} of {} changed",
                    child.index,
                    child.shard_id
                );
            }
            for (directory, _) in original
                .directories
                .iter()
                .filter(|(d, _)| d.end_height < reorg)
            {
                let same = replayed
                    .directories
                    .iter()
                    .find(|(d, _)| d.shard_id == directory.shard_id)
                    .map(|(d, _)| d)
                    .expect("the same shard");
                assert_eq!(same.directory, directory.directory, "reorg at {reorg}");
                assert_eq!(same.end_height, directory.end_height);
            }
            // Something above the reorg did change.
            assert!(
                replayed
                    .children
                    .iter()
                    .any(|c| c.end_height >= reorg && !original.children.contains(c))
            );
        }
    }

    /// The order a block's events arrive in changes nothing.
    #[test]
    fn building_is_deterministic_regardless_of_input_order() {
        let blocks = chain(3, 0, 120);
        let shuffled: Vec<Block> = blocks
            .iter()
            .map(|(h, events)| (*h, events.iter().rev().cloned().collect()))
            .collect();
        let a = run(small_policy(4), &blocks, |_| 0);
        let b = run(small_policy(4), &shuffled, |_| 0);
        assert_eq!(a.children, b.children);
        for ((x, _), (y, _)) in a.directories.iter().zip(&b.directories) {
            assert_eq!(x.directory, y.directory);
            assert_eq!(x.filter, y.filter);
        }
    }

    /// Tables are the pinned size whatever they hold, a page shard nothing
    /// was pushed into has no segment, and the filter matches every script.
    #[test]
    fn tables_are_the_pinned_size_and_empty_page_shards_have_none() {
        let mut blocks: Vec<Block> = (0..5).map(|h| (h, Vec::new())).collect();
        blocks[1].1.push((script(1), event(1, 1)));
        blocks[2].1.push((script(1), event(2, 2)));
        let quiet = run(small_policy(4), &blocks, |_| 0);
        assert_eq!(quiet.children.len(), 1);
        assert!(quiet.children[0].pages.is_empty(), "nothing was pushed out");
        assert_eq!(quiet.children[0].segments, 0);
        assert_eq!(quiet.children[0].page_rows, 0);
        let (directory, _) = &quiet.directories[0];
        assert_eq!(directory.directory_segments(), 1);
        assert_eq!(
            directory.directory[0].len(),
            DECOUPLED_2K_8K.directory_rows as usize
                * crate::transparent::layout::DIRECTORY_ROW_BYTES
        );
        let busy = run(small_policy(4), &chain(5, 0, 80), |_| 0);
        for child in busy.children.iter().filter(|c| c.page_rows > 0) {
            assert_eq!(child.segments, 1);
            assert_eq!(
                child.pages.len(),
                child.page_rows as usize * crate::transparent::layout::PAGE_ROW_BYTES
            );
            let segment = child.segment(&DECOUPLED_2K_8K, 0);
            assert_eq!(
                segment.len(),
                DECOUPLED_2K_8K.page_rows as usize * crate::transparent::layout::PAGE_ROW_BYTES
            );
            let digest: [u8; 32] = Sha256::digest(&segment).into();
            assert_eq!(child.segment_digests(&DECOUPLED_2K_8K), vec![digest]);
        }
        let (directory, _) = &busy.directories[0];
        let key = ShardKey::derive(
            RANGE_PROFILE,
            genesis(),
            directory.shard_id,
            directory.start_height,
            directory.end_height,
            hash_at(0, directory.end_height),
        );
        let validated =
            validate_filter(directory.filter.as_slice(), FilterLimits::default()).unwrap();
        let span = chain(5, 0, 80);
        let scripts: Vec<ScriptBytes> =
            histories(&span[directory.start_height as usize..=directory.end_height as usize])
                .into_keys()
                .map(ScriptBytes::new)
                .collect();
        let matched =
            crate::transparent::filter::match_range_scripts(&validated, key, &scripts).unwrap();
        assert_eq!(matched.len(), scripts.len());
    }

    /// A script too long for a directory entry is filtered but never indexed,
    /// so it has no entry and no runs, and is counted as excluded.
    #[test]
    fn an_unindexable_script_is_filtered_but_counted_as_excluded() {
        let long = ScriptBytes::new(vec![0x6a; MAX_SCRIPT_BYTES + 1]);
        let blocks: Vec<Block> = (0..4)
            .map(|h| (h, vec![(long.clone(), event(h as u32, h as u32))]))
            .collect();
        let built = run(small_policy(4), &blocks, |_| 0);
        let (directory, _) = &built.directories[0];
        assert_eq!(directory.excluded_scripts, 1);
        assert_eq!(directory.scripts, 0);
        assert!(built.children.iter().all(|c| c.runs == 0));
    }

    /// The builder's last check reads the encoded rows: an entry outside its
    /// assigned row, a tag held twice, or a missing entry is refused before
    /// publication, because a wallet would read any of them as absence.
    #[test]
    fn encoded_rows_must_hold_every_entry_where_it_was_assigned() {
        let entry = |byte: u8| DirectoryEntry {
            script: vec![0x76, byte],
            tag: [byte; crate::transparent::tag::SCRIPT_TAG_BYTES],
            event_count: 1,
            inline: vec![event(100, u32::from(byte))],
            head_child: 0,
            head_row: 0,
        };
        let geometry = DECOUPLED_2K_8K;
        let (a, b) = (entry(1), entry(2));
        let table = |rows: &[&[DirectoryEntry]]| -> Vec<Vec<u8>> {
            vec![
                rows.iter()
                    .flat_map(|row| encode_directory_row(row).unwrap())
                    .collect(),
            ]
        };
        let entries = [a.clone(), b.clone()];
        let (one_a, one_b) = (std::slice::from_ref(&a), std::slice::from_ref(&b));
        let good = table(&[one_a, one_b]);
        verify_encoded_rows(&good, &entries, &[0, 1], &geometry, 1).unwrap();
        assert!(verify_encoded_rows(&good, &entries, &[1, 0], &geometry, 1).is_err());
        let repeated = table(&[one_a, one_a]);
        assert!(verify_encoded_rows(&repeated, &entries, &[0, 1], &geometry, 1).is_err());
        let missing = table(&[one_a, &[]]);
        assert!(verify_encoded_rows(&missing, &entries, &[0, 1], &geometry, 1).is_err());
    }

    /// A block must follow the last, and its events must be at its height.
    #[test]
    fn a_block_out_of_order_or_out_of_range_is_refused() {
        let mut builder =
            DirectoryBuilder::new(0, &DECOUPLED_2K_8K, genesis(), RANGE_PROFILE).unwrap();
        builder
            .push_block((10, vec![(script(0), event(10, 0))]))
            .unwrap();
        assert!(builder.push_block((12, Vec::new())).is_err());
        assert!(
            builder
                .push_block((11, vec![(script(0), event(500, 0))]))
                .is_err()
        );
    }

    /// Scripts for a placement test, distinct and of the supported width.
    fn placement_set(count: u32) -> Vec<Vec<u8>> {
        (0..count)
            .map(|tag| script(tag).as_slice().to_vec())
            .collect()
    }

    fn place(count: u32, rows: u64, slots: u64) -> Placement {
        let owned = placement_set(count);
        let refs: Vec<&[u8]> = owned.iter().map(|s| s.as_slice()).collect();
        place_scripts(0, &refs, &vec![1; refs.len()], rows, slots as usize)
            .expect("placement terminates")
            .0
    }

    /// Relocation is what decides how full the directory may run.
    ///
    /// Without it a script never moves once placed, so the first row to reach
    /// its slot count ends the placement and costs the shard a whole segment —
    /// which every wallet touching that shard then pays for, twice, in queries
    /// and in setup. The measured ceiling for that rule was around 58% of slot
    /// capacity. Following an augmenting path instead keeps one segment far
    /// past it, at no cost to the client, which still reads the same two
    /// candidate rows.
    #[test]
    fn relocation_keeps_one_segment_past_the_greedy_ceiling() {
        let rows = 2_048u64;
        let slots = crate::transparent::records::DIRECTORY_SLOTS as u64;
        let capacity = rows * slots;

        // 86% of capacity, the load at which the shipped seal target overflowed
        // 42% of shards on the real journal under the greedy rule.
        let placed = place((capacity * 6 / 7) as u32, rows, slots);
        assert_eq!(
            placed.segments, 1,
            "relocation should hold 86% of capacity in one segment"
        );
        assert!(placed.max_row_load <= slots);
    }

    /// Placement must not depend on anything but the script set, because two
    /// operators disagreeing here publish different bytes under the same
    /// identity. Relocation makes this sharper than it was: a script's row now
    /// depends on every script placed before it, so a search that explored in a
    /// different order would silently produce a different table.
    #[test]
    fn placement_is_reproducible() {
        let rows = 2_048u64;
        let slots = crate::transparent::records::DIRECTORY_SLOTS as u64;
        let owned = placement_set((rows * slots * 6 / 7) as u32);
        let refs: Vec<&[u8]> = owned.iter().map(|s| s.as_slice()).collect();

        let first =
            place_scripts(0, &refs, &vec![1; refs.len()], rows, slots as usize).expect("placement");
        let again =
            place_scripts(0, &refs, &vec![1; refs.len()], rows, slots as usize).expect("placement");
        assert_eq!(first.0, again.0);
        assert_eq!(first.1, again.1, "the same input must place identically");
    }

    /// Every script must still be in one of its own two candidate rows. This is
    /// the only thing a wallet relies on, and the one property relocation could
    /// plausibly break: an entry that moved has to land on *its* alternate, not
    /// on a row that happened to have space.
    #[test]
    fn a_relocated_script_is_still_in_one_of_its_candidates() {
        let rows = 2_048u64;
        let slots = crate::transparent::records::DIRECTORY_SLOTS as u64;
        let owned = placement_set((rows * slots * 6 / 7) as u32);
        let refs: Vec<&[u8]> = owned.iter().map(|s| s.as_slice()).collect();

        let (placed, assignment) =
            place_scripts(0, &refs, &vec![1; refs.len()], rows, slots as usize).expect("placement");
        let span = rows * placed.segments as u64;
        let mut occupied = vec![0u64; span as usize];
        for (script, row) in refs.iter().zip(&assignment) {
            let candidates = candidate_rows(0, script, span);
            assert!(
                candidates.contains(&u64::from(*row)),
                "a script was placed outside both of its candidates"
            );
            occupied[*row as usize] += 1;
        }
        assert!(
            occupied.iter().all(|load| *load <= slots),
            "a row was filled past its slot count"
        );
        assert_eq!(assignment.len(), refs.len(), "every script is placed once");
    }

    /// One row, chosen by the published choice bit, holds every placed script:
    /// the single-lookup property, at the default geometry and at the
    /// half-height directory, where placement runs near 80% of capacity.
    #[test]
    fn the_choice_bit_names_the_one_row_holding_each_script() {
        let rows = 4_096u64;
        let slots = crate::transparent::records::DIRECTORY_SLOTS as u64;
        for (count, rows) in [(6_000u32, 8_192u64), (45_454, rows)] {
            let owned = placement_set(count);
            let refs: Vec<&[u8]> = owned.iter().map(|s| s.as_slice()).collect();
            let (placement, assignment) =
                place_scripts(11, &refs, &vec![1; refs.len()], rows, slots as usize).expect("fits");
            // The largest recent shard of the September census fits one
            // half-height segment under two-choice placement with relocation.
            assert_eq!(placement.segments, 1, "{count} scripts at {rows} rows");
            let space = rows * placement.segments as u64;
            let table = choice_table(11, &refs, &assignment, space).expect("peels");
            for (script, row) in refs.iter().zip(&assignment) {
                let chosen = candidate_rows(11, script, space)[table.choice(11, script)];
                assert_eq!(chosen, u64::from(*row), "{count} scripts at {rows} rows");
            }
        }
    }

    /// Routing holds across segments: a script set too large for one segment
    /// is placed over the whole logical row space, and the table names rows in
    /// that space.
    #[test]
    fn the_choice_bit_routes_across_segments() {
        let rows = 2_048u64;
        let slots = crate::transparent::records::DIRECTORY_SLOTS as u64;
        let owned = placement_set((rows * slots) as u32 + 1_000);
        let refs: Vec<&[u8]> = owned.iter().map(|s| s.as_slice()).collect();
        let (placement, assignment) =
            place_scripts(5, &refs, &vec![1; refs.len()], rows, slots as usize).expect("fits");
        assert!(placement.segments > 1);
        let space = rows * u64::from(placement.segments);
        let table = choice_table(5, &refs, &assignment, space).expect("peels");
        assert_eq!(
            verify_choice(5, &table, &refs, space, |i| u64::from(assignment[i])),
            None
        );
        // And a check against a different placement does catch misrouting.
        assert!(verify_choice(5, &table, &refs, space, |i| u64::from(assignment[i]) ^ 1).is_some());
    }

    /// A shard's bucket salt includes its id, so the same script sits in
    /// unrelated rows in different shards. An observer who learned one row
    /// would otherwise learn the script's row everywhere.
    #[test]
    fn the_same_script_lands_in_unrelated_rows_in_different_shards() {
        let wanted = script(1);
        let a = candidate_rows(0, wanted.as_slice(), DIRECTORY_ROWS as u64);
        let b = candidate_rows(1, wanted.as_slice(), DIRECTORY_ROWS as u64);
        assert_ne!(a, b);
    }

    #[test]
    fn mixed_size_directory_placement_preserves_every_byte_budget() {
        let rows = 256u64;
        let mut entries = Vec::new();
        let mut bytes = 0;
        for i in 0..100_000u32 {
            let size = [70, 98, 113, 121, 149, 177][i as usize % 6];
            if bytes + size > rows as usize * 4092 * 6 / 7 {
                break;
            }
            entries.push((script(i).as_slice().to_vec(), size));
            bytes += size;
        }
        let ordered = placement_order(entries.iter().map(|(s, n)| (s.as_slice(), *n)));
        let scripts: Vec<_> = ordered.iter().map(|(s, _)| *s).collect();
        let sizes: Vec<_> = ordered.iter().map(|(_, n)| *n).collect();
        let (placed, assignment) = place_scripts(42, &scripts, &sizes, rows, 4092).unwrap();
        assert_eq!(placed.segments, 1);
        let mut used = vec![0usize; rows as usize];
        for ((script, size), row) in ordered.iter().zip(&assignment) {
            assert!(candidate_rows(42, script, rows).contains(&u64::from(*row)));
            used[*row as usize] += size;
        }
        assert!(used.iter().all(|bytes| *bytes <= 4092));
        assert_eq!(used.iter().sum::<usize>(), bytes);
        assert_eq!(
            used.iter().max().copied().unwrap() as u64,
            placed.max_row_bytes
        );
    }

    /// SHA-256 over length-prefixed fields.
    #[derive(Default)]
    struct Pin(Sha256);

    impl Pin {
        fn put(&mut self, bytes: impl AsRef<[u8]>) {
            let bytes = bytes.as_ref();
            self.0.update((bytes.len() as u64).to_le_bytes());
            self.0.update(bytes);
        }

        fn hex(self) -> String {
            hex::encode(self.0.finalize())
        }
    }

    /// Everything placement and its choice table publish for `scripts`.
    fn pin_placement(
        pin: &mut Pin,
        shard_id: u64,
        (scripts, sizes): (&[&[u8]], &[usize]),
        rows: u64,
        capacity: usize,
    ) {
        let (placed, assignment) =
            place_scripts(shard_id, scripts, sizes, rows, capacity).expect("places");
        pin.put(format!("{placed:?}"));
        pin.put(
            assignment
                .iter()
                .flat_map(|row| row.to_le_bytes())
                .collect::<Vec<_>>(),
        );
        let space = rows * u64::from(placed.segments);
        let table = choice_table(shard_id, scripts, &assignment, space).expect("peels");
        pin.put(table.encode());
    }

    /// Transparent's published bytes, pinned at the commit before the
    /// directory primitives were shared, so moving them cannot change a byte.
    ///
    /// The stream inputs are the walking test's chains, which seal many page
    /// shards and directory shards. The placement inputs are the relocation,
    /// cross-segment and mixed-size placement tests'.
    #[test]
    fn published_bytes_match_the_pinned_digests() {
        let mut stream = Pin::default();
        for seed in 0..6u64 {
            let built = run(
                small_policy([2u32, 3, 32][seed as usize % 3]),
                &chain(seed, 500, 400),
                |_| 0,
            );
            for child in &built.children {
                // Every field of the manifest's page child: its segment
                // digests are a function of `pages` and `segments`.
                stream.put(&child.pages);
                stream.put(format!(
                    "{:?}",
                    BuiltChild {
                        pages: Vec::new(),
                        ..child.clone()
                    }
                ));
            }
            for (directory, sealed) in &built.directories {
                stream.put(format!(
                    "{} {} {} {} {} {} {} {} {} {}",
                    directory.shard_id,
                    directory.start_height,
                    directory.end_height,
                    directory.children,
                    directory.scripts,
                    directory.events,
                    directory.txids,
                    directory.excluded_scripts,
                    directory.tag_salt_counter,
                    directory.sealed
                ));
                stream.put(directory.filter.as_slice());
                for segment in &directory.directory {
                    stream.put(segment);
                }
                stream.put(
                    directory
                        .choice
                        .as_ref()
                        .map(crate::transparent::manifest::encode_directory_choice)
                        .unwrap_or_default(),
                );
                stream.put(format!("{sealed:?}"));
            }
        }

        let mut placement = Pin::default();
        let slots = crate::transparent::records::DIRECTORY_SLOTS as u64;
        for (shard_id, count) in [(0, 2_048 * slots * 6 / 7), (5, 2_048 * slots + 1_000)] {
            let owned = placement_set(count as u32);
            let refs: Vec<&[u8]> = owned.iter().map(|s| s.as_slice()).collect();
            let sizes = vec![1; refs.len()];
            pin_placement(
                &mut placement,
                shard_id,
                (&refs, &sizes),
                2_048,
                slots as usize,
            );
        }
        let mut mixed = Vec::new();
        let mut bytes = 0;
        for i in 0..100_000u32 {
            let size = [70, 98, 113, 121, 149, 177][i as usize % 6];
            if bytes + size > 256 * 4_092 * 6 / 7 {
                break;
            }
            mixed.push((script(i).as_slice().to_vec(), size));
            bytes += size;
        }
        let ordered = placement_order(mixed.iter().map(|(s, n)| (s.as_slice(), *n)));
        let scripts: Vec<_> = ordered.iter().map(|(s, _)| *s).collect();
        let sizes: Vec<_> = ordered.iter().map(|(_, n)| *n).collect();
        pin_placement(&mut placement, 42, (&scripts, &sizes), 256, 4_092);

        assert_eq!(
            [stream.hex(), placement.hex()],
            [
                "5c7c702bf604425131ed7567ec81693f8dc336a6c09084953873024cad611e3b",
                "b09f919075d25ece5ea5c15627126ead664afc3cee35647351e690cfee618d42",
            ]
        );
    }

    /// A small placement that fits one segment only through relocation:
    /// greedy two-choice placement of the same scripts overflows. Its final
    /// assignment is pinned at the commit before placement was shared.
    #[test]
    fn a_relocated_placement_matches_the_pinned_assignment() {
        let (shard_id, rows, slots) = (9, 8u64, 3usize);
        let owned = placement_set(16);
        let refs: Vec<&[u8]> = owned.iter().map(|s| s.as_slice()).collect();
        let mut used = vec![0usize; rows as usize];
        let greedy = refs.iter().all(|script| {
            let [a, b] = candidate_rows(shard_id, script, rows).map(|row| row as usize);
            let row = if used[a] <= used[b] { a } else { b };
            used[row] += 1;
            used[row] <= slots
        });
        assert!(!greedy, "greedy placement fits, so nothing relocates");
        let (placed, assignment) =
            place_scripts(shard_id, &refs, &vec![1; refs.len()], rows, slots).expect("places");
        assert_eq!(placed.segments, 1, "relocation keeps one segment");
        assert_eq!(assignment, [3, 6, 5, 2, 1, 6, 4, 3, 5, 7, 7, 5, 3, 2, 0, 2]);
    }
}
