//! Page cover: which page tables a pass reads inside a directory shard, and how
//! many times, stop following the wallet's history there.
//!
//! The reference client walks a script's chain of runs one page query at a
//! time. Without cover, the service sees exactly the page tables holding the
//! wallet's runs, each a block range, and one query per fragment. This
//! transport sits between the walk and the caller's transport and turns every
//! page query into a sweep: one query to each table of a cover set `C`, in a
//! fresh random order, the real query in its table's slot and a dummy, row 0
//! of the table, everywhere else. When the shard's page work ends it sends
//! cover sweeps until the shard's sweep count is a power of two.
//! `docs/pir-page-cover.md` states the rules and what stays visible.
//!
//! Nothing here reads a reply. `C`, the sweep orders and the padding depend on
//! the session's random source, the shard's manifest, the page work the store
//! already names, and the number of real page queries, never on what a reply
//! held. A link to a table outside `C` grows `C` by that table, which the
//! service sees.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::engine::client::{Table, TableClient};
use crate::engine::transport::{BoxError, BudgetStop, Overloaded, ShardTransport, StaleRevision};
use crate::engine::{GeometryParams, PendingPages, ServiceGeometry, WorkLimits};
use rand::rngs::{StdRng, SysRng};
use rand::seq::SliceRandom;
use rand::{RngExt, SeedableRng};
use sha2::{Digest, Sha256};
use transparent_shard::manifest::ShardManifest;

/// Shards with at most this many queryable page tables cover every one.
const SMALL_SHARD: u32 = 3;

/// The cover size drawn with probability [`BASE_ODDS`]; otherwise it is drawn
/// uniformly from one more than this to the shard's page table count.
const BASE_SIZE: u32 = 3;

/// The odds, in tenths, of drawing [`BASE_SIZE`].
const BASE_ODDS: u32 = 7;

/// Bytes a setup reply may carry beyond its masks' base64 encoding: the JSON
/// around them and their digest. A setup measured at 30,365 bytes carries
/// 30,040 bytes of base64.
const SETUP_ENVELOPE: u64 = 1024;

/// A reply's header per segment, before the scheme's response body.
const RESPONSE_HEADER: u64 = 16;

/// One open wallet's page cover state: its random source, each directory
/// shard's cover set, and the setups fetched for cover tables.
///
/// Kept in memory for the recovery handle's life. A walk retried by a later
/// pass of the same session, after a budget stop or a content failure, sweeps
/// the same `C`, so the service cannot intersect sets across syncs. Reopening
/// the wallet draws afresh.
pub(crate) struct CoverSession {
    rng: StdRng,
    /// `C` per directory shard and the sealed page tables it declares (see
    /// [`cover_key`]). A table the walk reaches outside `C` is added here, so
    /// later passes keep it.
    covers: HashMap<[u8; 32], BTreeSet<u32>>,
    /// Page setups fetched for a shard revision, by table and segment, until
    /// the walk asks for them: the walk keeps what it asked for in its store.
    setups: HashMap<(u64, String), Setups>,
    /// The parameter epoch each page setup fetched for a shard revision
    /// names, by table and segment, for as long as the session holds that
    /// revision's setups: what every page reply's header must carry.
    epochs: HashMap<(u64, String), HashMap<(u32, u32), [u8; 8]>>,
}

/// One shard revision's page setups, by table and segment: each setup's bytes
/// and the private bytes it cost.
type Setups = HashMap<(u32, u32), (Vec<u8>, u64)>;

impl CoverSession {
    /// A session drawing from a generator the operating system seeds.
    pub(crate) fn new() -> Result<Self, BoxError> {
        Ok(Self::with(StdRng::try_from_rng(&mut SysRng)?))
    }

    /// A session drawing from `seed`, for tests.
    #[cfg(feature = "testing")]
    pub(crate) fn seeded(seed: u64) -> Self {
        Self::with(StdRng::seed_from_u64(seed))
    }

    fn with(rng: StdRng) -> Self {
        Self {
            rng,
            covers: HashMap::new(),
            setups: HashMap::new(),
            epochs: HashMap::new(),
        }
    }
}

/// The page tables each shard revision's pending page work starts in: the
/// tables the walk is known to need before its first round there.
pub(crate) fn pending_tables(pending: &[PendingPages]) -> HashMap<(u64, String), BTreeSet<u32>> {
    let mut tables: HashMap<(u64, String), BTreeSet<u32>> = HashMap::new();
    for item in pending {
        tables
            .entry((item.shard_id, item.revision_digest.clone()))
            .or_default()
            .insert(u32::from(item.cursor.child));
    }
    tables
}

/// Draws a cover set over `tables`, the shard's queryable page tables, that
/// holds `known`.
///
/// A shard of at most [`SMALL_SHARD`] such tables covers them all. A larger one
/// draws a size: [`BASE_SIZE`] with odds [`BASE_ODDS`] in ten, otherwise
/// uniformly from one more than that to the table count. `C` is `known` plus
/// uniformly random other tables up to that size, or `known` alone when it is
/// already larger.
pub(crate) fn draw(rng: &mut StdRng, tables: &[u32], known: &BTreeSet<u32>) -> BTreeSet<u32> {
    let count = tables.len() as u32;
    if count <= SMALL_SHARD {
        return tables
            .iter()
            .copied()
            .chain(known.iter().copied())
            .collect();
    }
    let size = if rng.random_ratio(BASE_ODDS, 10) {
        BASE_SIZE
    } else {
        rng.random_range(BASE_SIZE + 1..=count)
    };
    let mut cover = known.clone();
    let mut others: Vec<u32> = tables
        .iter()
        .copied()
        .filter(|t| !cover.contains(t))
        .collect();
    others.shuffle(rng);
    let missing = (size as usize).saturating_sub(cover.len());
    cover.extend(others.into_iter().take(missing));
    cover
}

/// One sweep's order over `cover`: a fresh uniformly random permutation.
pub(crate) fn sweep_order(rng: &mut StdRng, cover: &BTreeSet<u32>) -> Vec<u32> {
    let mut order: Vec<u32> = cover.iter().copied().collect();
    order.shuffle(rng);
    order
}

/// The sweep count a shard's page work is padded to: the next power of two.
pub(crate) fn padded(sweeps: u64) -> u64 {
    sweeps.next_power_of_two()
}

/// The parameter epoch a page setup reply names: the first eight bytes of its
/// parameters' digest, as the client derives it when it opens the segment.
fn setup_epoch(setup: &[u8]) -> Result<[u8; 8], BoxError> {
    let parsed: serde_json::Value = serde_json::from_slice(setup)?;
    let digest = parsed["public_params_sha256"]
        .as_str()
        .and_then(|digest| hex::decode(digest.get(..16)?).ok())
        .ok_or("page cover: a page setup without a parameter digest")?;
    let mut epoch = [0u8; 8];
    epoch.copy_from_slice(&digest);
    Ok(epoch)
}

/// What keeps a shard's cover set across revisions: its id, its page table
/// count, and the chained identity of each sealed page table. A growing tail
/// republished over the same sealed tables keeps its `C`; one that seals
/// another table draws again.
fn cover_key(shard_id: u64, manifest: &ShardManifest) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"zakura page cover v1");
    hasher.update(shard_id.to_le_bytes());
    hasher.update((manifest.page_children.len() as u64).to_le_bytes());
    for (child, digest) in manifest.page_children.iter().zip(manifest.child_digests()) {
        if child.sealed {
            hasher.update(child.index.to_le_bytes());
            hasher.update(digest);
        }
    }
    hasher.finalize().into()
}

/// The shard whose page work is in progress, and its sweeps so far.
struct Work {
    shard_id: u64,
    revision: String,
    key: [u8; 32],
    sweeps: u64,
}

/// A pass's shard transport with page cover, over the caller's.
///
/// Counts every private query and private byte it sends, cover included,
/// against the pass's limits: a query and its upload before it is sent, its
/// reply once it arrives. A sweep starts only when it and the padding it may
/// need fit; otherwise the transport declines it, and everything after it,
/// with a [`BudgetStop`]. The walk then ends the pass on that budget, keeping
/// every reply it already received. A declined sweep sends nothing, so a
/// budget stop always falls between sweeps.
///
/// Every page reply, real or dummy, must have the length and segment headers
/// its table's published scheme and setups fix before the next query of the
/// sweep is sent. One that does not, or a request that fails other than by a
/// refusal the walk retries, fails the sweep and ends padding for the pass: a
/// service cannot single out a dummy slot by its framing, and one sending
/// oversized replies gets one of them through, not one per slot.
pub(crate) struct PageCover<'a, T> {
    inner: &'a mut T,
    session: &'a mut CoverSession,
    geometry: &'a ServiceGeometry,
    limits: WorkLimits,
    /// The page tables pending work already names, per shard revision.
    pending: HashMap<(u64, String), BTreeSet<u32>>,
    /// Manifests this pass fetched, per shard revision.
    manifests: HashMap<(u64, String), ShardManifest>,
    /// One pages client per geometry, for building dummies.
    clients: BTreeMap<String, TableClient>,
    /// The upload length of a query to a page table, per shard revision. A
    /// dummy body is never reused: each is a fresh query.
    uploads: HashMap<(u64, String, u32), u64>,
    /// Shard revisions whose page setups this pass fetched. A setup the
    /// session held from an earlier pass is handed to the walk at no cost.
    fetched: HashSet<(u64, String)>,
    current: Option<Work>,
    queries: u64,
    bytes: u64,
    stopped: Option<BudgetStop>,
    /// A cover sweep failed, or a page reply had the wrong length: no more
    /// padding this pass.
    padding_failed: bool,
}

impl<'a, T: ShardTransport> PageCover<'a, T> {
    pub(crate) fn new(
        inner: &'a mut T,
        session: &'a mut CoverSession,
        geometry: &'a ServiceGeometry,
        limits: WorkLimits,
        pending: HashMap<(u64, String), BTreeSet<u32>>,
    ) -> Self {
        Self {
            inner,
            session,
            geometry,
            limits,
            pending,
            manifests: HashMap::new(),
            clients: BTreeMap::new(),
            uploads: HashMap::new(),
            fetched: HashSet::new(),
            current: None,
            queries: 0,
            bytes: 0,
            stopped: None,
            padding_failed: false,
        }
    }

    /// Ends the pass: pads the shard whose page work was in progress.
    pub(crate) fn finish(mut self) {
        self.end_work();
    }

    /// The budget `queries` and `bytes` more would exceed, if any.
    fn exceeds(&self, queries: u64, bytes: u64) -> Option<BudgetStop> {
        if self
            .limits
            .max_queries
            .is_some_and(|max| self.queries + queries > max)
        {
            Some(BudgetStop::Queries)
        } else if self
            .limits
            .max_private_bytes
            .is_some_and(|max| self.bytes + bytes > max)
        {
            Some(BudgetStop::Bytes)
        } else {
            None
        }
    }

    /// Admits `queries` and `bytes` more of the walk's own work, or stops the
    /// pass: once stopped, nothing more the walk asks for is sent.
    fn admit(&mut self, queries: u64, bytes: u64) -> Result<(), BoxError> {
        if self.stopped.is_none() {
            self.stopped = self.exceeds(queries, bytes);
        }
        match self.stopped {
            Some(stop) => Err(stop.boxed()),
            None => Ok(()),
        }
    }

    fn params(&self, manifest: &ShardManifest) -> Result<&'a GeometryParams, BoxError> {
        self.geometry
            .geometries
            .iter()
            .find(|params| params.name == manifest.geometry)
            .ok_or_else(|| "page cover: the service declares no parameters for a geometry".into())
    }

    /// The length of every reply to a query to page table `table`: a header
    /// and the scheme's response per segment. The client refuses any other.
    fn page_reply_bytes(&self, key: &(u64, String), table: u32) -> Result<u64, BoxError> {
        let manifest = &self.manifests[key];
        let params = self.params(manifest)?;
        let child = manifest
            .child(table)
            .ok_or("page cover: a page table the manifest does not declare")?;
        Ok(
            (RESPONSE_HEADER + params.pages_scheme.response_bytes as u64)
                * child.page_segments.len() as u64,
        )
    }

    /// Upload and download of one query to page table `table`.
    fn page_query_bytes(&mut self, key: &(u64, String), table: u32) -> Result<u64, BoxError> {
        let download = self.page_reply_bytes(key, table)?;
        let upload_key = (key.0, key.1.clone(), table);
        let upload = match self.uploads.get(&upload_key) {
            Some(upload) => *upload,
            None => {
                let upload = self.dummy(key, table)?.len() as u64;
                self.uploads.insert(upload_key, upload);
                upload
            }
        };
        Ok(upload + download)
    }

    /// A query whose reply is not read: row 0 of page table `table`, among the
    /// rows every query to that table selects from, so it has the length of
    /// any other query to the table. Built as the walk builds its own dummies.
    fn dummy(&mut self, key: &(u64, String), table: u32) -> Result<Vec<u8>, BoxError> {
        let manifest = &self.manifests[key];
        let params = self.params(manifest)?;
        let child = manifest
            .child(table)
            .ok_or("page cover: a page table the manifest does not declare")?;
        let query_rows = child.query_rows() as usize;
        if !self.clients.contains_key(&manifest.geometry) {
            let geometry = transparent_shard::layout::by_name(&manifest.geometry)
                .ok_or("page cover: a geometry this build does not know")?;
            let client = TableClient::new_with_schema(
                &self.geometry.schema,
                Table::Pages(0),
                &manifest.geometry,
                geometry.page_rows,
                geometry.page_row_bytes as u32,
                &params.pages_scheme,
                params.pages_scheme_dq44.as_ref(),
            )?;
            self.clients.insert(manifest.geometry.clone(), client);
        }
        let client = &self.clients[&manifest.geometry];
        Ok(client
            .prepare_prefix(&key.1, Table::Pages(table), query_rows, 0)?
            .body)
    }

    /// Starts page work in `shard_id`'s revision `revision`, whose first page
    /// request names `table`, unless it is already in progress. The first time
    /// the session needs pages there, `C` is drawn; the first time it needs
    /// that revision's pages, every page table's setup is fetched.
    fn page_work(&mut self, shard_id: u64, revision: &str, table: u32) -> Result<(), BoxError> {
        if self
            .current
            .as_ref()
            .is_some_and(|work| work.shard_id == shard_id && work.revision == revision)
        {
            return Ok(());
        }
        self.end_work();
        let key = (shard_id, revision.to_owned());
        let manifest = self
            .manifests
            .get(&key)
            .ok_or("page cover: page work in a shard revision whose manifest it did not see")?;
        // A page table that holds no rows publishes no segment: no query can
        // address it, and no run can be in it.
        let tables: Vec<u32> = manifest
            .page_children
            .iter()
            .filter(|child| !child.page_segments.is_empty())
            .map(|child| child.index)
            .collect();
        let cover_key = cover_key(shard_id, manifest);
        if !self.session.covers.contains_key(&cover_key) {
            let mut known = self.pending.get(&key).cloned().unwrap_or_default();
            known.insert(table);
            let cover = draw(&mut self.session.rng, &tables, &known);
            self.session.covers.insert(cover_key, cover);
        }
        if !self.session.setups.contains_key(&key) {
            self.fetch_setups(&key)?;
        }
        self.current = Some(Work {
            shard_id,
            revision: revision.to_owned(),
            key: cover_key,
            sweeps: 0,
        });
        Ok(())
    }

    /// Fetches every segment's setup of every page table of a shard revision,
    /// in table order, so setup fetches never single out the tables the walk
    /// needs. Replaces what the session held for the shard. A setup reply
    /// longer than the estimate admitted for it fails the fetch before the
    /// next is asked for.
    fn fetch_setups(&mut self, key: &(u64, String)) -> Result<(), BoxError> {
        let manifest = &self.manifests[key];
        let params = self.params(manifest)?;
        let per_segment = params.pages_scheme.public_bytes.div_ceil(3) as u64 * 4 + SETUP_ENVELOPE;
        let requests: Vec<(u32, u32)> = manifest
            .page_children
            .iter()
            .flat_map(|child| (0..child.page_segments.len() as u32).map(move |s| (child.index, s)))
            .collect();
        self.admit(0, per_segment * requests.len() as u64)?;
        let mut setups = HashMap::with_capacity(requests.len());
        let mut epochs = HashMap::with_capacity(requests.len());
        for (table, segment) in requests {
            let (bytes, cost) = self
                .inner
                .setup(key.0, &key.1, Table::Pages(table), segment)?;
            self.bytes += cost;
            if cost > per_segment {
                return Err("page cover: a page setup reply longer than its scheme allows".into());
            }
            epochs.insert((table, segment), setup_epoch(&bytes)?);
            setups.insert((table, segment), (bytes, cost));
        }
        self.session
            .setups
            .retain(|(shard_id, _), _| *shard_id != key.0);
        self.session
            .epochs
            .retain(|(shard_id, _), _| *shard_id != key.0);
        self.session.setups.insert(key.clone(), setups);
        self.session.epochs.insert(key.clone(), epochs);
        self.fetched.insert(key.clone());
        Ok(())
    }

    /// Checks a page reply's framing the same way in every slot, real or
    /// dummy: its length, and each segment's header, the revision and table
    /// binding and the epoch of the setup fetched for that segment. Nothing
    /// past the header is read. A wrong epoch also forgets the session's
    /// setups for the revision, so the next attempt fetches all of them again.
    fn check_framing(
        &mut self,
        key: &(u64, String),
        table: u32,
        reply: &[u8],
    ) -> Result<(), BoxError> {
        let expected = self.page_reply_bytes(key, table)?;
        let segments = self.manifests[key]
            .child(table)
            .map_or(0, |child| child.page_segments.len());
        let failed = || -> BoxError { "page cover: a page reply with the wrong framing".into() };
        if reply.len() as u64 != expected || segments == 0 {
            return Err(failed());
        }
        let binding = transparent_shard::manifest::query_binding_for_schema(
            &self.geometry.schema,
            &key.1,
            &Table::Pages(table).name(),
        );
        let each = reply.len() / segments;
        let mut stale = false;
        for (segment, part) in reply.chunks(each).enumerate() {
            if part[..8] != binding {
                return Err(failed());
            }
            let held = self
                .session
                .epochs
                .get(key)
                .and_then(|epochs| epochs.get(&(table, segment as u32)));
            stale |= held.is_none_or(|epoch| part[8..16] != epoch[..]);
        }
        if stale {
            self.session.setups.remove(key);
            self.session.epochs.remove(key);
            return Err(failed());
        }
        Ok(())
    }

    /// One sweep over the current shard's `C`: `real`'s body in its table's
    /// slot, dummies elsewhere. Returns `real`'s reply. A real query to a table
    /// outside `C` adds the table first. A real sweep starts only when it and
    /// the padding it commits the shard to fit the budget.
    fn sweep(&mut self, real: Option<(u32, &[u8])>) -> Result<Vec<u8>, BoxError> {
        let Some(work) = self.current.as_ref() else {
            return Err("page cover: a sweep outside page work".into());
        };
        let (shard_id, key, sweep) = (work.shard_id, work.key, work.sweeps + 1);
        let revision_key = (shard_id, work.revision.clone());
        let mut cover = self.session.covers[&key].clone();
        if let Some((table, _)) = real {
            cover.insert(table);
        }
        let mut sweep_bytes = 0;
        for table in &cover {
            sweep_bytes += self.page_query_bytes(&revision_key, *table)?;
        }
        // A real sweep reserves the padding its count may need. A cover sweep
        // spends what an earlier real sweep reserved, so it is sent after a
        // budget stop too, unless a failed request spent the reservation.
        match real {
            Some(_) => {
                let sweeps = padded(sweep) - sweep + 1;
                self.admit(cover.len() as u64 * sweeps, sweep_bytes * sweeps)?;
            }
            None => {
                if let Some(stop) = self.exceeds(cover.len() as u64, sweep_bytes) {
                    return Err(stop.boxed());
                }
            }
        }
        // Only admitted growth changes the session's cover. A refused larger
        // sweep must leave the old cover's reserved padding affordable.
        if real.is_some() {
            self.session.covers.insert(key, cover.clone());
        }
        let mut reply = None;
        for table in sweep_order(&mut self.session.rng, &cover) {
            let dummy;
            let body = match real {
                Some((real_table, body)) if real_table == table => body,
                _ => {
                    dummy = self.dummy(&revision_key, table)?;
                    &dummy[..]
                }
            };
            self.queries += 1;
            self.bytes += body.len() as u64;
            let answer =
                match self
                    .inner
                    .query(shard_id, &revision_key.1, Table::Pages(table), body)
                {
                    Ok(answer) => answer,
                    Err(error) => {
                        // A failure other than a refusal the walk retries, an
                        // oversized reply among them, ends padding: the service
                        // gets no more cover queries to answer badly this pass.
                        if Overloaded::found_in(&error).is_none()
                            && StaleRevision::found_in(&error).is_none()
                        {
                            self.padding_failed = true;
                        }
                        return Err(error);
                    }
                };
            self.bytes += answer.len() as u64;
            // Checked the same way in every slot, before the next is sent:
            // nothing here depends on which slot is real.
            if let Err(error) = self.check_framing(&revision_key, table, &answer) {
                self.padding_failed = true;
                return Err(error);
            }
            if real.is_some_and(|(real_table, _)| real_table == table) {
                reply = Some(answer);
            }
        }
        if let Some(work) = self.current.as_mut() {
            work.sweeps = sweep;
        }
        Ok(reply.unwrap_or_default())
    }

    /// Ends the page work in progress: cover sweeps until its sweep count is
    /// a power of two. The first failed cover sweep ends padding for the pass.
    fn end_work(&mut self) {
        let Some(sweeps) = self.current.as_ref().map(|work| work.sweeps) else {
            return;
        };
        if sweeps > 0 {
            for _ in sweeps..padded(sweeps) {
                if self.padding_failed {
                    break;
                }
                if self.sweep(None).is_err() {
                    self.padding_failed = true;
                }
            }
        }
        self.current = None;
    }

    /// A page setup the walk asks for, from those fetched for cover. Asked
    /// again, after the walk dropped it, every page table's setup is fetched
    /// again.
    fn page_setup(
        &mut self,
        shard_id: u64,
        revision: &str,
        table: u32,
        segment: u32,
    ) -> Result<(Vec<u8>, u64), BoxError> {
        let key = (shard_id, revision.to_owned());
        if let Some((bytes, cost)) = self
            .session
            .setups
            .get_mut(&key)
            .and_then(|setups| setups.remove(&(table, segment)))
        {
            let cost = if self.fetched.contains(&key) { cost } else { 0 };
            return Ok((bytes, cost));
        }
        self.fetch_setups(&key)?;
        self.session
            .setups
            .get_mut(&key)
            .and_then(|setups| setups.remove(&(table, segment)))
            .ok_or_else(|| "page cover: a page setup the manifest does not declare".into())
    }
}

impl<T: ShardTransport> ShardTransport for PageCover<'_, T> {
    fn init(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        self.end_work();
        self.inner.init()
    }

    fn manifest(&mut self, shard_id: u64, revision: &str) -> Result<(Vec<u8>, u64), BoxError> {
        self.end_work();
        let (bytes, cost) = self.inner.manifest(shard_id, revision)?;
        // The walk checks it against the map before using it; one that does
        // not parse is refused there, before any page work.
        if let Ok(manifest) = serde_json::from_slice::<ShardManifest>(&bytes) {
            self.manifests
                .insert((shard_id, revision.to_owned()), manifest);
        }
        Ok((bytes, cost))
    }

    fn setup(
        &mut self,
        shard_id: u64,
        revision: &str,
        table: Table,
        segment: u32,
    ) -> Result<(Vec<u8>, u64), BoxError> {
        match table {
            Table::Pages(child) => {
                if let Some(stop) = self.stopped {
                    return Err(stop.boxed());
                }
                self.page_work(shard_id, revision, child)?;
                self.page_setup(shard_id, revision, child, segment)
            }
            Table::Directory => {
                self.end_work();
                let estimate = self
                    .manifests
                    .get(&(shard_id, revision.to_owned()))
                    .and_then(|manifest| self.params(manifest).ok())
                    .map_or(0, |params| {
                        params.directory_scheme.public_bytes.div_ceil(3) as u64 * 4 + SETUP_ENVELOPE
                    });
                self.admit(0, estimate)?;
                let (bytes, cost) = self.inner.setup(shard_id, revision, table, segment)?;
                self.bytes += cost;
                Ok((bytes, cost))
            }
        }
    }

    fn query(
        &mut self,
        shard_id: u64,
        revision: &str,
        table: Table,
        body: &[u8],
    ) -> Result<Vec<u8>, BoxError> {
        match table {
            Table::Pages(child) => {
                if let Some(stop) = self.stopped {
                    return Err(stop.boxed());
                }
                self.page_work(shard_id, revision, child)?;
                self.sweep(Some((child, body)))
            }
            Table::Directory => {
                self.end_work();
                let download = self
                    .manifests
                    .get(&(shard_id, revision.to_owned()))
                    .and_then(|manifest| {
                        self.params(manifest).ok().map(|params| {
                            (RESPONSE_HEADER + params.directory_scheme.response_bytes as u64)
                                * manifest.directory_segments.len() as u64
                        })
                    })
                    .unwrap_or(0);
                self.admit(1, body.len() as u64 + download)?;
                self.queries += 1;
                self.bytes += body.len() as u64;
                let answer = self.inner.query(shard_id, revision, table, body)?;
                self.bytes += answer.len() as u64;
                Ok(answer)
            }
        }
    }
}

#[cfg(test)]
mod tests;
