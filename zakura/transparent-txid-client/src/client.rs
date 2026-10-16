//! The lookup itself, ported from the shard server's reference tooling client
//! (`examples/support/txdisplay.rs`) onto a synchronous transport.

use crate::{
    Placement, ProtocolKind, Provenance, Route, Tier, TxidError, TxidLookup, TxidReply,
    TxidRequest, TxidTransport,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use transparent_events::Txid;
use transparent_native::{NativeScheme, TableProfile};
use transparent_shard::display::{
    self, display_by_name, DisplayIndexChunk, DisplayKind, DisplayManifest, DisplayMapEntry,
    DisplayRecentMap, DisplaySealParams, DisplayTable,
};
use transparent_shard::layout::Geometry;
use transparent_shard::txid::{self, Tag};

/// Native profiles are a pure function of geometry and table kind and costly
/// to derive, so clients may share them; nothing network-facing is shared.
pub type ProfileCache = Arc<Mutex<HashMap<(&'static str, DisplayKind), Arc<TableProfile>>>>;

/// A cached map at least this old, by the wall clock, is fetched again
/// before a height outside its coverage is reported as [`Placement::Below`]
/// or [`Placement::Above`].
pub const PLACEMENT_REFRESH_AGE: Duration = Duration::from_secs(30);

/// The fewest txids every bucket of the recent shard must hold before a
/// lookup queries it, whatever lower `recent_window` the map advertises. A
/// query names the shard and bucket it reads, so the txid is one of that
/// bucket's txids and no fewer may hide it. The production publication seals
/// archives only while recent keeps this many.
pub const MIN_RECENT_FLOOR: u64 = 10_000;

#[derive(Deserialize)]
struct InitTable {
    rows: u64,
    row_bytes: u32,
    /// The table's one scheme, the 8-bit profile's 28-bit dithered query.
    scheme: NativeScheme,
    setup_seed: u64,
}

#[derive(Deserialize)]
struct InitGeometry {
    name: String,
    txdirectory: InitTable,
}

#[derive(Deserialize)]
struct InitDocument {
    schema: String,
    codec: String,
    bucket_domain: String,
    native_schema: String,
    geometries: Vec<InitGeometry>,
}

struct Init {
    supported: bool,
    geometries: HashMap<String, InitGeometry>,
}

struct CachedMap {
    map: DisplayRecentMap,
    sha256: String,
    /// Wall-clock time of the fetch. A monotonic clock stops while a phone
    /// sleeps, so a map fetched before a long sleep would look fresh after it.
    fetched: SystemTime,
}

impl CachedMap {
    /// Whether the map is at least `age` old; a clock that went back since
    /// the fetch counts as old.
    fn older_than(&self, age: Duration) -> bool {
        self.fetched
            .elapsed()
            .map_or(true, |elapsed| elapsed >= age)
    }
}

/// The chain a publication serves. No publication changes it, so a map
/// naming another chain than the first map this client accepted is refused.
#[derive(Clone, PartialEq, Eq)]
struct Chain {
    network: String,
    genesis_hash: String,
}

/// What a publication of one chain may change only as a whole new
/// publication; init is fetched again when it does.
#[derive(Clone, PartialEq, Eq)]
struct Layout {
    schema: String,
    seal: DisplaySealParams,
}

struct Setup {
    public_params: Vec<u8>,
    epoch: [u8; 8],
}

/// What a lookup knows before its first query.
struct Located {
    init: Arc<Init>,
    entry: DisplayMapEntry,
    map_sha256: String,
    geometry: &'static Geometry,
    bucket: u32,
}

/// One table of one revision, ready to be queried.
struct Target {
    table: DisplayTable,
    profile: Arc<TableProfile>,
    setups: Vec<Arc<Setup>>,
}

/// One attempt's result before the retry policy is applied.
enum Attempt {
    Done(TxidLookup),
    /// Fetch init, the map, or both again, then try once more: the height
    /// lies outside a map at least the placement refresh age old or in its
    /// recent shard below the floor, or the map
    /// names a geometry init does not list. Only documents this lookup has
    /// not fetched are named.
    Refetch {
        init: bool,
        map: bool,
    },
}

/// What one lookup has fetched and revealed so far, which bounds it. Init
/// and the map are fetched at most once each for a missing document, a stale
/// placement or a missing geometry; the map once more after a 409, and init
/// once more after each map that changes the publication's layout. A lookup
/// therefore sends at most 2 map, 3 init and 2 query requests.
#[derive(Default)]
struct Fresh {
    /// Fetch the map before the next attempt uses it.
    refresh_map: bool,
    /// This lookup fetched the map, so its placement is final.
    map: bool,
    /// This lookup fetched init.
    init: bool,
    /// The bucket count of the shard this lookup named a bucket table of,
    /// in a setup or query path.
    buckets: Option<u32>,
}

/// The txid display client. Holds caches only; every request goes through
/// the transport passed to [`TxidDisplayClient::lookup`]. It pins the chain
/// (network and genesis hash) of the first map it accepts, so a wallet keeps
/// one client per chain and origin.
pub struct TxidDisplayClient {
    profiles: ProfileCache,
    placement_refresh_age: Duration,
    /// The least floor a lookup holds the recent shard to.
    min_recent_floor: u64,
    init: Option<Arc<Init>>,
    map: Option<Arc<CachedMap>>,
    /// The chain of the first map accepted; never changes.
    chain: Option<Chain>,
    /// The layout of the last map accepted; kept when the map is dropped.
    layout: Option<Layout>,
    /// Index chunks by digest; immutable, so kept while the map names them.
    chunks: HashMap<String, Arc<DisplayIndexChunk>>,
    /// Manifests and setups by revision digest, kept while the map names the
    /// revision through its recent entry or a cached chunk.
    manifests: HashMap<String, Arc<DisplayManifest>>,
    setups: HashMap<(String, DisplayTable, u32), Arc<Setup>>,
}

impl Default for TxidDisplayClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Sends one request unless cancelled, and maps every status but 200 to an
/// error. 409 comes back as [`TxidError::Stale`]; the lookup retries it once.
fn send(
    transport: &mut impl TxidTransport,
    cancel: &dyn Fn() -> bool,
    request: TxidRequest,
) -> Result<TxidReply, TxidError> {
    if cancel() {
        return Err(TxidError::Cancelled);
    }
    let reply = transport.send(request)?;
    match reply.status {
        200 => Ok(reply),
        409 => Err(TxidError::Stale),
        429 | 500..=599 => Err(TxidError::Unavailable {
            retry_after: reply
                .retry_after
                .as_deref()
                .and_then(|value| value.trim().parse::<u64>().ok())
                .map(Duration::from_secs),
        }),
        status @ 400..=499 => Err(TxidError::Refused(status)),
        status => Err(TxidError::Protocol(ProtocolKind::Status(status))),
    }
}

fn protocol<E>(kind: ProtocolKind) -> impl FnOnce(E) -> TxidError {
    move |_| TxidError::Protocol(kind)
}

fn tier(entry: &DisplayMapEntry) -> Tier {
    if entry.sealed {
        Tier::Archive
    } else {
        Tier::Recent
    }
}

impl TxidDisplayClient {
    pub fn new() -> Self {
        Self::with_profiles(ProfileCache::default())
    }

    /// A client sharing derived native profiles with others.
    pub fn with_profiles(profiles: ProfileCache) -> Self {
        Self {
            profiles,
            placement_refresh_age: PLACEMENT_REFRESH_AGE,
            min_recent_floor: MIN_RECENT_FLOOR,
            init: None,
            map: None,
            chain: None,
            layout: None,
            chunks: HashMap::new(),
            manifests: HashMap::new(),
            setups: HashMap::new(),
        }
    }

    /// Sets how old a cached map must be before a height outside it is
    /// placed only after fetching the map again; [`PLACEMENT_REFRESH_AGE`]
    /// by default. For tests: zero refetches the map for every such lookup
    /// that has not already fetched it, as a map gone stale would. A low age
    /// makes every lookup outside the map's coverage visible to the server
    /// as a map request.
    #[cfg(any(test, feature = "testing"))]
    pub fn with_placement_refresh_age(mut self, age: Duration) -> Self {
        self.placement_refresh_age = age;
        self
    }

    /// Sets the least floor a lookup holds the recent shard to;
    /// [`MIN_RECENT_FLOOR`] by default. For tests and test services, whose
    /// publications hold a handful of txids: the map's own `recent_window`
    /// still applies when higher.
    #[cfg(any(test, feature = "testing"))]
    pub fn with_min_recent_floor(mut self, floor: u64) -> Self {
        self.min_recent_floor = floor;
        self
    }

    pub fn profiles(&self) -> ProfileCache {
        self.profiles.clone()
    }

    /// The manifest digests of the revisions whose manifest or setups this
    /// client holds, sorted. For tests: lookups address revisions by the
    /// digests the map names, never by what is cached.
    #[cfg(any(test, feature = "testing"))]
    pub fn cached_revisions(&self) -> Vec<&str> {
        let mut digests: Vec<&str> = self
            .manifests
            .keys()
            .chain(self.setups.keys().map(|(digest, _, _)| digest))
            .map(String::as_str)
            .collect();
        digests.sort_unstable();
        digests.dedup();
        digests
    }

    /// The SHA-256 of the recent map this client holds, if any.
    pub fn map_sha256(&self) -> Option<&str> {
        self.map.as_ref().map(|cached| cached.sha256.as_str())
    }

    /// Fetches the recent map now, without a lookup, and returns its SHA-256.
    ///
    /// The map is validated as a lookup validates it (the
    /// `X-Txid-Map-Sha256` header and the canonical encoding) and, once
    /// valid, replaces the cached map, so [`Self::map_sha256`] reports it,
    /// and prunes the caches as a lookup's refresh does. A map naming
    /// another network or genesis hash than the first map accepted is
    /// [`ProtocolKind::Map`]. On any error the previously cached map is
    /// kept. Once a map is accepted, a cached init naming a schema or codec
    /// this client does not support is dropped, so the next lookup asks
    /// again. Sends exactly one `GET /v2/txid/map` unless `cancel` returns
    /// true first; statuses map to errors as in [`Self::lookup`], with no
    /// retry.
    pub fn refresh_map(
        &mut self,
        transport: &mut impl TxidTransport,
        cancel: &dyn Fn() -> bool,
    ) -> Result<[u8; 32], TxidError> {
        let cached = self.fetch_map(transport, cancel)?;
        // Lookups return before the map while init is unsupported.
        if self.init.as_ref().is_some_and(|init| !init.supported) {
            self.init = None;
        }
        let mut sha256 = [0; 32];
        hex::decode_to_slice(&cached.sha256, &mut sha256).expect("a hex SHA-256");
        Ok(sha256)
    }

    /// Forgets the recent map so the next lookup fetches it again. Cached
    /// index chunks stay: they are named by digest.
    pub fn invalidate_map(&mut self) {
        self.map = None;
    }

    /// Looks up `txid` (internal byte order) mined at `mined_height`, which
    /// the caller's accepted chain supplies. `cancel` is polled before every
    /// request.
    ///
    /// A 409 refreshes the recent map and retries the whole lookup once; a
    /// second 409 is [`TxidError::Stale`], as is a retry that would name the
    /// txid's bucket under another bucket count than this lookup already
    /// named. A height outside a map at least the placement refresh age old,
    /// or in its recent shard below the floor, refreshes the map and is
    /// placed again once. A geometry the map names
    /// but init lacks refetches whichever of init and the map this lookup
    /// has not fetched, once, before [`TxidLookup::Unsupported`]. Nothing
    /// else is retried. A lookup sends at most 2 map, 3 init and 2 query
    /// requests.
    pub fn lookup(
        &mut self,
        transport: &mut impl TxidTransport,
        txid: [u8; 32],
        mined_height: u64,
        cancel: &dyn Fn() -> bool,
    ) -> Result<TxidLookup, TxidError> {
        let txid = Txid(txid);
        // A refetch names only documents this lookup has not fetched, and a
        // 409 is retried once, so the loop ends.
        let mut fresh = Fresh::default();
        let mut stale_retried = false;
        loop {
            match self.attempt(transport, cancel, txid, mined_height, &mut fresh) {
                Ok(Attempt::Done(lookup)) => return Ok(lookup),
                Ok(Attempt::Refetch { init, map }) => {
                    if init {
                        self.init = None;
                    }
                    fresh.refresh_map |= map;
                }
                Err(TxidError::Stale) if !stale_retried => {
                    stale_retried = true;
                    fresh.refresh_map = true;
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn attempt(
        &mut self,
        transport: &mut impl TxidTransport,
        cancel: &dyn Fn() -> bool,
        txid: Txid,
        height: u64,
        fresh: &mut Fresh,
    ) -> Result<Attempt, TxidError> {
        let located = match self.locate(transport, cancel, txid, height, fresh)? {
            Ok(located) => located,
            Err(attempt) => return Ok(attempt),
        };
        let geometry = located.geometry;
        let provenance = Provenance {
            map_sha256: located.map_sha256.clone(),
            shard_id: located.entry.shard_id,
            revision: located.entry.revision,
            manifest_digest: located.entry.manifest_digest.clone(),
            tier: tier(&located.entry),
        };

        // Exactly one query, found or not: the entry's one row.
        let (shard_id, bucket, rows) = (
            located.entry.shard_id,
            located.bucket,
            geometry.directory_rows,
        );
        let seed = located.entry.placement_seeds[bucket as usize];
        let row = display::placement_row(&Tag::of(&txid), seed, shard_id, bucket, rows);
        let segments = located.entry.directory_segments[bucket as usize];
        let table = DisplayTable::Directory(bucket);
        // Setup and query paths name the bucket table from here on.
        fresh.buckets = Some(located.entry.n_buckets);
        let target = self.target(transport, cancel, &located, table, segments)?;
        let copies = self.query(transport, cancel, &located, &target, row)?;
        // Every entry in the row must be one the placement puts there.
        let in_row = |tag: &Tag| display::placement_row(tag, seed, shard_id, bucket, rows) == row;
        match txid::find_entry(&copies, &txid, in_row).map_err(protocol(ProtocolKind::Decode))? {
            Some(entry) => Ok(Attempt::Done(TxidLookup::Found { entry, provenance })),
            None => Ok(Attempt::Done(TxidLookup::Absent)),
        }
    }

    /// Init, recent map, index chunk, placement and manifest: everything
    /// before a query.
    fn locate(
        &mut self,
        transport: &mut impl TxidTransport,
        cancel: &dyn Fn() -> bool,
        txid: Txid,
        height: u64,
        fresh: &mut Fresh,
    ) -> Result<Result<Located, Attempt>, TxidError> {
        let mut init = self.init(transport, cancel, fresh)?;
        if !init.supported {
            return Ok(Err(Attempt::Done(TxidLookup::Unsupported)));
        }
        let cached = match (&self.map, fresh.refresh_map) {
            (Some(cached), false) => cached.clone(),
            _ => {
                fresh.refresh_map = false;
                fresh.map = true;
                self.fetch_map(transport, cancel)?
            }
        };
        // A map of another layout dropped init.
        if self.init.is_none() {
            init = self.init(transport, cancel, fresh)?;
            if !init.supported {
                return Ok(Err(Attempt::Done(TxidLookup::Unsupported)));
            }
        }
        if cached.map.schema != display::DISPLAY_SCHEMA {
            return Ok(Err(Attempt::Done(TxidLookup::Unsupported)));
        }
        cached
            .map
            .check_shape()
            .map_err(protocol(ProtocolKind::Map))?;
        // A placement from a map this lookup did not fetch, and old enough
        // to have been replaced, is checked against the current map first:
        // a new publication may start lower or reach further.
        let stale = !fresh.map && cached.older_than(self.placement_refresh_age);
        let placement = move |placement| {
            if stale {
                Attempt::Refetch {
                    init: false,
                    map: true,
                }
            } else {
                Attempt::Done(TxidLookup::PlacementUnknown(placement))
            }
        };
        if height < cached.map.start_height {
            return Ok(Err(placement(Placement::Below)));
        }
        let entry = match cached.map.chunk_for_height(height) {
            Some(index) => self
                .chunk(transport, cancel, &cached.map, index)?
                .shard_for_height(height)
                .cloned(),
            None => cached
                .map
                .recent
                .as_ref()
                .filter(|recent| height <= recent.end_height)
                .cloned(),
        };
        let Some(entry) = entry else {
            // The shape and chunk checks make the shards contiguous, so only
            // the tip is left; a map that is not fresh may not have reached
            // it yet.
            return Ok(Err(placement(Placement::Above)));
        };
        // Querying a shard tells the server the txid is among its bucket's
        // txids. Sealed shards were checked against `archive_target` with
        // the map; the recent shard is held here to the larger of the map's
        // floor and this client's, which a server cannot lower. Decided from
        // the public map alone, so it sends nothing, like a placement; a map
        // that is not fresh may have grown since.
        let floor = cached.map.seal.recent_window.max(self.min_recent_floor);
        if !entry.sealed && entry.min_bucket_records < floor {
            return Ok(Err(if stale {
                Attempt::Refetch {
                    init: false,
                    map: true,
                }
            } else {
                Attempt::Done(TxidLookup::RecentBelowFloor)
            }));
        }
        let Some(geometry) = display_by_name(&entry.geometry) else {
            return Ok(Err(Attempt::Done(TxidLookup::Unsupported)));
        };
        if !init.geometries.contains_key(geometry.name) {
            // Init lists the geometries of the publication it came from, and
            // the map names the shards of the one it came from. During a
            // swap either may be the older: a later publication may add a
            // geometry, or drop the one an old map names.
            return Ok(Err(if fresh.init && fresh.map {
                Attempt::Done(TxidLookup::Unsupported)
            } else {
                Attempt::Refetch {
                    init: !fresh.init,
                    map: !fresh.map,
                }
            }));
        }
        // The bucket is the tag modulo the bucket count; naming it under a
        // second count would tell the server more of the tag.
        if fresh
            .buckets
            .is_some_and(|buckets| buckets != entry.n_buckets)
        {
            return Err(TxidError::Stale);
        }
        let bucket = display::bucket(&Tag::of(&txid), entry.n_buckets);
        // Fetched and checked against the map entry before any query, even
        // though the entry already carries what a lookup needs.
        self.manifest(transport, cancel, &entry)?;
        Ok(Ok(Located {
            init,
            entry,
            map_sha256: cached.sha256.clone(),
            geometry,
            bucket,
        }))
    }

    fn init(
        &mut self,
        transport: &mut impl TxidTransport,
        cancel: &dyn Fn() -> bool,
        fresh: &mut Fresh,
    ) -> Result<Arc<Init>, TxidError> {
        if let Some(init) = &self.init {
            return Ok(init.clone());
        }
        let reply = send(
            transport,
            cancel,
            TxidRequest::new(Route::Init, Route::Init.template().into(), Vec::new()),
        )?;
        let document: InitDocument =
            serde_json::from_slice(&reply.body).map_err(protocol(ProtocolKind::Init))?;
        let supported = document.schema == display::DISPLAY_SCHEMA
            && document.codec == txid::CODEC
            && document.bucket_domain.as_bytes() == display::BUCKET_DOMAIN
            && document.native_schema == display::NATIVE_SCHEMA;
        let init = Arc::new(Init {
            supported,
            geometries: document
                .geometries
                .into_iter()
                .map(|g| (g.name.clone(), g))
                .collect(),
        });
        self.init = Some(init.clone());
        fresh.init = true;
        Ok(init)
    }

    /// Fetches and validates the recent map and makes it the cached one.
    fn fetch_map(
        &mut self,
        transport: &mut impl TxidTransport,
        cancel: &dyn Fn() -> bool,
    ) -> Result<Arc<CachedMap>, TxidError> {
        let reply = send(
            transport,
            cancel,
            TxidRequest::new(Route::Map, Route::Map.template().into(), Vec::new()),
        )?;
        let sha256 = hex::encode(Sha256::digest(&reply.body));
        if reply.map_sha256.as_deref().map(str::trim) != Some(sha256.as_str()) {
            return Err(TxidError::Protocol(ProtocolKind::MapHeader));
        }
        let map: DisplayRecentMap =
            serde_json::from_slice(&reply.body).map_err(protocol(ProtocolKind::Map))?;
        if map.to_bytes() != reply.body {
            return Err(TxidError::Protocol(ProtocolKind::MapCanonical));
        }
        map.check_shape().map_err(protocol(ProtocolKind::Map))?;
        let chain = Chain {
            network: map.network.clone(),
            genesis_hash: map.genesis_hash.clone(),
        };
        if self.chain.as_ref().is_some_and(|known| *known != chain) {
            return Err(TxidError::Protocol(ProtocolKind::Map));
        }
        self.chain = Some(chain);
        let layout = Layout {
            schema: map.schema.clone(),
            seal: map.seal,
        };
        if self.layout.as_ref().is_some_and(|old| *old != layout) {
            self.init = None;
        }
        self.layout = Some(layout);
        // Lookups ask only for what the map names, and only by digest.
        // Chunks it no longer names are dropped, and with them every
        // manifest and setup it no longer names through its recent entry
        // or a chunk still held: a superseded recent revision, the archives
        // of a chunk a seal or the window replaced (fetched again on their
        // next use), and everything of a publication this map replaced,
        // whatever shard ids it reuses.
        let named: HashSet<&str> = map.chunks.iter().map(|c| c.sha256.as_str()).collect();
        self.chunks
            .retain(|digest, _| named.contains(digest.as_str()));
        let revisions: HashSet<&str> = map
            .recent
            .iter()
            .chain(self.chunks.values().flat_map(|chunk| chunk.shards.iter()))
            .map(|entry| entry.manifest_digest.as_str())
            .collect();
        self.manifests
            .retain(|digest, _| revisions.contains(digest.as_str()));
        self.setups
            .retain(|(digest, _, _), _| revisions.contains(digest.as_str()));
        let cached = Arc::new(CachedMap {
            map,
            sha256,
            fetched: SystemTime::now(),
        });
        self.map = Some(cached.clone());
        Ok(cached)
    }

    /// Index chunk `index` of `map`, fetched unless cached, and checked
    /// against the digest and the position the map gives it.
    fn chunk(
        &mut self,
        transport: &mut impl TxidTransport,
        cancel: &dyn Fn() -> bool,
        map: &DisplayRecentMap,
        index: usize,
    ) -> Result<Arc<DisplayIndexChunk>, TxidError> {
        let digest = &map.chunks[index].sha256;
        let chunk = match self.chunks.get(digest) {
            Some(chunk) => chunk.clone(),
            None => {
                let reply = send(
                    transport,
                    cancel,
                    TxidRequest::new(Route::MapChunk, map.chunk_path(index), Vec::new()),
                )?;
                if hex::encode(Sha256::digest(&reply.body)) != *digest {
                    return Err(TxidError::Protocol(ProtocolKind::Map));
                }
                let chunk: DisplayIndexChunk =
                    serde_json::from_slice(&reply.body).map_err(protocol(ProtocolKind::Map))?;
                if chunk.to_bytes() != reply.body {
                    return Err(TxidError::Protocol(ProtocolKind::MapCanonical));
                }
                Arc::new(chunk)
            }
        };
        // Checked on every use: a cached chunk may sit at another position
        // of a newer map.
        map.check_chunk(index, &chunk)
            .map_err(protocol(ProtocolKind::Map))?;
        self.chunks.insert(digest.clone(), chunk.clone());
        Ok(chunk)
    }

    fn manifest(
        &mut self,
        transport: &mut impl TxidTransport,
        cancel: &dyn Fn() -> bool,
        entry: &DisplayMapEntry,
    ) -> Result<Arc<DisplayManifest>, TxidError> {
        if let Some(manifest) = self.manifests.get(&entry.manifest_digest) {
            // The digest was checked when the manifest was cached; a map
            // naming it must still describe it, field for field.
            if !entry.describes(manifest) {
                return Err(TxidError::Protocol(ProtocolKind::Manifest));
            }
            return Ok(manifest.clone());
        }
        let path = format!(
            "/v2/txid/shards/{}/revisions/{}/manifest",
            entry.shard_id, entry.manifest_digest
        );
        let reply = send(
            transport,
            cancel,
            TxidRequest::new(Route::Manifest, path, Vec::new()),
        )?;
        let manifest: DisplayManifest =
            serde_json::from_slice(&reply.body).map_err(protocol(ProtocolKind::Manifest))?;
        if manifest.canonical_bytes() != reply.body || !entry.describes(&manifest) {
            return Err(TxidError::Protocol(ProtocolKind::Manifest));
        }
        manifest
            .validate()
            .map_err(protocol(ProtocolKind::Manifest))?;
        let manifest = Arc::new(manifest);
        self.manifests
            .insert(entry.manifest_digest.clone(), manifest.clone());
        Ok(manifest)
    }

    /// The locally derived profile of `kind` at `geometry`, checked against
    /// what init publishes, which must reproduce it.
    fn profile(
        &self,
        init: &Init,
        geometry: &'static Geometry,
        kind: DisplayKind,
    ) -> Result<Arc<TableProfile>, TxidError> {
        let cached = self
            .profiles
            .lock()
            .unwrap()
            .get(&(geometry.name, kind))
            .cloned();
        let profile = match cached {
            Some(profile) => profile,
            None => {
                // The native profile is derived under display's own native
                // schema. Only the binding is display-specific.
                let profile = Arc::new(
                    TableProfile::new(
                        display::NATIVE_SCHEMA,
                        geometry.name,
                        kind.as_str(),
                        kind.rows(geometry),
                        kind.row_bytes(geometry),
                    )
                    .map_err(protocol(ProtocolKind::Profile))?,
                );
                self.profiles
                    .lock()
                    .unwrap()
                    .insert((geometry.name, kind), profile.clone());
                profile
            }
        };
        let served = init
            .geometries
            .get(geometry.name)
            .map(|g| match kind {
                DisplayKind::TxDirectory => &g.txdirectory,
            })
            .ok_or(TxidError::Protocol(ProtocolKind::Profile))?;
        if served.scheme != profile.scheme
            || served.rows != kind.rows(geometry)
            || served.row_bytes != kind.row_bytes(geometry)
            || served.setup_seed != display::setup_seed(geometry, kind)
        {
            return Err(TxidError::Protocol(ProtocolKind::Profile));
        }
        Ok(profile)
    }

    #[allow(clippy::too_many_arguments)]
    fn setup(
        &mut self,
        transport: &mut impl TxidTransport,
        cancel: &dyn Fn() -> bool,
        entry: &DisplayMapEntry,
        table: DisplayTable,
        segment: u32,
        segments: u32,
        profile: &TableProfile,
    ) -> Result<Arc<Setup>, TxidError> {
        let digest = &entry.manifest_digest;
        let key = (digest.clone(), table, segment);
        if let Some(setup) = self.setups.get(&key) {
            return Ok(setup.clone());
        }
        let path = format!(
            "/v2/txid/{}/shards/{}/revisions/{digest}/setup/{}/{segment}",
            entry.tier(),
            entry.shard_id,
            table.label()
        );
        let reply = send(
            transport,
            cancel,
            TxidRequest::new(Route::Setup, path, Vec::new()),
        )?;
        let bad = TxidError::Protocol(ProtocolKind::Setup);
        let s: serde_json::Value = serde_json::from_slice(&reply.body).map_err(|_| bad.clone())?;
        let bucket = serde_json::json!(table.bucket());
        if s["manifest_digest"] != *digest
            || s["shard_id"] != entry.shard_id
            || s["table"] != table.label()
            || s["bucket"] != bucket
            || s["segment"] != segment
            || s["segments"] != segments
            || s["geometry"] != entry.geometry
        {
            return Err(bad);
        }
        let public_params = B64
            .decode(s["public_params"].as_str().ok_or_else(|| bad.clone())?)
            .map_err(|_| bad.clone())?;
        if public_params.len() != profile.scheme.public_bytes
            || s["public_params_sha256"] != hex::encode(Sha256::digest(&public_params))
        {
            return Err(bad);
        }
        let epoch: [u8; 8] = hex::decode(
            s["public_params_epoch"]
                .as_str()
                .ok_or_else(|| bad.clone())?,
        )
        .map_err(|_| bad.clone())?
        .try_into()
        .map_err(|_| bad.clone())?;
        let setup = Arc::new(Setup {
            public_params,
            epoch,
        });
        self.setups.insert(key, setup.clone());
        Ok(setup)
    }

    /// The profile and every segment's setup of one table of a located shard.
    fn target(
        &mut self,
        transport: &mut impl TxidTransport,
        cancel: &dyn Fn() -> bool,
        located: &Located,
        table: DisplayTable,
        segments: u32,
    ) -> Result<Target, TxidError> {
        let profile = self.profile(&located.init, located.geometry, table.kind())?;
        let mut setups = Vec::with_capacity(segments as usize);
        for segment in 0..segments {
            setups.push(self.setup(
                transport,
                cancel,
                &located.entry,
                table,
                segment,
                segments,
                &profile,
            )?);
        }
        Ok(Target {
            table,
            profile,
            setups,
        })
    }

    /// One query for `row`, answered by every segment of the target table.
    /// Returns that row of each segment, in segment order.
    fn query(
        &mut self,
        transport: &mut impl TxidTransport,
        cancel: &dyn Fn() -> bool,
        located: &Located,
        target: &Target,
        row: u64,
    ) -> Result<Vec<Vec<u8>>, TxidError> {
        let entry = &located.entry;
        let binding = display::query_binding(&entry.manifest_digest, target.table);
        let stride = 16 + target.profile.scheme.response_bytes;
        let path = format!(
            "/v2/txid/{}/shards/{}/revisions/{}/query/{}",
            entry.tier(),
            entry.shard_id,
            entry.manifest_digest,
            target.table.label()
        );
        let (secret, upload) = target
            .profile
            .prepare(row as usize)
            .map_err(protocol(ProtocolKind::Profile))?;
        let mut body = binding.to_vec();
        body.extend(upload);
        let reply = send(
            transport,
            cancel,
            TxidRequest::new(Route::Query, path, body),
        )?;
        if reply.body.len() != target.setups.len() * stride {
            return Err(TxidError::Protocol(ProtocolKind::Length));
        }
        let mut copies = Vec::with_capacity(target.setups.len());
        for (frame, setup) in reply.body.chunks_exact(stride).zip(target.setups.iter()) {
            if frame[..8] != binding {
                return Err(TxidError::Protocol(ProtocolKind::Binding));
            }
            if frame[8..16] != setup.epoch {
                return Err(TxidError::Protocol(ProtocolKind::Epoch));
            }
            let decoded = target
                .profile
                .decode(&secret, &setup.public_params, &frame[16..])
                .map_err(protocol(ProtocolKind::Decode))?;
            if decoded.len() != target.profile.row_bytes {
                return Err(TxidError::Protocol(ProtocolKind::Length));
            }
            copies.push(decoded);
        }
        Ok(copies)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Method, TransportError};
    use std::collections::VecDeque;

    /// Replies from a script, recording every request.
    #[derive(Default)]
    struct Scripted {
        replies: VecDeque<Result<TxidReply, TransportError>>,
        sent: Vec<TxidRequest>,
    }

    impl TxidTransport for Scripted {
        fn send(&mut self, request: TxidRequest) -> Result<TxidReply, TransportError> {
            self.sent.push(request);
            self.replies.pop_front().expect("an unscripted request")
        }
    }

    fn reply(status: u16) -> TxidReply {
        TxidReply {
            status,
            ..TxidReply::default()
        }
    }

    fn init(codec: &str) -> TxidReply {
        TxidReply {
            status: 200,
            body: serde_json::json!({
                "schema": display::DISPLAY_SCHEMA,
                "codec": codec,
                "bucket_domain": std::str::from_utf8(display::BUCKET_DOMAIN).unwrap(),
                "native_schema": display::NATIVE_SCHEMA,
                "geometries": [],
            })
            .to_string()
            .into_bytes(),
            ..TxidReply::default()
        }
    }

    fn never() -> bool {
        false
    }

    /// A client that queries the fixtures' recent shards, which hold a
    /// handful of txids.
    fn test_client() -> TxidDisplayClient {
        TxidDisplayClient::new().with_min_recent_floor(1)
    }

    fn status_of(status: u16, retry_after: Option<&str>) -> TxidError {
        let mut transport = Scripted::default();
        transport.replies.push_back(Ok(TxidReply {
            retry_after: retry_after.map(str::to_string),
            ..reply(status)
        }));
        test_client()
            .lookup(&mut transport, [1; 32], 10, &never)
            .unwrap_err()
    }

    #[test]
    fn statuses_map_to_errors_without_retry() {
        assert_eq!(
            status_of(503, Some(" 3 ")),
            TxidError::Unavailable {
                retry_after: Some(Duration::from_secs(3))
            }
        );
        assert_eq!(
            status_of(503, Some("soon")),
            TxidError::Unavailable { retry_after: None }
        );
        assert_eq!(
            status_of(502, None),
            TxidError::Unavailable { retry_after: None }
        );
        for status in [400, 404, 408, 411, 421] {
            assert_eq!(status_of(status, None), TxidError::Refused(status));
        }
        for status in [204, 301] {
            assert_eq!(
                status_of(status, None),
                TxidError::Protocol(ProtocolKind::Status(status))
            );
        }
    }

    #[test]
    fn unsupported_init_sends_nothing_else() {
        let mut transport = Scripted::default();
        transport
            .replies
            .push_back(Ok(init("transparent-txid-display-v9")));
        let mut client = test_client();
        assert_eq!(
            client.lookup(&mut transport, [1; 32], 10, &never),
            Ok(TxidLookup::Unsupported)
        );
        // Cached: a second lookup sends nothing at all.
        assert_eq!(
            client.lookup(&mut transport, [2; 32], 10, &never),
            Ok(TxidLookup::Unsupported)
        );
        assert_eq!(transport.sent.len(), 1);
        assert_eq!(transport.sent[0].route, Route::Init);
        assert_eq!(transport.sent[0].method, Method::Get);
        assert_eq!(transport.sent[0].path(), "/v2/txid/init");
        assert!(transport.sent[0].body.is_empty());
    }

    #[test]
    fn malformed_metadata_is_protocol_and_transport_errors_pass_through() {
        let mut transport = Scripted::default();
        transport.replies.push_back(Ok(TxidReply {
            body: b"{".to_vec(),
            ..reply(200)
        }));
        assert_eq!(
            test_client().lookup(&mut transport, [1; 32], 10, &never),
            Err(TxidError::Protocol(ProtocolKind::Init))
        );
        let mut transport = Scripted::default();
        transport.replies.push_back(Ok(init(txid::CODEC)));
        let body = b"{}".to_vec();
        transport.replies.push_back(Ok(TxidReply {
            map_sha256: Some(hex::encode(Sha256::digest(&body))),
            body,
            ..reply(200)
        }));
        assert_eq!(
            test_client().lookup(&mut transport, [1; 32], 10, &never),
            Err(TxidError::Protocol(ProtocolKind::Map))
        );
        let mut transport = Scripted::default();
        transport
            .replies
            .push_back(Err(TransportError("connection refused".into())));
        assert_eq!(
            test_client().lookup(&mut transport, [1; 32], 10, &never),
            Err(TxidError::Transport(TransportError(
                "connection refused".into()
            )))
        );
    }

    fn map(start_height: u64) -> DisplayRecentMap {
        DisplayRecentMap {
            schema: display::DISPLAY_SCHEMA.into(),
            network: "main".into(),
            genesis_hash: "00".repeat(32),
            seal: display::DisplaySealParams {
                n_archive: 1,
                n_recent: 1,
                archive_target: 1,
                recent_window: 1,
                reorg_margin: 1,
            },
            start_height,
            first_shard_id: 0,
            archives: 0,
            unsealed_start: start_height,
            chunk_shards: display::INDEX_CHUNK_SHARDS,
            chunks: Vec::new(),
            recent: None,
        }
    }

    fn map_reply(body: Vec<u8>, header: Option<String>) -> Result<TxidReply, TransportError> {
        Ok(TxidReply {
            map_sha256: header,
            body,
            ..reply(200)
        })
    }

    #[test]
    fn malformed_refresh_preserves_warm_state_and_all_caches() {
        let mut valid = recent_map(100, 200, "txid-2k8");
        valid.archives = 1;
        valid.unsealed_start = 101;
        valid.recent.as_mut().unwrap().shard_id = 1;
        valid.chunks = vec![display::DisplayChunkRef {
            start_height: 100,
            sha256: "aa".repeat(32),
        }];
        valid.check_shape().unwrap();
        let mut client = test_client();
        let mut transport = Scripted::default();
        transport.replies.push_back(served(&valid));
        client.refresh_map(&mut transport, &never).unwrap();
        let cached = client.map.clone().unwrap();
        let chain = client.chain.clone();
        let layout = client.layout.clone();
        let init = Arc::new(Init {
            supported: true,
            geometries: HashMap::new(),
        });
        client.init = Some(init.clone());
        let mut archive = valid.recent.clone().unwrap();
        archive.shard_id = 0;
        archive.end_height = 100;
        archive.sealed = true;
        archive.revision = 0;
        let chunk = Arc::new(DisplayIndexChunk {
            schema: display::DISPLAY_SCHEMA.into(),
            base_shard_id: 0,
            shards: vec![archive],
        });
        valid.check_chunk(0, &chunk).unwrap();
        client
            .chunks
            .insert(valid.chunks[0].sha256.clone(), chunk.clone());
        let revision = valid.recent.as_ref().unwrap().manifest_digest.clone();
        let manifest = Arc::new(sample_manifest(false));
        client.manifests.insert(revision.clone(), manifest.clone());
        let key = (revision.clone(), DisplayTable::Directory(0), 0);
        let setup = Arc::new(Setup {
            public_params: Vec::new(),
            epoch: [0; 8],
        });
        client.setups.insert(key.clone(), setup.clone());

        let mut malformed = valid.clone();
        malformed.seal.archive_target += 1;
        malformed.chunks.clear();
        assert!(malformed.check_shape().is_err());
        transport.replies.push_back(served(&malformed));
        assert_eq!(
            client.refresh_map(&mut transport, &never),
            Err(TxidError::Protocol(ProtocolKind::Map))
        );
        assert!(Arc::ptr_eq(client.map.as_ref().unwrap(), &cached));
        assert!(client.chain == chain);
        assert!(client.layout == layout);
        assert!(Arc::ptr_eq(client.init.as_ref().unwrap(), &init));
        assert_eq!(client.chunks.len(), 1);
        assert!(Arc::ptr_eq(&client.chunks[&valid.chunks[0].sha256], &chunk));
        assert_eq!(client.manifests.len(), 1);
        assert!(Arc::ptr_eq(&client.manifests[&revision], &manifest));
        assert_eq!(client.setups.len(), 1);
        assert!(Arc::ptr_eq(&client.setups[&key], &setup));
        // A valid retry replaces the rejected response, retaining its named caches.
        valid.recent.as_mut().unwrap().end_height += 1;
        transport.replies.push_back(served(&valid));
        client.refresh_map(&mut transport, &never).unwrap();
        assert_eq!(client.map_sha256(), Some(valid.sha256().as_str()));
        assert!(!Arc::ptr_eq(client.map.as_ref().unwrap(), &cached));
        assert!(Arc::ptr_eq(&client.manifests[&revision], &manifest));
        assert!(Arc::ptr_eq(&client.setups[&key], &setup));
        assert!(transport.replies.is_empty());
    }

    #[test]
    fn malformed_first_map_does_not_pin_its_chain() {
        let valid = recent_map(100, 200, "txid-2k8");
        let mut malformed = valid.clone();
        malformed.network = "another chain".into();
        malformed.chunk_shards = 0;
        let mut transport = Scripted::default();
        transport
            .replies
            .extend([served(&malformed), served(&valid)]);
        let mut client = test_client();
        assert_eq!(
            client.refresh_map(&mut transport, &never),
            Err(TxidError::Protocol(ProtocolKind::Map))
        );
        assert!(client.map.is_none());
        assert!(client.chain.is_none());
        assert!(client.layout.is_none());
        client.refresh_map(&mut transport, &never).unwrap();
        assert_eq!(client.map_sha256(), Some(valid.sha256().as_str()));
    }

    #[test]
    fn refresh_map_validates_and_replaces_only_on_success() {
        let (a, b) = (
            recent_map(10, 19, "txid-2k8"),
            recent_map(20, 29, "txid-2k8"),
        );
        let digest = |m: &DisplayRecentMap| -> [u8; 32] { Sha256::digest(m.to_bytes()).into() };
        let mut transport = Scripted::default();
        transport
            .replies
            .push_back(map_reply(a.to_bytes(), Some(a.sha256())));
        // A wrong header, a missing header, a non-canonical body, then 503.
        transport
            .replies
            .push_back(map_reply(b.to_bytes(), Some(a.sha256())));
        transport.replies.push_back(map_reply(b.to_bytes(), None));
        let pretty = serde_json::to_vec_pretty(&b).unwrap();
        let pretty_sha = hex::encode(Sha256::digest(&pretty));
        transport
            .replies
            .push_back(map_reply(pretty, Some(pretty_sha)));
        transport.replies.push_back(Ok(TxidReply {
            retry_after: Some("2".into()),
            ..reply(503)
        }));
        transport
            .replies
            .push_back(map_reply(b.to_bytes(), Some(b.sha256())));

        let mut client = test_client();
        assert_eq!(client.map_sha256(), None);
        assert_eq!(client.refresh_map(&mut transport, &never), Ok(digest(&a)));
        assert_eq!(client.map_sha256(), Some(a.sha256().as_str()));
        for expected in [
            TxidError::Protocol(ProtocolKind::MapHeader),
            TxidError::Protocol(ProtocolKind::MapHeader),
            TxidError::Protocol(ProtocolKind::MapCanonical),
            TxidError::Unavailable {
                retry_after: Some(Duration::from_secs(2)),
            },
        ] {
            assert_eq!(client.refresh_map(&mut transport, &never), Err(expected));
            assert_eq!(client.map_sha256(), Some(a.sha256().as_str()));
        }
        assert_eq!(client.refresh_map(&mut transport, &never), Ok(digest(&b)));
        assert_eq!(client.map_sha256(), Some(b.sha256().as_str()));
        assert_eq!(
            client.refresh_map(&mut transport, &|| true),
            Err(TxidError::Cancelled)
        );
        // Only the map was ever asked for: no init, no query.
        assert_eq!(transport.sent.len(), 6);
        assert!(transport
            .sent
            .iter()
            .all(|r| r.route == Route::Map && r.method == Method::Get));
    }

    #[test]
    fn cancel_is_checked_before_the_first_request() {
        let mut transport = Scripted::default();
        assert_eq!(
            test_client().lookup(&mut transport, [1; 32], 10, &|| true),
            Err(TxidError::Cancelled)
        );
        assert!(transport.sent.is_empty());
    }

    #[test]
    fn templates_carry_no_identifiers() {
        for route in Route::ALL {
            let template = route.template();
            assert!(template.starts_with("/v2/txid/"));
            assert!(!template["/v1".len()..].contains(|c: char| c.is_ascii_digit()));
            assert_eq!(route.method() == Method::Post, route == Route::Query);
        }
        let request = TxidRequest::new(Route::Query, "/x".into(), vec![1]);
        assert_eq!(request.content_type(), Some("application/octet-stream"));
        assert_eq!(request.template(), Route::Query.template());
    }

    /// An init document listing `geometries`. The listed parameters are
    /// placeholders: these lookups end before a profile is compared.
    fn init_with(geometries: &[&str]) -> TxidReply {
        let scheme = NativeScheme {
            profile: String::new(),
            d: 0,
            q_bits: 0,
            p_bits: 0,
            gadget_bits: 0,
            ell: 0,
            secret: String::new(),
            mask_bits: 0,
            query_bits: 0,
            response_bits: 0,
            rows: 0,
            row_bytes: 0,
            cols: 0,
            native_encoding: String::new(),
            query_mask_seed: String::new(),
            packing_setup_id: String::new(),
            request_bytes: 0,
            public_bytes: 0,
            response_bytes: 0,
        };
        let mut reply = init(txid::CODEC);
        let mut document: serde_json::Value = serde_json::from_slice(&reply.body).unwrap();
        document["geometries"] = geometries
            .iter()
            .map(|name| {
                serde_json::json!({
                    "name": name,
                    "txdirectory": {
                        "rows": 0,
                        "row_bytes": 0,
                        "scheme": scheme,
                        "setup_seed": 0,
                    },
                })
            })
            .collect();
        reply.body = document.to_string().into_bytes();
        reply
    }

    fn hex_of(text: &str) -> String {
        hex::encode(Sha256::digest(text))
    }

    /// A map of one recent shard over `start..=end` in `geometry`.
    fn recent_map(start: u64, end: u64, geometry: &str) -> DisplayRecentMap {
        DisplayRecentMap {
            recent: Some(DisplayMapEntry {
                shard_id: 0,
                start_height: start,
                end_height: end,
                parent_block_hash: hex_of(&format!("block {}", start - 1)),
                terminal_block_hash: hex_of(&format!("block {end}")),
                geometry: geometry.into(),
                n_buckets: 1,
                directory_segments: vec![1],
                placement_seeds: vec![0],
                records: 10,
                min_bucket_records: 10,
                manifest_digest: hex_of(&format!("recent {start} {end} {geometry}")),
                revision: 3,
                sealed: false,
            }),
            ..map(start)
        }
    }

    fn served(map: &DisplayRecentMap) -> Result<TxidReply, TransportError> {
        map_reply(map.to_bytes(), Some(map.sha256()))
    }

    /// 503, which ends a lookup at the request it answers.
    fn busy() -> Result<TxidReply, TransportError> {
        Ok(reply(503))
    }

    /// The routes sent since the last call; every scripted reply was used.
    fn sent(transport: &mut Scripted) -> Vec<Route> {
        assert!(transport.replies.is_empty(), "unused replies");
        transport.sent.drain(..).map(|r| r.route).collect()
    }

    /// Sets the cached map's wall-clock fetch time to `at`.
    fn fetched_at(client: &mut TxidDisplayClient, at: SystemTime) {
        let cached = client.map.take().unwrap();
        client.map = Some(Arc::new(CachedMap {
            map: cached.map.clone(),
            sha256: cached.sha256.clone(),
            fetched: at,
        }));
    }

    /// Makes the cached map as old as [`PLACEMENT_REFRESH_AGE`].
    fn age(client: &mut TxidDisplayClient) {
        fetched_at(client, SystemTime::now() - PLACEMENT_REFRESH_AGE);
    }

    const BUSY: TxidError = TxidError::Unavailable { retry_after: None };

    fn placed(placement: Placement) -> Result<TxidLookup, TxidError> {
        Ok(TxidLookup::PlacementUnknown(placement))
    }

    /// A valid one-bucket `txid-2k8` manifest of shard 0 over 100..=109.
    fn sample_manifest(sealed: bool) -> DisplayManifest {
        let entries: Vec<_> = (0u8..4)
            .map(|i| {
                txid::DisplayFacts {
                    txid: Txid([i; 32]),
                    coinbase: false,
                    fee: 1,
                    has_shielded_components: false,
                    spent: vec![txid::DisplayOutput {
                        value: 2,
                        script: vec![0; 25],
                    }],
                    outputs: vec![txid::DisplayOutput {
                        value: 1,
                        script: vec![0; 25],
                    }],
                }
                .entry()
                .unwrap()
            })
            .collect();
        let built = display::build_shard(0, &display::TXID_2K8, 1, &entries).unwrap();
        let manifest = DisplayManifest::new(
            display::ManifestHeader {
                network: "main".into(),
                genesis_hash: "00".repeat(32),
                shard_id: 0,
                start_height: 100,
                end_height: 109,
                parent_block_hash: "11".repeat(32),
                terminal_block_hash: "22".repeat(32),
                parent_manifest_digest: String::new(),
                sealed,
                revision: if sealed { 0 } else { 3 },
                supersedes: String::new(),
                archive_target: 1,
            },
            &display::TXID_2K8,
            &built,
        );
        manifest.validate().unwrap();
        manifest
    }

    #[test]
    fn a_stale_map_is_fetched_again_before_a_placement() {
        let old = recent_map(100, 200, "txid-2k8");
        let mut transport = Scripted::default();
        transport.replies.push_back(Ok(init_with(&["txid-2k8"])));
        transport.replies.push_back(served(&old));
        let mut client = test_client();
        // A fresh map places a height below or above it with no request.
        assert_eq!(
            client.lookup(&mut transport, [1; 32], 60, &never),
            placed(Placement::Below)
        );
        assert_eq!(
            client.lookup(&mut transport, [1; 32], 250, &never),
            placed(Placement::Above)
        );
        assert_eq!(sent(&mut transport), [Route::Init, Route::Map]);

        // A stale one is fetched once, and the placement is the new map's.
        // So is one fetched "after" now: the wall clock went back.
        for (height, placement, back) in [
            (60, Placement::Below, false),
            (250, Placement::Above, false),
            (60, Placement::Below, true),
        ] {
            if back {
                fetched_at(&mut client, SystemTime::now() + Duration::from_secs(3_600));
            } else {
                age(&mut client);
            }
            transport.replies.push_back(served(&old));
            assert_eq!(
                client.lookup(&mut transport, [1; 32], height, &never),
                placed(placement)
            );
            assert_eq!(sent(&mut transport), [Route::Map]);
        }

        // A new publication starting lower or reaching further covers the
        // height, and the lookup goes on to the shard.
        age(&mut client);
        transport
            .replies
            .extend([served(&recent_map(50, 200, "txid-2k8")), busy()]);
        assert_eq!(
            client.lookup(&mut transport, [1; 32], 60, &never),
            Err(BUSY)
        );
        assert_eq!(sent(&mut transport), [Route::Map, Route::Manifest]);
        age(&mut client);
        transport
            .replies
            .extend([served(&recent_map(50, 300, "txid-2k8")), busy()]);
        assert_eq!(
            client.lookup(&mut transport, [1; 32], 250, &never),
            Err(BUSY)
        );
        assert_eq!(sent(&mut transport), [Route::Map, Route::Manifest]);
    }

    #[test]
    fn a_placement_refresh_is_taken_once_per_lookup() {
        let map = recent_map(100, 200, "txid-2k8");
        let mut transport = Scripted::default();
        transport.replies.push_back(Ok(init_with(&["txid-2k8"])));
        transport.replies.push_back(served(&map));
        let mut client = test_client().with_placement_refresh_age(Duration::ZERO);
        // A map this lookup fetched is final, however old.
        assert_eq!(
            client.lookup(&mut transport, [1; 32], 60, &never),
            placed(Placement::Below)
        );
        assert_eq!(sent(&mut transport), [Route::Init, Route::Map]);
        // A later lookup fetches it once, and no more.
        for height in [60, 250] {
            transport.replies.push_back(served(&map));
            assert!(matches!(
                client.lookup(&mut transport, [1; 32], height, &never),
                Ok(TxidLookup::PlacementUnknown(_))
            ));
            assert_eq!(sent(&mut transport), [Route::Map]);
        }
        // A height the map covers is not a placement: nothing is refetched.
        transport.replies.push_back(busy());
        assert_eq!(
            client.lookup(&mut transport, [1; 32], 150, &never),
            Err(BUSY)
        );
        assert_eq!(sent(&mut transport), [Route::Manifest]);
    }

    #[test]
    fn a_failed_placement_refresh_is_an_error_not_a_placement() {
        let map = recent_map(100, 200, "txid-2k8");
        let mut transport = Scripted::default();
        transport
            .replies
            .extend([Ok(init_with(&["txid-2k8"])), served(&map)]);
        let mut client = test_client();
        assert_eq!(
            client.lookup(&mut transport, [1; 32], 60, &never),
            placed(Placement::Below)
        );
        assert_eq!(sent(&mut transport), [Route::Init, Route::Map]);
        // Once stale, a placement waits on the refresh, and its failure is
        // the lookup's error; the map held is kept.
        let held = client.map_sha256().unwrap().to_string();
        for (reply, expected) in [
            (
                Ok(TxidReply {
                    retry_after: Some("5".into()),
                    ..reply(503)
                }),
                TxidError::Unavailable {
                    retry_after: Some(Duration::from_secs(5)),
                },
            ),
            (
                Err(TransportError("reset".into())),
                TxidError::Transport(TransportError("reset".into())),
            ),
            (Ok(reply(404)), TxidError::Refused(404)),
        ] {
            age(&mut client);
            transport.replies.push_back(reply);
            assert_eq!(
                client.lookup(&mut transport, [1; 32], 60, &never),
                Err(expected)
            );
            assert_eq!(sent(&mut transport), [Route::Map]);
            assert_eq!(client.map_sha256(), Some(held.as_str()));
        }
        // Cancelled before the refresh: nothing is sent.
        age(&mut client);
        assert_eq!(
            client.lookup(&mut transport, [1; 32], 60, &|| true),
            Err(TxidError::Cancelled)
        );
        assert!(sent(&mut transport).is_empty());
    }

    #[test]
    fn a_geometry_init_lacks_refetches_init_and_the_map_once() {
        let map = recent_map(100, 200, "txid-2k8");
        let mut transport = Scripted::default();
        // Init lacks the geometry the map names: a lookup that fetched both
        // has nothing to refetch.
        transport.replies.extend([Ok(init_with(&[])), served(&map)]);
        let mut client = test_client();
        assert_eq!(
            client.lookup(&mut transport, [1; 32], 150, &never),
            Ok(TxidLookup::Unsupported)
        );
        assert_eq!(sent(&mut transport), [Route::Init, Route::Map]);

        // The publication now serves it. Init, cached from before, is
        // fetched again and lists it; so is the map, which this lookup had
        // not fetched.
        transport
            .replies
            .extend([Ok(init_with(&["txid-2k8"])), served(&map), busy()]);
        assert_eq!(
            client.lookup(&mut transport, [1; 32], 150, &never),
            Err(BUSY)
        );
        assert_eq!(
            sent(&mut transport),
            [Route::Init, Route::Map, Route::Manifest]
        );
        transport.replies.push_back(busy());
        assert_eq!(
            client.lookup(&mut transport, [1; 32], 150, &never),
            Err(BUSY)
        );
        assert_eq!(sent(&mut transport), [Route::Manifest]);

        // A server whose init keeps lacking it: no refetch in a lookup that
        // fetched both, then one of each per lookup, never a query.
        let mut client = test_client();
        transport.replies.extend([Ok(init_with(&[])), served(&map)]);
        assert_eq!(
            client.lookup(&mut transport, [1; 32], 150, &never),
            Ok(TxidLookup::Unsupported)
        );
        assert_eq!(sent(&mut transport), [Route::Init, Route::Map]);
        for _ in 0..2 {
            transport.replies.extend([Ok(init_with(&[])), served(&map)]);
            assert_eq!(
                client.lookup(&mut transport, [1; 32], 150, &never),
                Ok(TxidLookup::Unsupported)
            );
            assert_eq!(sent(&mut transport), [Route::Init, Route::Map]);
        }
    }

    #[test]
    fn a_map_older_than_init_is_fetched_again_for_a_missing_geometry() {
        // The client holds a map naming a geometry this lookup's init lacks:
        // the map may be the stale document, so it is fetched again rather
        // than returning `Unsupported` for every lookup it covers.
        let mut transport = Scripted::default();
        transport
            .replies
            .push_back(served(&recent_map(100, 200, "txid-2k8")));
        let mut client = test_client();
        client.refresh_map(&mut transport, &never).unwrap();
        transport.replies.extend([
            Ok(init_with(&[])),
            served(&recent_map(100, 201, "txid-2k8")),
        ]);
        assert_eq!(
            client.lookup(&mut transport, [1; 32], 150, &never),
            Ok(TxidLookup::Unsupported)
        );
        assert_eq!(sent(&mut transport), [Route::Map, Route::Init, Route::Map]);
    }

    #[test]
    fn a_new_layout_refetches_init_and_another_chain_is_refused() {
        let mut transport = Scripted::default();
        transport.replies.extend([
            Ok(init_with(&["txid-2k8"])),
            served(&recent_map(100, 200, "txid-2k8")),
            busy(),
        ]);
        let mut client = test_client();
        assert_eq!(
            client.lookup(&mut transport, [1; 32], 150, &never),
            Err(BUSY)
        );
        assert_eq!(
            sent(&mut transport),
            [Route::Init, Route::Map, Route::Manifest]
        );

        // The recent shard moves: the same layout, init kept.
        transport
            .replies
            .extend([served(&recent_map(100, 201, "txid-2k8")), busy()]);
        client.refresh_map(&mut transport, &never).unwrap();
        assert_eq!(
            client.lookup(&mut transport, [1; 32], 150, &never),
            Err(BUSY)
        );
        assert_eq!(sent(&mut transport), [Route::Map, Route::Manifest]);

        // Other seal parameters: init is fetched again, also after the map
        // was dropped.
        let seals: [fn(&mut DisplaySealParams); 2] =
            [|seal| seal.archive_target = 2, |seal| seal.reorg_margin = 2];
        for (index, mutate) in seals.into_iter().enumerate() {
            let mut other = recent_map(100, 202 + index as u64, "txid-2k8");
            mutate(&mut other.seal);
            if index == 1 {
                client.invalidate_map();
            }
            transport.replies.push_back(served(&other));
            client.refresh_map(&mut transport, &never).unwrap();
            transport
                .replies
                .extend([Ok(init_with(&["txid-2k8"])), busy()]);
            assert_eq!(
                client.lookup(&mut transport, [1; 32], 150, &never),
                Err(BUSY)
            );
            assert_eq!(
                sent(&mut transport),
                [Route::Map, Route::Init, Route::Manifest],
                "{index}"
            );
        }
        let current = recent_map(100, 203, "txid-2k8");
        let mut current_seal = current.clone();
        current_seal.seal.reorg_margin = 2;
        assert_eq!(client.map_sha256(), Some(current_seal.sha256().as_str()));

        // Another network or genesis is another chain: refused, and the map
        // held is kept, also after it was dropped.
        let chains: [fn(&mut DisplayRecentMap); 2] = [
            |m| m.network = "test".into(),
            |m| m.genesis_hash = "11".repeat(32),
        ];
        for mutate in chains {
            let mut other = current_seal.clone();
            mutate(&mut other);
            transport.replies.push_back(served(&other));
            assert_eq!(
                client.refresh_map(&mut transport, &never),
                Err(TxidError::Protocol(ProtocolKind::Map))
            );
            assert_eq!(client.map_sha256(), Some(current_seal.sha256().as_str()));
            client.invalidate_map();
            transport.replies.push_back(served(&other));
            assert_eq!(
                client.lookup(&mut transport, [1; 32], 150, &never),
                Err(TxidError::Protocol(ProtocolKind::Map))
            );
            assert_eq!(sent(&mut transport), [Route::Map, Route::Map]);
            transport.replies.push_back(served(&current_seal));
            client.refresh_map(&mut transport, &never).unwrap();
            sent(&mut transport);
        }

        // Within a lookup: a 409 brings a map of another layout, whose init
        // this client does not support. Lookups then send nothing, until
        // `refresh_map` drops the unsupported init.
        let mut other = recent_map(100, 210, "txid-2k8");
        other.seal.recent_window = 2;
        transport.replies.extend([
            Ok(reply(409)),
            served(&other),
            Ok(init("transparent-txid-display-v9")),
        ]);
        assert_eq!(
            client.lookup(&mut transport, [1; 32], 150, &never),
            Ok(TxidLookup::Unsupported)
        );
        assert_eq!(
            sent(&mut transport),
            [Route::Manifest, Route::Map, Route::Init]
        );
        assert_eq!(
            client.lookup(&mut transport, [1; 32], 150, &never),
            Ok(TxidLookup::Unsupported)
        );
        assert!(sent(&mut transport).is_empty());
        transport
            .replies
            .extend([served(&other), Ok(init_with(&["txid-2k8"])), busy()]);
        client.refresh_map(&mut transport, &never).unwrap();
        assert_eq!(
            client.lookup(&mut transport, [1; 32], 150, &never),
            Err(BUSY)
        );
        assert_eq!(
            sent(&mut transport),
            [Route::Map, Route::Init, Route::Manifest]
        );
    }

    /// A map of one recent shard over 100..=200 whose bucket holds
    /// `records` txids, advertising `recent_window`.
    fn thin_map(records: u64, recent_window: u64) -> DisplayRecentMap {
        let mut map = recent_map(100, 200, "txid-2k8");
        map.seal.recent_window = recent_window;
        let recent = map.recent.as_mut().unwrap();
        recent.records = records;
        recent.min_bucket_records = records;
        map
    }

    #[test]
    fn a_recent_shard_below_the_floor_is_not_queried() {
        // The map advertises `recent_window` 1; the client's own floor holds.
        let thin = thin_map(MIN_RECENT_FLOOR - 1, 1);
        let mut transport = Scripted::default();
        transport
            .replies
            .extend([Ok(init_with(&["txid-2k8"])), served(&thin)]);
        let mut client = TxidDisplayClient::new();
        for txid in [[1; 32], [2; 32]] {
            assert_eq!(
                client.lookup(&mut transport, txid, 150, &never),
                Ok(TxidLookup::RecentBelowFloor)
            );
        }
        // Init and the map once; no manifest, setup or query.
        assert_eq!(sent(&mut transport), [Route::Init, Route::Map]);

        // At exactly the floor the lookup goes on to the shard.
        let mut transport = Scripted::default();
        transport.replies.extend([
            Ok(init_with(&["txid-2k8"])),
            served(&thin_map(MIN_RECENT_FLOOR, 1)),
            busy(),
        ]);
        assert_eq!(
            TxidDisplayClient::new().lookup(&mut transport, [1; 32], 150, &never),
            Err(BUSY)
        );
        assert_eq!(
            sent(&mut transport),
            [Route::Init, Route::Map, Route::Manifest]
        );
    }

    #[test]
    fn the_floor_is_the_larger_of_the_maps_and_the_clients() {
        // A map floor above the client's applies too.
        for (records, expected) in [(19, None), (20, Some(Route::Manifest))] {
            let mut transport = Scripted::default();
            transport
                .replies
                .extend([Ok(init_with(&["txid-2k8"])), served(&thin_map(records, 20))]);
            if expected.is_some() {
                transport.replies.push_back(busy());
            }
            let found = test_client().lookup(&mut transport, [1; 32], 150, &never);
            assert_eq!(
                found,
                match expected {
                    None => Ok(TxidLookup::RecentBelowFloor),
                    Some(_) => Err(BUSY),
                }
            );
            let routes: Vec<_> = [Route::Init, Route::Map]
                .into_iter()
                .chain(expected)
                .collect();
            assert_eq!(sent(&mut transport), routes);
        }
    }

    #[test]
    fn a_thin_recent_shard_in_a_stale_map_is_checked_against_the_current_map() {
        let mut transport = Scripted::default();
        transport
            .replies
            .extend([Ok(init_with(&["txid-2k8"])), served(&thin_map(5, 10))]);
        let mut client = test_client();
        assert_eq!(
            client.lookup(&mut transport, [1; 32], 150, &never),
            Ok(TxidLookup::RecentBelowFloor)
        );
        assert_eq!(sent(&mut transport), [Route::Init, Route::Map]);
        // Once the map is old, the shard may have grown: the map is fetched
        // again, once, and the lookup follows it.
        age(&mut client);
        transport.replies.push_back(served(&thin_map(5, 10)));
        assert_eq!(
            client.lookup(&mut transport, [1; 32], 150, &never),
            Ok(TxidLookup::RecentBelowFloor)
        );
        assert_eq!(sent(&mut transport), [Route::Map]);
        age(&mut client);
        transport
            .replies
            .extend([served(&thin_map(10, 10)), busy()]);
        assert_eq!(
            client.lookup(&mut transport, [1; 32], 150, &never),
            Err(BUSY)
        );
        assert_eq!(sent(&mut transport), [Route::Map, Route::Manifest]);
    }

    #[test]
    fn a_cached_manifest_must_still_describe_the_entry() {
        let manifest = sample_manifest(false);
        let digest = manifest.digest();
        let mut map = map(100);
        map.recent = Some(DisplayMapEntry::from_manifest(&manifest, &digest));
        // Same digest, another entry: the shape check passes, the cached
        // manifest does not describe it.
        map.recent.as_mut().unwrap().records += 1;
        map.check_shape().unwrap();
        let mut client = test_client();
        client.manifests.insert(digest, Arc::new(manifest));
        let mut transport = Scripted::default();
        transport
            .replies
            .extend([Ok(init_with(&["txid-2k8"])), served(&map)]);
        assert_eq!(
            client.lookup(&mut transport, [1; 32], 105, &never),
            Err(TxidError::Protocol(ProtocolKind::Manifest))
        );
        assert_eq!(sent(&mut transport), [Route::Init, Route::Map]);
    }

    #[test]
    fn a_map_with_no_bucket_or_too_many_is_refused_before_any_query() {
        let none = |m: &mut DisplayRecentMap| {
            m.seal.n_recent = 0;
            let recent = m.recent.as_mut().unwrap();
            recent.n_buckets = 0;
            recent.directory_segments.clear();
        };
        let excess = |m: &mut DisplayRecentMap| {
            m.seal.n_recent = display::MAX_BUCKETS + 1;
            let recent = m.recent.as_mut().unwrap();
            recent.n_buckets = m.seal.n_recent;
            recent.directory_segments = vec![1; m.seal.n_recent as usize];
        };
        for mutate in [none, excess] {
            let mut hostile = recent_map(100, 200, "txid-2k8");
            mutate(&mut hostile);
            let mut transport = Scripted::default();
            transport
                .replies
                .extend([Ok(init_with(&["txid-2k8"])), served(&hostile)]);
            assert_eq!(
                test_client().lookup(&mut transport, [1; 32], 150, &never),
                Err(TxidError::Protocol(ProtocolKind::Map))
            );
            assert_eq!(sent(&mut transport), [Route::Init, Route::Map]);
        }
    }

    #[test]
    fn a_new_map_keeps_only_the_revisions_it_names() {
        // Retention reads digests only, so one manifest stands in for all.
        let manifest = Arc::new(sample_manifest(true));
        let setup = Arc::new(Setup {
            public_params: Vec::new(),
            epoch: [0; 8],
        });
        let digest = |n: u8| format!("{n:02x}").repeat(32);
        let archive = |shard_id: u64, n: u8| DisplayMapEntry {
            shard_id,
            sealed: true,
            revision: 0,
            manifest_digest: digest(n),
            ..recent_map(100, 109, "txid-2k8").recent.unwrap()
        };
        let chunk = |base_shard_id: u64, shards: Vec<DisplayMapEntry>| {
            Arc::new(DisplayIndexChunk {
                schema: display::DISPLAY_SCHEMA.into(),
                base_shard_id,
                shards,
            })
        };
        let mut client = test_client();
        // Chunk 0xa0 lists archives 0 and 1 (revisions 1, 2); chunk 0xa1
        // lists archive 32 (revision 3); revision 4 is the recent shard's.
        client
            .chunks
            .insert(digest(0xa0), chunk(0, vec![archive(0, 1), archive(1, 2)]));
        client
            .chunks
            .insert(digest(0xa1), chunk(32, vec![archive(32, 3)]));
        for n in 1..=4 {
            client.manifests.insert(digest(n), manifest.clone());
            client
                .setups
                .insert((digest(n), DisplayTable::Directory(0), 0), setup.clone());
        }
        let mut next = recent_map(100, 300, "txid-2k8");
        let named = |chunks: &[u8]| {
            chunks
                .iter()
                .enumerate()
                .map(|(index, &n)| display::DisplayChunkRef {
                    start_height: 100 + index as u64 * display::INDEX_CHUNK_SHARDS,
                    sha256: digest(n),
                })
                .collect::<Vec<_>>()
        };
        let mut transport = Scripted::default();

        // A seal replaced chunk 0xa1 and a block the recent revision: the
        // archives of chunk 0xa0 stay, the rest goes.
        next.chunks = named(&[0xa0, 0xb1]);
        next.archives = 33;
        next.unsealed_start = 133;
        next.recent.as_mut().unwrap().shard_id = 33;
        next.check_shape().unwrap();
        transport.replies.push_back(served(&next));
        client.refresh_map(&mut transport, &never).unwrap();
        assert_eq!(client.cached_revisions(), [digest(1), digest(2)]);
        assert_eq!(client.chunks.keys().collect::<Vec<_>>(), [&digest(0xa0)]);
        // The recent revision the map names keeps its manifest and setups.
        let recent = next.recent.as_ref().unwrap().manifest_digest.clone();
        client.manifests.insert(recent.clone(), manifest.clone());
        client.setups.insert(
            (recent.clone(), DisplayTable::Directory(0), 0),
            setup.clone(),
        );
        transport.replies.push_back(served(&next));
        client.refresh_map(&mut transport, &never).unwrap();
        let mut kept = vec![digest(1), digest(2), recent];
        kept.sort();
        assert_eq!(client.cached_revisions(), kept);

        // A fresh publication reuses shard ids 0 and 1 under new digests:
        // nothing of the old one stays, whatever ids it had.
        let mut fresh = recent_map(50, 300, "txid-2k8");
        fresh.chunks = named(&[0xc0]);
        fresh.chunks[0].start_height = fresh.start_height;
        fresh.archives = 1;
        fresh.unsealed_start = fresh.start_height + 1;
        fresh.recent.as_mut().unwrap().shard_id = 1;
        fresh.check_shape().unwrap();
        transport.replies.push_back(served(&fresh));
        client.refresh_map(&mut transport, &never).unwrap();
        assert!(client.cached_revisions().is_empty());
        assert!(client.chunks.is_empty());
        assert!(transport.replies.is_empty());
    }
}
