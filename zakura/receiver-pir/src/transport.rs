//! Receiver discovery over a caller-supplied, bounded transport.
//!
//! Routes never name a receiver: inventory heads and chunks, shard filters (addressed by
//! digest) and PIR setup are public, and payment and witness rows are selected inside PIR.
use crate::{
    inventory::{Capture, DescriptorCache, Head, Inventory, MAX_CAPTURE_BYTES, MAX_CHUNK_BYTES},
    public_bytes, response_bytes, Client, Error, Publication, WitnessClient, MAX_MANIFEST_BYTES,
};
use receiver_directory::{
    shards::ShardFilter, witness::PAYLOAD_BYTES, Hash, RawRecord, ReceiverBytes,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

/// Hosts supply their route policy, cancellation, and timeout for every request.
/// Enforce `limit` while streaming, reject non-success responses, and map HTTP
/// 410 to [`Error::Revision`]. Do not follow redirects or retry in cleartext.
#[allow(async_fn_in_trait)]
pub trait Transport {
    /// GET `url`, returning a body of at most `limit` bytes.
    async fn get(&self, url: &str, limit: usize) -> Result<Vec<u8>, Error>;
    /// POST `body` to `url`, returning a body of at most `limit` bytes.
    async fn post(&self, url: &str, body: Vec<u8>, limit: usize) -> Result<Vec<u8>, Error>;
}

impl<T: Transport> Transport for &T {
    async fn get(&self, url: &str, limit: usize) -> Result<Vec<u8>, Error> {
        T::get(self, url, limit).await
    }
    async fn post(&self, url: &str, body: Vec<u8>, limit: usize) -> Result<Vec<u8>, Error> {
        T::post(self, url, body, limit).await
    }
}

/// Durable storage the host provides for verified shard descriptors, so a capture can skip
/// chunks that cannot have changed. It holds one opaque value. A lost, stale or corrupted
/// value only costs a full capture, never a wrong inventory.
pub trait DescriptorStore {
    /// The value last saved, if any.
    fn load(&self) -> Option<Vec<u8>>;
    /// Replaces the saved value. A failed save may be dropped.
    fn save(&self, value: &[u8]);
}

/// One segment's payment and companion witness PIR sessions.
pub struct Segment {
    publication: Publication,
    client: Client,
    witnesses: WitnessClient,
}

impl Segment {
    /// Downloads both sessions' public setup and checks it against their digests.
    async fn connect<T: Transport>(
        origin: &str,
        http: &T,
        publication: Publication,
    ) -> Result<Self, Error> {
        publication.validate()?;
        let payments = &publication.payments;
        let public = http
            .get(
                &format!(
                    "{origin}/v1/receiver/public/{}",
                    hex::encode(payments.id()?)
                ),
                public_bytes(payments.directory.rows)?,
            )
            .await?;
        let client = Client::new(payments.clone(), &public)?;
        let witness = &publication.witnesses;
        let public = http
            .get(
                &format!("{origin}/v1/receiver/public/{}", hex::encode(witness.id()?)),
                public_bytes(witness.table.rows)?,
            )
            .await?;
        let witnesses = WitnessClient::new(witness.clone(), &public)?;
        Ok(Self {
            publication,
            client,
            witnesses,
        })
    }

    /// The payment and witness sessions.
    pub fn publication(&self) -> &Publication {
        &self.publication
    }
}

/// Why a capture failed: a check of a saved descriptor, or of data this capture fetched.
enum Fetched {
    Cached(Error),
    Fresh(Error),
}

impl Fetched {
    /// The underlying error.
    fn into_error(self) -> Error {
        match self {
            Fetched::Cached(e) | Fetched::Fresh(e) => e,
        }
    }
}

/// Bounded public reads of one network's inventory, before any PIR session opens.
pub struct Inventories;

impl Inventories {
    /// Downloads the small publication head, checking its protocol and network. Select a
    /// local chain anchor for its end before capturing the inventory it names.
    pub async fn head<T: Transport>(origin: &str, http: &T, genesis: &Hash) -> Result<Head, Error> {
        let bytes = http
            .get(
                &format!("{}/v1/receiver/inventory", origin.trim_end_matches('/')),
                MAX_MANIFEST_BYTES,
            )
            .await?;
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(Error::Malformed);
        }
        let head: Head = serde_json::from_slice(&bytes)?;
        head.validate(genesis)?;
        Ok(head)
    }

    /// Downloads every chunk of `head`'s inventory and proves the list complete, within
    /// [`MAX_CAPTURE_BYTES`]. A missing chunk or a replaced inventory is an error, never a
    /// shorter history.
    pub async fn capture<T: Transport>(
        origin: &str,
        http: &T,
        head: Head,
    ) -> Result<Inventory, Error> {
        Self::capture_within(origin, http, head, MAX_CAPTURE_BYTES).await
    }

    /// [`Self::capture`], retaining at most `budget` serialized bytes. Each chunk is checked
    /// as it arrives, so the first malformed one ends the capture.
    pub async fn capture_within<T: Transport>(
        origin: &str,
        http: &T,
        head: Head,
        budget: usize,
    ) -> Result<Inventory, Error> {
        Self::fetch(origin, http, head, budget, None)
            .await
            .map_err(Fetched::into_error)
    }

    /// [`Self::capture`], reusing settled shard descriptors from `store` for whole chunks
    /// and downloading only the rest: new shards, sealed shards whose witnesses are still
    /// provisional, and the recent tier. The result is proved complete against the head
    /// exactly as a full capture is. If it fails, the capture is repeated without the cache.
    /// Either way the verified inventory's settled descriptors replace the saved value.
    pub async fn capture_cached<T: Transport, S: DescriptorStore>(
        origin: &str,
        http: &T,
        head: Head,
        store: &S,
    ) -> Result<Inventory, Error> {
        Self::capture_cached_within(origin, http, head, store, MAX_CAPTURE_BYTES).await
    }

    /// [`Self::capture_cached`], retaining at most `budget` serialized bytes, cached chunks
    /// included.
    pub async fn capture_cached_within<T: Transport, S: DescriptorStore>(
        origin: &str,
        http: &T,
        head: Head,
        store: &S,
        budget: usize,
    ) -> Result<Inventory, Error> {
        let saved = store.load();
        let cache = saved
            .as_deref()
            .and_then(|bytes| DescriptorCache::decode(bytes, &head));
        let inventory = match &cache {
            Some(cache) => match Self::fetch(origin, http, head.clone(), budget, Some(cache)).await
            {
                Ok(inventory) => inventory,
                // Neither comes from a cached descriptor, so a full capture would repeat it.
                Err(Fetched::Fresh(e @ (Error::Transport(_) | Error::Unsupported))) => {
                    return Err(e);
                }
                // Anything else may come from the saved descriptors, which a full capture
                // replaces once verified.
                Err(_) => Self::fetch(origin, http, head, budget, None)
                    .await
                    .map_err(Fetched::into_error)?,
            },
            None => Self::fetch(origin, http, head, budget, None)
                .await
                .map_err(Fetched::into_error)?,
        };
        if let Ok(bytes) = DescriptorCache::of(&inventory).encode() {
            if saved.as_deref() != Some(&bytes[..]) {
                store.save(&bytes);
            }
        }
        Ok(inventory)
    }

    /// Captures `head`'s inventory chunk by chunk, taking each chunk `cache` holds whole
    /// from it and downloading the others.
    async fn fetch<T: Transport>(
        origin: &str,
        http: &T,
        head: Head,
        budget: usize,
        cache: Option<&DescriptorCache>,
    ) -> Result<Inventory, Fetched> {
        let origin = origin.trim_end_matches('/');
        let inventory = hex::encode(head.inventory);
        let mut capture = Capture::new(head.clone(), budget).map_err(Fetched::Fresh)?;
        let mut cached = false;
        while let Some(index) = capture.next_chunk() {
            if let Some(shards) = cache.and_then(|cache| cache.chunk(&head, index)) {
                capture.push_cached(shards).map_err(Fetched::Cached)?;
                cached = true;
                continue;
            }
            let bytes = http
                .get(
                    &format!("{origin}/v1/receiver/inventory/{inventory}/{index}"),
                    MAX_CHUNK_BYTES,
                )
                .await
                .map_err(Fetched::Fresh)?;
            capture.push(&bytes).map_err(Fetched::Fresh)?;
        }
        // The identity check covers cached descriptors too.
        capture.finish().map_err(|e| {
            if cached {
                Fetched::Cached(e)
            } else {
                Fetched::Fresh(e)
            }
        })
    }

    /// Downloads rolling-hint availability without opening or waiting for a PIR session.
    pub async fn block_head<T: Transport>(
        origin: &str,
        http: &T,
        genesis: &[u8; 32],
    ) -> Result<receiver_directory::blocks::Head, Error> {
        let bytes = http
            .get(
                &format!(
                    "{}/v1/receiver/block-filters/head",
                    origin.trim_end_matches('/')
                ),
                16 * 1024,
            )
            .await?;
        if bytes.len() > 16 * 1024 {
            return Err(Error::Malformed);
        }
        let head: receiver_directory::blocks::Head = serde_json::from_slice(&bytes)?;
        head.validate(genesis)?;
        Ok(head)
    }

    /// Fetches a bounded prefix for one captured head. Errors never mean an empty range.
    /// The wallet must verify returned block hashes against its own chain before advancing.
    pub async fn block_batch<T: Transport>(
        origin: &str,
        http: &T,
        head: &receiver_directory::blocks::Head,
        from: u32,
        limit: u32,
    ) -> Result<receiver_directory::blocks::Batch, Error> {
        head.check_request(from, limit)?;
        let bytes = http
            .get(
                &format!(
                    "{}/v1/receiver/block-filters/{}/{}/{}",
                    origin.trim_end_matches('/'),
                    head.revision,
                    from,
                    limit
                ),
                receiver_directory::blocks::MAX_BATCH_BYTES,
            )
            .await?;
        let batch = receiver_directory::blocks::Batch::decode(&bytes)?;
        batch.check(head, from, limit)?;
        Ok(batch)
    }
}

/// Lookups against one captured inventory. Segment sessions open lazily and shard filters
/// are fetched on demand, each kept within its own byte budget; neither request names a
/// receiver. Reconnect with a new
/// capture for a replacement inventory: a cursor from one never applies to another.
pub struct InventoryClient<T> {
    origin: String,
    http: T,
    inventory: Inventory,
    filters: bool,
    segments: Mutex<Lru<(u32, u32), Segment>>,
    filter_cache: Mutex<Lru<u32, ShardFilter>>,
    /// Each segment's coordinates by its payment session, built once per capture.
    sessions: HashMap<Hash, (u32, u32)>,
    /// Filter answers by shard and receiver, so a filter is traversed once per batch.
    screened: Mutex<HashMap<(u32, ReceiverBytes), bool>>,
    traversals: std::sync::atomic::AtomicU64,
}

/// Most remembered filter answers; the memo starts over past it.
const SCREENED_ANSWERS: usize = 1 << 20;

/// Default bound on the encoded shard filters one client keeps in memory.
pub const FILTER_CACHE_BYTES: usize = 64 * 1024 * 1024;
/// Default bound on the public setup one client keeps for opened segment sessions. Each
/// segment keeps two setups of 14,848 bytes, so this holds about 560 segments.
pub const SEGMENT_CACHE_BYTES: usize = 16 * 1024 * 1024;

/// Values kept within a byte budget, least recently used evicted first. An evicted value is
/// rebuilt by its caller when next needed; holders of an evicted value keep it alive.
struct Lru<K, V> {
    budget: usize,
    used: usize,
    /// Keys by recency, least recent first.
    order: std::collections::VecDeque<K>,
    values: HashMap<K, (Arc<V>, usize)>,
}

impl<K: Copy + Eq + std::hash::Hash, V> Lru<K, V> {
    /// An empty cache holding at most `budget` bytes.
    fn new(budget: usize) -> Self {
        Self {
            budget,
            used: 0,
            order: Default::default(),
            values: HashMap::new(),
        }
    }

    /// The value for `key`, if kept, marking it most recently used.
    fn get(&mut self, key: K) -> Option<Arc<V>> {
        let found = self.values.get(&key)?.0.clone();
        self.order.retain(|k| *k != key);
        self.order.push_back(key);
        Some(found)
    }

    /// Keeps `value`, `size` bytes, evicting the least recently used until it fits. A value
    /// larger than the whole budget is not kept.
    fn insert(&mut self, key: K, value: Arc<V>, size: usize) {
        if size > self.budget || self.values.contains_key(&key) {
            return;
        }
        while self.used + size > self.budget {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if let Some((_, evicted)) = self.values.remove(&oldest) {
                self.used -= evicted;
            }
        }
        self.used += size;
        self.order.push_back(key);
        self.values.insert(key, (value, size));
    }
}

impl<T: Transport> InventoryClient<T> {
    /// Uses `inventory`, which the caller accepted against its chain with
    /// [`Inventory::accept`]. With `filters`, sealed shards' filters may stand in for PIR
    /// when they exclude a receiver; without, every required segment is read blind.
    pub fn new(origin: &str, http: T, inventory: Inventory, filters: bool) -> Self {
        let mut sessions = HashMap::new();
        for shard in inventory.shards() {
            for (segment, publication) in shard.segments.iter().enumerate() {
                // Capture validated every session, so each has an identity.
                if let Ok(id) = publication.payments.id() {
                    sessions.entry(id).or_insert((shard.index, segment as u32));
                }
            }
        }
        Self {
            sessions,
            screened: Mutex::new(HashMap::new()),
            traversals: Default::default(),
            origin: origin.trim_end_matches('/').to_owned(),
            http,
            inventory,
            filters,
            segments: Mutex::new(Lru::new(SEGMENT_CACHE_BYTES)),
            filter_cache: Mutex::new(Lru::new(FILTER_CACHE_BYTES)),
        }
    }

    /// Keeps at most `bytes` of encoded shard filters in memory instead of
    /// [`FILTER_CACHE_BYTES`]; evicted filters are fetched again when needed.
    pub fn with_filter_budget(self, bytes: usize) -> Self {
        *self.filter_cache.lock().unwrap() = Lru::new(bytes);
        self
    }

    /// Keeps at most `bytes` of opened segment sessions' public setup instead of
    /// [`SEGMENT_CACHE_BYTES`]; evicted sessions are opened again when needed.
    pub fn with_segment_budget(self, bytes: usize) -> Self {
        *self.segments.lock().unwrap() = Lru::new(bytes);
        self
    }

    /// The captured inventory.
    pub fn inventory(&self) -> &Inventory {
        &self.inventory
    }

    /// Whether shard filters may replace PIR for receivers they exclude.
    pub fn uses_filters(&self) -> bool {
        self.filters
    }

    /// Segment `segment` of shard `shard`, connecting its sessions on first use.
    pub async fn segment(&self, shard: u32, segment: u32) -> Result<Arc<Segment>, Error> {
        if let Some(found) = self.segments.lock().unwrap().get((shard, segment)) {
            return Ok(found);
        }
        let publication = self
            .inventory
            .shards()
            .get(shard as usize)
            .and_then(|s| s.segments.get(segment as usize))
            .ok_or(Error::Malformed)?
            .clone();
        let connected = Arc::new(Segment::connect(&self.origin, &self.http, publication).await?);
        let size = connected.client.retained_bytes() + connected.witnesses.retained_bytes();
        self.segments
            .lock()
            .unwrap()
            .insert((shard, segment), connected.clone(), size);
        Ok(connected)
    }

    /// Shard `shard`'s validated filter, or `None` when it has none or it could not be
    /// fetched or checked: the caller then reads the shard over PIR.
    pub async fn filter(&self, shard: u32) -> Option<Arc<ShardFilter>> {
        if let Some(cached) = self.filter_cache.lock().unwrap().get(shard) {
            return Some(cached);
        }
        let descriptor = self.inventory.shards().get(shard as usize)?;
        let reference = descriptor.filter.as_ref()?;
        let fetched = self
            .http
            .get(
                &format!(
                    "{}/v1/receiver/shard-filters/{}",
                    self.origin,
                    hex::encode(reference.digest)
                ),
                reference.bytes as usize,
            )
            .await
            .ok()
            .filter(|bytes| bytes.len() == reference.bytes as usize)
            .and_then(|bytes| ShardFilter::decode_named(&bytes, &reference.digest).ok())
            .filter(|filter| {
                filter.receivers() == u64::from(reference.receivers)
                    && filter
                        .check(
                            &self.inventory.head().genesis,
                            self.inventory.head().history_revision,
                            &descriptor.coverage(),
                        )
                        .is_ok()
            })
            .map(Arc::new);
        // A transport failure is retried by a later step rather than remembered.
        if let Some(filter) = &fetched {
            self.filter_cache
                .lock()
                .unwrap()
                .insert(shard, filter.clone(), filter.bytes().len());
        }
        fetched
    }

    /// Whether shard `shard`'s validated filter may hold each of `receivers`, in order, or
    /// `None` when the shard has no usable filter. One traversal of the filter answers every
    /// receiver not screened against it before, and each answer is remembered, so a caller
    /// that screens its receivers together reads each filter once per round.
    pub async fn screen(&self, shard: u32, receivers: &[ReceiverBytes]) -> Option<Vec<bool>> {
        let pending: Vec<ReceiverBytes> = {
            let screened = self.screened.lock().unwrap();
            let mut pending: Vec<_> = receivers
                .iter()
                .filter(|r| !screened.contains_key(&(shard, **r)))
                .copied()
                .collect();
            pending.sort_unstable();
            pending.dedup();
            pending
        };
        if !pending.is_empty() {
            let filter = self.filter(shard).await?;
            self.traversals
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let found = filter.matches(&pending);
            let mut screened = self.screened.lock().unwrap();
            if screened.len() + pending.len() > SCREENED_ANSWERS {
                screened.clear();
            }
            screened.extend(pending.iter().map(|r| (shard, *r)).zip(found));
        }
        let screened = self.screened.lock().unwrap();
        receivers
            .iter()
            .map(|r| screened.get(&(shard, *r)).copied())
            .collect()
    }

    /// How many filter traversals [`Self::screen`] has made.
    pub fn filter_traversals(&self) -> u64 {
        self.traversals.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Reads page `page` of `receiver`'s history in one segment over PIR: one query, whose
    /// row choice is hidden in its encryption. Absence is `None` only on page zero; a
    /// missing later page is an error. The record is checked structurally only.
    pub async fn page(
        &self,
        segment: &Segment,
        receiver: ReceiverBytes,
        page: u32,
    ) -> Result<Option<RawRecord>, Error> {
        let query = segment.client.prepare(receiver, page)?;
        let body = self
            .http
            .post(
                &format!("{}/v1/receiver/query", self.origin),
                query.body().to_vec(),
                response_bytes(segment.client.manifest().directory.rows)?,
            )
            .await?;
        segment.client.decode(query, &body)
    }

    /// The segment whose payment session is `payments`, if this inventory holds it: the
    /// first in chain order, found in the index built at construction.
    pub fn find_segment(&self, payments: &Hash) -> Option<(u32, u32)> {
        self.sessions.get(payments).copied()
    }

    /// Reads the companion witness payload for `ordinal` in one segment over PIR. The
    /// ordinal must come from that segment's payment records. The payload is unchecked.
    pub async fn witness(
        &self,
        segment: &Segment,
        ordinal: u32,
    ) -> Result<[u8; PAYLOAD_BYTES], Error> {
        let query = segment.witnesses.prepare(ordinal)?;
        let body = self
            .http
            .post(
                &format!("{}/v1/receiver/query", self.origin),
                query.body().to_vec(),
                response_bytes(segment.witnesses.manifest().table.rows)?,
            )
            .await?;
        segment.witnesses.decode(query, &body)
    }
}
