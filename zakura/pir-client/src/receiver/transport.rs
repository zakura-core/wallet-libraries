//! Receiver discovery over a caller-supplied, bounded transport.
//!
//! Routes never name a receiver: inventory heads and chunks, shard filters and choice
//! objects (both addressed by digest) and PIR setup are public, and directory and companion
//! rows are selected inside PIR.
use super::{
    Client, Directory, Hash, ReceiverBytes, Session, Table, decode_choice,
    descriptor_cache::DescriptorCache,
    inventory::{Capture, Head, Inventory, MAX_CAPTURE_BYTES, MAX_CHUNK_BYTES},
    native::{public_bytes, response_bytes},
    session::{Error, MAX_MANIFEST_BYTES},
    shards::ShardFilter,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use zakura_pir_protocol::directory::choice::ChoiceTable;
use zakura_pir_protocol::endpoint::{Endpoint, PirProduct};

/// The URL of one receiver operation, such as `/inventory`, below the configured server
/// base `origin`: `{origin}/receiver/v1{operation}`, keeping any base path. This is the
/// only place receiver routes are composed; nothing falls back to another route.
fn receiver_url(origin: &str, operation: &str) -> Result<String, Error> {
    Ok(Endpoint::parse(origin)?.product_url(PirProduct::Receiver, operation)?)
}

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
            .get(&receiver_url(origin, "/inventory")?, MAX_MANIFEST_BYTES)
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
    /// and downloading only the rest: new shards, sealed shards whose companion payloads are
    /// still provisional, and the recent tier. The result is proved complete against the head
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
                // None comes from a cached descriptor, so a full capture would repeat it.
                Err(Fetched::Fresh(
                    e @ (Error::Transport(_) | Error::Unsupported | Error::Endpoint(_)),
                )) => {
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
        if let Ok(bytes) = DescriptorCache::of(&inventory).encode()
            && saved.as_deref() != Some(&bytes[..])
        {
            store.save(&bytes);
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
                    &receiver_url(origin, &format!("/inventory/{inventory}/{index}"))
                        .map_err(Fetched::Fresh)?,
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

    /// Downloads which block hints the server holds, without opening a PIR session.
    pub async fn block_head<T: Transport>(
        origin: &str,
        http: &T,
        genesis: &[u8; 32],
    ) -> Result<super::blocks::Head, Error> {
        let bytes = http
            .get(&receiver_url(origin, "/block-filters/head")?, 16 * 1024)
            .await?;
        if bytes.len() > 16 * 1024 {
            return Err(Error::Malformed);
        }
        let head: super::blocks::Head = serde_json::from_slice(&bytes)?;
        head.validate(genesis)?;
        Ok(head)
    }

    /// Fetches up to `limit` heights of hints from `from` for one captured head. The server
    /// stops at [`super::blocks::MAX_RANGE_BYTES`], so a dense gap takes more than one request:
    /// continue after the returned range's end. Errors never mean an empty range.
    pub async fn block_range<T: Transport>(
        origin: &str,
        http: &T,
        head: &super::blocks::Head,
        from: u32,
        limit: u32,
    ) -> Result<super::blocks::Range, Error> {
        head.check_range(from, limit)?;
        let bytes = http
            .get(
                &receiver_url(
                    origin,
                    &format!("/block-filters/{}/{from}/{limit}", head.revision),
                )?,
                super::blocks::MAX_RANGE_BYTES,
            )
            .await?;
        let range = super::blocks::Range::decode(&bytes)?;
        range.check(head, from, limit)?;
        Ok(range)
    }
}

/// Lookups against one captured inventory. Sessions' public setup and choice objects are
/// fetched on demand and shard filters likewise, each kept within its own byte budget and
/// checked against its digest; no request names a receiver. Reconnect with a new capture
/// for a replacement inventory: a cursor resumes there only under the directory session it
/// binds.
pub struct InventoryClient<T> {
    origin: String,
    http: T,
    inventory: Inventory,
    filters: bool,
    /// Verified public setup by session ID.
    setups: Mutex<Lru<Hash, Vec<u8>>>,
    /// Choice object bytes by digest, decoded against each directory that uses them.
    choices: Mutex<Lru<Hash, Vec<u8>>>,
    filter_cache: Mutex<Lru<u32, ShardFilter>>,
    /// Filter answers by shard and receiver, so a filter is traversed once per batch.
    screened: Mutex<HashMap<(u32, ReceiverBytes), bool>>,
    traversals: std::sync::atomic::AtomicU64,
}

/// Most remembered filter answers; the memo starts over past it.
const SCREENED_ANSWERS: usize = 1 << 20;

/// Default bound on the encoded shard filters one client keeps in memory.
pub const FILTER_CACHE_BYTES: usize = 64 * 1024 * 1024;
/// Default bound on the public setup one client keeps for opened sessions.
pub const SEGMENT_CACHE_BYTES: usize = 16 * 1024 * 1024;
/// Default bound on the choice objects one client keeps, each at most about 50 KB.
pub const CHOICE_CACHE_BYTES: usize = 4 * 1024 * 1024;

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
        Self {
            screened: Mutex::new(HashMap::new()),
            traversals: Default::default(),
            origin: origin.to_owned(),
            http,
            inventory,
            filters,
            setups: Mutex::new(Lru::new(SEGMENT_CACHE_BYTES)),
            choices: Mutex::new(Lru::new(CHOICE_CACHE_BYTES)),
            filter_cache: Mutex::new(Lru::new(FILTER_CACHE_BYTES)),
        }
    }

    /// Keeps at most `bytes` of encoded shard filters in memory instead of
    /// [`FILTER_CACHE_BYTES`]; evicted filters are fetched again when needed.
    pub fn with_filter_budget(self, bytes: usize) -> Self {
        *self.filter_cache.lock().unwrap() = Lru::new(bytes);
        self
    }

    /// Keeps at most `bytes` of opened sessions' public setup instead of
    /// [`SEGMENT_CACHE_BYTES`]; evicted setups are fetched again when needed.
    pub fn with_segment_budget(self, bytes: usize) -> Self {
        *self.setups.lock().unwrap() = Lru::new(bytes);
        self
    }

    /// Keeps at most `bytes` of choice objects instead of [`CHOICE_CACHE_BYTES`]; evicted
    /// objects are fetched again when needed.
    pub fn with_choice_budget(self, bytes: usize) -> Self {
        *self.choices.lock().unwrap() = Lru::new(bytes);
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

    /// `session`'s PIR client, downloading its public setup on first use (one GET of
    /// `/public/{session}`) and checking it against the session's digest.
    pub async fn open<M: Table + Clone>(&self, session: &Session<M>) -> Result<Client<M>, Error> {
        let id = session.id()?;
        let cached = self.setups.lock().unwrap().get(id);
        let public = match cached {
            Some(public) => public,
            None => Arc::new(
                self.http
                    .get(
                        &receiver_url(&self.origin, &format!("/public/{}", hex::encode(id)))?,
                        public_bytes(),
                    )
                    .await?,
            ),
        };
        let client = Client::new(session.clone(), public.clone())?;
        self.setups
            .lock()
            .unwrap()
            .insert(id, public.clone(), public.len());
        Ok(client)
    }

    /// `directory`'s choice object, downloading it on first use (one GET of
    /// `/choice/{digest}`). Every use, a cached one included, refuses an object whose
    /// digest, length or key count differs from `directory`'s reference.
    pub async fn choice(&self, directory: &Directory) -> Result<ChoiceTable, Error> {
        let reference = &directory.choice;
        let cached = self.choices.lock().unwrap().get(reference.digest);
        let bytes = match cached {
            Some(bytes) => bytes,
            None => Arc::new(
                self.http
                    .get(
                        &receiver_url(
                            &self.origin,
                            &format!("/choice/{}", hex::encode(reference.digest)),
                        )?,
                        reference.bytes as usize,
                    )
                    .await?,
            ),
        };
        let table = decode_choice(directory, &bytes)?;
        self.choices
            .lock()
            .unwrap()
            .insert(reference.digest, bytes.clone(), bytes.len());
        Ok(table)
    }

    /// Reads row `row` of `client`'s table over PIR: one freshly encrypted query, whose row
    /// is hidden in its encryption. The row is untrusted.
    pub async fn query<M: Table>(&self, client: &Client<M>, row: u32) -> Result<Vec<u8>, Error> {
        let query = client.prepare(row)?;
        let body = self
            .http
            .post(
                &receiver_url(&self.origin, "/query")?,
                query.body().to_vec(),
                response_bytes(),
            )
            .await?;
        client.decode(query, &body)
    }

    /// Shard `shard`'s validated filter, or `None` when it has none or it could not be
    /// fetched or checked: the caller then reads the shard over PIR.
    pub async fn filter(&self, shard: u32) -> Option<Arc<ShardFilter>> {
        if let Some(cached) = self.filter_cache.lock().unwrap().get(shard) {
            return Some(cached);
        }
        let descriptor = self.inventory.shards().get(shard as usize)?;
        let reference = descriptor.filter.as_ref()?;
        let url = receiver_url(
            &self.origin,
            &format!("/shard-filters/{}", hex::encode(reference.digest)),
        )
        .ok()?;
        let fetched = self
            .http
            .get(&url, reference.bytes as usize)
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
}
