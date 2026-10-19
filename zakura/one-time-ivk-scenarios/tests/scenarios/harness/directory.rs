//! The receiver directory, served in process over the receiver routes, its recovery
//! objects and real PIR.
//! The service's own HTTP router is tested against these clients in wallet-pir.

use std::{
    cell::{OnceCell, RefCell},
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Mutex},
};

use receiver_directory::{
    Hash, RawRecord,
    catalog::{BucketIndex, CatalogHead},
    paid::{BUCKET_BLOCKS, PaidSet, Span, bucket_start},
    seen::SeenSet,
    snapshot::{Manifest, PROFILE, Snapshot},
};
use receiver_pir::{MIN_ROWS, server::Server};
use zakura_pir_receiver::{DirectoryError, Transport};
use zakura_receiver_crypto::{
    Record,
    witness::{Publication, WitnessSnapshot},
};

use zcash_protocol::consensus::BlockHeight;

use super::{
    chain::{ACTIVATION, Chain, GENESIS},
    near::Near,
};

/// The origin wallets send requests to; the transport serves them in process.
pub const ORIGIN: &str = "https://receiver.test";

/// What [`Directory`] panics with for an injected [`Fault`] whose app stops mid-request.
pub const APP_STOPS: &str = "the app stops during a directory request";

/// A failure injected into one directory endpoint.
#[derive(Clone, Debug)]
pub struct Fault {
    /// The requests it targets, by method and path prefix, such as
    /// `POST /v1/receiver/query`.
    pub request: &'static str,
    /// Targeted requests answered normally before it hits.
    pub after: usize,
    /// The HTTP status the hit request gets, or `None` when the app stops during it.
    pub status: Option<u16>,
}

/// How a publication differs from a faithful index of the chain.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// The start of the oldest paid bucket the directory still retains, or every bucket
    /// since Ironwood activation if `None`.
    pub retained_from: Option<u32>,
    /// The payment-history epoch.
    pub epoch: u64,
    /// Blocks the publication trails the tip by. The live indexer publishes 2 below.
    pub depth: u32,
    /// Note positions the indexer left out.
    pub omit: BTreeSet<u64>,
    /// A manifest whose last block does not match the chain.
    pub bad: Option<Bad>,
    /// A publication the indexer made earlier, served instead of a fresh one, as an
    /// indexer that stalled (or has not seen a reorg yet) would.
    pub frozen: Option<Arc<Frozen>>,
}

/// How a bad publication's manifest misstates its last block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bad {
    /// One more note commitment than the chain holds there.
    TreeSize,
    /// Another block hash.
    Hash,
}

/// What a publication is built from: the chain's indexed payments, commitments and last
/// block through its end, NEAR's sets as of when it was made, and its recovery objects.
pub struct Frozen {
    records: Vec<Record>,
    commitments: Vec<[u8; 32]>,
    end_height: u32,
    end_hash: [u8; 32],
    end_position: u64,
    sets: Vec<receiver_directory::snapshot::ProviderSet>,
    /// The catalog head's digest and every object it names, by route.
    catalog: (Hash, BTreeMap<String, Vec<u8>>),
}

impl std::fmt::Debug for Frozen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Frozen(end {})", self.end_height)
    }
}

impl Frozen {
    /// The publication of every zero-OVK payment through `depth` blocks below the tip,
    /// with NEAR's sets as of `now`.
    pub fn capture(chain: &Chain, near: &Near, now: i64, options: &Options) -> Self {
        let depth = options.depth.max(2);
        let end = chain.tip() - depth;
        let end_height = u32::from(end);
        let mut pages: BTreeMap<[u8; 43], u32> = BTreeMap::new();
        let visible: Vec<&Record> = chain
            .mined()
            .iter()
            .filter_map(|m| m.indexed.as_ref())
            .filter(|r| r.payment.height <= end_height)
            .filter(|r| !options.omit.contains(&r.payment.position))
            .collect();
        for record in &visible {
            *pages.entry(*record.receiver.as_bytes()).or_default() += 1;
        }
        let mut next_page: BTreeMap<[u8; 43], u32> = BTreeMap::new();
        let records: Vec<Record> = visible
            .into_iter()
            .map(|record| {
                let receiver = *record.receiver.as_bytes();
                let page = next_page.entry(receiver).or_default();
                let mut record = record.clone();
                record.page = *page;
                record.total = pages[&receiver];
                *page += 1;
                record
            })
            .collect();
        let end_position = chain.tree_size_at(end);
        let commitments =
            chain.commitments()[..usize::try_from(end_position).expect("fits")].to_vec();
        let sets = near.sets(now);
        let catalog = catalog(chain, &records, end_height, &sets, options);
        Self {
            records,
            commitments,
            end_height,
            end_hash: chain.hash_at(end).0,
            end_position,
            sets,
            catalog,
        }
    }
}

thread_local! {
    /// The last PIR server this thread built, whose row preprocessing the next publication
    /// with the same rows reuses, as the live service does.
    static LAST_SERVER: RefCell<Option<Arc<Server>>> = const { RefCell::new(None) };
    /// Every paid set this thread built, encoded, with its digest, by content (see
    /// [`PaidSets`]), so each publication builds only new buckets.
    static PAID_SETS: RefCell<PaidSets> = const { RefCell::new(BTreeMap::new()) };
}

/// Encoded paid sets and their digests by interval, boundary hashes, epoch and receivers.
type PaidSets = BTreeMap<(u32, Hash, u32, Hash, u64, Vec<[u8; 43]>), (Hash, Vec<u8>)>;

/// The catalog head digest and recovery objects, by route, of a publication ending at
/// `end` whose payments are `records`, with NEAR's seen set from `sets`: every closed
/// bucket from the oldest `options` retains, and a cumulative snapshot through the latest
/// closed bucket's end, under `options`' epoch.
fn catalog(
    chain: &Chain,
    records: &[Record],
    end: u32,
    sets: &[receiver_directory::snapshot::ProviderSet],
    options: &Options,
) -> (Hash, BTreeMap<String, Vec<u8>>) {
    // A block before the chain's first, such as one a bucket starts after, gets a stand-in.
    let hash = |height: u32| {
        chain
            .known_hash(BlockHeight::from(height))
            .map_or([height as u8; 32], |hash| hash.0)
    };
    // A set is the same bytes whenever its interval, boundaries, epoch and receivers are.
    let paid = |start: u32, end: u32| {
        let (start_hash, end_hash) = (hash(start), hash(end));
        let receivers: Vec<[u8; 43]> = records
            .iter()
            .filter(|r| (start + 1..=end).contains(&r.payment.height))
            .map(|r| *r.receiver.as_bytes())
            .collect();
        let key = (start, start_hash, end, end_hash, options.epoch, receivers);
        PAID_SETS.with_borrow_mut(|sets| {
            sets.entry(key)
                .or_insert_with_key(|key| {
                    let span = Span {
                        start,
                        start_hash,
                        end,
                        end_hash,
                    };
                    let set =
                        PaidSet::build(GENESIS, options.epoch, span, &key.5).expect("a paid set");
                    (set.digest(), set.encode())
                })
                .clone()
        })
    };
    let latest_end = end - end % BUCKET_BLOCKS;
    let oldest = options
        .retained_from
        .unwrap_or_else(|| bucket_start(ACTIVATION + 1).expect("above zero"))
        .min(latest_end);
    let mut objects = BTreeMap::new();
    let mut starts = Vec::new();
    for start in (oldest..latest_end).step_by(BUCKET_BLOCKS as usize) {
        let (digest, bytes) = paid(start, start + BUCKET_BLOCKS);
        objects.insert(format!("bucket/{start}/{}", hex::encode(digest)), bytes);
        starts.push((start, digest));
    }
    let (paid_digest, paid_bytes) = paid(ACTIVATION - BUCKET_BLOCKS, latest_end.max(ACTIVATION));
    let seen = sets
        .iter()
        .find(|set| set.label.ends_with("/seen"))
        .expect("NEAR's seen set");
    let (since, until) = (seen.since_unix, seen.until_unix);
    let mut seen = SeenSet::new(GENESIS, since).union(&seen.receivers);
    seen.until_unix = until;
    let index = BucketIndex::new(GENESIS, starts).expect("a bucket index");
    let head = CatalogHead {
        genesis: GENESIS,
        epoch: options.epoch,
        oldest_start: oldest,
        latest_end,
        paid: paid_digest,
        seen: seen.digest().expect("a seen set"),
        index: index.digest(),
    };
    for (route, digest, bytes) in [
        ("paid", head.paid, paid_bytes),
        ("seen", head.seen, seen.encode().expect("a seen set")),
        ("bucket-index", head.index, index.encode()),
    ] {
        objects.insert(format!("{route}/{}", hex::encode(digest)), bytes);
    }
    let digest = head.digest().expect("a catalog head");
    objects.insert(
        format!("catalog/{}", hex::encode(digest)),
        head.encode().expect("a catalog head"),
    );
    (digest, objects)
}

/// A directory serving one publication, with injectable failures.
pub struct Directory {
    routes: Routes,
    requests: Mutex<Vec<String>>,
    faults: Mutex<VecDeque<u16>>,
    targeted: Mutex<Vec<Fault>>,
    /// Request and response body bytes, as (sent, received).
    bytes: Mutex<(u64, u64)>,
}

impl Directory {
    /// Publishes every zero-OVK payment through `depth` blocks below the tip, with
    /// NEAR's sets as of `now`, or serves the frozen publication `options` names.
    pub fn publish(chain: &Chain, near: &Near, now: i64, options: &Options) -> Self {
        match &options.frozen {
            Some(frozen) => Self::build(frozen, options.bad),
            None => Self::build(&Frozen::capture(chain, near, now, options), options.bad),
        }
    }

    /// Serves `frozen`, with its last block misstated as `bad` says.
    fn build(frozen: &Frozen, bad: Option<Bad>) -> Self {
        let records = &frozen.records;
        let mut end_hash = frozen.end_hash;
        let mut end_position = frozen.end_position;
        match bad {
            Some(Bad::Hash) => end_hash[0] ^= 0xff,
            Some(Bad::TreeSize) => end_position += 1,
            None => {}
        }
        let manifest = Manifest {
            profile: PROFILE.into(),
            genesis: GENESIS,
            start_height: ACTIVATION,
            start_parent: [0; 32],
            start_position: 0,
            end_height: frozen.end_height,
            end_hash,
            end_position,
            rows: MIN_ROWS,
            salt: [5; 32],
            records: 0,
            data_sha256: [0; 32],
            filters: Vec::new(),
            filters_sha256: [0; 32],
            catalog_sha256: frozen.catalog.0,
        };
        // The publisher validated every record before writing its row slot.
        let raw: Vec<RawRecord> = records
            .iter()
            .map(|r| {
                let slot = r.encode().expect("a valid record");
                RawRecord::decode(&slot)
                    .expect("a row slot")
                    .expect("a record")
            })
            .collect();
        let snapshot = Snapshot::build(manifest, &raw, &frozen.sets).expect("a valid publication");
        let mut commitments = frozen.commitments.clone();
        if bad == Some(Bad::TreeSize) {
            // A witness file must hold the tree its manifest claims.
            commitments.push(commitments.last().copied().unwrap_or([0; 32]));
        }
        let positions = records
            .iter()
            .map(|r| u32::try_from(r.payment.position).expect("small positions"))
            .collect();
        // A chain without Ironwood outputs has no witnesses to serve.
        // A bad manifest's witnesses may not build; it then serves none.
        let witnesses = (!commitments.is_empty()).then(|| {
            let built =
                WitnessSnapshot::build(&publication(&snapshot.manifest), &commitments, &positions);
            match bad {
                None => Some(built.expect("witnesses build").encode()),
                Some(_) => built.ok().map(|w| w.encode()),
            }
        });
        let server = LAST_SERVER.with_borrow_mut(|last| {
            let server = match last.as_deref() {
                Some(previous) => Server::new_reusing_rows(snapshot, previous),
                None => Server::new(snapshot),
            };
            let server = Arc::new(server.expect("the PIR server prepares"));
            *last = Some(server.clone());
            server
        });
        let mut routes = Routes::new(server, witnesses.flatten());
        routes.objects = frozen.catalog.1.clone();
        Self {
            routes,
            requests: Mutex::new(Vec::new()),
            faults: Mutex::new(VecDeque::new()),
            targeted: Mutex::new(Vec::new()),
            bytes: Mutex::new((0, 0)),
        }
    }

    /// Every request served so far, as method and path.
    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }

    /// Request and response body bytes so far, as (sent, received).
    pub fn bytes(&self) -> (u64, u64) {
        *self.bytes.lock().unwrap()
    }

    /// Answers the next `statuses.len()` requests with these HTTP statuses instead.
    pub fn fail_next(&self, statuses: &[u16]) {
        self.faults.lock().unwrap().extend(statuses.iter().copied());
    }

    /// Adds endpoint-specific failures (see [`Fault`]).
    pub fn fail_at(&self, faults: &[Fault]) {
        self.targeted.lock().unwrap().extend(faults.iter().cloned());
    }

    /// The status an injected fault answers request `request` with, if one hits it.
    /// Panics with [`APP_STOPS`] for a fault whose app stops during the request.
    fn fault_for(&self, request: &str) -> Option<u16> {
        let mut targeted = self.targeted.lock().unwrap();
        let aimed = |fault: &Fault| request.starts_with(fault.request);
        let hit = targeted
            .iter()
            .position(|fault| aimed(fault) && fault.after == 0)
            .map(|i| targeted.remove(i));
        if hit.is_none() {
            for fault in targeted.iter_mut().filter(|fault| aimed(fault)) {
                fault.after -= 1;
            }
        }
        drop(targeted);
        match hit {
            Some(Fault { status: None, .. }) => panic!("{APP_STOPS}"),
            Some(Fault { status, .. }) => status,
            None => self.faults.lock().unwrap().pop_front(),
        }
    }

    /// Encrypted lookups served so far.
    pub fn lookups(&self) -> usize {
        let requests = self.requests.lock().unwrap();
        requests
            .iter()
            .filter(|r| *r == "POST /v1/receiver/query")
            .count()
    }

    async fn send(
        &self,
        method: &str,
        url: &str,
        body: Vec<u8>,
        limit: usize,
    ) -> Result<Vec<u8>, DirectoryError> {
        let path = url
            .strip_prefix(ORIGIN)
            .expect("requests stay on the origin");
        let request = format!("{method} {path}");
        self.requests.lock().unwrap().push(request.clone());
        self.bytes.lock().unwrap().0 += body.len() as u64;
        let status = match self.fault_for(&request) {
            Some(status) => status,
            None => {
                let (status, body) = self.routes.answer(method, path, &body);
                if body.len() > limit {
                    return Err(DirectoryError::Transport("response over its limit".into()));
                }
                if status == 200 {
                    self.bytes.lock().unwrap().1 += body.len() as u64;
                    return Ok(body);
                }
                status
            }
        };
        // Vizor maps 409 and 410 to a new publication and everything else to a
        // retryable transport failure.
        match status {
            409 | 410 => Err(DirectoryError::Revision),
            status => Err(DirectoryError::Transport(format!("HTTP {status}"))),
        }
    }
}

/// The fields of `manifest` its witness file binds to.
fn publication(manifest: &Manifest) -> Publication {
    Publication {
        genesis: manifest.genesis,
        directory_revision: manifest.revision().expect("a valid manifest"),
        end_height: manifest.end_height,
        end_hash: manifest.end_hash,
        start_position: manifest.start_position,
        end_position: manifest.end_position,
        records: manifest.records,
    }
}

/// One publication's receiver routes, answered as the receiver service answers them:
/// its manifest, PIR setup, filters and witnesses, real PIR evaluation of each encrypted
/// query, and its immutable recovery objects. A session it does not serve is gone (410),
/// and an object it does not serve is not found (404).
struct Routes {
    server: Arc<Server>,
    id: String,
    witnesses: Option<Vec<u8>>,
    /// Recovery objects by route, such as `catalog/<digest>`.
    objects: BTreeMap<String, Vec<u8>>,
}

impl Routes {
    fn new(server: Arc<Server>, witnesses: Option<Vec<u8>>) -> Self {
        Self {
            id: hex::encode(server.id()),
            server,
            witnesses,
            objects: BTreeMap::new(),
        }
    }

    /// The status and body for `method` on `path`.
    fn answer(&self, method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
        let route = path.strip_prefix("/v1/receiver/").unwrap_or(path);
        let object = ["catalog/", "bucket-index/", "bucket/", "paid/", "seen/"];
        if method == "GET" && object.iter().any(|kind| route.starts_with(kind)) {
            return match self.objects.get(route) {
                Some(bytes) => (200, bytes.clone()),
                None => (404, Vec::new()),
            };
        }
        if (method, route) == ("POST", "query") {
            return match self.server.respond(body) {
                Ok(response) => (200, response),
                Err(receiver_pir::Error::Revision) => (410, Vec::new()),
                Err(receiver_pir::Error::Malformed) => (400, Vec::new()),
                Err(_) => (500, Vec::new()),
            };
        }
        if (method, route) == ("GET", "init") {
            let manifest = serde_json::to_vec(self.server.manifest()).expect("a manifest");
            return (200, manifest);
        }
        let Some((material, id)) = route.split_once('/').filter(|_| method == "GET") else {
            return (404, Vec::new());
        };
        if hex::decode(id).ok().filter(|id| id.len() == 32).is_none() {
            return (400, Vec::new());
        }
        if id != self.id {
            return (410, Vec::new());
        }
        match material {
            "public" => (200, self.server.public().to_vec()),
            "filters" => (200, self.server.filters().to_vec()),
            "witness" => match &self.witnesses {
                Some(bytes) => (200, bytes.clone()),
                None => (503, Vec::new()),
            },
            _ => (404, Vec::new()),
        }
    }
}

impl Transport for Directory {
    async fn get(&self, url: &str, limit: usize) -> Result<Vec<u8>, DirectoryError> {
        self.send("GET", url, Vec::new(), limit).await
    }

    async fn post(
        &self,
        url: &str,
        body: Vec<u8>,
        limit: usize,
    ) -> Result<Vec<u8>, DirectoryError> {
        self.send("POST", url, body, limit).await
    }
}

/// A directory published on its first request, so a discovery run with nothing due pays
/// for no PIR setup. An unreachable directory refuses every request.
pub struct Served<'a> {
    make: Box<dyn Fn() -> Directory + 'a>,
    directory: OnceCell<Directory>,
    reachable: bool,
}

impl<'a> Served<'a> {
    /// A directory `make` publishes when first asked, or an unreachable one.
    pub fn new(reachable: bool, make: impl Fn() -> Directory + 'a) -> Self {
        Self {
            make: Box::new(make),
            directory: OnceCell::new(),
            reachable,
        }
    }

    /// The published directory, if a request needed it.
    pub fn published(&self) -> Option<&Directory> {
        self.directory.get()
    }

    fn get_or_publish(&self) -> Result<&Directory, DirectoryError> {
        if !self.reachable {
            return Err(DirectoryError::Transport("connection refused".into()));
        }
        Ok(self.directory.get_or_init(|| (self.make)()))
    }
}

impl Transport for Served<'_> {
    async fn get(&self, url: &str, limit: usize) -> Result<Vec<u8>, DirectoryError> {
        self.get_or_publish()?.get(url, limit).await
    }

    async fn post(
        &self,
        url: &str,
        body: Vec<u8>,
        limit: usize,
    ) -> Result<Vec<u8>, DirectoryError> {
        self.get_or_publish()?.post(url, body, limit).await
    }
}
