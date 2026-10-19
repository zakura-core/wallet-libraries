//! Fixtures shared by this crate's integration tests: restored SQLite wallets on a mock
//! chain, and a receiver directory served in process over the service's routes and real
//! PIR, with its recovery objects.
#![allow(dead_code)]

use std::{collections::BTreeMap, sync::Mutex};

use orchard::keys::{FullViewingKey, Scope};
use receiver_directory::{
    Hash, RawRecord,
    catalog::{BucketIndex, CatalogHead},
    paid::{BUCKET_BLOCKS, PaidSet, Span, bucket_start},
    seen::SeenSet,
    snapshot::{Manifest, PROFILE, Snapshot},
};
use receiver_pir::{MIN_ROWS, server::Server};
use zakura_pir_receiver::{DirectoryError, Transport, WriteLock};
use zakura_receiver_crypto::{
    Payment, Receiver, Record,
    witness::{Publication, WitnessSnapshot},
};
use zcash_client_backend::data_api::{
    Account as _, WalletRead as _,
    chain::BlockSource as _,
    testing::{AddressType, IronwoodFvk, TestBuilder, TestState},
    transparent_ledger::ChainPoint,
};
use zcash_client_sqlite::{
    testing::{
        BlockCache,
        db::{TestDb, TestDbFactory},
    },
    wallet::one_time_ivk::{KeyId, Purpose},
};
use zcash_primitives::block::BlockHash;
use zcash_protocol::{consensus::BlockHeight, local_consensus::LocalNetwork, value::Zatoshis};

pub type State = TestState<BlockCache, TestDb, LocalNetwork>;

/// The genesis hash the fixture's publications commit to.
pub const GENESIS: [u8; 32] = [9; 32];
/// The origin requests name. The transport serves them in process.
pub const ORIGIN: &str = "https://receiver.test";
/// Ironwood activation, the history every publication must cover.
pub const ACTIVATION: u32 = 100_000;
/// The caller's clock.
pub const NOW: i64 = 1_700_000_000;
/// The payout's value.
pub const VALUE: u64 = 100_000;

/// A restored wallet with Ironwood active from its first block, stored as `factory` makes
/// it.
pub fn ironwood_wallet_in(factory: TestDbFactory) -> State {
    let activation = BlockHeight::from_u32(ACTIVATION);
    TestBuilder::new()
        .with_network(LocalNetwork {
            nu6: Some(activation),
            nu6_1: Some(activation),
            nu6_2: Some(activation),
            nu6_3: Some(activation),
            ..TestBuilder::<(), ()>::DEFAULT_NETWORK
        })
        .with_data_store_factory(factory)
        .with_block_cache(BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build()
}

/// The wallet's fully scanned tip.
pub fn tip(st: &State) -> ChainPoint {
    let block = st.wallet().block_fully_scanned().unwrap().unwrap();
    ChainPoint {
        height: block.block_height(),
        hash: block.block_hash(),
    }
}

/// The test account's Orchard key, which its one-time keys derive from.
pub fn parent(st: &State) -> FullViewingKey {
    FullViewingKey::from(st.test_account().unwrap().usk().orchard())
}

/// The receiver of one-time key `key` under the Orchard key `parent`.
pub fn key_receiver(parent: &FullViewingKey, key: KeyId) -> Receiver {
    let fvk = key.derive(parent).unwrap();
    Receiver::from_bytes(fvk.address_at(0u32, Scope::External).to_raw_address_bytes()).unwrap()
}

/// The receiver of the test account's incoming one-time key `index`.
pub fn receiver(st: &State, index: u64) -> Receiver {
    key_receiver(&parent(st), KeyId::new(Purpose::Receive, index))
}

/// Pays one-time key `key` under the Orchard key `parent` in a new block left unscanned,
/// and returns the payment as the directory lists it. The output is the chain's Ironwood
/// leaf at `position`, which is the number of earlier Ironwood outputs.
pub fn pay_unscanned(st: &mut State, parent: &FullViewingKey, key: KeyId, position: u64) -> Record {
    let fvk = key.derive(parent).unwrap();
    let (height, _, _) = st.generate_next_block(
        &IronwoodFvk(fvk),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(VALUE),
    );
    let block = cached(st, height);
    let tx = &block.vtx[0];
    let compact = &tx.ironwood_actions[0];
    Record {
        receiver: key_receiver(parent, key),
        page: 0,
        total: 1,
        payment: Payment {
            height: u32::from(height),
            block_hash: block.hash().0,
            txid: *tx.txid().as_ref(),
            // The mock block has no coinbase; the directory refuses index 0 as one.
            tx_index: u32::try_from(tx.index).unwrap() + 1,
            action_index: 0,
            position,
            action_nullifier: compact.nullifier.as_slice().try_into().unwrap(),
            cmx: compact.cmx.as_slice().try_into().unwrap(),
            ephemeral_key: compact.ephemeral_key.as_slice().try_into().unwrap(),
            ciphertext_prefix: compact.ciphertext.as_slice().try_into().unwrap(),
        },
    }
}

/// The cached block at `height`.
pub fn cached(
    st: &State,
    height: BlockHeight,
) -> zcash_client_backend::proto::compact_formats::CompactBlock {
    let mut block = None;
    st.cache()
        .with_blocks::<_, ()>(Some(height), Some(1), |cb| {
            block = Some(cb);
            Ok(())
        })
        .unwrap();
    block.unwrap()
}

/// The test account's total balance in zatoshis.
pub fn balance(st: &State) -> u64 {
    st.get_total_balance(st.test_account().unwrap().id())
        .into_u64()
}

/// The value of the wallet's one-time-key notes, which needs no wallet summary.
pub fn one_time_value(st: &State) -> u64 {
    st.wallet()
        .conn()
        .query_row(
            "SELECT COALESCE(SUM(value), 0) FROM ironwood_received_notes
             WHERE one_time_key_id IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap()
}

/// A publication of `records` ending at `end`, with the common witnesses over the
/// chain's Ironwood `commitments`, if any, and a catalog head of digest `catalog` with the recovery `objects` it names, by route (see
/// [`recovery_objects`]), served by the receiver service's routes.
pub fn publish(
    records: &[Record],
    commitments: &[[u8; 32]],
    end: ChainPoint,
    (catalog, objects): (Hash, BTreeMap<String, Vec<u8>>),
) -> Routes {
    // Each record's row slot, which the publisher writes after validating it.
    let records: Vec<_> = records
        .iter()
        .map(|record| {
            RawRecord::decode(&record.encode().unwrap())
                .unwrap()
                .unwrap()
        })
        .collect();
    let manifest = Manifest {
        profile: PROFILE.into(),
        genesis: GENESIS,
        start_height: ACTIVATION,
        start_parent: [0; 32],
        start_position: 0,
        end_height: end.height.into(),
        end_hash: end.hash.0,
        end_position: commitments.len() as u64,
        rows: MIN_ROWS,
        salt: [5; 32],
        records: 0,
        data_sha256: [0; 32],
        filters: Vec::new(),
        filters_sha256: [0; 32],
        catalog_sha256: catalog,
    };
    let snapshot = Snapshot::build(manifest, &records, &[]).unwrap();
    let positions = records
        .iter()
        .map(|record| u32::try_from(record.payment.position).unwrap())
        .collect();
    // A chain without Ironwood outputs has no witnesses to serve.
    let witnesses = (!commitments.is_empty()).then(|| {
        WitnessSnapshot::build(&publication(&snapshot.manifest), commitments, &positions)
            .unwrap()
            .encode()
    });
    let mut routes = Routes::new(Server::new(snapshot).unwrap(), witnesses);
    routes.objects = objects;
    routes
}

/// The fields of `manifest` its witness file binds to.
pub fn publication(manifest: &Manifest) -> Publication {
    Publication {
        genesis: manifest.genesis,
        directory_revision: manifest.revision().unwrap(),
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
pub struct Routes {
    server: Server,
    id: String,
    witnesses: Option<Vec<u8>>,
    /// Recovery objects by route, such as `catalog/<digest>`.
    pub objects: BTreeMap<String, Vec<u8>>,
}

impl Routes {
    fn new(server: Server, witnesses: Option<Vec<u8>>) -> Self {
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
            return (200, serde_json::to_vec(self.server.manifest()).unwrap());
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

/// Serves a directory's routes in process and records every request.
pub struct Directory {
    routes: Routes,
    requests: Mutex<Vec<String>>,
}

impl Directory {
    /// Serves `routes` at [`ORIGIN`].
    pub fn new(routes: Routes) -> Self {
        Self {
            routes,
            requests: Mutex::new(Vec::new()),
        }
    }

    /// Every request so far, as method and path.
    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }

    /// Sends one request to the routes, failing over `limit` bytes as a transport must.
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
        self.requests
            .lock()
            .unwrap()
            .push(format!("{method} {path}"));
        let (status, body) = self.routes.answer(method, path, &body);
        if body.len() > limit {
            return Err(DirectoryError::Transport("response over its limit".into()));
        }
        match status {
            200 => Ok(body),
            409 | 410 => Err(DirectoryError::Revision),
            status => Err(DirectoryError::Transport(format!("HTTP {status}"))),
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

/// The receiver lookups `directory` has served.
pub fn lookups(directory: &Directory) -> usize {
    let requests = directory.requests();
    requests
        .iter()
        .filter(|r| *r == "POST /v1/receiver/query")
        .count()
}

/// A test needs no lock: nothing else writes to its wallet.
pub struct NoLock;

impl WriteLock for NoLock {
    fn write<T>(&self, _: &'static str, write: impl FnOnce() -> T) -> T {
        write()
    }
}

/// Forwards to a [`Directory`] but fails every witness download, as when the common
/// witness file cannot be fetched.
pub struct WithoutWitnesses<'a>(pub &'a Directory);

impl Transport for WithoutWitnesses<'_> {
    async fn get(&self, url: &str, limit: usize) -> Result<Vec<u8>, DirectoryError> {
        if url.contains("/witness/") {
            return Err(DirectoryError::Transport("witnesses unavailable".into()));
        }
        self.0.get(url, limit).await
    }

    async fn post(
        &self,
        url: &str,
        body: Vec<u8>,
        limit: usize,
    ) -> Result<Vec<u8>, DirectoryError> {
        self.0.post(url, body, limit).await
    }
}

/// The `purpose` key indices registered in the wallet, in order.
pub fn registered(st: &State, purpose: Purpose) -> Vec<u64> {
    let code = match purpose {
        Purpose::Refund => 0,
        _ => 1,
    };
    let sql = format!(
        "SELECT key_index FROM ironwood_one_time_keys WHERE purpose = {code} ORDER BY key_index"
    );
    let conn = st.wallet().conn();
    let mut stmt = conn.prepare(&sql).unwrap();
    let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0)).unwrap();
    rows.map(|r| u64::from_be_bytes(r.unwrap().try_into().unwrap()))
        .collect()
}

/// What a directory's recovery objects say about the chain (see [`recovery_objects`]).
#[derive(Clone)]
pub struct History {
    /// The payment-history epoch.
    pub epoch: u64,
    /// The start of the oldest retained bucket, a multiple of [`BUCKET_BLOCKS`].
    pub oldest_start: u32,
    /// The cumulative snapshot's cutoff, or the latest closed bucket's end if `None`.
    pub cutoff: Option<u32>,
    /// The receivers the seen set holds.
    pub seen: Vec<Receiver>,
}

impl Default for History {
    /// Epoch one, retaining every bucket from Ironwood activation, with an empty seen set.
    fn default() -> Self {
        Self {
            epoch: 1,
            oldest_start: bucket_start(ACTIVATION + 1).unwrap(),
            cutoff: None,
            seen: Vec::new(),
        }
    }
}

/// The hash of `st`'s block at `height`, or a stand-in for a block the chain never had,
/// such as one before the wallet's first.
pub fn block_hash(st: &State, height: u32) -> Hash {
    let mut found = None;
    // A height the cache never held is a miss.
    let _ = st
        .cache()
        .with_blocks::<_, ()>(Some(BlockHeight::from(height)), Some(1), |cb| {
            found = Some(cb.hash().0);
            Ok(())
        });
    found.unwrap_or_else(|| {
        let mut hash = [0xee; 32];
        hash[..4].copy_from_slice(&height.to_le_bytes());
        hash
    })
}

/// The paid set of `records` over `(start, end]` of `st`'s chain under `epoch`.
fn paid_set(st: &State, records: &[Record], epoch: u64, start: u32, end: u32) -> PaidSet {
    let span = Span {
        start,
        start_hash: block_hash(st, start),
        end,
        end_hash: block_hash(st, end),
    };
    let paid = records
        .iter()
        .filter(|r| (start + 1..=end).contains(&r.payment.height))
        .map(|r| r.receiver.as_bytes());
    PaidSet::build(GENESIS, epoch, span, paid).unwrap()
}

/// The catalog head digest and recovery objects by route of a publication ending at
/// `end`, whose payments are `records`, as `history` describes it: every closed bucket
/// from its oldest retained start, the cumulative snapshot and the seen set.
pub fn recovery_objects(
    st: &State,
    records: &[Record],
    end: u32,
    history: &History,
) -> (Hash, BTreeMap<String, Vec<u8>>) {
    let latest_end = end - end % BUCKET_BLOCKS;
    let mut objects = BTreeMap::new();
    let mut starts = Vec::new();
    for start in (history.oldest_start..latest_end).step_by(BUCKET_BLOCKS as usize) {
        let bucket = paid_set(st, records, history.epoch, start, start + BUCKET_BLOCKS);
        let digest = bucket.digest();
        objects.insert(
            format!("bucket/{start}/{}", hex::encode(digest)),
            bucket.encode(),
        );
        starts.push((start, digest));
    }
    let cutoff = history.cutoff.unwrap_or(latest_end);
    let paid = paid_set(
        st,
        records,
        history.epoch,
        ACTIVATION - BUCKET_BLOCKS,
        cutoff,
    );
    let seen = SeenSet::new(GENESIS, NOW - 86_400).union(history.seen.iter().map(|r| r.as_bytes()));
    let index = BucketIndex::new(GENESIS, starts).unwrap();
    let head = CatalogHead {
        genesis: GENESIS,
        epoch: history.epoch,
        oldest_start: history.oldest_start,
        latest_end,
        paid: paid.digest(),
        seen: seen.digest().unwrap(),
        index: index.digest(),
    };
    objects.insert(
        format!("paid/{}", hex::encode(paid.digest())),
        paid.encode(),
    );
    objects.insert(
        format!("seen/{}", hex::encode(head.seen)),
        seen.encode().unwrap(),
    );
    objects.insert(
        format!("bucket-index/{}", hex::encode(head.index)),
        index.encode(),
    );
    let catalog = head.digest().unwrap();
    objects.insert(
        format!("catalog/{}", hex::encode(catalog)),
        head.encode().unwrap(),
    );
    (catalog, objects)
}

/// `records` with each one's page and page count among its receiver's, in chain order.
pub fn paged(records: &[Record]) -> Vec<Record> {
    records
        .iter()
        .enumerate()
        .map(|(i, record)| {
            let same = |r: &&Record| r.receiver.as_bytes() == record.receiver.as_bytes();
            let mut record = record.clone();
            record.page = records[..i].iter().filter(same).count().try_into().unwrap();
            record.total = records.iter().filter(same).count().try_into().unwrap();
            record
        })
        .collect()
}

/// The note commitments of `records`, the chain's only Ironwood outputs, in chain order.
pub fn commitments(records: &[Record]) -> Vec<[u8; 32]> {
    records.iter().map(|record| record.payment.cmx).collect()
}

/// A directory publishing `records` as the PIR publication ending at `end`, whose
/// witnesses cover the chain's Ironwood `commitments`, and as `history`'s recovery objects.
pub fn recovering(
    st: &State,
    records: &[Record],
    commitments: &[[u8; 32]],
    end: ChainPoint,
    history: &History,
) -> Directory {
    let records = paged(records);
    let objects = recovery_objects(st, &records, u32::from(end.height), history);
    Directory::new(publish(&records, commitments, end, objects))
}
