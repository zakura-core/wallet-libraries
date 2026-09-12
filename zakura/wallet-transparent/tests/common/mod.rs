//! Fixtures shared by the recovery suites: a synthetic chain paying the
//! wallet's own scripts, a publisher for it, the real shard service run in
//! process, a wallet with its chain accepted, an independent traversal, and an
//! exact comparison.
//!
//! Ported from `enhance-pir`'s own wallet suites so what is exercised here is
//! what will serve a wallet, with the one difference that matters: the scripts
//! paid are the ones this wallet derived from its seed, not synthetic tags.
#![allow(dead_code)]

pub mod blocks;
pub mod catalogue;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use transparent_events::{ReceiveEvent, SpendEvent, TransparentEvent, Txid};
use transparent_filter::{
    BlockHash, ScriptBytes, SealParameters, ShardMap, ShardMapEntry, filter_hash,
};
use transparent_shard::build::build_shard;
use transparent_shard::layout::{Geometry, RECENT_8K};
use transparent_shard::manifest::{
    ManifestLayout, ManifestOccupancy, ManifestSeal, SCHEMA, ShardManifest, TableGeometry,
};
use transparent_shard_server::service::{ServiceConfig, ServiceState, router};
use transparent_shard_server::shardset::{DEFAULT_RETAIN_REVISIONS, ShardSet};
use transparent_wallet::client::Table;
use transparent_wallet::http::{HttpOptions, HttpShardTransport};
use transparent_wallet::ledger::Ledger;
use transparent_wallet::transport::{BoxError, FilterSource, ShardTransport};
use transparent_wallet::{WalletStore, WorkLimits};
use zakura_wallet_core::AccountId;
use zakura_wallet_store::{WalletDb, testing::test_db};
use zakura_wallet_sync::TransparentProgress;
use zakura_wallet_transparent::{Endpoints, PirStore, TransparentPir};
use zcash_protocol::consensus::{BlockHeight, Network};

pub const GENESIS: &str = transparent_filter::MAINNET_GENESIS_DISPLAY;
/// Ironwood activation: where the pilot set began, and a realistic birthday.
pub const FIRST: u64 = 3_428_143;
pub const SPAN: u64 = 200;
pub const SHARDS: u64 = 4;

pub fn params() -> Network {
    Network::MainNetwork
}

pub fn genesis() -> BlockHash {
    BlockHash::from_display_hex(GENESIS).unwrap()
}

pub fn hash_at(height: u64) -> BlockHash {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&height.to_le_bytes());
    BlockHash::from_internal_bytes(bytes)
}

/// A different chain from `fork_height` on: every block at or past it has
/// another hash, as a reorg leaves it.
pub fn hash_forked(fork_height: u64) -> impl Fn(u64) -> BlockHash {
    move |height| {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&height.to_le_bytes());
        if height >= fork_height {
            bytes[31] = 0xff;
        }
        BlockHash::from_internal_bytes(bytes)
    }
}

/// A decoy script nobody owns.
pub fn script(tag: u32) -> ScriptBytes {
    let mut bytes = vec![0x76, 0xa9, 0x14];
    bytes.extend_from_slice(&tag.to_le_bytes());
    bytes.extend_from_slice(&[0u8; 16]);
    bytes.extend_from_slice(&[0x88, 0xac]);
    ScriptBytes::new(bytes)
}

pub fn txid(tag: u64) -> Txid {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&tag.to_le_bytes());
    Txid(bytes)
}

/// Where a published set's shards fall: the first covered height, the span
/// of each shard and how many shards a full set holds.
///
/// The suite's fixed constants are one layout; a real-chain sample or a set
/// with another span is another. Everything that turns a height into a shard
/// goes through one of these so the two cannot disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    pub first: u64,
    pub span: u64,
    pub shards: u64,
}

pub const DEFAULT_LAYOUT: Layout = Layout {
    first: FIRST,
    span: SPAN,
    shards: SHARDS,
};

impl Layout {
    pub fn shard_of(&self, height: u64) -> usize {
        ((height - self.first) / self.span) as usize
    }

    pub fn bounds(&self, id: u64) -> (u64, u64) {
        (
            self.first + id * self.span,
            self.first + (id + 1) * self.span - 1,
        )
    }

    /// The last height a full set covers.
    pub fn last(&self) -> u64 {
        self.bounds(self.shards - 1).1
    }
}

pub fn shard_of(height: u64) -> usize {
    DEFAULT_LAYOUT.shard_of(height)
}

pub fn shard_bounds(id: u64) -> (u64, u64) {
    DEFAULT_LAYOUT.bounds(id)
}

pub type Events = Vec<Vec<(ScriptBytes, TransparentEvent)>>;

/// How many receives the paged script gets: more than fit inline and in one
/// page, so retrieval has to fetch pages.
pub fn long_history() -> u64 {
    u64::from(transparent_shard::EVENTS_PER_PAGE + transparent_shard::INLINE_EVENTS + 5)
}

/// Unrelated activity in every shard, so the wallet's scripts are not alone in
/// the filters and every shard has something to serve.
pub fn decoys() -> Events {
    let mut per_shard: Events = (0..SHARDS).map(|_| Vec::new()).collect();
    for shard in 0..SHARDS {
        for tag in 100..400u32 {
            let height = FIRST + shard * SPAN + u64::from(tag % 50);
            per_shard[shard as usize].push((
                script(tag),
                TransparentEvent::Receive(ReceiveEvent {
                    height: height as u32,
                    txid: txid(u64::from(tag) * 1_000 + shard),
                    transaction_index: 3,
                    output_index: 0,
                    value: 1,
                    coinbase: false,
                }),
            ));
        }
    }
    per_shard
}

/// The cases that matter, over three of the wallet's own scripts: `mine[0]`
/// is received in shard 0 and spent in shard 2; `mine[1]` is received in
/// shards 1 and 3; `mine[2]` has a history long enough to need pages, in
/// shard 1. Decoys everywhere.
pub fn chain(mine: &[ScriptBytes]) -> Events {
    let mut per_shard = decoys();
    let mut push = |height: u64, s: ScriptBytes, event: TransparentEvent| {
        per_shard[shard_of(height)].push((s, event));
    };

    push(
        FIRST + 5,
        mine[0].clone(),
        TransparentEvent::Receive(ReceiveEvent {
            height: (FIRST + 5) as u32,
            txid: txid(100),
            transaction_index: 0,
            output_index: 0,
            value: 50_000,
            coinbase: false,
        }),
    );
    push(
        FIRST + 2 * SPAN + 10,
        mine[0].clone(),
        TransparentEvent::Spend(SpendEvent {
            height: (FIRST + 2 * SPAN + 10) as u32,
            spending_txid: txid(200),
            transaction_index: 0,
            input_index: 0,
            spent_txid: txid(100),
            spent_output_index: 0,
        }),
    );
    for (n, height) in [FIRST + SPAN + 3, FIRST + 3 * SPAN + 7].iter().enumerate() {
        push(
            *height,
            mine[1].clone(),
            TransparentEvent::Receive(ReceiveEvent {
                height: *height as u32,
                txid: txid(300 + n as u64),
                transaction_index: 1,
                output_index: 0,
                value: 7_000 + n as u64,
                coinbase: false,
            }),
        );
    }
    for i in 0..long_history() {
        let height = FIRST + SPAN + 20 + i % 100;
        push(
            height,
            mine[2].clone(),
            TransparentEvent::Receive(ReceiveEvent {
                height: height as u32,
                txid: txid(1_000 + i),
                transaction_index: 2,
                output_index: 0,
                value: 11,
                coinbase: false,
            }),
        );
    }
    per_shard
}

/// What the full chain leaves the wallet holding.
pub fn full_balance() -> u64 {
    7_000 + 7_001 + 11 * long_history()
}

/// Writes a publishable shard set to `dir`, as the publisher would.
pub fn publish(dir: &Path, per_shard: &[Vec<(ScriptBytes, TransparentEvent)>]) -> ShardMap {
    publish_with(dir, per_shard, |_| &RECENT_8K, 0, "", hash_at)
}

/// Writes a publishable shard set whose chain hashes come from `hash`.
///
/// `tail_revision` and `tail_supersedes` apply to the unsealed last shard
/// alone, because it is the only one that can be republished. The last shard
/// is unsealed only when the set holds `SHARDS` shards; a shorter prefix is
/// published entirely sealed, as a set that has since grown looks in
/// hindsight, and a longer one seals everything but its own last shard.
pub fn publish_with(
    dir: &Path,
    per_shard: &[Vec<(ScriptBytes, TransparentEvent)>],
    geometry_for: impl Fn(u64) -> &'static Geometry,
    tail_revision: u32,
    tail_supersedes: &str,
    hash: impl Fn(u64) -> BlockHash,
) -> ShardMap {
    publish_layout(
        dir,
        per_shard,
        DEFAULT_LAYOUT,
        geometry_for,
        tail_revision,
        tail_supersedes,
        hash,
    )
}

/// `publish_with` over a layout other than the suite's constants.
pub fn publish_layout(
    dir: &Path,
    per_shard: &[Vec<(ScriptBytes, TransparentEvent)>],
    layout: Layout,
    geometry_for: impl Fn(u64) -> &'static Geometry,
    tail_revision: u32,
    tail_supersedes: &str,
    hash: impl Fn(u64) -> BlockHash,
) -> ShardMap {
    let mut entries = Vec::new();
    let mut parent_digest = String::new();
    let count = per_shard.len() as u64;
    for (shard_id, events) in per_shard.iter().enumerate() {
        let shard_id = shard_id as u64;
        let geometry = geometry_for(shard_id);
        let (start, end) = layout.bounds(shard_id);
        let built = build_shard(
            shard_id,
            start,
            end,
            genesis(),
            hash(end),
            transparent_filter::RANGE_PROFILE,
            geometry,
            events,
        )
        .expect("build");
        let is_tail = shard_id + 1 == count && count >= layout.shards;

        let manifest = ShardManifest {
            schema: SCHEMA.to_string(),
            profile: transparent_filter::RANGE_PROFILE.to_string(),
            geometry: geometry.name.to_string(),
            network: transparent_filter::NETWORK.to_string(),
            genesis_hash: GENESIS.to_string(),
            shard_id,
            start_height: start,
            end_height: end,
            parent_block_hash: hash(start - 1).to_display_hex(),
            terminal_block_hash: hash(end).to_display_hex(),
            parent_manifest_digest: parent_digest.clone(),
            sealed: !is_tail,
            revision: if is_tail { tail_revision } else { 0 },
            supersedes: if is_tail {
                tail_supersedes.to_string()
            } else {
                String::new()
            },
            seal: ManifestSeal {
                scripts_target: 8_192,
                scripts_capacity: 16_384,
                page_rows_target: 2_048,
                page_rows_capacity: 4_096,
            },
            layout: ManifestLayout {
                max_script_bytes: transparent_shard::MAX_SCRIPT_BYTES as u32,
                inline_events: transparent_shard::INLINE_EVENTS,
                events_per_page: transparent_shard::EVENTS_PER_PAGE,
                page_row_header_bytes: transparent_shard::PAGE_ROW_HEADER_BYTES as u32,
                page_entry_header_bytes: transparent_shard::PAGE_ENTRY_HEADER_BYTES as u32,
                directory_choices: transparent_shard::build::DIRECTORY_CHOICES as u32,
            },
            filter_hash: filter_hash(built.filter.as_slice()).to_display_hex(),
            directory_segments: built
                .directory
                .iter()
                .map(|segment| TableGeometry {
                    rows: geometry.directory_rows,
                    row_bytes: geometry.directory_row_bytes as u32,
                    sha256: hex::encode(<sha2::Sha256 as sha2::Digest>::digest(segment)),
                })
                .collect(),
            page_segments: built
                .pages
                .iter()
                .map(|segment| TableGeometry {
                    rows: geometry.page_rows,
                    row_bytes: geometry.page_row_bytes as u32,
                    sha256: hex::encode(<sha2::Sha256 as sha2::Digest>::digest(segment)),
                })
                .collect(),
            occupancy: ManifestOccupancy {
                scripts: built.scripts,
                page_rows: built.page_rows,
                fragments: built.fragments,
                events: built.events,
                blocks: layout.span,
                txids: 0,
                excluded_scripts: built.excluded_scripts,
            },
        };

        let digest = manifest.digest();
        let shard_dir = dir.join(&digest);
        std::fs::create_dir_all(&shard_dir).unwrap();
        std::fs::write(shard_dir.join("manifest.json"), manifest.canonical_bytes()).unwrap();
        std::fs::write(shard_dir.join("filter.bin"), built.filter.as_slice()).unwrap();
        for (index, segment) in built.directory.iter().enumerate() {
            std::fs::write(shard_dir.join(format!("directory.{index}.bin")), segment).unwrap();
        }
        for (index, segment) in built.pages.iter().enumerate() {
            std::fs::write(shard_dir.join(format!("pages.{index}.bin")), segment).unwrap();
        }

        entries.push(ShardMapEntry {
            shard_id,
            geometry: geometry.name.to_string(),
            start_height: start,
            end_height: end,
            parent_block_hash: manifest.parent_block_hash.clone(),
            terminal_block_hash: manifest.terminal_block_hash.clone(),
            filter_hash: manifest.filter_hash.clone(),
            scripts: built.scripts,
            page_rows: built.page_rows,
            txids: 0,
            directory_segments: built.directory_segments(),
            page_segments: built.page_segments(),
            manifest_digest: digest.clone(),
            revision: manifest.revision,
            sealed: manifest.sealed,
        });
        parent_digest = digest;
    }

    let map = ShardMap {
        genesis_hash: GENESIS.to_string(),
        network: transparent_filter::NETWORK.to_string(),
        profile: transparent_filter::RANGE_PROFILE.to_string(),
        range_envelope_version: transparent_filter::RANGE_ENVELOPE_VERSION,
        start_height: layout.first,
        seal: entries
            .iter()
            .map(|entry| {
                (
                    entry.geometry.clone(),
                    SealParameters {
                        max_scripts: 8_192,
                        max_page_rows: 2_048,
                        max_txids: 0,
                    },
                )
            })
            .collect(),
        shards: entries,
    };
    map.check_shape().expect("a well-formed map");
    std::fs::write(
        dir.join("shards.json"),
        serde_json::to_vec_pretty(&map).unwrap(),
    )
    .unwrap();
    map
}

/// Filters read from the published files, charged at their real size, and
/// open to being tampered with by a test.
pub struct Filters {
    pub filters: BTreeMap<u64, Vec<u8>>,
    pub map: Vec<u8>,
    /// How many times the map was read.
    pub map_reads: u64,
    /// How many times a filter was read.
    pub filter_reads: u64,
}

impl Filters {
    pub fn load(dir: &Path, map: &ShardMap) -> Self {
        let mut filters = BTreeMap::new();
        for entry in &map.shards {
            filters.insert(
                entry.shard_id,
                std::fs::read(dir.join(&entry.manifest_digest).join("filter.bin")).unwrap(),
            );
        }
        Self {
            filters,
            map: serde_json::to_vec(map).unwrap(),
            map_reads: 0,
            filter_reads: 0,
        }
    }
}

impl FilterSource for Filters {
    fn shard_map(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        self.map_reads += 1;
        Ok((self.map.clone(), self.map.len() as u64))
    }

    fn filter(&mut self, shard_id: u64) -> Result<(Vec<u8>, u64), BoxError> {
        self.filter_reads += 1;
        let bytes = self.filters.get(&shard_id).ok_or("no such shard")?.clone();
        let len = bytes.len() as u64;
        Ok((bytes, len))
    }
}

/// The real transport, counting what crosses it, with an init a test can
/// replace.
pub struct Counting {
    inner: HttpShardTransport,
    pub init_override: Option<Vec<u8>>,
    /// Shards whose setup was fetched; cached setup makes a re-read skip this.
    pub opened: Vec<u64>,
    /// Shards a private query went to.
    pub queried: Vec<u64>,
    pub queries: u64,
    pub manifests: u64,
    /// Private queries per shard, so a re-read of one shard is visible even
    /// when the shard was queried before.
    pub queries_by_shard: BTreeMap<u64, u64>,
    /// Setup fetches per shard.
    pub setups_by_shard: BTreeMap<u64, u64>,
    /// Every revision digest a private query named, in order, without repeats.
    pub revisions: Vec<String>,
}

impl Counting {
    pub fn new(base: &str) -> Self {
        Self {
            inner: HttpShardTransport::new(base, &HttpOptions::default()).unwrap(),
            init_override: None,
            opened: Vec::new(),
            queried: Vec::new(),
            queries: 0,
            manifests: 0,
            queries_by_shard: BTreeMap::new(),
            setups_by_shard: BTreeMap::new(),
            revisions: Vec::new(),
        }
    }

    /// Private queries that went to `shard_id`.
    pub fn queries_to(&self, shard_id: u64) -> u64 {
        self.queries_by_shard.get(&shard_id).copied().unwrap_or(0)
    }
}

impl ShardTransport for Counting {
    fn init(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        match &self.init_override {
            Some(init) => Ok((init.clone(), init.len() as u64)),
            None => self.inner.init(),
        }
    }

    fn manifest(&mut self, shard_id: u64, revision: &str) -> Result<(Vec<u8>, u64), BoxError> {
        self.manifests += 1;
        self.inner.manifest(shard_id, revision)
    }

    fn setup(
        &mut self,
        shard_id: u64,
        revision: &str,
        table: Table,
        segment: u32,
    ) -> Result<(Vec<u8>, u64), BoxError> {
        if !self.opened.contains(&shard_id) {
            self.opened.push(shard_id);
        }
        *self.setups_by_shard.entry(shard_id).or_default() += 1;
        self.inner.setup(shard_id, revision, table, segment)
    }

    fn query(
        &mut self,
        shard_id: u64,
        revision: &str,
        table: Table,
        body: &[u8],
    ) -> Result<Vec<u8>, BoxError> {
        self.queries += 1;
        if !self.queried.contains(&shard_id) {
            self.queried.push(shard_id);
        }
        *self.queries_by_shard.entry(shard_id).or_default() += 1;
        if !self.revisions.iter().any(|r| r == revision) {
            self.revisions.push(revision.to_owned());
        }
        self.inner.query(shard_id, revision, table, body)
    }
}

/// The independent result: the same events replayed with no retrieval at all.
pub fn traverse(
    per_shard: &[Vec<(ScriptBytes, TransparentEvent)>],
    wallet: &[ScriptBytes],
) -> Ledger {
    let mut events: Vec<(Vec<u8>, TransparentEvent)> = Vec::new();
    for shard in per_shard {
        for (s, event) in shard {
            if wallet.iter().any(|w| w.as_slice() == s.as_slice()) {
                events.push((s.as_slice().to_vec(), *event));
            }
        }
    }
    let mut ledger = Ledger::new();
    ledger.replay(&mut events).expect("traversal");
    ledger
}

pub fn compare(recovered: &Ledger, expected: &Ledger) {
    let mut mine: Vec<_> = recovered.utxos().cloned().collect();
    let mut theirs: Vec<_> = expected.utxos().cloned().collect();
    mine.sort_by_key(|u| (u.txid, u.output_index));
    theirs.sort_by_key(|u| (u.txid, u.output_index));
    assert_eq!(mine, theirs, "UTXO sets differ");

    let mut my_spends = recovered.spends().to_vec();
    let mut their_spends = expected.spends().to_vec();
    my_spends.sort_by_key(|s| (s.spent_txid, s.spent_output_index));
    their_spends.sort_by_key(|s| (s.spent_txid, s.spent_output_index));
    assert_eq!(my_spends, their_spends, "spend sets differ");

    assert_eq!(recovered.confirmed_balance(), expected.confirmed_balance());
    assert_eq!(recovered.history(), expected.history(), "histories differ");
    assert_eq!(
        recovered.unresolved().len(),
        expected.unresolved().len(),
        "unresolved spends differ"
    );
}

/// Starts the service on an ephemeral port and returns its base URL.
pub async fn serve(dir: &Path) -> String {
    let set = ShardSet::open(dir, DEFAULT_RETAIN_REVISIONS).expect("load");
    let state = ServiceState::build(set, ServiceConfig::default()).expect("state");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router(state)).await.unwrap();
    });
    format!("http://{addr}")
}

// ------------------------------------------------------------- the wallet

/// A wallet with one account, born at the first covered height.
pub fn wallet() -> (WalletDb, AccountId) {
    let mut db = test_db().unwrap();
    let id = db
        .create_account(
            &params(),
            &[7u8; 32],
            zip32::AccountId::try_from(0).unwrap(),
            BlockHeight::from_u32(FIRST as u32),
        )
        .unwrap();
    (db, id)
}

/// The account's watched scripts, external first, in derivation order.
pub fn my_scripts(db: &WalletDb, account: AccountId) -> Vec<ScriptBytes> {
    db.connection()
        .prepare(
            "SELECT transparent_script FROM cache.addresses
             WHERE transparent_script IS NOT NULL AND account_id = ?1
             ORDER BY key_scope, transparent_child_index",
        )
        .unwrap()
        .query_map([account.0], |row| row.get::<_, Vec<u8>>(0))
        .unwrap()
        .map(|s| ScriptBytes::new(s.unwrap()))
        .collect()
}

/// Records the wallet as having accepted `hash` at `height`.
pub fn accept(db: &WalletDb, height: u64, hash: BlockHash) {
    db.connection()
        .execute(
            "INSERT OR REPLACE INTO cache.blocks
                (height, hash, time, orchard_tree_size, ironwood_tree_size,
                 orchard_action_count, ironwood_action_count)
             VALUES (?1, ?2, 0, 0, 0, 0, 0)",
            rusqlite::params![height as u32, &hash.internal_bytes()[..]],
        )
        .unwrap();
}

/// Accepts every boundary of the first `count` shards, on the chain `hash`
/// describes.
pub fn accept_through_with(db: &WalletDb, count: u64, hash: impl Fn(u64) -> BlockHash) {
    accept_layout(db, DEFAULT_LAYOUT, count, hash);
}

/// `accept_through_with` over another layout.
pub fn accept_layout(db: &WalletDb, layout: Layout, count: u64, hash: impl Fn(u64) -> BlockHash) {
    accept(db, layout.first - 1, hash(layout.first - 1));
    for id in 0..count {
        let (start, end) = layout.bounds(id);
        accept(db, start - 1, hash(start - 1));
        accept(db, end, hash(end));
    }
}

pub fn accept_through(db: &WalletDb, count: u64) {
    accept_through_with(db, count, hash_at);
}

pub fn pir() -> TransparentPir<Network> {
    TransparentPir::new(
        Endpoints::new("https://filters.invalid", "https://shards.invalid"),
        params(),
    )
    .with_limits(WorkLimits::UNLIMITED)
}

/// One recovery of `db` against the service at `base`, off the async runtime.
pub async fn recover(
    db: WalletDb,
    base: String,
    dir: &Path,
    map: &ShardMap,
    limits: WorkLimits,
) -> (
    WalletDb,
    Counting,
    Result<TransparentProgress, zakura_wallet_transparent::Error>,
) {
    let filters = Filters::load(dir, map);
    recover_with(db, base, filters, limits, |t| t).await
}

/// One recovery with the filters and transport a test prepared.
pub async fn recover_with(
    db: WalletDb,
    base: String,
    filters: Filters,
    limits: WorkLimits,
    prepare: impl FnOnce(Counting) -> Counting + Send + 'static,
) -> (
    WalletDb,
    Counting,
    Result<TransparentProgress, zakura_wallet_transparent::Error>,
) {
    tokio::task::spawn_blocking(move || {
        let mut db = db;
        let mut filters = filters;
        let mut transport = prepare(Counting::new(&base));
        let result = pir()
            .with_limits(limits)
            .recover_with(&mut db, &mut filters, &mut transport);
        (db, transport, result)
    })
    .await
    .unwrap()
}

/// The ledger the store holds, replayed the library's way.
pub fn store_ledger(db: &mut WalletDb) -> Ledger {
    PirStore::new(db, BTreeMap::new()).ledger().unwrap()
}

pub fn state(db: &WalletDb, account: AccountId) -> zakura_wallet_store::TransparentState {
    db.transparent_state(account, BlockHeight::from_u32(FIRST as u32))
        .unwrap()
}

pub fn h(height: u64) -> BlockHeight {
    BlockHeight::from_u32(height as u32)
}

// ------------------------------------------------------ shared filters

/// Filters a test can swap between requests, from outside the run.
#[derive(Clone)]
pub struct SharedFilters(pub Arc<Mutex<Filters>>);

impl SharedFilters {
    pub fn new(filters: Filters) -> Self {
        Self(Arc::new(Mutex::new(filters)))
    }

    /// Replaces the map and filters with those of another published set.
    pub fn replace(&self, dir: &Path, map: &ShardMap) {
        let fresh = Filters::load(dir, map);
        let mut held = self.0.lock().unwrap();
        held.filters = fresh.filters;
        held.map = fresh.map;
    }

    pub fn map_reads(&self) -> u64 {
        self.0.lock().unwrap().map_reads
    }

    pub fn filter_reads(&self) -> u64 {
        self.0.lock().unwrap().filter_reads
    }
}

impl FilterSource for SharedFilters {
    fn shard_map(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        self.0.lock().unwrap().shard_map()
    }

    fn filter(&mut self, shard_id: u64) -> Result<(Vec<u8>, u64), BoxError> {
        self.0.lock().unwrap().filter(shard_id)
    }
}

// ------------------------------------------------- the service, observed

/// One request the service saw.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    /// The whole request target, query string included.
    pub uri: String,
    /// Every header, `name: value`, one per line.
    pub headers: String,
    pub body: Vec<u8>,
}

/// What a request path names, by the service's routes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Map,
    Init,
    Filter {
        shard: u64,
    },
    Manifest {
        shard: u64,
        revision: String,
    },
    Setup {
        shard: u64,
        revision: String,
        table: String,
        segment: u32,
    },
    Query {
        shard: u64,
        revision: String,
        table: String,
    },
    Health,
}

impl Route {
    /// Classifies a request, or returns `None` for a path the service does not
    /// serve.
    pub fn of(method: &str, path: &str) -> Option<Route> {
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        let hex64 = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit());
        match (method, parts.as_slice()) {
            ("GET", ["v1", "shards"]) | ("GET", ["v1", "filters", "shards"]) => Some(Route::Map),
            ("GET", ["v1", "shards", "init"]) => Some(Route::Init),
            ("GET", ["v1", "health"]) | ("GET", ["v1", "ready"]) | ("GET", ["metrics"]) => {
                Some(Route::Health)
            }
            ("GET", ["v1", "filters", "shards", shard, "filter"]) => Some(Route::Filter {
                shard: shard.parse().ok()?,
            }),
            ("GET", ["v1", "shards", shard, "revisions", revision, "manifest"])
                if hex64(revision) =>
            {
                Some(Route::Manifest {
                    shard: shard.parse().ok()?,
                    revision: (*revision).to_owned(),
                })
            }
            (
                "GET",
                [
                    "v1",
                    "shards",
                    shard,
                    "revisions",
                    revision,
                    "setup",
                    table,
                    segment,
                ],
            ) if hex64(revision) && (*table == "directory" || *table == "pages") => {
                Some(Route::Setup {
                    shard: shard.parse().ok()?,
                    revision: (*revision).to_owned(),
                    table: (*table).to_owned(),
                    segment: segment.parse().ok()?,
                })
            }
            ("POST", ["v1", "shards", shard, "revisions", revision, "query", table])
                if hex64(revision) && (*table == "directory" || *table == "pages") =>
            {
                Some(Route::Query {
                    shard: shard.parse().ok()?,
                    revision: (*revision).to_owned(),
                    table: (*table).to_owned(),
                })
            }
            _ => None,
        }
    }

    pub fn shard(&self) -> Option<u64> {
        match self {
            Route::Filter { shard }
            | Route::Manifest { shard, .. }
            | Route::Setup { shard, .. }
            | Route::Query { shard, .. } => Some(*shard),
            _ => None,
        }
    }
}

/// What to tamper with in a response, once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tamper {
    Manifest {
        shard: u64,
    },
    Setup {
        shard: u64,
        segment: u32,
    },
    /// The nth page-table answer for the shard, counting from 1.
    Page {
        shard: u64,
        nth: u32,
    },
    /// The nth directory-table answer for the shard, counting from 1.
    Directory {
        shard: u64,
        nth: u32,
    },
}

/// A request to hold until the test lets it go.
#[derive(Clone)]
pub struct HoldOn {
    pub shard: u64,
    /// `directory`, `pages`, or `None` for either.
    pub table: Option<&'static str>,
    /// Which matching request to hold, counting from 1.
    pub nth: u32,
    pub gate: Arc<tokio::sync::Notify>,
    /// Set the moment the held request arrives.
    pub in_flight: Arc<AtomicBool>,
}

impl HoldOn {
    pub fn new(shard: u64, table: Option<&'static str>, nth: u32) -> Self {
        Self {
            shard,
            table,
            nth,
            gate: Arc::new(tokio::sync::Notify::new()),
            in_flight: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn is_in_flight(&self) -> bool {
        self.in_flight.load(Ordering::SeqCst)
    }

    /// Lets the held request through.
    pub fn release(&self) {
        self.gate.notify_one();
    }
}

/// Faults the service injects, and what it has seen.
#[derive(Default)]
pub struct Faults {
    /// Private queries still to refuse with 503.
    pub overload_remaining: u64,
    /// The `Retry-After` the refusal carries, if any.
    pub overload_retry_after: Option<String>,
    pub hold: Option<HoldOn>,
    pub tamper: Option<Tamper>,
    /// Every request seen, in order.
    pub requests: Vec<Request>,
    /// Query answers per (shard, table), counting from 1, for `nth` matching.
    pub answers: BTreeMap<(u64, String), u32>,
    /// Query requests per (shard, table), likewise.
    pub arrivals: BTreeMap<(u64, String), u32>,
    /// Requests that were refused as overloaded.
    pub refused: u64,
    /// How many responses were tampered with.
    pub tampered: u64,
}

impl Faults {
    pub fn none() -> Arc<Mutex<Faults>> {
        Arc::new(Mutex::new(Faults::default()))
    }

    pub fn overload(remaining: u64, retry_after: Option<&str>) -> Arc<Mutex<Faults>> {
        Arc::new(Mutex::new(Faults {
            overload_remaining: remaining,
            overload_retry_after: retry_after.map(str::to_owned),
            ..Faults::default()
        }))
    }

    pub fn tamper(tamper: Tamper) -> Arc<Mutex<Faults>> {
        Arc::new(Mutex::new(Faults {
            tamper: Some(tamper),
            ..Faults::default()
        }))
    }

    pub fn hold(hold: HoldOn) -> Arc<Mutex<Faults>> {
        Arc::new(Mutex::new(Faults {
            hold: Some(hold),
            ..Faults::default()
        }))
    }
}

/// A running service a test can stop.
///
/// The service runs on a runtime of its own, on its own thread, so that
/// stopping it drops the listener and every open connection at once — a
/// wallet mid-request sees the connection reset, as it would if the process
/// died — rather than only the accept loop.
pub struct ServerHandle {
    stop: Mutex<Option<std::sync::mpsc::Sender<()>>>,
}

impl ServerHandle {
    /// Stops accepting and drops every connection: the service is gone.
    pub fn stop(&self) {
        if let Some(stop) = self.stop.lock().unwrap().take() {
            let _ = stop.send(());
        }
    }
}

async fn fault_layer(
    axum::extract::State(faults): axum::extract::State<Arc<Mutex<Faults>>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::body::{Body, to_bytes};
    let method = req.method().to_string();
    let path = req.uri().path().to_owned();
    let uri = req.uri().to_string();
    let headers = req
        .headers()
        .iter()
        .map(|(name, value)| format!("{name}: {}", String::from_utf8_lossy(value.as_bytes())))
        .collect::<Vec<_>>()
        .join("\n");
    let (parts, body) = req.into_parts();
    let bytes = to_bytes(body, usize::MAX).await.unwrap_or_default();
    let route = Route::of(&method, &path);

    // Record, then decide what to do with it, under one lock.
    let (refuse, hold, tamper) = {
        let mut f = faults.lock().unwrap();
        f.requests.push(Request {
            method: method.clone(),
            path: path.clone(),
            uri,
            headers,
            body: bytes.to_vec(),
        });
        let mut refuse = None;
        let mut hold = None;
        let mut tamper = None;
        if let Some(Route::Query { shard, table, .. }) = &route {
            let arrival = f.arrivals.entry((*shard, table.clone())).or_default();
            *arrival += 1;
            let arrival = *arrival;
            if f.overload_remaining > 0 {
                f.overload_remaining -= 1;
                f.refused += 1;
                refuse = Some(f.overload_retry_after.clone());
            } else if let Some(h) = f.hold.as_ref().filter(|h| {
                h.shard == *shard && h.table.is_none_or(|t| t == table) && h.nth == arrival
            }) {
                hold = Some(h.clone());
            }
        }
        // Count answers per (shard, table) first, so a tamper can name the nth.
        if let Some(Route::Query { shard, table, .. }) = &route {
            *f.answers.entry((*shard, table.clone())).or_default() += 1;
        }
        let answered = |f: &Faults, shard: u64, table: &str| {
            f.answers
                .get(&(shard, table.to_owned()))
                .copied()
                .unwrap_or(0)
        };
        if let Some(t) = f.tamper.clone() {
            let hit = match (&t, &route) {
                (Tamper::Manifest { shard }, Some(Route::Manifest { shard: s, .. })) => shard == s,
                (
                    Tamper::Setup { shard, segment },
                    Some(Route::Setup {
                        shard: s,
                        segment: seg,
                        ..
                    }),
                ) => shard == s && segment == seg,
                (
                    Tamper::Page { shard, nth },
                    Some(Route::Query {
                        shard: s, table, ..
                    }),
                ) => shard == s && table == "pages" && answered(&f, *s, table) == *nth,
                (
                    Tamper::Directory { shard, nth },
                    Some(Route::Query {
                        shard: s, table, ..
                    }),
                ) => shard == s && table == "directory" && answered(&f, *s, table) == *nth,
                _ => false,
            };
            if hit {
                f.tampered += 1;
                tamper = Some(());
            }
        }
        (refuse, hold, tamper)
    };

    if let Some(retry_after) = refuse {
        let mut builder = axum::response::Response::builder().status(503);
        if let Some(delay) = retry_after {
            builder = builder.header("Retry-After", delay);
        }
        return builder.body(Body::from("busy")).unwrap();
    }
    if let Some(hold) = hold {
        hold.in_flight.store(true, Ordering::SeqCst);
        hold.gate.notified().await;
    }

    let req = axum::extract::Request::from_parts(parts, Body::from(bytes));
    let response = next.run(req).await;
    if tamper.is_some() {
        let (parts, body) = response.into_parts();
        let mut bytes = to_bytes(body, usize::MAX)
            .await
            .unwrap_or_default()
            .to_vec();
        if !bytes.is_empty() {
            let at = bytes.len() / 2;
            bytes[at] ^= 0x5a;
        }
        return axum::response::Response::from_parts(parts, Body::from(bytes));
    }
    response
}

/// Starts the service with `faults` in front of it.
pub async fn serve_with(dir: &Path, faults: Arc<Mutex<Faults>>) -> (String, ServerHandle) {
    let set = ShardSet::open(dir, DEFAULT_RETAIN_REVISIONS).expect("load");
    let state = ServiceState::build(set, ServiceConfig::default()).expect("state");
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    std_listener.set_nonblocking(true).unwrap();
    let addr = std_listener.local_addr().unwrap();
    let app = router(state).layer(axum::middleware::from_fn_with_state(faults, fault_layer));
    let (stop, stopped) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.spawn(async move {
            let listener = tokio::net::TcpListener::from_std(std_listener).unwrap();
            axum::serve(listener, app).await.unwrap();
        });
        // Run until stopped. A dropped handle is not a stop: the service
        // lives as long as the test process, as `serve` always has.
        match stopped.recv() {
            Ok(()) => runtime.shutdown_background(),
            Err(_) => loop {
                std::thread::park();
            },
        }
    });
    (
        format!("http://{addr}"),
        ServerHandle {
            stop: Mutex::new(Some(stop)),
        },
    )
}

/// Starts the service and records every request it sees.
pub async fn serve_traced(dir: &Path) -> (String, Arc<Mutex<Faults>>) {
    let faults = Faults::none();
    let (base, _) = serve_with(dir, faults.clone()).await;
    (base, faults)
}

/// Everything the service must never be told in the clear.
#[derive(Debug, Default)]
pub struct Needles {
    /// Text that must not appear in a path or a body: script hex, addresses,
    /// txid hex in both byte orders, and `txid:n` outpoints.
    pub text: Vec<String>,
    /// Bytes that must not appear in a body: raw scripts and raw txids.
    pub bytes: Vec<Vec<u8>>,
}

impl Needles {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn script(mut self, script: &[u8]) -> Self {
        self.text.push(hex::encode(script));
        self.text.push(base64_std(script));
        self.text.push(base64_url(script));
        self.bytes.push(script.to_vec());
        // The twenty-byte hash a P2PKH or P2SH script wraps: a request that
        // carried the bare hash would name the address just as well.
        let s = script;
        let hash = if s.len() == 25 && s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14 {
            Some(&s[3..23])
        } else if s.len() == 23 && s[0] == 0xa9 && s[1] == 0x14 {
            Some(&s[2..22])
        } else {
            None
        };
        if let Some(hash) = hash {
            self.text.push(hex::encode(hash));
            self.text.push(base64_std(hash));
            self.text.push(base64_url(hash));
            self.bytes.push(hash.to_vec());
        }
        self
    }

    pub fn address(mut self, address: &str) -> Self {
        self.text.push(address.to_owned());
        self
    }

    pub fn txid(mut self, txid: &Txid) -> Self {
        self.text.push(txid.to_display_hex());
        self.text.push(hex::encode(txid.0));
        self.text.push(base64_std(&txid.0));
        self.text.push(base64_url(&txid.0));
        let mut display = txid.0;
        display.reverse();
        self.bytes.push(txid.0.to_vec());
        self.bytes.push(display.to_vec());
        self
    }

    /// Every script and address of `account`, and every txid of an event at
    /// one of its scripts in `events`.
    pub fn of(db: &WalletDb, account: AccountId, events: &Events) -> Self {
        let mut needles = Self::new();
        let mine: BTreeSet<Vec<u8>> = my_scripts(db, account)
            .into_iter()
            .map(|s| s.as_slice().to_vec())
            .collect();
        for script in &mine {
            needles = needles.script(script);
        }
        for address in db.transparent_addresses(account).unwrap() {
            needles = needles.address(&address);
        }
        let mut seen = BTreeSet::new();
        for shard in events {
            for (script, event) in shard {
                if !mine.contains(script.as_slice()) {
                    continue;
                }
                if seen.insert(event.txid()) {
                    needles = needles.txid(&event.txid());
                }
                if let TransparentEvent::Spend(spend) = event
                    && seen.insert(spend.spent_txid)
                {
                    needles = needles.txid(&spend.spent_txid);
                }
            }
        }
        needles
    }
}

fn base64_with(bytes: &[u8], alphabet: &[u8; 64]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(alphabet[(n >> 18) as usize & 63] as char);
        out.push(alphabet[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(alphabet[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(alphabet[n as usize & 63] as char);
        }
    }
    out
}

pub fn base64_std(bytes: &[u8]) -> String {
    base64_with(
        bytes,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    )
}

pub fn base64_url(bytes: &[u8]) -> String {
    base64_with(
        bytes,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    )
}

/// Every request went to a route the protocol has, and none of them — path,
/// query string, headers or body — carried a script (raw, hex, base64 or its
/// bare hash), an address, a txid (either byte order, hex or base64) or an
/// outpoint. Returns the shards named.
pub fn assert_no_plaintext(requests: &[Request], needles: &Needles) -> BTreeSet<u64> {
    let mut shards = BTreeSet::new();
    for request in requests {
        let route = Route::of(&request.method, &request.path).unwrap_or_else(|| {
            panic!(
                "{} {} is not a route the private protocol has",
                request.method, request.path
            )
        });
        if let Some(shard) = route.shard() {
            shards.insert(shard);
        }
        assert!(
            !request.uri.contains('?') || request.uri.ends_with('?'),
            "a request carried a query string: {} {}",
            request.method,
            request.uri
        );
        let texts = [
            ("request line", request.uri.clone()),
            ("headers", request.headers.clone()),
            ("body", String::from_utf8_lossy(&request.body).into_owned()),
        ];
        for needle in &needles.text {
            for (what, text) in &texts {
                let hit = text.contains(needle.as_str())
                    || text
                        .to_ascii_lowercase()
                        .contains(&needle.to_ascii_lowercase());
                assert!(
                    !hit,
                    "a request's {what} names the wallet: {} {}",
                    request.method, request.path
                );
            }
        }
        for needle in &needles.bytes {
            for (what, bytes) in [
                ("request line", request.uri.as_bytes()),
                ("headers", request.headers.as_bytes()),
                ("body", request.body.as_slice()),
            ] {
                assert!(
                    !bytes.windows(needle.len()).any(|w| w == needle.as_slice()),
                    "a request's {what} carries the wallet's bytes: {} {}",
                    request.method,
                    request.path
                );
            }
        }
    }
    shards
}

// ------------------------------------------------ interrupting transports

/// A transport that raises the wallet's stop signal after a number of
/// private queries, as a wallet being closed mid-recovery would.
pub struct StopAfter {
    pub inner: Counting,
    pub signal: zakura_wallet_transparent::StopSignal,
    pub after: u64,
}

impl ShardTransport for StopAfter {
    fn init(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        self.inner.init()
    }
    fn manifest(&mut self, shard_id: u64, revision: &str) -> Result<(Vec<u8>, u64), BoxError> {
        self.inner.manifest(shard_id, revision)
    }
    fn setup(
        &mut self,
        shard_id: u64,
        revision: &str,
        table: Table,
        segment: u32,
    ) -> Result<(Vec<u8>, u64), BoxError> {
        self.inner.setup(shard_id, revision, table, segment)
    }
    fn query(
        &mut self,
        shard_id: u64,
        revision: &str,
        table: Table,
        body: &[u8],
    ) -> Result<Vec<u8>, BoxError> {
        let answer = self.inner.query(shard_id, revision, table, body)?;
        if self.inner.queries >= self.after {
            self.signal.stop();
        }
        Ok(answer)
    }
}

/// A transport whose connection is lost after a number of private queries:
/// every request from then on goes to a port nothing listens on.
pub struct Cut {
    pub inner: Counting,
    pub dead: HttpShardTransport,
    pub after: u64,
}

impl Cut {
    pub fn new(base: &str, after: u64) -> Self {
        Self {
            inner: Counting::new(base),
            dead: HttpShardTransport::new("http://127.0.0.1:1", &HttpOptions::default()).unwrap(),
            after,
        }
    }

    fn cut(&self) -> bool {
        self.inner.queries >= self.after
    }
}

impl ShardTransport for Cut {
    fn init(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        if self.cut() {
            return self.dead.init();
        }
        self.inner.init()
    }
    fn manifest(&mut self, shard_id: u64, revision: &str) -> Result<(Vec<u8>, u64), BoxError> {
        if self.cut() {
            return self.dead.manifest(shard_id, revision);
        }
        self.inner.manifest(shard_id, revision)
    }
    fn setup(
        &mut self,
        shard_id: u64,
        revision: &str,
        table: Table,
        segment: u32,
    ) -> Result<(Vec<u8>, u64), BoxError> {
        if self.cut() {
            return self.dead.setup(shard_id, revision, table, segment);
        }
        self.inner.setup(shard_id, revision, table, segment)
    }
    fn query(
        &mut self,
        shard_id: u64,
        revision: &str,
        table: Table,
        body: &[u8],
    ) -> Result<Vec<u8>, BoxError> {
        if self.cut() {
            return self.dead.query(shard_id, revision, table, body);
        }
        self.inner.query(shard_id, revision, table, body)
    }
}

/// A transport that moves to another service after a number of private
/// queries, and swaps the filters to that service's set as it goes: the
/// publication was replaced under a running wallet.
pub struct SwitchAfter {
    pub a: Counting,
    pub b: Counting,
    pub after: u64,
    pub filters: SharedFilters,
    pub replacement: (std::path::PathBuf, ShardMap),
    pub switched: bool,
}

impl SwitchAfter {
    fn current(&mut self) -> &mut Counting {
        if !self.switched && self.a.queries >= self.after {
            self.switched = true;
            self.filters
                .replace(&self.replacement.0, &self.replacement.1);
        }
        if self.switched {
            &mut self.b
        } else {
            &mut self.a
        }
    }

    pub fn queries(&self) -> u64 {
        self.a.queries + self.b.queries
    }
}

impl ShardTransport for SwitchAfter {
    fn init(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        self.current().init()
    }
    fn manifest(&mut self, shard_id: u64, revision: &str) -> Result<(Vec<u8>, u64), BoxError> {
        self.current().manifest(shard_id, revision)
    }
    fn setup(
        &mut self,
        shard_id: u64,
        revision: &str,
        table: Table,
        segment: u32,
    ) -> Result<(Vec<u8>, u64), BoxError> {
        self.current().setup(shard_id, revision, table, segment)
    }
    fn query(
        &mut self,
        shard_id: u64,
        revision: &str,
        table: Table,
        body: &[u8],
    ) -> Result<Vec<u8>, BoxError> {
        self.current().query(shard_id, revision, table, body)
    }
}

/// One recovery through any transport, off the async runtime.
///
/// The transport is built inside the blocking thread: an HTTP client made
/// on the async runtime's thread cannot be dropped there.
pub async fn recover_through<T, F>(
    db: WalletDb,
    filters: F,
    make_transport: impl FnOnce() -> T + Send + 'static,
    pir: TransparentPir<Network>,
) -> (
    WalletDb,
    F,
    T,
    Result<TransparentProgress, zakura_wallet_transparent::Error>,
)
where
    T: ShardTransport + Send + 'static,
    F: FilterSource + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let mut db = db;
        let mut filters = filters;
        let mut transport = make_transport();
        let result = pir.recover_with(&mut db, &mut filters, &mut transport);
        (db, filters, transport, result)
    })
    .await
    .unwrap()
}

// ------------------------------------------------------- more wallets

/// A wallet with one account born at `birthday`.
pub fn wallet_born_at(birthday: u64) -> (WalletDb, AccountId) {
    let mut db = test_db().unwrap();
    let id = db
        .create_account(
            &params(),
            &[7u8; 32],
            zip32::AccountId::try_from(0).unwrap(),
            h(birthday),
        )
        .unwrap();
    (db, id)
}

/// A wallet on disk, so it can be closed and reopened.
pub fn wallet_on_disk(dir: &Path) -> (WalletDb, AccountId) {
    let mut db = WalletDb::open(&dir.join("wallet.db"), &dir.join("cache.db")).unwrap();
    let id = db
        .create_account(
            &params(),
            &[7u8; 32],
            zip32::AccountId::try_from(0).unwrap(),
            h(FIRST),
        )
        .unwrap();
    (db, id)
}

pub fn reopen(dir: &Path) -> WalletDb {
    WalletDb::open(&dir.join("wallet.db"), &dir.join("cache.db")).unwrap()
}

/// The account's transparent keys.
pub fn keys_of(
    db: &WalletDb,
    account: AccountId,
) -> zakura_wallet_store::transparent_keys::TransparentKeys {
    let ufvk = db
        .accounts(&params())
        .unwrap()
        .into_iter()
        .find(|a| a.id == account)
        .unwrap()
        .ufvk;
    zakura_wallet_store::transparent_keys::TransparentKeys::derive(&ufvk).unwrap()
}

/// The address the account would derive at `index` in `scope`, whether or not
/// it has: its encoding and its script.
pub fn derived(
    db: &WalletDb,
    account: AccountId,
    scope: zakura_wallet_core::KeyScope,
    index: u32,
) -> (String, ScriptBytes) {
    let address = keys_of(db, account)
        .address(&params(), scope, index)
        .unwrap()
        .unwrap();
    (address.encoded, ScriptBytes::new(address.script))
}

/// The wallet's private state, for before/after comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub last_commit: u64,
    pub events: Vec<zakura_wallet_store::transparent::LedgerEvent>,
    pub pending: Vec<zakura_wallet_store::transparent::PendingPages>,
    pub anchor: Option<zakura_wallet_store::transparent::TransparentAnchor>,
    pub completion: Option<String>,
    pub terminals: Vec<(BlockHeight, String)>,
}

impl Snapshot {
    pub fn of(db: &WalletDb) -> Self {
        let mut events = db.transparent_events().unwrap();
        events.sort_by(|a, b| (a.height, &a.record).cmp(&(b.height, &b.record)));
        Self {
            last_commit: db.transparent_last_commit().unwrap(),
            events,
            pending: db.transparent_pending().unwrap(),
            anchor: db.transparent_anchor().unwrap(),
            completion: db.transparent_completion().unwrap(),
            terminals: db.transparent_coverage_terminals().unwrap(),
        }
    }
}

/// Nothing committed was lost, nothing was accepted as complete.
pub fn assert_progress_kept(before: &Snapshot, after: &Snapshot) {
    assert!(
        after.last_commit >= before.last_commit,
        "commits went backwards"
    );
    for event in &before.events {
        assert!(
            after.events.contains(event),
            "a committed event was lost: {:?}",
            event.key
        );
    }
    assert_eq!(
        after.anchor, before.anchor,
        "an interrupted run moved the anchor"
    );
    assert_ne!(
        after.completion.as_deref(),
        Some("complete"),
        "an interrupted run must not record completion"
    );
}

/// The projection the wallet shows agrees with the ledger the store holds.
pub fn assert_projection_matches_ledger(db: &mut WalletDb, account: AccountId) {
    let mine: BTreeSet<Vec<u8>> = my_scripts(db, account)
        .into_iter()
        .map(|s| s.as_slice().to_vec())
        .collect();
    let ledger = store_ledger(db);
    let ledger_balance: u64 = ledger
        .utxos()
        .filter(|u| mine.contains(&u.script))
        .map(|u| u.value)
        .sum();
    assert_eq!(
        db.transparent_balance(account).unwrap().total().into_u64(),
        ledger_balance,
        "the balance shown is not the ledger's"
    );
    let receives = db
        .transparent_events()
        .unwrap()
        .iter()
        .filter(|e| mine.contains(&e.script))
        .filter(|e| {
            matches!(
                e.key,
                zakura_wallet_store::transparent::EventKey::Receive { .. }
            )
        })
        .count();
    let projected: i64 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM cache.transparent_received_outputs WHERE account_id = ?1",
            [account.0],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        projected as usize, receives,
        "every receive is projected once"
    );
    let spends = db
        .transparent_events()
        .unwrap()
        .iter()
        .filter(|e| mine.contains(&e.script))
        .filter(|e| {
            matches!(
                e.key,
                zakura_wallet_store::transparent::EventKey::Spend { .. }
            )
        })
        .count();
    let unresolved = state(db, account).unresolved_spends as usize;
    let marked: i64 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM cache.transparent_received_output_spends s
             JOIN cache.transparent_received_outputs o ON o.id = s.output_id
             WHERE o.account_id = ?1",
            [account.0],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        marked as usize + unresolved,
        spends,
        "every resolved spend is marked once"
    );
}

/// The queries a fresh wallet with the same seed needs to read the whole set.
pub async fn fresh_query_count(dir: &Path, map: &ShardMap) -> (u64, u64) {
    let (fresh, _) = wallet();
    accept_through(&fresh, SHARDS);
    let base = serve(dir).await;
    let (_, whole, progress) = recover(fresh, base, dir, map, WorkLimits::UNLIMITED).await;
    progress.unwrap();
    (whole.queries, whole.opened.len() as u64)
}

/// Every event the store holds, decoded.
pub fn stored_events(db: &WalletDb) -> Vec<(Vec<u8>, TransparentEvent)> {
    db.transparent_events()
        .unwrap()
        .into_iter()
        .map(|e| (e.script, TransparentEvent::from_bytes(&e.record).unwrap()))
        .collect()
}
