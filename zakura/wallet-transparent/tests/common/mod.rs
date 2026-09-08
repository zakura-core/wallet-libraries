//! Fixtures shared by the recovery suites: a synthetic chain paying the
//! wallet's own scripts, a publisher for it, the real shard service run in
//! process, a wallet with its chain accepted, an independent traversal, and an
//! exact comparison.
//!
//! Ported from `enhance-pir`'s own wallet suites so what is exercised here is
//! what will serve a wallet, with the one difference that matters: the scripts
//! paid are the ones this wallet derived from its seed, not synthetic tags.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::Path;

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

pub fn shard_of(height: u64) -> usize {
    ((height - FIRST) / SPAN) as usize
}

pub fn shard_bounds(id: u64) -> (u64, u64) {
    (FIRST + id * SPAN, FIRST + (id + 1) * SPAN - 1)
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
    let mut entries = Vec::new();
    let mut parent_digest = String::new();
    let count = per_shard.len() as u64;
    for (shard_id, events) in per_shard.iter().enumerate() {
        let shard_id = shard_id as u64;
        let geometry = geometry_for(shard_id);
        let start = FIRST + shard_id * SPAN;
        let end = start + SPAN - 1;
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
        let is_tail = shard_id + 1 == count && count >= SHARDS;

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
                blocks: SPAN,
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
        start_height: FIRST,
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
        }
    }
}

impl FilterSource for Filters {
    fn shard_map(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        Ok((self.map.clone(), self.map.len() as u64))
    }

    fn filter(&mut self, shard_id: u64) -> Result<(Vec<u8>, u64), BoxError> {
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
        }
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
    accept(db, FIRST - 1, hash(FIRST - 1));
    for id in 0..count {
        let (start, end) = shard_bounds(id);
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
