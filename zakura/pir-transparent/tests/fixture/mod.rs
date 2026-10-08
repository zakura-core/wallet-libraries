//! An in-process transparent shard service: a publisher that writes real shards
//! for a synthetic chain, and a loopback server per publication whose requests
//! one recorder captures as the service received them.
//!
//! Adapted from wallet-pir's shard-server test fixtures at 648264bb
//! (`transparent-shard-server/tests/common/{mod,prepared}.rs`), through the
//! crates' public APIs only. Unlike those, a test chooses every shard's range,
//! seal state and revision number, as a publisher would over time.

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use axum::{body::Body, extract::Request, middleware::Next, response::Response};
use sha2::{Digest, Sha256};
use tokio::{net::TcpListener, runtime::Runtime, task::JoinHandle};
use transparent_events::TransparentEvent;
use transparent_filter::{
    BlockHash, ScriptBytes, SealParameters, ShardMap, ShardMapEntry, filter_hash,
};
use transparent_shard::build::build_shard;
use transparent_shard::layout::{Geometry, RECENT_4K};
use transparent_shard::manifest::{
    ManifestLayout, ManifestOccupancy, ManifestSeal, SCHEMA, ShardManifest, TableGeometry,
};
use transparent_shard_server::service::{ServiceConfig, ServiceState, router};
use transparent_shard_server::shardset::{DEFAULT_RETAIN_REVISIONS, ShardSet};

/// Every shard's geometry: the smallest one a build publishes, which keeps the
/// tables a pass sets up and queries small.
pub const GEOMETRY: &Geometry = &RECENT_4K;

/// The seal thresholds the fixture's publisher seals under.
pub const SEAL: SealParameters = SealParameters {
    max_scripts: 2_048,
    max_page_rows: 1_024,
    max_txids: 0,
};

/// A block hash for a height the wallet never scanned, distinct per height.
pub fn synthetic(height: u64) -> BlockHash {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&height.to_le_bytes());
    bytes[31] = 0x5a;
    BlockHash::from_internal_bytes(bytes)
}

/// One shard of a publication: its range, whether it is sealed, its published
/// revision number, and every event in it, keyed by the script it concerns.
pub struct ShardSpec {
    pub start: u64,
    pub end: u64,
    pub sealed: bool,
    pub revision: u32,
    pub events: Vec<(ScriptBytes, TransparentEvent)>,
}

/// Writes a publishable shard set for `shards`, numbered from zero, to `dir`,
/// as the publisher would: one directory per manifest digest and the map in
/// `shards.json`. `hash` gives each shard's parent and terminal block. Every
/// shard has [`GEOMETRY`], sealed under `seal`.
pub fn publish(
    dir: &Path,
    shards: &[ShardSpec],
    seal: SealParameters,
    hash: impl Fn(u64) -> BlockHash,
) -> ShardMap {
    let genesis = BlockHash::from_display_hex(transparent_filter::MAINNET_GENESIS_DISPLAY)
        .expect("mainnet's genesis hash");
    let mut entries = Vec::new();
    let mut parent_digest = String::new();
    for (shard_id, spec) in shards.iter().enumerate() {
        let shard_id = shard_id as u64;
        let built = build_shard(
            shard_id,
            spec.start,
            spec.end,
            genesis,
            hash(spec.end),
            transparent_filter::RANGE_PROFILE,
            GEOMETRY,
            &spec.events,
        )
        .expect("a buildable shard");
        let segments = |tables: &[Vec<u8>], rows: u64, row_bytes: usize| -> Vec<TableGeometry> {
            tables
                .iter()
                .map(|segment| TableGeometry {
                    rows,
                    row_bytes: row_bytes as u32,
                    sha256: hex::encode(Sha256::digest(segment)),
                })
                .collect()
        };
        let manifest = ShardManifest {
            schema: SCHEMA.to_string(),
            profile: transparent_filter::RANGE_PROFILE.to_string(),
            geometry: GEOMETRY.name.to_string(),
            network: transparent_filter::NETWORK.to_string(),
            genesis_hash: transparent_filter::MAINNET_GENESIS_DISPLAY.to_string(),
            shard_id,
            start_height: spec.start,
            end_height: spec.end,
            parent_block_hash: hash(spec.start - 1).to_display_hex(),
            terminal_block_hash: hash(spec.end).to_display_hex(),
            tag_salt_counter: built.tag_salt_counter,
            parent_manifest_digest: parent_digest.clone(),
            sealed: spec.sealed,
            revision: spec.revision,
            // Nothing reads it; a continuous publisher would name the revision
            // this one replaces.
            supersedes: String::new(),
            seal: ManifestSeal {
                scripts_target: seal.max_scripts,
                scripts_capacity: seal.max_scripts * 2,
                page_rows_target: seal.max_page_rows,
                page_rows_capacity: seal.max_page_rows * 2,
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
            directory_segments: segments(
                &built.directory,
                GEOMETRY.directory_rows,
                GEOMETRY.directory_row_bytes,
            ),
            page_segments: segments(&built.pages, GEOMETRY.page_rows, GEOMETRY.page_row_bytes),
            occupancy: ManifestOccupancy {
                scripts: built.scripts,
                page_rows: built.page_rows,
                fragments: built.fragments,
                events: built.events,
                blocks: spec.end - spec.start + 1,
                txids: 0,
                excluded_scripts: built.excluded_scripts,
            },
            directory_choice: None,
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
            geometry: GEOMETRY.name.to_string(),
            start_height: spec.start,
            end_height: spec.end,
            parent_block_hash: manifest.parent_block_hash.clone(),
            terminal_block_hash: manifest.terminal_block_hash.clone(),
            filter_hash: manifest.filter_hash.clone(),
            scripts: built.scripts,
            page_rows: built.page_rows,
            txids: 0,
            directory_segments: built.directory_segments(),
            page_segments: built.page_segments(),
            manifest_digest: digest.clone(),
            revision: spec.revision,
            sealed: spec.sealed,
        });
        parent_digest = digest;
    }
    let map = ShardMap {
        genesis_hash: transparent_filter::MAINNET_GENESIS_DISPLAY.to_string(),
        network: transparent_filter::NETWORK.to_string(),
        profile: transparent_filter::RANGE_PROFILE.to_string(),
        range_envelope_version: transparent_filter::RANGE_ENVELOPE_VERSION,
        start_height: shards[0].start,
        seal: [(GEOMETRY.name.to_string(), seal)].into_iter().collect(),
        shards: entries,
    };
    map.check_shape().expect("a well-formed map");
    std::fs::write(dir.join("shards.json"), serde_json::to_vec(&map).unwrap()).unwrap();
    map
}

/// One request as the service received it.
#[derive(Clone, Debug)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    /// Every header, by name and raw value.
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}

/// A loopback shard service, restarted for each publication, that records
/// every request it receives before handling it.
pub struct Server {
    runtime: Runtime,
    requests: Arc<Mutex<Vec<Recorded>>>,
    serving: Option<JoinHandle<()>>,
}

impl Server {
    pub fn start() -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        Self {
            runtime,
            requests: Arc::default(),
            serving: None,
        }
    }

    /// Stops serving the previous publication and serves the one in `dir`,
    /// returning its base URL.
    pub fn serve(&mut self, dir: &Path) -> String {
        if let Some(previous) = self.serving.take() {
            previous.abort();
        }
        let requests = self.requests.clone();
        let set = ShardSet::open(dir, DEFAULT_RETAIN_REVISIONS).expect("a verified shard set");
        let (url, serving) = self.runtime.block_on(async move {
            let state = ServiceState::build(set, ServiceConfig::default()).expect("a service");
            let app = router(state).layer(axum::middleware::from_fn(
                move |request: Request, next: Next| record(requests.clone(), request, next),
            ));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let serving = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            (url, serving)
        });
        self.serving = Some(serving);
        url
    }

    /// Every request any publication's server received, in arrival order.
    pub fn requests(&self) -> Vec<Recorded> {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// Records `request`, headers and body included, then hands it on unchanged.
async fn record(requests: Arc<Mutex<Vec<Recorded>>>, request: Request, next: Next) -> Response {
    let (parts, body) = request.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX)
        .await
        .expect("a readable request body");
    requests
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(Recorded {
            method: parts.method.to_string(),
            path: parts.uri.path().to_owned(),
            query: parts.uri.query().map(str::to_owned),
            headers: parts
                .headers
                .iter()
                .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
                .collect(),
            body: body.to_vec(),
        });
    next.run(Request::from_parts(parts, Body::from(body))).await
}
