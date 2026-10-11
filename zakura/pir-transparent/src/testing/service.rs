//! A real transparent shard service for application tests: a publisher that
//! writes shards for a synthetic chain, and wallet-pir's shard server answering
//! requests in process, so a test reaches real filters and real PIR without a
//! network.
//!
//! Adapted from wallet-pir's shard-server test fixtures at 648264bb
//! (`transparent-shard-server/tests/common/{mod,prepared}.rs`), through the
//! crates' public APIs only. Unlike those, a test chooses every shard's range,
//! geometry, seal state and revision, and the re-cuts a map declares, as a
//! publisher would over time.

use std::path::Path;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, Response};
use sha2::{Digest, Sha256};
use tokio::runtime::Runtime;
use tower::ServiceExt;
use transparent_events::TransparentEvent;
use transparent_filter::{
    BlockHash, Recut, ScriptBytes, SealParameters, ShardMap, ShardMapEntry, SupersededShard,
    filter_hash,
};
use transparent_shard::build::build_shard;
use transparent_shard::layout::{Geometry, RECENT_4K, RECENT_8K};
use transparent_shard::manifest::{
    ManifestLayout, ManifestOccupancy, ManifestSeal, SCHEMA, ShardManifest, TableGeometry,
};
use transparent_shard_server::service::{ServiceConfig, ServiceState, router};
use transparent_shard_server::shardset::{DEFAULT_RETAIN_REVISIONS, ShardSet};

/// A shard's usual geometry: the smallest one a build publishes, which keeps the
/// tables a pass sets up and queries small.
pub const GEOMETRY: &Geometry = &RECENT_4K;

/// The geometry a re-cut merges sealed shards into, standing in for an archive
/// geometry, whose tables are far too large for a test.
pub const WIDE: &Geometry = &RECENT_8K;

/// The seal thresholds the publisher seals under.
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

/// One shard of a publication: its range, geometry, whether it is sealed, its
/// published revision, the manifest digest that revision supersedes, and every
/// event in it, keyed by the script it concerns.
pub struct ShardSpec {
    pub start: u64,
    pub end: u64,
    pub geometry: &'static Geometry,
    pub sealed: bool,
    pub revision: u32,
    /// Empty for a first revision. A republished tail names the digest it
    /// replaces, as a continuous publisher does; nothing in a pass reads it.
    pub supersedes: String,
    pub events: Vec<(ScriptBytes, TransparentEvent)>,
}

impl ShardSpec {
    /// The first revision of a shard over `start..=end` in [`GEOMETRY`].
    pub fn first(
        start: u64,
        end: u64,
        sealed: bool,
        events: Vec<(ScriptBytes, TransparentEvent)>,
    ) -> Self {
        Self {
            start,
            end,
            geometry: GEOMETRY,
            sealed,
            revision: 0,
            supersedes: String::new(),
            events,
        }
    }
}

/// Writes a publishable shard set for `shards`, numbered from zero, to `dir`,
/// as the publisher would: one directory per manifest digest and the map in
/// `shards.json`, declaring `recuts`. `hash` gives each shard's parent and
/// terminal block. Every geometry a shard or a declaration names is sealed
/// under `seal`. Returns the map.
pub fn publish(
    dir: &Path,
    shards: &[ShardSpec],
    seal: SealParameters,
    hash: impl Fn(u64) -> BlockHash,
    recuts: Vec<Recut>,
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
            spec.geometry,
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
            geometry: spec.geometry.name.to_string(),
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
            supersedes: spec.supersedes.clone(),
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
                spec.geometry.directory_rows,
                spec.geometry.directory_row_bytes,
            ),
            page_segments: segments(
                &built.pages,
                spec.geometry.page_rows,
                spec.geometry.page_row_bytes,
            ),
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
        std::fs::create_dir_all(&shard_dir).expect("a shard directory");
        let write = |name: String, bytes: &[u8]| {
            std::fs::write(shard_dir.join(name), bytes).expect("a writable shard set");
        };
        write("manifest.json".into(), &manifest.canonical_bytes());
        write("filter.bin".into(), built.filter.as_slice());
        for (index, segment) in built.directory.iter().enumerate() {
            write(format!("directory.{index}.bin"), segment);
        }
        for (index, segment) in built.pages.iter().enumerate() {
            write(format!("pages.{index}.bin"), segment);
        }
        entries.push(ShardMapEntry {
            shard_id,
            geometry: spec.geometry.name.to_string(),
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
        seal: shards
            .iter()
            .map(|spec| spec.geometry.name.to_string())
            .chain(
                recuts
                    .iter()
                    .flat_map(|recut| &recut.superseded)
                    .map(|shard| shard.geometry.clone()),
            )
            .map(|geometry| (geometry, seal))
            .collect(),
        shards: entries,
        recuts,
    };
    map.check_shape().expect("a well-formed map");
    std::fs::write(
        dir.join("shards.json"),
        serde_json::to_vec(&map).expect("a serializable map"),
    )
    .expect("a writable shard set");
    map
}

/// `entry` as a re-cut declares it superseded: exactly as it was published.
pub fn superseded(entry: &ShardMapEntry) -> SupersededShard {
    SupersededShard {
        shard_id: entry.shard_id,
        geometry: entry.geometry.clone(),
        start_height: entry.start_height,
        end_height: entry.end_height,
        terminal_block_hash: entry.terminal_block_hash.clone(),
        manifest_digest: entry.manifest_digest.clone(),
        revision: entry.revision,
        sealed: entry.sealed,
    }
}

/// The shard server for one published set, answering in process: no socket,
/// no TLS, the service's own routes and replies.
#[derive(Clone)]
pub struct InProcess {
    runtime: Arc<Runtime>,
    router: axum::Router,
}

impl InProcess {
    /// Serves the shard set [`publish`] wrote to `dir`.
    pub fn serve(dir: &Path) -> Self {
        let set = ShardSet::open(dir, DEFAULT_RETAIN_REVISIONS).expect("a verified shard set");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a runtime");
        let state = runtime
            .block_on(async { ServiceState::build(set, ServiceConfig::default()) })
            .expect("a service");
        Self {
            runtime: Arc::new(runtime),
            router: router(state),
        }
    }

    /// The service's reply to `request`, whose URI is the route's path and
    /// query. Callable from inside another runtime: the request is served on
    /// this service's runtime from a thread of its own.
    pub fn answer(&self, request: Request<Vec<u8>>) -> Response<Vec<u8>> {
        let (runtime, router) = (self.runtime.clone(), self.router.clone());
        std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    runtime.block_on(async move {
                        let response = router
                            .oneshot(request.map(Body::from))
                            .await
                            .expect("the router is infallible");
                        let (parts, body) = response.into_parts();
                        let body = axum::body::to_bytes(body, usize::MAX)
                            .await
                            .expect("a readable reply");
                        Response::from_parts(parts, body.to_vec())
                    })
                })
                .join()
                .expect("the service answered")
        })
    }
}
