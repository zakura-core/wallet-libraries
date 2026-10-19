//! The txid display service in process: a recent-replica worker serving one
//! recent shard, built with the library's display publication and answered
//! with real native PIR ([`zakura_pir_client::transparent::testing::native`]).
//!
//! It serves the routes a lookup reads, with the production service's paths,
//! documents and headers: `/v2/txid/init`, `/v2/txid/map` (the recent map of
//! the split, with `x-txid-map-sha256`), the canonical manifest, and the
//! recent tier's setup and query of every bucket's table. A route it does not
//! serve is 404, and a malformed request is 400.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use sha2::{Digest, Sha256};
use zakura_pir_client::transparent::native::TableProfile;
use zakura_pir_client::transparent::testing::native::{self, Segment};
use zakura_pir_publisher::transparent::display::{
    BUCKET_DOMAIN, DISPLAY_SCHEMA, DisplayKind, DisplayManifest, DisplayMap, DisplayMapEntry,
    DisplaySealParams, DisplayTable, ManifestHeader, NATIVE_SCHEMA, TXID_4K8, build_shard,
    query_binding, setup_seed,
};

/// What the router answers from.
struct Published {
    init: Vec<u8>,
    recent_map: Vec<u8>,
    recent_sha256: String,
    shard_id: u64,
    digest: String,
    manifest: Vec<u8>,
    profile: Arc<TableProfile>,
    /// Every bucket's table: its segments, in order.
    tables: BTreeMap<DisplayTable, Vec<Segment>>,
}

/// The display service: its router and the runtime that drives it.
pub struct DisplayService {
    pub runtime: tokio::runtime::Runtime,
    pub router: Router,
}

impl DisplayService {
    /// A recent-replica worker serving one recent shard of `records` over
    /// `[start, end]`: one bucket, archive target one, at [`TXID_4K8`].
    pub fn start(
        start: u64,
        end: u64,
        records: &[zakura_pir_client::transparent::DisplayEntry],
    ) -> Self {
        let geometry = &TXID_4K8;
        let kind = DisplayKind::TxDirectory;
        let shard_id = 0;
        let built = build_shard(shard_id, geometry, 1, records).unwrap();
        let block_hash = |height: u64| hex::encode(Sha256::digest(height.to_le_bytes()));
        let manifest = DisplayManifest::new(
            ManifestHeader {
                network: "main".into(),
                genesis_hash: "ee".repeat(32),
                shard_id,
                start_height: start,
                end_height: end,
                parent_block_hash: block_hash(start - 1),
                terminal_block_hash: block_hash(end),
                parent_manifest_digest: String::new(),
                sealed: false,
                revision: 0,
                supersedes: String::new(),
                archive_target: 1,
            },
            geometry,
            &built,
        );
        manifest.validate().unwrap();
        let digest = manifest.digest();
        let map = DisplayMap {
            schema: DISPLAY_SCHEMA.to_owned(),
            network: manifest.network.clone(),
            genesis_hash: manifest.genesis_hash.clone(),
            seal: DisplaySealParams {
                n_archive: 1,
                n_recent: 1,
                archive_target: 1,
                recent_window: 1,
                reorg_margin: 1,
            },
            start_height: start,
            first_shard_id: shard_id,
            shards: vec![DisplayMapEntry::from_manifest(&manifest, &digest)],
        };
        map.check_shape().unwrap();
        // One recent shard needs no index chunk.
        let split = map.split().unwrap();
        assert!(split.chunks.is_empty());
        let recent_sha256 = hex::encode(Sha256::digest(&split.recent_bytes));

        let rows = kind.rows(geometry);
        let row_bytes = kind.row_bytes(geometry);
        let profile = Arc::new(
            TableProfile::new(NATIVE_SCHEMA, geometry.name, kind.as_str(), rows, row_bytes)
                .unwrap(),
        );
        let tables = built
            .tables()
            .into_iter()
            .map(|table| {
                let segments = built
                    .segments(table)
                    .iter()
                    .map(|rows| Segment::build(profile.clone(), rows).unwrap())
                    .collect();
                (table, segments)
            })
            .collect();
        let init = serde_json::to_vec(&serde_json::json!({
            "schema": DISPLAY_SCHEMA,
            "codec": zakura_pir_publisher::transparent::txid::CODEC,
            "bucket_domain": String::from_utf8_lossy(BUCKET_DOMAIN),
            "native_schema": NATIVE_SCHEMA,
            "network": map.network,
            "genesis_hash": map.genesis_hash,
            "map_sha256": map.sha256(),
            "start_height": map.start_height,
            "first_shard_id": map.first_shard_id,
            "covered_through": map.covered_through().unwrap_or_default(),
            "shards": map.shards.len(),
            "role": "recent-replica",
            "geometries": [{
                "name": geometry.name,
                "txdirectory": {
                    "rows": rows,
                    "row_bytes": row_bytes,
                    "scheme": profile.scheme,
                    "setup_seed": setup_seed(geometry, kind),
                },
            }],
        }))
        .unwrap();
        let published = Arc::new(Published {
            init,
            recent_map: split.recent_bytes,
            recent_sha256,
            shard_id,
            digest,
            manifest: manifest.canonical_bytes(),
            profile,
            tables,
        });

        const SETUP: &str = "shards/:shard_id/revisions/:digest/setup/:table/:segment";
        const QUERY: &str = "shards/:shard_id/revisions/:digest/query/:table";
        let router = Router::new()
            .route("/v2/txid/init", get(init_route))
            .route("/v2/txid/map", get(recent_map))
            .route(
                "/v2/txid/shards/:shard_id/revisions/:digest/manifest",
                get(manifest_route),
            )
            .route(&format!("/v2/txid/recent/{SETUP}"), get(setup))
            .route(&format!("/v2/txid/recent/{QUERY}"), post(query))
            .with_state(published);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        Self { runtime, router }
    }
}

type Shared = State<Arc<Published>>;

fn json(value: serde_json::Value) -> Response {
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        serde_json::to_vec(&value).unwrap(),
    )
        .into_response()
}

fn refuse(status: StatusCode, error: impl Into<String>) -> Response {
    let error: String = error.into();
    (
        status,
        [("content-type", "application/json")],
        serde_json::to_vec(&serde_json::json!({ "error": error })).unwrap(),
    )
        .into_response()
}

async fn init_route(State(p): Shared) -> Response {
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        p.init.clone(),
    )
        .into_response()
}

async fn recent_map(State(p): Shared) -> Response {
    (
        StatusCode::OK,
        [
            ("content-type", "application/json"),
            ("x-txid-map-sha256", p.recent_sha256.as_str()),
            ("cache-control", "no-cache"),
        ],
        p.recent_map.clone(),
    )
        .into_response()
}

async fn manifest_route(
    State(p): Shared,
    Path((shard_id, digest)): Path<(u64, String)>,
) -> Response {
    if shard_id != p.shard_id || digest != p.digest {
        return refuse(StatusCode::NOT_FOUND, "no such revision");
    }
    (
        StatusCode::OK,
        [
            ("content-type", "application/json"),
            ("cache-control", "public, max-age=31536000, immutable"),
            ("x-manifest-sha256", p.digest.as_str()),
        ],
        p.manifest.clone(),
    )
        .into_response()
}

/// The segments of `label` in the revision `(shard_id, digest)`.
fn table<'a>(
    p: &'a Published,
    shard_id: u64,
    digest: &str,
    label: &str,
) -> Result<(DisplayTable, &'a [Segment]), Response> {
    if shard_id != p.shard_id || digest != p.digest {
        return Err(refuse(StatusCode::NOT_FOUND, "no such revision"));
    }
    let table = DisplayTable::parse(label)
        .ok_or_else(|| refuse(StatusCode::BAD_REQUEST, "unknown display table"))?;
    let segments = p
        .tables
        .get(&table)
        .ok_or_else(|| refuse(StatusCode::BAD_REQUEST, "no such bucket"))?;
    Ok((table, segments))
}

async fn setup(
    State(p): Shared,
    Path((shard_id, digest, label, segment)): Path<(u64, String, String, u32)>,
) -> Response {
    let (table, segments) = match table(&p, shard_id, &digest, &label) {
        Ok(found) => found,
        Err(refused) => return refused,
    };
    let Some(built) = segments.get(segment as usize) else {
        return refuse(StatusCode::BAD_REQUEST, "no such segment");
    };
    json(serde_json::json!({
        "shard_id": shard_id,
        "manifest_digest": digest,
        "geometry": TXID_4K8.name,
        "table": table.label(),
        "bucket": table.bucket(),
        "segment": segment,
        "segments": segments.len(),
        "public_params": base64::engine::general_purpose::STANDARD.encode(built.public()),
        "public_params_sha256": built.public_sha256(),
        "public_params_epoch": hex::encode(built.epoch()),
    }))
}

/// Every segment's reply to the query, concatenated in segment order.
async fn query(
    State(p): Shared,
    Path((shard_id, digest, label)): Path<(u64, String, String)>,
    body: Bytes,
) -> Response {
    let (table, segments) = match table(&p, shard_id, &digest, &label) {
        Ok(found) => found,
        Err(refused) => return refused,
    };
    let binding = query_binding(&digest, table);
    let (keys, selection) = match native::parse(&p.profile, binding, &body, p.profile.rows) {
        Ok(parsed) => parsed,
        Err(error) => return refuse(StatusCode::BAD_REQUEST, error),
    };
    let mut reply = Vec::new();
    for segment in segments {
        match segment.answer(binding, &keys, &selection) {
            Ok(frame) => reply.extend(frame),
            Err(error) => return refuse(StatusCode::INTERNAL_SERVER_ERROR, error),
        }
    }
    (
        StatusCode::OK,
        [("content-type", "application/octet-stream")],
        reply,
    )
        .into_response()
}
