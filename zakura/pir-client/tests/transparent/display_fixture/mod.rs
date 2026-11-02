//! The txid display service in process: a recent-replica worker serving one
//! recent shard, built with the library's display publication and answered
//! with real native PIR ([`zakura_pir_client::transparent::testing::native`]).
//!
//! It serves the routes a lookup reads, with the production service's paths,
//! documents and headers: `/transparent/v1/txid/init`, `/transparent/v1/txid/map` (the recent map of
//! the split, with `x-txid-map-sha256`), the canonical manifest, and the
//! recent tier's setup and query of every bucket's table. A route it does not
//! serve is 404, and a malformed request is 400.

use std::collections::BTreeMap;
use std::sync::Arc;

use http::{Method, Request, StatusCode};

use base64::Engine as _;
use sha2::{Digest, Sha256};
use zakura_pir_client::transparent::native::TableProfile;
use zakura_pir_client::transparent::testing::native::{self, Segment};
use zakura_pir_publisher::transparent::display::{
    BUCKET_DOMAIN, DISPLAY_SCHEMA, DisplayKind, DisplayManifest, DisplayMap, DisplayMapEntry,
    DisplaySealParams, DisplayTable, ManifestHeader, NATIVE_SCHEMA, TXID_4K8, build_shard,
    query_binding, setup_seed,
};

type Response = http::Response<Vec<u8>>;

const PREFIX: &str = "/transparent/v1/txid/";
const QUERY_BODY_LIMIT: usize = 2 * 1024 * 1024;

enum Route<'a> {
    Init,
    RecentMap,
    Manifest(&'a str, &'a str),
    Setup(&'a str, &'a str, &'a str, &'a str),
    Query(&'a str, &'a str, &'a str),
}

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

/// The in-process HTTP handler for the display publication.
pub struct DisplayService {
    published: Arc<Published>,
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

        Self { published }
    }

    /// Answers the fixture's HTTP routes without a network hop.
    pub(super) fn answer(&self, request: Request<Vec<u8>>) -> Response {
        let method = request.method();
        let Some(path) = request.uri().path().strip_prefix(PREFIX) else {
            return response(StatusCode::NOT_FOUND, &[], vec![]);
        };
        let parts: Vec<_> = path.split('/').collect();
        if parts.iter().any(|part| part.is_empty()) {
            return response(StatusCode::NOT_FOUND, &[], vec![]);
        }
        let route = match parts.as_slice() {
            ["init"] => Route::Init,
            ["map"] => Route::RecentMap,
            ["shards", shard, "revisions", digest, "manifest"] => Route::Manifest(shard, digest),
            [
                "recent",
                "shards",
                shard,
                "revisions",
                digest,
                "setup",
                table,
                segment,
            ] => Route::Setup(shard, digest, table, segment),
            [
                "recent",
                "shards",
                shard,
                "revisions",
                digest,
                "query",
                table,
            ] => Route::Query(shard, digest, table),
            _ => return response(StatusCode::NOT_FOUND, &[], vec![]),
        };
        let allow = if matches!(route, Route::Query(..)) {
            "POST"
        } else {
            "GET,HEAD"
        };
        let head = method == Method::HEAD;
        if (allow == "POST" && method != Method::POST)
            || (allow != "POST" && method != Method::GET && !head)
        {
            return response(StatusCode::METHOD_NOT_ALLOWED, &[("allow", allow)], vec![]);
        }
        let result = (|| {
            let p = &self.published;
            Ok(match route {
                Route::Init => init_route(p),
                Route::RecentMap => recent_map(p),
                Route::Manifest(shard, digest) => manifest_route(
                    p,
                    number(shard, "shard_id", 0)?,
                    &parameter(digest, "digest")?,
                ),
                Route::Setup(shard, digest, table, segment) => setup(
                    p,
                    number(shard, "shard_id", 0)?,
                    &parameter(digest, "digest")?,
                    &parameter(table, "table")?,
                    number(segment, "segment", 3)?,
                ),
                Route::Query(shard, digest, table) => {
                    let shard_id = number(shard, "shard_id", 0)?;
                    let digest = parameter(digest, "digest")?;
                    let table = parameter(table, "table")?;
                    // Preserve the previous Bytes extractor's default limit.
                    if request.body().len() > QUERY_BODY_LIMIT {
                        return Err(text(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "Failed to buffer the request body: length limit exceeded".into(),
                        ));
                    }
                    query(p, shard_id, &digest, &table, request.body())
                }
            })
        })();
        let mut reply = result.unwrap_or_else(|reply| reply);
        if head {
            reply.body_mut().clear();
        }
        reply
    }
}

fn response(status: StatusCode, headers: &[(&str, &str)], body: Vec<u8>) -> Response {
    let mut response = http::Response::builder()
        .status(status)
        .header("content-length", body.len());
    for (name, value) in headers {
        response = response.header(*name, *value);
    }
    response.body(body).unwrap()
}

fn text(status: StatusCode, body: String) -> Response {
    response(
        status,
        &[("content-type", "text/plain; charset=utf-8")],
        body.into_bytes(),
    )
}

/// Path captures are percent-decoded before typed extraction.
fn parameter(value: &str, name: &str) -> Result<String, Response> {
    let mut bytes = Vec::with_capacity(value.len());
    let mut input = value.as_bytes().iter().copied();
    while let Some(byte) = input.next() {
        if byte == b'%' {
            let mut next = input.clone();
            if let Some(decoded) = next.next().and_then(|a| {
                let high = char::from(a).to_digit(16)?;
                let low = char::from(next.next()?).to_digit(16)?;
                Some((high * 16 + low) as u8)
            }) {
                bytes.push(decoded);
                input = next;
                continue;
            }
        }
        bytes.push(byte);
    }
    String::from_utf8(bytes).map_err(|_| {
        text(
            StatusCode::BAD_REQUEST,
            format!("Invalid URL: Invalid UTF-8 in `{name}`"),
        )
    })
}

fn number<T: std::str::FromStr>(value: &str, name: &str, index: usize) -> Result<T, Response> {
    let value = parameter(value, name)?;
    value.parse().map_err(|_| {
        text(
            StatusCode::BAD_REQUEST,
            format!(
                "Invalid URL: Cannot parse value at index {index} with value `{value:?}` to a `{}`",
                std::any::type_name::<T>()
            ),
        )
    })
}

fn json(value: serde_json::Value) -> Response {
    response(
        StatusCode::OK,
        &[("content-type", "application/json")],
        serde_json::to_vec(&value).unwrap(),
    )
}

fn refuse(status: StatusCode, error: impl Into<String>) -> Response {
    let error: String = error.into();
    response(
        status,
        &[("content-type", "application/json")],
        serde_json::to_vec(&serde_json::json!({ "error": error })).unwrap(),
    )
}

fn init_route(p: &Published) -> Response {
    response(
        StatusCode::OK,
        &[("content-type", "application/json")],
        p.init.clone(),
    )
}

fn recent_map(p: &Published) -> Response {
    response(
        StatusCode::OK,
        &[
            ("content-type", "application/json"),
            ("x-txid-map-sha256", p.recent_sha256.as_str()),
            ("cache-control", "no-cache"),
        ],
        p.recent_map.clone(),
    )
}

fn manifest_route(p: &Published, shard_id: u64, digest: &str) -> Response {
    if shard_id != p.shard_id || digest != p.digest {
        return refuse(StatusCode::NOT_FOUND, "no such revision");
    }
    response(
        StatusCode::OK,
        &[
            ("content-type", "application/json"),
            ("cache-control", "public, max-age=31536000, immutable"),
            ("x-manifest-sha256", p.digest.as_str()),
        ],
        p.manifest.clone(),
    )
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

fn setup(p: &Published, shard_id: u64, digest: &str, label: &str, segment: u32) -> Response {
    let (table, segments) = match table(p, shard_id, digest, label) {
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
fn query(p: &Published, shard_id: u64, digest: &str, label: &str, body: &[u8]) -> Response {
    let (table, segments) = match table(p, shard_id, digest, label) {
        Ok(found) => found,
        Err(refused) => return refused,
    };
    let binding = query_binding(digest, table);
    let (keys, selection) = match native::parse(&p.profile, binding, body, p.profile.rows) {
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
    response(
        StatusCode::OK,
        &[("content-type", "application/octet-stream")],
        reply,
    )
}
