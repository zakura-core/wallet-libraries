//! The shard service answering a publication [`super::service::publish`]
//! wrote, in process: the routes, replies and refusals a wallet reaches, and
//! real native PIR evaluation over the published tables. A protocol fixture,
//! not a server: no admission, metrics, disk cache or runtime scheduling.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use axum::http::{Request, Response};
use base64::Engine as _;
use sha2::{Digest, Sha256};
use transparent_filter::ShardMap;
use transparent_native::TableProfile;
use transparent_shard::display::setup_seed_in;
use transparent_shard::layout::Geometry;
use transparent_shard::manifest::{
    SCHEMA, ShardManifest, pages_table, parse_pages_table, query_binding,
};

use super::native::{self, Segment};

/// Superseded revisions of a shard still answered, newest first, as a shard
/// service retains them so a wallet holding one can still verify it.
const RETAIN_REVISIONS: usize = 3;

/// The shard service for one published set, answering in process: no socket,
/// no TLS, the shard service's routes and replies, with every query evaluated
/// by real native PIR over the published tables.
#[derive(Clone)]
pub struct InProcess {
    publication: Arc<FixturePublication>,
}

impl InProcess {
    /// Serves the shard set [`super::service::publish`] wrote to `dir`.
    pub fn serve(dir: &Path) -> Self {
        Self {
            publication: Arc::new(FixturePublication::open(dir)),
        }
    }

    /// The service's reply to `request`, whose URI is the route's path and
    /// query. Callable from any thread, inside a runtime or not.
    pub fn answer(&self, request: Request<Vec<u8>>) -> Response<Vec<u8>> {
        let (parts, body) = request.into_parts();
        let reply = self
            .publication
            .answer(parts.method.as_str(), parts.uri.path(), &body);
        let mut response = Response::builder().status(reply.status);
        for (name, value) in &reply.headers {
            response = response.header(*name, value.as_str());
        }
        response.body(reply.body).expect("a well-formed reply")
    }
}

/// One reply: status, headers and body.
struct Reply {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn ok(content_type: &str, extra: Vec<(&'static str, String)>, body: Vec<u8>) -> Self {
        let mut headers = vec![("content-type", content_type.to_string())];
        headers.extend(extra);
        Self {
            status: 200,
            headers,
            body,
        }
    }

    fn json(status: u16, body: serde_json::Value) -> Self {
        Self {
            status,
            headers: vec![("content-type", "application/json".into())],
            body: body.to_string().into_bytes(),
        }
    }

    fn bad(message: impl Into<String>) -> Self {
        Self::json(400, serde_json::json!({ "error": message.into() }))
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self::json(404, serde_json::json!({ "error": message.into() }))
    }
}

const IMMUTABLE: &str = "public, max-age=31536000, immutable";

/// One revision the publication holds: its manifest, the canonical bytes its
/// digest is the hash of, and the directory its files are in.
struct Revision {
    manifest: ShardManifest,
    canonical: Vec<u8>,
    geometry: &'static Geometry,
    path: PathBuf,
}

/// A table a request names: the directory, or page shard `j`.
#[derive(Clone, Copy)]
enum Table {
    Directory,
    Pages(u32),
}

impl Table {
    fn parse(name: &str) -> Option<Self> {
        if name == "directory" {
            return Some(Self::Directory);
        }
        parse_pages_table(name).map(Self::Pages)
    }

    /// The file and binding name: `directory` or `pages-<j>`.
    fn name(self) -> String {
        match self {
            Self::Directory => "directory".into(),
            Self::Pages(child) => pages_table(child),
        }
    }

    /// The kind its native profile and setup seed are derived for: `pages`
    /// for every page shard.
    fn kind(self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::Pages(_) => "pages",
        }
    }
}

impl Revision {
    /// Segments of `table`; zero for a page shard the revision does not have.
    fn segments(&self, table: Table) -> u32 {
        match table {
            Table::Directory => self.manifest.directory_segments.len() as u32,
            Table::Pages(child) => self
                .manifest
                .page_children
                .get(child as usize)
                .map_or(0, |child| child.page_segments.len() as u32),
        }
    }

    /// Rows a query to `table` selects over: every row of the directory, a
    /// page shard's manifest-fixed query rows.
    fn query_rows(&self, table: Table, full: usize) -> usize {
        match table {
            Table::Directory => full,
            Table::Pages(child) => self
                .manifest
                .page_children
                .get(child as usize)
                .map_or(full, |child| child.query_rows() as usize),
        }
    }
}

type SegmentKey = (&'static str, &'static str, [u8; 32]);

/// A published shard set loaded for answering: the map's bytes and digest,
/// every current revision and the superseded ones still held, and the native
/// tables, built as queries first reach them.
struct FixturePublication {
    map: ShardMap,
    map_json: Vec<u8>,
    map_digest: String,
    revisions: HashMap<String, Revision>,
    /// Each shard's current revision, by shard id.
    current: BTreeMap<u64, String>,
    profiles: Mutex<HashMap<(&'static str, &'static str), Arc<TableProfile>>>,
    /// Built segments by geometry, kind and the bytes' digest, so a page shard
    /// unchanged across revisions is preprocessed once.
    segments: Mutex<HashMap<SegmentKey, Arc<Segment>>>,
}

impl FixturePublication {
    fn open(dir: &Path) -> Self {
        let raw = std::fs::read(dir.join("shards.json")).expect("a published map");
        let map: ShardMap = serde_json::from_slice(&raw).expect("a well-formed map");
        map.check_shape().expect("a well-formed map");
        // Serialized once, so what is served and what is digested are the
        // same bytes.
        let map_json = serde_json::to_vec(&map).expect("a serializable map");
        let map_digest = hex::encode(Sha256::digest(&map_json));
        let mut on_disk = HashMap::new();
        for entry in std::fs::read_dir(dir).expect("a shard set directory") {
            let path = entry.expect("a directory entry").path();
            if !path.is_dir() {
                continue;
            }
            let canonical = std::fs::read(path.join("manifest.json")).expect("a manifest");
            let manifest: ShardManifest =
                serde_json::from_slice(&canonical).expect("a well-formed manifest");
            assert_eq!(manifest.canonical_bytes(), canonical, "a canonical manifest");
            let geometry = transparent_shard::layout::by_name(&manifest.geometry)
                .expect("a registered geometry");
            let revision = Revision {
                manifest,
                canonical,
                geometry,
                path,
            };
            on_disk.insert(revision.manifest.digest(), revision);
        }
        let mut revisions = HashMap::new();
        let mut current = BTreeMap::new();
        for entry in &map.shards {
            let revision = on_disk
                .remove(&entry.manifest_digest)
                .expect("the map's revisions are published");
            assert_eq!(revision.manifest.shard_id, entry.shard_id);
            current.insert(entry.shard_id, entry.manifest_digest.clone());
            revisions.insert(entry.manifest_digest.clone(), revision);
        }
        let mut superseded: BTreeMap<u64, Vec<(String, Revision)>> = BTreeMap::new();
        for (digest, revision) in on_disk {
            let shard_id = revision.manifest.shard_id;
            if current.contains_key(&shard_id) {
                superseded
                    .entry(shard_id)
                    .or_default()
                    .push((digest, revision));
            }
        }
        for (_, mut held) in superseded {
            held.sort_by_key(|(_, revision)| std::cmp::Reverse(revision.manifest.revision));
            revisions.extend(held.into_iter().take(RETAIN_REVISIONS));
        }
        Self {
            map,
            map_json,
            map_digest,
            revisions,
            current,
            profiles: Mutex::default(),
            segments: Mutex::default(),
        }
    }

    fn answer(&self, method: &str, path: &str, body: &[u8]) -> Reply {
        let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
        match (method, parts.as_slice()) {
            ("GET", ["v2", "shards"] | ["v2", "filters", "shards"]) => Reply::ok(
                "application/json",
                vec![
                    ("x-shard-map-sha256", self.map_digest.clone()),
                    ("cache-control", "no-cache".into()),
                ],
                self.map_json.clone(),
            ),
            ("GET", ["v2", "filters", "shards", shard_id, "filter"]) => {
                match shard_id.parse::<u64>() {
                    Ok(shard_id) => self.filter(shard_id),
                    Err(_) => Reply::bad("invalid shard id"),
                }
            }
            ("GET", ["v2", "shards", "init"]) => self.init(),
            (_, ["v2", "shards", shard_id, "revisions", digest, rest @ ..]) => {
                let Ok(shard_id) = shard_id.parse::<u64>() else {
                    return Reply::bad("invalid shard id");
                };
                match (method, rest) {
                    ("GET", ["manifest"]) => self.manifest(shard_id, digest),
                    ("GET", ["setup", table, segment]) => match segment.parse::<u32>() {
                        Ok(segment) => self.setup(shard_id, digest, table, segment),
                        Err(_) => Reply::bad("invalid segment"),
                    },
                    ("POST", ["query", table]) => self.query(shard_id, digest, table, body),
                    _ => Reply::not_found("no such route"),
                }
            }
            _ => Reply::not_found("no such route"),
        }
    }

    /// The revision a request names, or its refusal: a digest of another
    /// shard is a bad request, one no longer held is stale and names the map.
    fn revision(&self, shard_id: u64, digest: &str) -> Result<&Revision, Reply> {
        match self.revisions.get(digest) {
            Some(revision) if revision.manifest.shard_id == shard_id => Ok(revision),
            Some(_) => Err(Reply::bad(format!(
                "revision {digest} is not a revision of shard {shard_id}"
            ))),
            None => Err(Reply::json(
                409,
                serde_json::json!({
                    "error": format!("revision {digest} of shard {shard_id} is no longer served"),
                    "retry": "refresh the shard map and re-derive coverage for this shard",
                    "map_sha256": self.map_digest,
                }),
            )),
        }
    }

    fn filter(&self, shard_id: u64) -> Reply {
        let Some(revision) = self.current.get(&shard_id).map(|d| &self.revisions[d]) else {
            return Reply::not_found(format!("no shard {shard_id}"));
        };
        let filter = std::fs::read(revision.path.join("filter.bin")).expect("a filter");
        Reply::ok(
            "application/octet-stream",
            vec![("cache-control", IMMUTABLE.into())],
            filter,
        )
    }

    fn profile(&self, geometry: &'static Geometry, kind: &'static str) -> Arc<TableProfile> {
        let mut profiles = self.profiles.lock().unwrap_or_else(PoisonError::into_inner);
        profiles
            .entry((geometry.name, kind))
            .or_insert_with(|| {
                let (rows, row_bytes) = match kind {
                    "directory" => (geometry.directory_rows, geometry.directory_row_bytes),
                    _ => (geometry.page_rows, geometry.page_row_bytes),
                };
                Arc::new(
                    TableProfile::new(SCHEMA, geometry.name, kind, rows, row_bytes as u32)
                        .expect("a native table profile"),
                )
            })
            .clone()
    }

    fn init(&self) -> Reply {
        let Some(last) = self.map.shards.last() else {
            return Reply::json(503, serde_json::json!({ "error": "no shards" }));
        };
        let mut geometries: Vec<&'static Geometry> = Vec::new();
        for revision in self.revisions.values() {
            if !geometries
                .iter()
                .any(|known| known.name == revision.geometry.name)
            {
                geometries.push(revision.geometry);
            }
        }
        geometries.sort_by_key(|geometry| geometry.name);
        let geometries: Vec<serde_json::Value> = geometries
            .into_iter()
            .map(|geometry| {
                let directory = self.profile(geometry, "directory");
                let pages = self.profile(geometry, "pages");
                let mut init = serde_json::json!({
                    "name": geometry.name,
                    "directory_rows": geometry.directory_rows,
                    "directory_row_bytes": geometry.directory_row_bytes as u32,
                    "directory_scheme": directory.scheme,
                    "directory_setup_seed": setup_seed_in(SCHEMA, geometry.name, "directory"),
                    "page_rows": geometry.page_rows,
                    "page_row_bytes": geometry.page_row_bytes as u32,
                    "pages_scheme": pages.scheme,
                    "pages_setup_seed": setup_seed_in(SCHEMA, geometry.name, "pages"),
                });
                if let Some(scheme) = &directory.dithered_scheme {
                    init["directory_scheme_dq44"] = serde_json::json!(scheme);
                }
                if let Some(scheme) = &pages.dithered_scheme {
                    init["pages_scheme_dq44"] = serde_json::json!(scheme);
                }
                init
            })
            .collect();
        Reply::json(
            200,
            serde_json::json!({
                "schema": SCHEMA,
                "profile": self.map.profile,
                "network": self.map.network,
                "genesis_hash": self.map.genesis_hash,
                "shards": self.map.shards.len(),
                "start_height": self.map.start_height,
                "covered_through": last.end_height,
                "map_sha256": self.map_digest,
                "geometries": geometries,
                "assigned_shards": self.map.shards.len(),
                "worker_id": null,
                "role": null,
                "assignment_sha256": null,
            }),
        )
    }

    fn manifest(&self, shard_id: u64, digest: &str) -> Reply {
        match self.revision(shard_id, digest) {
            Ok(revision) => Reply::ok(
                "application/json",
                vec![
                    ("cache-control", IMMUTABLE.into()),
                    ("x-manifest-sha256", digest.to_string()),
                ],
                revision.canonical.clone(),
            ),
            Err(refusal) => refusal,
        }
    }

    /// Segment `segment` of `table` in `revision`, built on first use.
    fn segment(&self, revision: &Revision, table: Table, segment: u32) -> Arc<Segment> {
        let rows = std::fs::read(
            revision
                .path
                .join(format!("{}.{segment}.bin", table.name())),
        )
        .expect("a published segment");
        let key = (
            revision.geometry.name,
            table.kind(),
            <[u8; 32]>::from(Sha256::digest(&rows)),
        );
        let cached = self
            .segments
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
            .cloned();
        if let Some(built) = cached {
            return built;
        }
        let profile = self.profile(revision.geometry, table.kind());
        let built = Arc::new(Segment::build(profile, &rows).expect("a native segment"));
        self.segments
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key, built.clone());
        built
    }

    fn setup(&self, shard_id: u64, digest: &str, table: &str, segment: u32) -> Reply {
        let Some(table) = Table::parse(table) else {
            return Reply::bad("unknown table");
        };
        let revision = match self.revision(shard_id, digest) {
            Ok(revision) => revision,
            Err(refusal) => return refusal,
        };
        let segments = revision.segments(table);
        if segment >= segments {
            return Reply::bad(format!(
                "shard {shard_id} has no {} segment {segment}",
                table.name()
            ));
        }
        let built = self.segment(revision, table, segment);
        Reply::json(
            200,
            serde_json::json!({
                "shard_id": shard_id,
                "manifest_digest": digest,
                "geometry": revision.geometry.name,
                "table": table.name(),
                "segment": segment,
                "segments": segments,
                "public_params": base64::engine::general_purpose::STANDARD.encode(built.public()),
                "public_params_sha256": built.public_sha256(),
                "public_params_epoch": hex::encode(built.epoch()),
            }),
        )
    }

    /// Every segment answers the same query, and the replies come back
    /// concatenated in segment order.
    fn query(&self, shard_id: u64, digest: &str, table: &str, body: &[u8]) -> Reply {
        let Some(table) = Table::parse(table) else {
            return Reply::bad("unknown table");
        };
        let revision = match self.revision(shard_id, digest) {
            Ok(revision) => revision,
            Err(refusal) => return refusal,
        };
        let segments = revision.segments(table);
        if segments == 0 {
            return Reply::bad("table capability unavailable");
        }
        let profile = self.profile(revision.geometry, table.kind());
        let query_rows = revision.query_rows(table, profile.rows);
        let binding = query_binding(digest, &table.name());
        let (keys, query) = match native::parse(&profile, binding, body, query_rows) {
            Ok(parsed) => parsed,
            Err(error) => return Reply::bad(error),
        };
        let mut answer = Vec::new();
        for segment in 0..segments {
            match self
                .segment(revision, table, segment)
                .answer(binding, &keys, &query)
            {
                Ok(reply) => answer.extend(reply),
                Err(error) => return Reply::bad(error),
            }
        }
        Reply::ok("application/octet-stream", Vec::new(), answer)
    }
}
