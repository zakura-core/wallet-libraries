//! Test support for applications, with feature `testing`: batches no companion
//! issued, their settlement, and a fake txid display publication.
//!
//! Nothing here is for production: a batch built here carries no export receipt,
//! so no companion acknowledges it, and the publication answers no private query
//! with a record.

use sha2::{Digest, Sha256};
use transparent_native::TableProfile;
use transparent_shard::display::{
    DISPLAY_SCHEMA, DisplayBucket, DisplayLayout, DisplayManifest, DisplayMap, DisplayMapEntry,
    DisplaySealParams,
};
use transparent_shard::manifest::TableGeometry;
use zcash_client_backend::data_api::transparent_ledger::{
    RecoveryRevision, TransparentLedgerCommit,
};

use crate::catalog::BatchState;
use crate::http::{HttpMethod, HttpReply};
use crate::recovery::{Progress, RecoveryBatch};

/// A batch as a pass returns it: `commits` (empty unless `state` is ready), the pass's
/// `progress`, and the retired revisions it resolves.
pub fn batch<A>(
    commits: Vec<TransparentLedgerCommit<A>>,
    progress: Progress,
    state: BatchState,
    retired: Vec<RecoveryRevision>,
) -> RecoveryBatch<A> {
    assert!(
        state == BatchState::Ready || (commits.is_empty() && retired.is_empty()),
        "only a ready batch has commits or retirements"
    );
    RecoveryBatch::unissued(commits, progress, state, retired)
}

/// Applies `batch` through `ReferenceRecovery::apply_and_acknowledge`'s own commit loop,
/// with no companion: the same checks before any commit (a ready batch, no outer SQL
/// transaction, trust for retirements), the same commits, each in its own wallet
/// transaction, and the same policy-generation check after them, with the same failures.
/// Without a companion there is no export receipt to check and nothing to acknowledge.
#[cfg(feature = "sqlite")]
pub fn apply<P: zcash_protocol::consensus::Parameters, CL, R>(
    batch: RecoveryBatch<zcash_client_sqlite::AccountUuid>,
    wallet: &mut zcash_client_sqlite::WalletDb<rusqlite::Connection, P, CL, R>,
    trust: crate::Trust,
) -> Result<crate::Applied, crate::ApplyFailure> {
    use zcash_client_backend::data_api::transparent_ledger::TransparentLedgerRead as _;

    let progress = batch.progress();
    let (stats, retired, expected_generation) =
        crate::apply::apply_commits(batch, wallet, trust, || {})?;
    if let Some(expected) = expected_generation {
        wallet
            .with_immediate_read_transaction(|snapshot| {
                snapshot
                    .check_transparent_policy_generation(expected)
                    .map_err(|error| crate::ApplyError::from_wallet(stats.applied, error))
            })
            .map_err(|error| crate::ApplyFailure {
                error,
                stats,
                progress,
            })?;
    }
    Ok(crate::Applied {
        stats,
        progress,
        retired: retired.len(),
    })
}

/// The geometry every fake publication uses.
const GEOMETRY: &str = "txid-2k";
const ROWS: u64 = 2048;
const ROW_BYTES: u32 = 4096;

/// A txid display service publishing one recent shard over `start..=end` that holds no
/// record. Every route of a lookup is answered well formed, so a lookup sends its whole
/// transcript and finds nothing.
pub struct TxidPublication {
    init: Vec<u8>,
    map: Vec<u8>,
    map_hex: String,
    map_sha256: [u8; 32],
    manifest: Vec<u8>,
    digest: String,
    public_bytes: usize,
    response_bytes: usize,
}

impl TxidPublication {
    pub fn new(start: u64, end: u64) -> Self {
        let directory = TableProfile::new(
            transparent_shard::SCHEMA,
            GEOMETRY,
            "txdirectory",
            ROWS,
            ROW_BYTES,
        )
        .expect("the txid-2k directory profile");
        let init = serde_json::to_vec(&serde_json::json!({
            "schema": DISPLAY_SCHEMA,
            "codec": transparent_shard::txid::CODEC,
            "bucket_domain": "transparent-txid-display/bucket/v2",
            "native_schema": transparent_shard::SCHEMA,
            "geometries": [{
                "name": GEOMETRY,
                "txdirectory": {
                    "rows": ROWS,
                    "row_bytes": ROW_BYTES,
                    "scheme": directory.scheme,
                    "setup_seed": setup_seed("txdirectory"),
                },
            }],
        }))
        .expect("an init document");
        let manifest = DisplayManifest {
            schema: DISPLAY_SCHEMA.to_owned(),
            network: "main".to_owned(),
            genesis_hash: "ee".repeat(32),
            shard_id: 0,
            start_height: start,
            end_height: end,
            parent_block_hash: "ff".repeat(32),
            terminal_block_hash: "dd".repeat(32),
            parent_manifest_digest: String::new(),
            sealed: false,
            revision: 1,
            supersedes: String::new(),
            geometry: GEOMETRY.to_owned(),
            n_buckets: 1,
            archive_target: 1,
            layout: DisplayLayout::current(),
            blocks: end - start + 1,
            records: 0,
            buckets: vec![DisplayBucket {
                bucket: 0,
                records: 0,
                directory_segments: vec![TableGeometry {
                    rows: ROWS,
                    row_bytes: ROW_BYTES,
                    sha256: "cc".repeat(32),
                }],
            }],
        };
        manifest.validate().expect("a valid manifest");
        let digest = manifest.digest();
        let map = DisplayMap {
            schema: DISPLAY_SCHEMA.to_owned(),
            network: "main".to_owned(),
            genesis_hash: "ee".repeat(32),
            seal: DisplaySealParams {
                n_archive: 1,
                n_recent: 1,
                archive_target: 1,
                recent_floor: 1,
                reorg_margin: 1,
            },
            start_height: start,
            first_shard_id: 0,
            shards: vec![DisplayMapEntry::from_manifest(&manifest, &digest)],
        };
        // Served as the recent map; one recent shard needs no index chunk.
        let split = map.split().expect("a split map");
        assert!(split.chunks.is_empty());
        let map = split.recent_bytes;
        let map_sha256: [u8; 32] = Sha256::digest(&map).into();
        Self {
            init,
            map,
            map_hex: hex::encode(map_sha256),
            map_sha256,
            manifest: manifest.canonical_bytes(),
            digest,
            public_bytes: directory.scheme.public_bytes,
            response_bytes: directory.scheme.response_bytes,
        }
    }

    /// The digest of the recent map, as the wallet records it.
    pub fn map_sha256(&self) -> [u8; 32] {
        self.map_sha256
    }

    /// The service's reply to a request for `path` with `body`; 404 for any other route.
    pub fn answer(&self, method: HttpMethod, path: &str, body: &[u8]) -> HttpReply {
        let ok = |body: Vec<u8>| HttpReply {
            status: 200,
            body,
            ..HttpReply::default()
        };
        let shard = format!("/v1/txid/recent/shards/0/revisions/{}", self.digest);
        match (method, path) {
            (HttpMethod::Get, "/v1/txid/init") => ok(self.init.clone()),
            (HttpMethod::Get, "/v1/txid/map") => HttpReply {
                map_sha256: Some(self.map_hex.clone()),
                ..ok(self.map.clone())
            },
            (HttpMethod::Get, path)
                if path == format!("/v1/txid/shards/0/revisions/{}/manifest", self.digest) =>
            {
                ok(self.manifest.clone())
            }
            (HttpMethod::Get, path) if path.starts_with(&format!("{shard}/setup/")) => {
                let rest = &path[shard.len() + "/setup/".len()..];
                let Some((table, segment)) = rest.split_once('/') else {
                    return not_found();
                };
                let Ok(segment) = segment.parse::<u32>() else {
                    return not_found();
                };
                let params = vec![0u8; self.public_bytes];
                ok(serde_json::to_vec(&serde_json::json!({
                    "manifest_digest": self.digest, "shard_id": 0, "table": table,
                    "bucket": 0, "segment": segment, "segments": 1, "geometry": GEOMETRY,
                    "public_params": base64_encode(&params),
                    "public_params_sha256": hex::encode(Sha256::digest(&params)),
                    "public_params_epoch": "0000000000000000",
                }))
                .expect("a setup document"))
            }
            (HttpMethod::Post, path) if path.starts_with(&format!("{shard}/query/")) => {
                // Echo the binding; an all-zero row holds no entry.
                let mut reply = body.get(..8).unwrap_or_default().to_vec();
                reply.extend([0u8; 8]);
                reply.extend(vec![0u8; self.response_bytes]);
                ok(reply)
            }
            _ => not_found(),
        }
    }
}

/// An init document naming a display codec no client supports.
pub fn unsupported_txid_init() -> HttpReply {
    HttpReply {
        status: 200,
        body: serde_json::to_vec(&serde_json::json!({
            "schema": DISPLAY_SCHEMA,
            "codec": "transparent-txid-display-v9",
            "bucket_domain": "transparent-txid-display/bucket/v2",
            "native_schema": transparent_shard::SCHEMA,
            "geometries": [],
        }))
        .expect("an init document"),
        ..HttpReply::default()
    }
}

fn not_found() -> HttpReply {
    HttpReply {
        status: 404,
        ..HttpReply::default()
    }
}

/// The seed a table's public query setup derives from, as the service publishes it.
fn setup_seed(kind: &str) -> u64 {
    let digest = Sha256::new()
        .chain_update(transparent_shard::SCHEMA.as_bytes())
        .chain_update(b"/setup-seed\0txid-2k\0")
        .chain_update(kind.as_bytes())
        .finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("eight bytes"))
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TxidDisplayService;
    use crate::http::{HttpExchange, HttpFailure, HttpRequest};
    use transparent_txid_client::TxidLookup;

    struct Serving(TxidPublication);

    impl HttpExchange for Serving {
        fn send(&self, request: &HttpRequest) -> Result<HttpReply, HttpFailure> {
            Ok(self.0.answer(request.method, &request.path, &request.body))
        }
    }

    #[test]
    fn a_lookup_in_the_fake_publication_finds_nothing() {
        let service = TxidDisplayService::new();
        let publication = Serving(TxidPublication::new(3_000_000, 3_000_009));
        let found = service.lookup(&publication, [7; 32], 3_000_005, &|| false);
        assert_eq!(found, Ok(TxidLookup::Absent));
        assert_eq!(service.map_sha256(), Some(publication.0.map_sha256()));
    }
}
