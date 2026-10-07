//! An in-process Enhance PIR service: one generation of schema-11 records laid out at their
//! Ironwood commitment tree positions, served over the native two-mask protocol through the
//! client's `Transport`, with every request recorded as the service received it.
//!
//! The server side uses `zakura-pir-native`'s `test_server` primitives, as the client crate's own
//! protocol tests do; the manifest follows the canonical coverage and session identity the
//! client validates (adapted from `zakura-pir-enhance`'s `test_support::synthetic_manifest`).
//! Records come from the caller, which derives them from serialized transactions by the Enhance
//! publisher's rules.

use std::cell::RefCell;

use base64::Engine as _;
use sha2::{Digest, Sha256};
use zakura_pir_enhance::{
    ClientError, EnhanceRecord, GenerationAcceptance, Geometry, Manifest, PROTOCOL_REVISION,
    RECORD_BYTES, RECORDS_PER_ROW, ROW_BYTES, SCHEMA_VERSION, SessionRef, ShardSession,
    UnitIdentity,
    native::{COLS, query_masks},
    parameter_id, parameters,
    transport::{Method, Request, ResponseBody, Transport},
    types::{HEADER_BYTES, Lifecycle, setup_seed, setup_seed_bytes, unit_parameter_id},
};
use zakura_pir_native::{D, test_server::Database};

/// The service's base URL. The transport never leaves the process.
pub const BASE: &str = "https://enhance.fixture.test";

/// One request as the service received it.
#[derive(Clone, Debug)]
pub struct Recorded {
    pub post: bool,
    pub url: String,
    pub body: Vec<u8>,
}

/// One served generation.
pub struct EnhanceService {
    manifest: Manifest,
    /// Shard 0's PIR database: every record of the generation.
    db: Database,
    requests: RefCell<Vec<Recorded>>,
}

impl EnhanceService {
    /// Serves `records`, each at its commitment tree position, for a generation anchored at
    /// `anchor_height` with display-order `anchor_hash` and an Ironwood tree of `tree_size`.
    pub fn new(
        records: &[(u64, EnhanceRecord)],
        anchor_height: u64,
        anchor_hash: [u8; 32],
        tree_size: u64,
    ) -> Self {
        let coverage = Lifecycle::default()
            .coverage(tree_size, Geometry::default())
            .expect("a coverable tree");
        assert_eq!(coverage.shards.len(), 1, "one shard covers the fixture");
        let shard = &coverage.shards[0];
        let rows = usize::try_from(shard.logical_rows).unwrap();

        // Rows of 33 records, then columns of little-endian u16 coefficients.
        let mut layout = vec![vec![0u8; 2 * COLS]; rows];
        for (position, record) in records {
            assert!(*position < tree_size, "a record outside the generation");
            let row = usize::try_from(position / RECORDS_PER_ROW as u64).unwrap();
            let slot = usize::try_from(position % RECORDS_PER_ROW as u64).unwrap();
            layout[row][slot * RECORD_BYTES..(slot + 1) * RECORD_BYTES]
                .copy_from_slice(record.as_bytes());
        }
        const { assert!(ROW_BYTES <= 2 * COLS) };
        let columns: Vec<Vec<u16>> = (0..COLS)
            .map(|col| {
                layout
                    .iter()
                    .map(|row| u16::from_le_bytes([row[2 * col], row[2 * col + 1]]))
                    .collect()
            })
            .collect();
        let masks = query_masks(shard.id);
        let db = Database::new(columns, &masks[..rows / D], setup_seed_bytes());
        let public_sha256 = hex::encode(Sha256::digest(db.public()));

        let unit_identities = coverage
            .shards
            .iter()
            .map(|shard| {
                (
                    shard.id,
                    shard
                        .units
                        .iter()
                        .map(|unit| UnitIdentity {
                            recovery_epoch: 0,
                            table: "enhance".into(),
                            shard_id: shard.id,
                            local_row_start: unit.local_row_start,
                            allocated_rows: unit.allocated_rows,
                            setup_sha256: hex::encode(Sha256::digest(setup_seed(shard.id))),
                            parameter_id: unit_parameter_id(unit.allocated_rows).unwrap(),
                            content_sha256: hex::encode(Sha256::digest(
                                records
                                    .iter()
                                    .flat_map(|(_, r)| r.as_bytes().to_vec())
                                    .collect::<Vec<_>>(),
                            )),
                        })
                        .collect(),
                )
            })
            .collect();
        let manifest = Manifest {
            recovery_epoch: 0,
            placement_revision: 1,
            domain_recovery_epochs: coverage
                .shards
                .iter()
                .map(|shard| (shard.id, "0".into()))
                .collect(),
            schema_version: SCHEMA_VERSION,
            protocol_revision: PROTOCOL_REVISION.into(),
            network: "main".into(),
            pool: "ironwood".into(),
            generation: 1,
            anchor_height,
            anchor_block_hash: hex::encode(anchor_hash),
            geometry: Geometry::default(),
            sessions: coverage
                .shards
                .iter()
                .map(|shard| SessionRef {
                    shard_id: shard.id,
                    public_params_sha256: public_sha256.clone(),
                    parameter_id: parameter_id(shard.logical_rows).unwrap(),
                })
                .collect(),
            coverage,
            unit_identities,
        };
        manifest.validate().expect("a valid manifest");
        Self {
            manifest,
            db,
            requests: RefCell::default(),
        }
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Every request received, in arrival order.
    pub fn requests(&self) -> Vec<Recorded> {
        self.requests.borrow().clone()
    }

    fn respond(&self, request: &Request) -> Vec<u8> {
        let path = request
            .url
            .strip_prefix(BASE)
            .expect("requests go to the service");
        match (request.method, path) {
            (Method::Get, "/v1/enhance/init") => serde_json::to_vec(&self.manifest).unwrap(),
            (Method::Get, session) if session.starts_with("/v1/enhance/session/") => {
                let shard = &self.manifest.coverage.shards[0];
                assert_eq!(
                    session.trim_start_matches("/v1/enhance/session/"),
                    hex::encode(self.manifest.session_id(shard.id).unwrap())
                );
                serde_json::to_vec(&ShardSession {
                    session_id: hex::encode(self.manifest.session_id(shard.id).unwrap()),
                    generation: self.manifest.generation,
                    shard_id: shard.id,
                    params: parameters(shard.logical_rows).unwrap(),
                    public_params_base64: base64::engine::general_purpose::STANDARD
                        .encode(self.db.public()),
                })
                .unwrap()
            }
            (Method::Post, "/v1/enhance/query") => {
                // The binding header, echoed, then the native answer for the selection.
                let mut response = request.body[..HEADER_BYTES].to_vec();
                response.extend(self.db.answer(&request.body[HEADER_BYTES..]));
                response
            }
            (method, path) => panic!("unexpected request {method:?} {path}"),
        }
    }
}

impl Transport for &EnhanceService {
    async fn execute(&self, request: Request) -> Result<ResponseBody, ClientError> {
        self.requests.borrow_mut().push(Recorded {
            post: matches!(request.method, Method::Post),
            url: request.url.clone(),
            body: request.body.clone(),
        });
        let bytes = self.respond(&request);
        let mut body = request.response_body();
        body.extend(&bytes)?;
        Ok(body.finish())
    }
}

/// Wallet acceptance of the served generation. The service is mainnet-only, while the fixture
/// wallet runs on a local network with mainnet heights; the anchor is still checked against the
/// wallet's scanned chain, as `zakura_pir_enhance::wallet::acceptance` does.
pub fn accept(
    manifest: &Manifest,
    activation_height: u64,
    scanned: zcash_client_backend::data_api::enhance_pir::EnhancePirSnapshotStatus,
) -> GenerationAcceptance {
    use zcash_client_backend::data_api::enhance_pir::EnhancePirSnapshotStatus;
    assert_eq!(scanned, EnhancePirSnapshotStatus::Accepted);
    let anchor = zakura_pir_enhance::wallet::snapshot_anchor(manifest).unwrap();
    let mut display_hash = anchor.block_hash.0;
    display_hash.reverse();
    GenerationAcceptance::new(
        "main",
        activation_height,
        zakura_pir_enhance::AcceptedAnchor::new(
            manifest.anchor_height,
            display_hash,
            manifest.coverage.records,
        ),
        zakura_pir_enhance::ClientResourceLimits::new(32_768),
    )
}
