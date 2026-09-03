use ipir_sp::modulus_switch::{published_c1_len, recover_published_c1, response_body_len};
use ipir_sp::serialize::serialize_packing_keys;
use ipir_sp::{IPIRClient, YpirSchemeParams};
use rand::{Rng, rngs::OsRng};
use sha2::{Digest, Sha256};

use crate::{
    DatabaseId, GenerationManifest, MANIFEST_SCHEMA_VERSION, MemoPirSnapshotAnchor, POOL, PirRow,
    TableExpectation, TableManifest,
};

/// Expands a wire setup seed into the 32-byte form the iPIR client consumes.
///
/// This must stay byte-identical to `nullifier_pir::backend::seed_from_u64`, which the pinned
/// `ipir-sp` revision does not export; the server side of this protocol derives its offline
/// setup the same way.
fn seed_bytes(value: u64) -> [u8; 32] {
    let mut seed = [0; 32];
    seed[..8].copy_from_slice(&value.to_le_bytes());
    seed
}
#[cfg(feature = "https-client")]
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
#[cfg(feature = "https-client")]
const MAX_PARAMS_BYTES: usize = 64 * 1024;
#[cfg(feature = "https-client")]
const MAX_PIR_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Failures while validating a snapshot or performing a PIR query.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// HTTP transport failed.
    #[cfg(feature = "https-client")]
    #[error("HTTP transport failed: {0}")]
    Http(#[from] reqwest::Error),
    /// A server JSON document was malformed.
    #[error("server JSON was malformed: {0}")]
    Json(#[from] serde_json::Error),
    /// Metadata is inconsistent with the pinned protocol.
    #[error("server metadata is incompatible: {0}")]
    Metadata(&'static str),
    /// The generation does not publish the requested table.
    #[error("generation does not publish the {0} table")]
    TableUnavailable(DatabaseId),
    /// The requested position is not present in the advertised snapshot.
    #[error("position is outside advertised coverage")]
    OutsideCoverage,
    /// The underlying PIR implementation rejected an operation.
    #[error("PIR operation failed: {0}")]
    Pir(String),
    /// A query response failed strict framing validation.
    #[error("malformed PIR response: {0}")]
    Response(&'static str),
    /// Production transports require HTTPS.
    #[cfg(feature = "https-client")]
    #[error("PIR endpoint must use HTTPS")]
    InsecureTransport,
    /// The table was built against a different offline-setup seed than this client pins.
    ///
    /// Separate from [`ClientError::Metadata`] because this is almost always server
    /// misconfiguration and the operator needs both values to diagnose it.
    #[error("table setup seed {advertised:#x} does not match the pinned seed {expected:#x}")]
    SetupSeedMismatch {
        /// Seed advertised by the server.
        advertised: u64,
        /// Seed this client requires.
        expected: u64,
    },
}

/// Validated, transport-neutral client state for one table of one immutable
/// generation. A wallet holds one session per table it queries and pins them
/// all to the same generation for a pass.
pub struct PirSession {
    manifest: GenerationManifest,
    table: DatabaseId,
    expectation: TableExpectation,
    anchor: MemoPirSnapshotAnchor,
    ypir: YpirSchemeParams,
    client: IPIRClient,
    setup: Vec<Vec<u64>>,
    published_c1: Vec<Vec<u64>>,
    epoch: [u8; 8],
}

/// A freshly randomized query and the private decoding state paired with it.
///
/// This value is intentionally single-use: decoding consumes it.
pub struct PreparedQuery {
    body: Vec<u8>,
    seed: [u8; 32],
    global_row: u64,
}

/// The ACTION query type wallets used before tables were named.
pub type PreparedMemoQuery = PreparedQuery;

impl std::fmt::Debug for PreparedQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedQuery").finish_non_exhaustive()
    }
}

impl PreparedQuery {
    /// Serialized request body for `POST /v1/{table}/query`.
    pub fn request_body(&self) -> &[u8] {
        &self.body
    }
}

impl PirSession {
    /// Validates the manifest's entry for `expectation.table`, the generated
    /// parameters, and the public parameters, exactly as every table is checked.
    pub fn new(
        expected_network: &str,
        manifest: GenerationManifest,
        expectation: TableExpectation,
        params_json: &[u8],
        public_params: &[u8],
    ) -> Result<Self, ClientError> {
        if manifest.schema_version != MANIFEST_SCHEMA_VERSION
            || manifest.network != expected_network
            || manifest.pool != POOL
        {
            return Err(ClientError::Metadata("wrong schema, network, or pool"));
        }
        if manifest.envelope.protocol_version != crate::ENVELOPE_PROTOCOL_VERSION {
            return Err(ClientError::Metadata("unknown envelope protocol version"));
        }
        let table = expectation.table;
        let entry = manifest
            .tables
            .get(&table)
            .ok_or(ClientError::TableUnavailable(table))?;
        // Checked before anything expensive, and before the parameters are even parsed: a seed
        // disagreement makes every later step produce plausible-looking garbage.
        if entry.setup_seed != expectation.setup_seed {
            return Err(ClientError::SetupSeedMismatch {
                advertised: entry.setup_seed,
                expected: expectation.setup_seed,
            });
        }
        let layout = expectation.layout;
        if entry.record_bytes as usize != layout.record_bytes
            || entry.records_per_row as usize != layout.records_per_row
            || entry.row_bytes as usize != layout.row_bytes()
            || entry.shard_rows as usize != layout.shard_rows
            || entry.logical_rows < entry.used_rows
            || !entry.logical_rows.is_power_of_two()
            || entry.logical_rows < layout.shard_rows as u64
            || entry.used_rows != entry.positions.div_ceil(layout.records_per_row as u64)
        {
            return Err(ClientError::Metadata("invalid database geometry"));
        }
        let anchor_height = u32::try_from(manifest.anchor_height)
            .map_err(|_| ClientError::Metadata("anchor height is out of range"))?;
        let mut anchor_hash = hex::decode(&manifest.anchor_block_hash)
            .map_err(|_| ClientError::Metadata("anchor block hash is not hexadecimal"))?;
        if anchor_hash.len() != 32 {
            return Err(ClientError::Metadata(
                "anchor block hash has the wrong length",
            ));
        }
        // Manifests use the conventional RPC/explorer display order; BlockHash stores wire order.
        anchor_hash.reverse();
        let anchor = MemoPirSnapshotAnchor {
            height: anchor_height,
            block_hash: anchor_hash.try_into().expect("length checked"),
            ironwood_tree_size: manifest.ironwood_tree_size,
        };

        let ypir: YpirSchemeParams = serde_json::from_slice(params_json)?;
        let (rlwe, expected) =
            ipir_sp::params_for_simplepir(entry.logical_rows, layout.item_size_bits())
                .map_err(|e| ClientError::Pir(e.to_string()))?;
        if ypir != expected {
            return Err(ClientError::Metadata(
                "parameters do not match pinned generator",
            ));
        }
        let digest = Sha256::digest(public_params);
        if hex::encode(digest) != entry.public_params_sha256 {
            return Err(ClientError::Metadata("public parameter digest mismatch"));
        }
        let mut epoch = [0; 8];
        epoch.copy_from_slice(&digest[..8]);
        if hex::encode(epoch) != entry.public_params_epoch {
            return Err(ClientError::Metadata("public parameter epoch mismatch"));
        }
        let blocks = ypir.db_cols / rlwe.d;
        if public_params.len() != blocks * published_c1_len(rlwe.d, rlwe.q) {
            return Err(ClientError::Metadata("invalid public parameter length"));
        }
        let published_c1 = recover_published_c1(public_params, rlwe.d, blocks, rlwe.q);
        let client = IPIRClient::new(&rlwe, &ypir);
        // Derived from the validated wire value rather than the constant directly, so the
        // manifest field stays load-bearing and cannot drift out of the code path.
        let setup =
            client.generate_public_query_setup_simplepir_from_seed(seed_bytes(entry.setup_seed));
        Ok(Self {
            manifest,
            table,
            expectation,
            anchor,
            ypir,
            client,
            setup,
            published_c1,
            epoch,
        })
    }

    /// Returns the validated generation manifest.
    pub fn manifest(&self) -> &GenerationManifest {
        &self.manifest
    }

    /// Returns the table this session queries.
    pub fn table(&self) -> DatabaseId {
        self.table
    }

    /// Returns the validated manifest entry for this session's table.
    pub fn table_manifest(&self) -> &TableManifest {
        &self.manifest.tables[&self.table]
    }

    /// Returns the generation every query from this session is bound to.
    pub fn generation(&self) -> u64 {
        self.manifest.generation
    }

    /// Returns the parsed anchor to compare with the wallet before issuing queries.
    pub fn snapshot_anchor(&self) -> MemoPirSnapshotAnchor {
        self.anchor
    }

    /// Returns the row holding `position`, if the table covers it.
    pub fn row_for_position(&self, position: u64) -> Option<u64> {
        let entry = self.table_manifest();
        if position >= entry.positions {
            return None;
        }
        let row = position / self.expectation.layout.records_per_row as u64;
        (row < entry.logical_rows).then_some(row)
    }

    /// Creates a randomized query for the row containing `position`.
    pub fn prepare_position(&self, position: u64) -> Result<PreparedQuery, ClientError> {
        let row = self
            .row_for_position(position)
            .ok_or(ClientError::OutsideCoverage)?;
        self.prepare_row(row as usize)
    }

    /// Creates a cover query indistinguishable from a real row query.
    pub fn prepare_dummy(&self) -> Result<PreparedQuery, ClientError> {
        self.prepare_row(OsRng.gen_range(0..self.ypir.db_rows))
    }

    /// Returns the populated positions (records) of this session's table.
    pub fn positions(&self) -> u64 {
        self.table_manifest().positions
    }

    /// Returns the logical (queryable) row count.
    pub fn rows(&self) -> usize {
        self.ypir.db_rows
    }

    /// Creates a randomized query for one row. Callers that address rows
    /// directly (witness sub-shards, nullifier buckets) use this; ACTION
    /// callers use [`PirSession::prepare_position`].
    pub fn prepare_row(&self, row: usize) -> Result<PreparedQuery, ClientError> {
        if row >= self.ypir.db_rows {
            return Err(ClientError::OutsideCoverage);
        }
        let (query, packing_keys, seed) =
            self.client.generate_fresh_query_simplepir(&self.setup, row);
        let mut body = self.manifest.generation.to_le_bytes().to_vec();
        body.extend(
            serialize_packing_keys(self.client.rlwe_params(), &packing_keys)
                .map_err(|e| ClientError::Pir(e.to_string()))?,
        );
        body.extend(query.to_switched_bytes(self.client.rlwe_params().q, self.ypir.query_bits));
        Ok(PreparedQuery {
            body,
            seed,
            global_row: row as u64,
        })
    }

    /// Strictly validates and decodes a response to `query`.
    pub fn decode(&self, query: PreparedQuery, response: &[u8]) -> Result<PirRow, ClientError> {
        if response.get(..8) != Some(self.manifest.generation.to_le_bytes().as_slice()) {
            return Err(ClientError::Response("generation mismatch"));
        }
        if response.get(8..16) != Some(self.epoch.as_slice()) {
            return Err(ClientError::Response("public parameter epoch mismatch"));
        }
        let expected = (self.ypir.db_cols / self.client.rlwe_params().d)
            * response_body_len(self.client.rlwe_params().d, self.ypir.q_prime_1);
        if response.len() != 16 + expected {
            return Err(ClientError::Response("invalid response length"));
        }
        let decoded =
            self.client
                .decode_response_simplepir(query.seed, &self.published_c1, &response[16..]);
        let row_bytes = self.expectation.layout.row_bytes();
        let bytes = decoded
            .get(..row_bytes)
            .ok_or(ClientError::Response("decoded row is too short"))?
            .to_vec();
        Ok(PirRow::new(
            self.table,
            self.expectation.layout,
            query.global_row,
            bytes,
        ))
    }
}

/// HTTPS transport for one table of the PIR protocol.
#[cfg(feature = "https-client")]
pub struct HttpPirClient {
    http: reqwest::Client,
    base_url: String,
    session: PirSession,
}

/// The ACTION transport wallets used before tables were named.
#[cfg(feature = "https-client")]
pub type HttpMemoPirClient = HttpPirClient;

#[cfg(feature = "https-client")]
impl HttpPirClient {
    /// Downloads the current generation over HTTPS and validates `expectation.table`.
    pub async fn connect(
        base_url: &str,
        expected_network: &str,
        expectation: TableExpectation,
    ) -> Result<Self, ClientError> {
        if !base_url.starts_with("https://") {
            return Err(ClientError::InsecureTransport);
        }
        let base_url = base_url.trim_end_matches('/').to_owned();
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()?;
        let manifest: GenerationManifest = serde_json::from_slice(
            &read_limited(
                http.get(format!("{base_url}/v1/generation")).send().await?,
                MAX_MANIFEST_BYTES,
            )
            .await?,
        )?;
        let table = expectation.table;
        let params = read_limited(
            http.get(format!("{base_url}/v1/{table}/params"))
                .send()
                .await?,
            MAX_PARAMS_BYTES,
        )
        .await?;
        let public_params = read_limited(
            http.get(format!("{base_url}/v1/{table}/public-params"))
                .send()
                .await?,
            MAX_PIR_BODY_BYTES,
        )
        .await?;
        let session = PirSession::new(
            expected_network,
            manifest,
            expectation,
            &params,
            &public_params,
        )?;
        Ok(Self {
            http,
            base_url,
            session,
        })
    }

    /// Returns the validated session.
    pub fn session(&self) -> &PirSession {
        &self.session
    }

    /// Returns the parsed anchor to compare with the wallet before issuing queries.
    pub fn snapshot_anchor(&self) -> MemoPirSnapshotAnchor {
        self.session.snapshot_anchor()
    }

    /// Privately retrieves the complete row containing `position`.
    pub async fn query_position(&self, position: u64) -> Result<PirRow, ClientError> {
        let query = self.session.prepare_position(position)?;
        self.send(query).await
    }

    /// Sends one randomized cover query and discards its decoded result.
    pub async fn query_dummy(&self) -> Result<(), ClientError> {
        let query = self.session.prepare_dummy()?;
        self.send(query).await.map(|_| ())
    }

    async fn send(&self, query: PreparedQuery) -> Result<PirRow, ClientError> {
        let response = self
            .http
            .post(format!(
                "{}/v1/{}/query",
                self.base_url,
                self.session.table()
            ))
            .body(query.request_body().to_vec())
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(ClientError::Response("server rejected query"));
        }
        let response = read_limited(response, MAX_PIR_BODY_BYTES).await?;
        self.session.decode(query, &response)
    }
}

#[cfg(feature = "https-client")]
async fn read_limited(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, ClientError> {
    response = response.error_for_status()?;
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(ClientError::Response("HTTP body exceeds limit"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(ClientError::Response("HTTP body exceeds limit"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ACTION_EXPECTATION, MEMO_SETUP_SEED, RECORD_BYTES, RECORDS_PER_ROW, ROW_BYTES, SHARD_ROWS,
        ShardDescriptor,
    };
    use std::collections::BTreeMap;

    fn action_table() -> TableManifest {
        TableManifest {
            record_bytes: RECORD_BYTES as u32,
            records_per_row: RECORDS_PER_ROW as u32,
            row_bytes: ROW_BYTES as u32,
            shard_rows: SHARD_ROWS as u32,
            positions: 1,
            used_rows: 1,
            logical_rows: SHARD_ROWS as u64,
            parameter_id: "test".to_owned(),
            setup_seed: MEMO_SETUP_SEED,
            public_params_epoch: String::new(),
            public_params_sha256: String::new(),
            shards: Vec::<ShardDescriptor>::new(),
        }
    }

    fn manifest(tables: BTreeMap<DatabaseId, TableManifest>) -> GenerationManifest {
        GenerationManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            protocol_revision: "ipir-sp-e875404".to_owned(),
            network: "main".to_owned(),
            pool: POOL.to_owned(),
            anchor_height: 1,
            anchor_block_hash: "00".repeat(32),
            ironwood_tree_size: 1,
            generation: 1,
            anchor_tree_root: String::new(),
            cold_checkpoint_height: 0,
            envelope: crate::Envelope {
                protocol_version: crate::ENVELOPE_PROTOCOL_VERSION,
                k_nf: 8,
                k_act: 4,
                k_wit: 4,
            },
            tables,
        }
    }

    fn action_manifest() -> GenerationManifest {
        let mut tables = BTreeMap::new();
        tables.insert(DatabaseId::Action, action_table());
        manifest(tables)
    }

    #[test]
    fn rejects_a_generation_without_the_requested_table() {
        let mut tables = BTreeMap::new();
        tables.insert(DatabaseId::Witness, action_table());
        let result = PirSession::new("main", manifest(tables), ACTION_EXPECTATION, b"x", &[]);
        assert!(matches!(
            result,
            Err(ClientError::TableUnavailable(DatabaseId::Action))
        ));
    }

    #[test]
    fn rejects_a_table_built_against_another_setup_seed() {
        let mut manifest = action_manifest();
        manifest
            .tables
            .get_mut(&DatabaseId::Action)
            .unwrap()
            .setup_seed = MEMO_SETUP_SEED ^ 1;

        let result = PirSession::new("main", manifest, ACTION_EXPECTATION, b"not JSON", &[]);

        assert!(matches!(
            result,
            Err(ClientError::SetupSeedMismatch {
                advertised,
                expected,
            }) if advertised == MEMO_SETUP_SEED ^ 1 && expected == MEMO_SETUP_SEED
        ));
    }

    #[test]
    fn rejects_a_table_whose_layout_differs_from_the_expectation() {
        let mut manifest = action_manifest();
        manifest
            .tables
            .get_mut(&DatabaseId::Action)
            .unwrap()
            .record_bytes = 612;
        let result = PirSession::new("main", manifest, ACTION_EXPECTATION, b"not JSON", &[]);
        assert!(matches!(
            result,
            Err(ClientError::Metadata("invalid database geometry"))
        ));
    }

    #[test]
    fn rejects_wrong_schema_or_network_before_parsing_parameters() {
        let result = PirSession::new(
            "test",
            action_manifest(),
            ACTION_EXPECTATION,
            b"not JSON",
            &[],
        );
        assert!(matches!(result, Err(ClientError::Metadata(_))));
        let mut old = action_manifest();
        old.schema_version = 2;
        let result = PirSession::new("main", old, ACTION_EXPECTATION, b"not JSON", &[]);
        assert!(matches!(result, Err(ClientError::Metadata(_))));
    }

    #[test]
    fn expands_a_wire_seed_like_the_reference_implementation() {
        assert_eq!(seed_bytes(0), [0; 32]);

        let mut expected = [0; 32];
        expected[..8].copy_from_slice(&[0x1a, 0x13, 0x07, 0xec, 0x84, 0xe2, 0x1a, 0xaf]);
        assert_eq!(seed_bytes(MEMO_SETUP_SEED), expected);
    }
}
