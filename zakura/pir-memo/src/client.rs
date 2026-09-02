use ipir_sp::modulus_switch::{published_c1_len, recover_published_c1, response_body_len};
use ipir_sp::serialize::serialize_packing_keys;
use ipir_sp::{IPIRClient, YpirSchemeParams};
use rand::{Rng, rngs::OsRng};
use sha2::{Digest, Sha256};
use zcash_client_backend::data_api::memo_pir::MemoPirSnapshotAnchor;
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::BlockHeight;

use crate::{
    Coverage, ITEM_SIZE_BITS, MEMO_SETUP_SEED, MemoPirRow, MemoSnapshotMetadata, POOL,
    RECORD_BYTES, RECORDS_PER_ROW, ROW_BYTES, SCHEMA_VERSION, SHARD_ROWS,
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
const MAX_METADATA_BYTES: usize = 1024 * 1024;
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
    #[error("memo PIR endpoint must use HTTPS")]
    InsecureTransport,
    /// The snapshot was built against a different offline-setup seed than this client pins.
    ///
    /// Separate from [`ClientError::Metadata`] because this is almost always server
    /// misconfiguration, and both seeds are the whole diagnostic.
    #[error(
        "snapshot setup seed {advertised:#x} does not match the pinned memo-PIR seed {expected:#x}"
    )]
    SetupSeedMismatch {
        /// Seed advertised by the server.
        advertised: u64,
        /// Seed this client requires.
        expected: u64,
    },
}

/// Validated, transport-neutral client state for one immutable snapshot generation.
pub struct MemoPirSession {
    metadata: MemoSnapshotMetadata,
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
pub struct PreparedMemoQuery {
    body: Vec<u8>,
    seed: [u8; 32],
    global_row: u64,
}

impl std::fmt::Debug for PreparedMemoQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedMemoQuery").finish_non_exhaustive()
    }
}

impl PreparedMemoQuery {
    /// Serialized request body for `/memo/query`.
    pub fn request_body(&self) -> &[u8] {
        &self.body
    }
}

impl MemoPirSession {
    /// Validates metadata, generated parameters, and public parameters for a snapshot.
    pub fn new(
        expected_network: &str,
        metadata: MemoSnapshotMetadata,
        params_json: &[u8],
        public_params: &[u8],
    ) -> Result<Self, ClientError> {
        if metadata.schema_version != SCHEMA_VERSION
            || metadata.network != expected_network
            || metadata.pool != POOL
        {
            return Err(ClientError::Metadata("wrong schema, network, or pool"));
        }
        // Checked before anything expensive, and before the parameters are even parsed: a seed
        // disagreement makes every later step produce plausible-looking garbage.
        if metadata.setup_seed != MEMO_SETUP_SEED {
            return Err(ClientError::SetupSeedMismatch {
                advertised: metadata.setup_seed,
                expected: MEMO_SETUP_SEED,
            });
        }
        if !matches!(
            metadata.coverage,
            Coverage::Full {
                covered_position_start: 0
            }
        ) || metadata.first_global_row != 0
        {
            return Err(ClientError::Metadata(
                "snapshot does not cover the full pool",
            ));
        }
        if metadata.record_bytes as usize != RECORD_BYTES
            || metadata.records_per_row as usize != RECORDS_PER_ROW
            || metadata.row_bytes as usize != ROW_BYTES
            || metadata.shard_rows as usize != SHARD_ROWS
            || metadata.logical_rows < metadata.used_rows
            || !metadata.logical_rows.is_power_of_two()
            || metadata.logical_rows < SHARD_ROWS as u64
            || metadata.used_rows != metadata.ironwood_tree_size.div_ceil(RECORDS_PER_ROW as u64)
        {
            return Err(ClientError::Metadata("invalid database geometry"));
        }
        let anchor_height = u32::try_from(metadata.anchor_height)
            .map_err(|_| ClientError::Metadata("anchor height is out of range"))?;
        let mut anchor_hash = hex::decode(&metadata.anchor_block_hash)
            .map_err(|_| ClientError::Metadata("anchor block hash is not hexadecimal"))?;
        if anchor_hash.len() != 32 {
            return Err(ClientError::Metadata(
                "anchor block hash has the wrong length",
            ));
        }
        // Metadata uses the conventional RPC/explorer display order; BlockHash stores wire order.
        anchor_hash.reverse();
        let anchor = MemoPirSnapshotAnchor {
            height: BlockHeight::from(anchor_height),
            block_hash: BlockHash::from_slice(&anchor_hash),
            ironwood_tree_size: metadata.ironwood_tree_size,
        };

        let ypir: YpirSchemeParams = serde_json::from_slice(params_json)?;
        let (rlwe, expected) = ipir_sp::params_for_simplepir(metadata.logical_rows, ITEM_SIZE_BITS)
            .map_err(|e| ClientError::Pir(e.to_string()))?;
        if ypir != expected {
            return Err(ClientError::Metadata(
                "parameters do not match pinned generator",
            ));
        }
        let digest = Sha256::digest(public_params);
        if hex::encode(digest) != metadata.public_params_sha256 {
            return Err(ClientError::Metadata("public parameter digest mismatch"));
        }
        let mut epoch = [0; 8];
        epoch.copy_from_slice(&digest[..8]);
        if hex::encode(epoch) != metadata.public_params_epoch {
            return Err(ClientError::Metadata("public parameter epoch mismatch"));
        }
        let blocks = ypir.db_cols / rlwe.d;
        if public_params.len() != blocks * published_c1_len(rlwe.d, rlwe.q) {
            return Err(ClientError::Metadata("invalid public parameter length"));
        }
        let published_c1 = recover_published_c1(public_params, rlwe.d, blocks, rlwe.q);
        let client = IPIRClient::new(&rlwe, &ypir);
        // Derived from the validated wire value rather than the constant directly, so the
        // metadata field stays load-bearing and cannot drift out of the code path.
        let setup =
            client.generate_public_query_setup_simplepir_from_seed(seed_bytes(metadata.setup_seed));
        Ok(Self {
            metadata,
            anchor,
            ypir,
            client,
            setup,
            published_c1,
            epoch,
        })
    }

    /// Returns the validated snapshot metadata.
    pub fn metadata(&self) -> &MemoSnapshotMetadata {
        &self.metadata
    }

    /// Returns the parsed anchor to compare with the wallet before issuing queries.
    pub fn snapshot_anchor(&self) -> MemoPirSnapshotAnchor {
        self.anchor
    }

    /// Creates a randomized query for the row containing `position`.
    pub fn prepare_position(&self, position: u64) -> Result<PreparedMemoQuery, ClientError> {
        let (row, _) = self
            .metadata
            .row_for_position(position)
            .ok_or(ClientError::OutsideCoverage)?;
        self.prepare_row(row)
    }

    /// Creates a cover query indistinguishable from a real row query.
    pub fn prepare_dummy(&self) -> Result<PreparedMemoQuery, ClientError> {
        self.prepare_row(OsRng.gen_range(0..self.ypir.db_rows))
    }

    fn prepare_row(&self, row: usize) -> Result<PreparedMemoQuery, ClientError> {
        let (query, packing_keys, seed) =
            self.client.generate_fresh_query_simplepir(&self.setup, row);
        let mut body = self.metadata.generation.to_le_bytes().to_vec();
        body.extend(
            serialize_packing_keys(self.client.rlwe_params(), &packing_keys)
                .map_err(|e| ClientError::Pir(e.to_string()))?,
        );
        body.extend(query.to_switched_bytes(self.client.rlwe_params().q, self.ypir.query_bits));
        Ok(PreparedMemoQuery {
            body,
            seed,
            global_row: row as u64,
        })
    }

    /// Strictly validates and decodes a response to `query`.
    pub fn decode(
        &self,
        query: PreparedMemoQuery,
        response: &[u8],
    ) -> Result<MemoPirRow, ClientError> {
        if response.get(..8) != Some(self.metadata.generation.to_le_bytes().as_slice()) {
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
        let bytes: [u8; ROW_BYTES] = decoded
            .get(..ROW_BYTES)
            .ok_or(ClientError::Response("decoded row is too short"))?
            .try_into()
            .expect("length checked");
        Ok(MemoPirRow::new(query.global_row, bytes))
    }
}

/// HTTPS transport for the memo-PIR protocol.
#[cfg(feature = "https-client")]
pub struct HttpMemoPirClient {
    http: reqwest::Client,
    base_url: String,
    session: MemoPirSession,
}

#[cfg(feature = "https-client")]
impl HttpMemoPirClient {
    /// Downloads and validates an immutable snapshot over HTTPS.
    pub async fn connect(base_url: &str, expected_network: &str) -> Result<Self, ClientError> {
        if !base_url.starts_with("https://") {
            return Err(ClientError::InsecureTransport);
        }
        let base_url = base_url.trim_end_matches('/').to_owned();
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()?;
        let metadata: MemoSnapshotMetadata = serde_json::from_slice(
            &read_limited(
                http.get(format!("{base_url}/memo/metadata")).send().await?,
                MAX_METADATA_BYTES,
            )
            .await?,
        )?;
        let params = read_limited(
            http.get(format!("{base_url}/memo/params")).send().await?,
            MAX_PARAMS_BYTES,
        )
        .await?;
        let public_params = read_limited(
            http.get(format!("{base_url}/memo/public-params"))
                .send()
                .await?,
            MAX_PIR_BODY_BYTES,
        )
        .await?;
        let session = MemoPirSession::new(expected_network, metadata, &params, &public_params)?;
        Ok(Self {
            http,
            base_url,
            session,
        })
    }

    /// Returns the validated snapshot metadata.
    pub fn metadata(&self) -> &MemoSnapshotMetadata {
        self.session.metadata()
    }

    /// Returns the parsed anchor to compare with the wallet before issuing queries.
    pub fn snapshot_anchor(&self) -> MemoPirSnapshotAnchor {
        self.session.snapshot_anchor()
    }

    /// Privately retrieves the complete row containing `position`.
    pub async fn query_position(&self, position: u64) -> Result<MemoPirRow, ClientError> {
        let query = self.session.prepare_position(position)?;
        self.send(query).await
    }

    /// Sends one randomized cover query and discards its decoded result.
    pub async fn query_dummy(&self) -> Result<(), ClientError> {
        let query = self.session.prepare_dummy()?;
        self.send(query).await.map(|_| ())
    }

    async fn send(&self, query: PreparedMemoQuery) -> Result<MemoPirRow, ClientError> {
        let response = self
            .http
            .post(format!("{}/memo/query", self.base_url))
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
    use crate::ShardDescriptor;

    fn metadata(coverage: Coverage) -> MemoSnapshotMetadata {
        MemoSnapshotMetadata {
            schema_version: SCHEMA_VERSION,
            network: "main".to_owned(),
            pool: POOL.to_owned(),
            anchor_height: 1,
            anchor_block_hash: "00".repeat(32),
            ironwood_tree_size: 1,
            coverage,
            record_bytes: RECORD_BYTES as u32,
            records_per_row: RECORDS_PER_ROW as u32,
            row_bytes: ROW_BYTES as u32,
            shard_rows: SHARD_ROWS as u32,
            used_rows: 1,
            logical_rows: SHARD_ROWS as u64,
            first_global_row: 0,
            generation: 1,
            parameter_id: "test".to_owned(),
            setup_seed: MEMO_SETUP_SEED,
            public_params_epoch: String::new(),
            public_params_sha256: String::new(),
            shards: Vec::<ShardDescriptor>::new(),
        }
    }

    #[test]
    fn rejects_windowed_coverage_before_parsing_parameters() {
        let result = MemoPirSession::new(
            "main",
            metadata(Coverage::Windowed {
                requested_lookback_blocks: 10,
                max_active_shards: 1,
                covered_position_start: 1,
                effective_start_height: 1,
            }),
            b"not JSON",
            &[],
        );
        assert!(matches!(result, Err(ClientError::Metadata(_))));
    }

    #[test]
    fn rejects_a_snapshot_built_against_another_setup_seed() {
        let mut metadata = metadata(Coverage::Full {
            covered_position_start: 0,
        });
        metadata.setup_seed = MEMO_SETUP_SEED ^ 1;

        let result = MemoPirSession::new("main", metadata, b"not JSON", &[]);

        assert!(matches!(
            result,
            Err(ClientError::SetupSeedMismatch {
                advertised,
                expected,
            }) if advertised == MEMO_SETUP_SEED ^ 1 && expected == MEMO_SETUP_SEED
        ));
    }

    #[test]
    fn expands_a_wire_seed_like_the_reference_implementation() {
        assert_eq!(seed_bytes(0), [0; 32]);

        let mut expected = [0; 32];
        expected[..8].copy_from_slice(&[0x1a, 0x13, 0x07, 0xec, 0x84, 0xe2, 0x1a, 0xaf]);
        assert_eq!(seed_bytes(MEMO_SETUP_SEED), expected);
    }

    #[test]
    fn rejects_wrong_network_before_parsing_parameters() {
        let result = MemoPirSession::new(
            "test",
            metadata(Coverage::Full {
                covered_position_start: 0,
            }),
            b"not JSON",
            &[],
        );
        assert!(matches!(result, Err(ClientError::Metadata(_))));
    }
}
