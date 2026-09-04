use crate::types::{
    COLD_SETUP_SEED, ITEM_SIZE_BITS, NETWORK, PROTOCOL_REVISION, ROW_BYTES, SCHEMA_VERSION,
    SHARD_ROWS, SpendLookup, TransparentSpendGeneration, TransparentSpendSession,
    TransparentSpendTableSession, WARM_SETUP_SEED, bucket_for_outpoint, scan_bucket,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ipir_sp::modulus_switch::{published_c1_len, recover_published_c1, response_body_len};
use ipir_sp::serialize::serialize_packing_keys;
use ipir_sp::{IPIRClient, YpirSchemeParams};
use rand::{Rng, rngs::OsRng};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64 error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("incompatible session: {0}")]
    Session(String),
    #[error("PIR error: {0}")]
    Pir(String),
    #[error("malformed response: {0}")]
    Response(String),
}

struct PreparedQuery {
    body: Vec<u8>,
    seed: ipir_sp::IPIRSeed,
}

struct TableClient {
    generation: TransparentSpendGeneration,
    params: YpirSchemeParams,
    client: IPIRClient,
    setup: Vec<Vec<u64>>,
    published_c1: Vec<Vec<u64>>,
    epoch: [u8; 8],
}

impl TableClient {
    fn new(session: TransparentSpendTableSession, expected_seed: u64) -> Result<Self, ClientError> {
        let generation = session.generation;
        if generation.schema_version != SCHEMA_VERSION
            || generation.protocol_revision != PROTOCOL_REVISION
            || generation.network != NETWORK
            || generation.row_bytes as usize != ROW_BYTES
            || generation.shard_rows as usize != SHARD_ROWS
            || generation.buckets != generation.logical_rows
            || !generation.logical_rows.is_power_of_two()
            || generation.logical_rows < SHARD_ROWS as u64
            || generation.setup_seed != expected_seed
        {
            return Err(ClientError::Session("invalid table metadata".to_string()));
        }
        let (rlwe, expected_params) =
            ipir_sp::params_for_simplepir(generation.logical_rows, ITEM_SIZE_BITS)
                .map_err(|error| ClientError::Pir(error.to_string()))?;
        if session.params != expected_params {
            return Err(ClientError::Session(
                "unexpected PIR parameters".to_string(),
            ));
        }
        let public_params = BASE64_STANDARD.decode(session.public_params_base64)?;
        let digest = Sha256::digest(&public_params);
        if hex::encode(digest) != generation.public_params_sha256 {
            return Err(ClientError::Session(
                "public parameter digest mismatch".to_string(),
            ));
        }
        let mut epoch = [0; 8];
        epoch.copy_from_slice(&digest[..8]);
        if hex::encode(epoch) != generation.public_params_epoch {
            return Err(ClientError::Session(
                "public parameter epoch mismatch".to_string(),
            ));
        }
        let blocks = session.params.db_cols / rlwe.d;
        if public_params.len() != blocks * published_c1_len(rlwe.d, rlwe.q) {
            return Err(ClientError::Session(
                "public parameter length mismatch".to_string(),
            ));
        }
        let published_c1 = recover_published_c1(&public_params, rlwe.d, blocks, rlwe.q);
        let client = IPIRClient::new(&rlwe, &session.params);
        let mut seed = [0; 32];
        seed[..8].copy_from_slice(&expected_seed.to_le_bytes());
        let setup = client.generate_public_query_setup_simplepir_from_seed(seed);
        Ok(Self {
            generation,
            params: session.params,
            client,
            setup,
            published_c1,
            epoch,
        })
    }

    fn prepare(&self, row: usize) -> Result<PreparedQuery, ClientError> {
        if row >= self.params.db_rows {
            return Err(ClientError::Session("bucket outside table".to_string()));
        }
        let (query, packing_keys, seed) =
            self.client.generate_fresh_query_simplepir(&self.setup, row);
        let mut body = self.generation.generation.to_le_bytes().to_vec();
        body.extend(
            serialize_packing_keys(self.client.rlwe_params(), &packing_keys)
                .map_err(|error| ClientError::Pir(error.to_string()))?,
        );
        body.extend(query.to_switched_bytes(self.client.rlwe_params().q, self.params.query_bits));
        Ok(PreparedQuery { body, seed })
    }

    fn prepare_dummy(&self) -> Result<PreparedQuery, ClientError> {
        self.prepare(OsRng.gen_range(0..self.params.db_rows))
    }

    fn decode(&self, query: PreparedQuery, response: &[u8]) -> Result<Vec<u8>, ClientError> {
        if response.get(..8) != Some(self.generation.generation.to_le_bytes().as_slice()) {
            return Err(ClientError::Response("generation mismatch".to_string()));
        }
        if response.get(8..16) != Some(self.epoch.as_slice()) {
            return Err(ClientError::Response(
                "parameter epoch mismatch".to_string(),
            ));
        }
        let expected = (self.params.db_cols / self.client.rlwe_params().d)
            * response_body_len(self.client.rlwe_params().d, self.params.q_prime_1);
        if response.len() != 16 + expected {
            return Err(ClientError::Response(
                "response length mismatch".to_string(),
            ));
        }
        let decoded =
            self.client
                .decode_response_simplepir(query.seed, &self.published_c1, &response[16..]);
        decoded
            .get(..ROW_BYTES)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| ClientError::Response("decoded row is too short".to_string()))
    }
}

pub struct TransparentSpendPirClient {
    http: reqwest::Client,
    base_url: String,
    session: TransparentSpendSession,
    cold: TableClient,
    warm: TableClient,
}

impl TransparentSpendPirClient {
    pub async fn connect(base_url: &str) -> Result<Self, ClientError> {
        let base_url = base_url.trim_end_matches('/').to_string();
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()?;
        let response = http
            .get(format!("{base_url}/v1/transparent-spend/init"))
            .send()
            .await?
            .error_for_status()?;
        let bytes = response.bytes().await?;
        if bytes.len() > 2 * 1024 * 1024 {
            return Err(ClientError::Response(
                "session body is too large".to_string(),
            ));
        }
        let session: TransparentSpendSession = serde_json::from_slice(&bytes)?;
        for table in [&session.cold.generation, &session.warm.generation] {
            if table.tip_height != session.tip_height
                || table.tip_block_hash != session.tip_block_hash
                || table.generation != session.generation
                || table.cold_end_height != session.cold_end_height
                || table.ironwood_tree_size != session.ironwood_tree_size
            {
                return Err(ClientError::Session(
                    "table/session identity mismatch".to_string(),
                ));
            }
        }
        let cold = TableClient::new(session.cold.clone(), COLD_SETUP_SEED)?;
        let warm = TableClient::new(session.warm.clone(), WARM_SETUP_SEED)?;
        Ok(Self {
            http,
            base_url,
            session,
            cold,
            warm,
        })
    }

    pub fn session(&self) -> &TransparentSpendSession {
        &self.session
    }

    pub async fn lookup(&self, txid: [u8; 32], index: u32) -> Result<SpendLookup, ClientError> {
        let cold_bucket = bucket_for_outpoint(&txid, index, self.cold.params.db_rows)
            .ok_or_else(|| ClientError::Session("invalid cold bucket count".to_string()))?;
        let warm_bucket = bucket_for_outpoint(&txid, index, self.warm.params.db_rows)
            .ok_or_else(|| ClientError::Session("invalid warm bucket count".to_string()))?;
        let cold_query = self.cold.prepare(cold_bucket)?;
        let warm_query = self.warm.prepare(warm_bucket)?;
        let cold_request = self.request("cold", &cold_query.body);
        let warm_request = self.request("warm", &warm_query.body);
        let (cold_response, warm_response) = tokio::try_join!(cold_request, warm_request)?;
        let cold_row = self.cold.decode(cold_query, &cold_response)?;
        let warm_row = self.warm.decode(warm_query, &warm_response)?;
        let cold =
            scan_bucket(&cold_row, &txid, index).map_err(|e| ClientError::Response(e.into()))?;
        let warm =
            scan_bucket(&warm_row, &txid, index).map_err(|e| ClientError::Response(e.into()))?;
        match (cold, warm) {
            (Some(_), Some(_)) => Err(ClientError::Response("spend appears in both tiers".into())),
            (Some(entry), None) | (None, Some(entry)) => Ok(SpendLookup::Spent(entry)),
            (None, None) => Ok(SpendLookup::Unspent {
                as_of_height: self.session.tip_height,
            }),
        }
    }

    pub async fn query_dummy(&self) -> Result<(), ClientError> {
        let cold = self.cold.prepare_dummy()?;
        let warm = self.warm.prepare_dummy()?;
        let (cold_response, warm_response) = tokio::try_join!(
            self.request("cold", &cold.body),
            self.request("warm", &warm.body),
        )?;
        self.cold.decode(cold, &cold_response)?;
        self.warm.decode(warm, &warm_response)?;
        Ok(())
    }

    async fn request(&self, tier: &str, body: &[u8]) -> Result<Vec<u8>, ClientError> {
        let response = self
            .http
            .post(format!(
                "{}/v1/transparent-spend/{tier}/query",
                self.base_url
            ))
            .body(body.to_vec())
            .send()
            .await?
            .error_for_status()?;
        let bytes = response.bytes().await?;
        if bytes.len() > 16 * 1024 * 1024 {
            return Err(ClientError::Response(
                "response body is too large".to_string(),
            ));
        }
        Ok(bytes.to_vec())
    }
}
