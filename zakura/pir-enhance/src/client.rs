use crate::types::{
    ENHANCE_SETUP_SEED, EnhanceGeneration, EnhanceRecord, ITEM_SIZE_BITS, NETWORK, POOL,
    PROTOCOL_REVISION, RECORD_BYTES, RECORDS_PER_ROW, ROW_BYTES, SCHEMA_VERSION, SHARD_ROWS,
    setup_seed_bytes,
};
use ipir_sp::modulus_switch::{published_c1_len, recover_published_c1, response_body_len};
use ipir_sp::serialize::serialize_packing_keys;
use ipir_sp::{IPIRClient, YpirSchemeParams};
use rand::{Rng, rngs::OsRng};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[cfg(feature = "https-client")]
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("server generation is incompatible: {0}")]
    Generation(String),
    #[error("position {0} is outside advertised coverage")]
    OutsideCoverage(u64),
    #[error("PIR error: {0}")]
    Pir(String),
    #[error("malformed PIR response: {0}")]
    Response(String),
}

pub struct QuerySession {
    generation: EnhanceGeneration,
    ypir: YpirSchemeParams,
    client: IPIRClient,
    setup: Vec<Vec<u64>>,
    published_c1: Vec<Vec<u64>>,
    epoch: [u8; 8],
}

pub struct PreparedQuery {
    row: usize,
    body: Vec<u8>,
    seed: ipir_sp::IPIRSeed,
}

impl PreparedQuery {
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn row(&self) -> usize {
        self.row
    }
}

impl QuerySession {
    pub fn new(
        generation: EnhanceGeneration,
        ypir: YpirSchemeParams,
        public_params: &[u8],
    ) -> Result<Self, ClientError> {
        if generation.schema_version != SCHEMA_VERSION
            || generation.protocol_revision != PROTOCOL_REVISION
            || generation.network != NETWORK
            || generation.pool != POOL
        {
            return Err(ClientError::Generation(
                "wrong schema, protocol, network, or pool".to_string(),
            ));
        }
        if generation.setup_seed != ENHANCE_SETUP_SEED {
            return Err(ClientError::Generation(
                "setup seed does not match Enhance PIR".to_string(),
            ));
        }
        if generation.record_bytes as usize != RECORD_BYTES
            || generation.records_per_row as usize != RECORDS_PER_ROW
            || generation.row_bytes as usize != ROW_BYTES
            || generation.shard_rows as usize != SHARD_ROWS
            || generation.logical_rows < generation.used_rows
            || !generation.logical_rows.is_power_of_two()
            || generation.logical_rows < SHARD_ROWS as u64
            || generation.used_rows
                != generation
                    .ironwood_tree_size
                    .div_ceil(RECORDS_PER_ROW as u64)
        {
            return Err(ClientError::Generation(
                "invalid database geometry".to_string(),
            ));
        }
        let (rlwe, expected) =
            ipir_sp::params_for_simplepir(generation.logical_rows, ITEM_SIZE_BITS)
                .map_err(|error| ClientError::Pir(error.to_string()))?;
        if ypir != expected {
            return Err(ClientError::Generation(
                "parameters do not match the pinned generator".to_string(),
            ));
        }
        let digest = Sha256::digest(public_params);
        if hex::encode(digest) != generation.public_params_sha256 {
            return Err(ClientError::Generation(
                "public parameter digest mismatch".to_string(),
            ));
        }
        let mut epoch = [0; 8];
        epoch.copy_from_slice(&digest[..8]);
        if hex::encode(epoch) != generation.public_params_epoch {
            return Err(ClientError::Generation(
                "public parameter epoch mismatch".to_string(),
            ));
        }
        let blocks = ypir.db_cols / rlwe.d;
        let expected_len = blocks * published_c1_len(rlwe.d, rlwe.q);
        if public_params.len() != expected_len {
            return Err(ClientError::Generation(format!(
                "public parameters have {} bytes, expected {expected_len}",
                public_params.len()
            )));
        }
        let published_c1 = recover_published_c1(public_params, rlwe.d, blocks, rlwe.q);
        let client = IPIRClient::new(&rlwe, &ypir);
        let setup = client.generate_public_query_setup_simplepir_from_seed(setup_seed_bytes());
        Ok(Self {
            generation,
            ypir,
            client,
            setup,
            published_c1,
            epoch,
        })
    }

    pub fn generation(&self) -> &EnhanceGeneration {
        &self.generation
    }

    pub fn params(&self) -> &YpirSchemeParams {
        &self.ypir
    }

    pub fn setup(&self) -> &[Vec<u64>] {
        &self.setup
    }

    pub fn prepare_position(&self, position: u64) -> Result<(PreparedQuery, usize), ClientError> {
        let (row, slot) = self
            .generation
            .row_for_position(position)
            .ok_or(ClientError::OutsideCoverage(position))?;
        Ok((self.prepare_row(row)?, slot))
    }

    pub fn prepare_dummy(&self) -> Result<PreparedQuery, ClientError> {
        self.prepare_row(OsRng.gen_range(0..self.ypir.db_rows))
    }

    pub fn prepare_row(&self, row: usize) -> Result<PreparedQuery, ClientError> {
        if row >= self.ypir.db_rows {
            return Err(ClientError::OutsideCoverage(row as u64));
        }
        let (query, packing_keys, seed) =
            self.client.generate_fresh_query_simplepir(&self.setup, row);
        let mut body = self.generation.generation.to_le_bytes().to_vec();
        body.extend(
            serialize_packing_keys(self.client.rlwe_params(), &packing_keys)
                .map_err(|error| ClientError::Pir(error.to_string()))?,
        );
        body.extend(query.to_switched_bytes(self.client.rlwe_params().q, self.ypir.query_bits));
        Ok(PreparedQuery { row, body, seed })
    }

    pub fn decode(&self, query: PreparedQuery, response: &[u8]) -> Result<Vec<u8>, ClientError> {
        if response.get(..8) != Some(self.generation.generation.to_le_bytes().as_slice()) {
            return Err(ClientError::Response("generation mismatch".to_string()));
        }
        if response.get(8..16) != Some(self.epoch.as_slice()) {
            return Err(ClientError::Response(
                "public parameter epoch mismatch".to_string(),
            ));
        }
        let expected_body_len = (self.ypir.db_cols / self.client.rlwe_params().d)
            * response_body_len(self.client.rlwe_params().d, self.ypir.q_prime_1);
        if response.len() != 16 + expected_body_len {
            return Err(ClientError::Response(format!(
                "response has {} bytes, expected {}",
                response.len(),
                16 + expected_body_len
            )));
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

pub fn record_in_row(row: &[u8], slot: usize) -> EnhanceRecord {
    let start = slot * RECORD_BYTES;
    let bytes: [u8; RECORD_BYTES] = row[start..start + RECORD_BYTES]
        .try_into()
        .expect("validated Enhance row bounds");
    EnhanceRecord(bytes)
}

#[cfg(feature = "https-client")]
pub struct EnhancePirClient {
    http: reqwest::Client,
    base_url: String,
    session: QuerySession,
}

#[cfg(feature = "https-client")]
impl EnhancePirClient {
    pub async fn connect(base_url: &str) -> Result<Self, ClientError> {
        let base_url = base_url.trim_end_matches('/').to_string();
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()?;
        let generation: EnhanceGeneration = serde_json::from_slice(
            &read_limited(
                http.get(format!("{base_url}/v1/enhance/generation"))
                    .send()
                    .await?,
                1024 * 1024,
            )
            .await?,
        )?;
        let generation_id = generation.generation;
        let ypir: YpirSchemeParams = serde_json::from_slice(
            &read_limited(
                http.get(format!(
                    "{base_url}/v1/enhance/params?generation={generation_id}"
                ))
                .send()
                .await?,
                64 * 1024,
            )
            .await?,
        )?;
        let public_params = read_limited(
            http.get(format!(
                "{base_url}/v1/enhance/public-params?generation={generation_id}"
            ))
            .send()
            .await?,
            16 * 1024 * 1024,
        )
        .await?;
        let session = QuerySession::new(generation, ypir, &public_params)?;
        Ok(Self {
            http,
            base_url,
            session,
        })
    }

    pub fn generation(&self) -> &EnhanceGeneration {
        self.session.generation()
    }

    pub async fn query_position(&self, position: u64) -> Result<EnhanceRecord, ClientError> {
        let (query, slot) = self.session.prepare_position(position)?;
        let row = self.send(query).await?;
        Ok(record_in_row(&row, slot))
    }

    pub async fn query_dummy(&self) -> Result<(), ClientError> {
        self.send(self.session.prepare_dummy()?).await.map(|_| ())
    }

    async fn send(&self, query: PreparedQuery) -> Result<Vec<u8>, ClientError> {
        let response = self
            .http
            .post(format!("{}/v1/enhance/query", self.base_url))
            .body(query.body().to_vec())
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(ClientError::Response(format!(
                "server returned {}",
                response.status()
            )));
        }
        let response = read_limited(response, 16 * 1024 * 1024).await?;
        self.session.decode(query, &response)
    }
}

#[cfg(feature = "https-client")]
async fn read_limited(response: reqwest::Response, limit: usize) -> Result<Vec<u8>, ClientError> {
    let mut response = response.error_for_status()?;
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(ClientError::Response("HTTP body exceeds limit".to_string()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(ClientError::Response("HTTP body exceeds limit".to_string()));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
