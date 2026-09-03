use crate::types::{
    ENHANCE_SETUP_SEED, EnhanceGeneration, EnhanceRecord, EnhanceSession, ITEM_SIZE_BITS, NETWORK,
    POOL, PROTOCOL_REVISION, RECORD_BYTES, RECORDS_PER_ROW, ROW_BYTES, SCHEMA_VERSION, SHARD_ROWS,
    checked_logical_rows_for, setup_seed_bytes,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ipir_sp::modulus_switch::{published_c1_len, recover_published_c1, response_body_len};
use ipir_sp::serialize::serialize_packing_keys;
use ipir_sp::{IPIRClient, YpirSchemeParams};
use rand::{Rng, rngs::OsRng};
use sha2::{Digest, Sha256};

/// Wallet-accepted chain state to which an Enhance PIR generation must be bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedAnchor {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub ironwood_tree_size: u64,
}

impl AcceptedAnchor {
    pub fn new(height: u64, block_hash: [u8; 32], ironwood_tree_size: u64) -> Self {
        Self {
            height,
            block_hash,
            ironwood_tree_size,
        }
    }
}

/// A local cap on generation-dependent client work.
///
/// Setup memory grows with `logical_rows`, so this value must be selected by
/// the application for the least-capable device it supports. It is local
/// policy and must not be derived from server metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientResourceLimits {
    pub max_logical_rows: u64,
}

impl ClientResourceLimits {
    pub const fn new(max_logical_rows: u64) -> Self {
        Self { max_logical_rows }
    }
}

/// The wallet-owned inputs required before a generation may be instantiated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerationAcceptance {
    pub anchor: AcceptedAnchor,
    pub limits: ClientResourceLimits,
}

impl GenerationAcceptance {
    pub const fn new(anchor: AcceptedAnchor, limits: ClientResourceLimits) -> Self {
        Self { anchor, limits }
    }

    pub fn validate(&self, generation: &EnhanceGeneration) -> Result<(), ClientError> {
        validate_generation(generation, self)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[cfg(feature = "https-client")]
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid public parameters base64: {0}")]
    PublicParamsBase64(#[from] base64::DecodeError),
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
    pub fn from_session(
        session: EnhanceSession,
        acceptance: &GenerationAcceptance,
    ) -> Result<Self, ClientError> {
        acceptance.validate(&session.generation)?;
        let public_params = BASE64_STANDARD.decode(session.public_params_base64)?;
        Self::new(
            session.generation,
            session.params,
            &public_params,
            acceptance,
        )
    }

    pub fn new(
        generation: EnhanceGeneration,
        ypir: YpirSchemeParams,
        public_params: &[u8],
        acceptance: &GenerationAcceptance,
    ) -> Result<Self, ClientError> {
        acceptance.validate(&generation)?;
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
        let blocks = ypir
            .db_cols
            .checked_div(rlwe.d)
            .filter(|_| ypir.db_cols.is_multiple_of(rlwe.d))
            .ok_or_else(|| ClientError::Generation("invalid PIR dimensions".to_string()))?;
        let expected_len = checked_generation_product(
            blocks,
            published_c1_len(rlwe.d, rlwe.q),
            "public parameter length",
        )?;
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
        let d = self.client.rlwe_params().d;
        let blocks = self
            .ypir
            .db_cols
            .checked_div(d)
            .filter(|_| self.ypir.db_cols.is_multiple_of(d))
            .ok_or_else(|| ClientError::Response("invalid PIR dimensions".to_string()))?;
        let expected_body_len = checked_response_product(
            blocks,
            response_body_len(d, self.ypir.q_prime_1),
            "response body length",
        )?;
        let expected_len = 16usize
            .checked_add(expected_body_len)
            .ok_or_else(|| ClientError::Response("response length overflows usize".to_string()))?;
        if response.len() != expected_len {
            return Err(ClientError::Response(format!(
                "response has {} bytes, expected {}",
                response.len(),
                expected_len
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

fn validate_generation(
    generation: &EnhanceGeneration,
    acceptance: &GenerationAcceptance,
) -> Result<(), ClientError> {
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

    let advertised_hash: [u8; 32] = hex::decode(&generation.anchor_block_hash)
        .map_err(|_| ClientError::Generation("invalid anchor block hash".to_string()))?
        .try_into()
        .map_err(|_| ClientError::Generation("invalid anchor block hash".to_string()))?;
    if generation.anchor_height != acceptance.anchor.height
        || advertised_hash != acceptance.anchor.block_hash
        || generation.ironwood_tree_size != acceptance.anchor.ironwood_tree_size
    {
        return Err(ClientError::Generation(
            "generation anchor is not accepted by the wallet".to_string(),
        ));
    }

    let expected_used_rows = generation
        .ironwood_tree_size
        .checked_add(RECORDS_PER_ROW as u64 - 1)
        .ok_or_else(|| ClientError::Generation("database geometry overflows".to_string()))?
        / RECORDS_PER_ROW as u64;
    let expected_logical_rows = checked_logical_rows_for(expected_used_rows)
        .ok_or_else(|| ClientError::Generation("database geometry overflows".to_string()))?;
    if generation.record_bytes as usize != RECORD_BYTES
        || generation.records_per_row as usize != RECORDS_PER_ROW
        || generation.row_bytes as usize != ROW_BYTES
        || generation.shard_rows as usize != SHARD_ROWS
        || generation.used_rows != expected_used_rows
        || generation.logical_rows != expected_logical_rows
    {
        return Err(ClientError::Generation(
            "invalid database geometry".to_string(),
        ));
    }
    if generation.logical_rows > acceptance.limits.max_logical_rows {
        return Err(ClientError::Generation(format!(
            "generation has {} logical rows, exceeding the local limit of {}",
            generation.logical_rows, acceptance.limits.max_logical_rows
        )));
    }
    usize::try_from(generation.logical_rows)
        .map_err(|_| ClientError::Generation("logical row count exceeds usize".to_string()))?;

    Ok(())
}

fn checked_generation_product(left: usize, right: usize, name: &str) -> Result<usize, ClientError> {
    left.checked_mul(right)
        .ok_or_else(|| ClientError::Generation(format!("{name} overflows usize")))
}

fn checked_response_product(left: usize, right: usize, name: &str) -> Result<usize, ClientError> {
    left.checked_mul(right)
        .ok_or_else(|| ClientError::Response(format!("{name} overflows usize")))
}

#[cfg(feature = "https-client")]
pub struct EnhancePirClient {
    http: reqwest::Client,
    base_url: String,
    session: QuerySession,
}

#[cfg(feature = "https-client")]
pub struct PendingEnhancePirClient {
    http: reqwest::Client,
    base_url: String,
    session: EnhanceSession,
}

#[cfg(feature = "https-client")]
impl PendingEnhancePirClient {
    pub fn generation(&self) -> &EnhanceGeneration {
        &self.session.generation
    }

    pub async fn connect(
        self,
        acceptance: &GenerationAcceptance,
    ) -> Result<EnhancePirClient, ClientError> {
        acceptance.validate(&self.session.generation)?;
        let session = QuerySession::from_session(self.session, acceptance)?;
        Ok(EnhancePirClient {
            http: self.http,
            base_url: self.base_url,
            session,
        })
    }
}

#[cfg(feature = "https-client")]
impl EnhancePirClient {
    pub async fn fetch_session(base_url: &str) -> Result<PendingEnhancePirClient, ClientError> {
        let base_url = base_url.trim_end_matches('/').to_string();
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()?;
        let session: EnhanceSession = serde_json::from_slice(
            &read_limited(
                http.get(format!("{base_url}/v1/enhance/init"))
                    .send()
                    .await?,
                1024 * 1024,
            )
            .await?,
        )?;
        Ok(PendingEnhancePirClient {
            http,
            base_url,
            session,
        })
    }

    pub async fn connect(
        base_url: &str,
        acceptance: &GenerationAcceptance,
    ) -> Result<Self, ClientError> {
        Self::fetch_session(base_url)
            .await?
            .connect(acceptance)
            .await
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
        if body
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > limit)
        {
            return Err(ClientError::Response("HTTP body exceeds limit".to_string()));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use inspiring::{GadgetParams, RlweParams, TopKeyImages};
    use ipir_sp::{
        serialize::{deserialize_packing_keys, serialized_packing_keys_len},
        server::{IPIRServer, build_pack_preprocessed_blocks, published_c1_rows},
    };

    use super::*;

    fn acceptance_for(
        generation: &EnhanceGeneration,
        max_logical_rows: u64,
    ) -> GenerationAcceptance {
        GenerationAcceptance::new(
            AcceptedAnchor::new(
                generation.anchor_height,
                hex::decode(&generation.anchor_block_hash)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                generation.ironwood_tree_size,
            ),
            ClientResourceLimits::new(max_logical_rows),
        )
    }

    fn valid_session() -> EnhanceSession {
        let (rlwe, params) = ipir_sp::params_for_simplepir(SHARD_ROWS as u64, ITEM_SIZE_BITS)
            .expect("fixed Enhance geometry");
        let public_params = vec![
            0;
            checked_generation_product(
                params.db_cols / rlwe.d,
                published_c1_len(rlwe.d, rlwe.q),
                "test public parameters",
            )
            .unwrap()
        ];
        let digest = Sha256::digest(&public_params);
        let generation = EnhanceGeneration {
            schema_version: SCHEMA_VERSION,
            protocol_revision: PROTOCOL_REVISION.to_string(),
            network: NETWORK.to_string(),
            pool: POOL.to_string(),
            anchor_height: 3_428_143,
            anchor_block_hash: "00".repeat(32),
            ironwood_tree_size: 1,
            generation: 1,
            record_bytes: RECORD_BYTES as u32,
            records_per_row: RECORDS_PER_ROW as u32,
            row_bytes: ROW_BYTES as u32,
            shard_rows: SHARD_ROWS as u32,
            used_rows: 1,
            logical_rows: SHARD_ROWS as u64,
            parameter_id: "test".to_string(),
            setup_seed: ENHANCE_SETUP_SEED,
            public_params_epoch: hex::encode(&digest[..8]),
            public_params_sha256: hex::encode(digest),
            shards: vec![],
        };
        EnhanceSession {
            generation,
            params,
            public_params_base64: BASE64_STANDARD.encode(public_params),
        }
    }

    fn set_public_params(session: &mut EnhanceSession, public_params: Vec<u8>) {
        let digest = Sha256::digest(&public_params);
        session.generation.public_params_epoch = hex::encode(&digest[..8]);
        session.generation.public_params_sha256 = hex::encode(digest);
        session.public_params_base64 = BASE64_STANDARD.encode(public_params);
    }

    fn assert_generation_error(session: EnhanceSession, expected: &str) {
        let acceptance = acceptance_for(&session.generation, SHARD_ROWS as u64);
        assert!(matches!(
            QuerySession::from_session(session, &acceptance),
            Err(ClientError::Generation(message)) if message == expected
        ));
    }

    fn prepared_query() -> PreparedQuery {
        PreparedQuery {
            row: 0,
            body: vec![],
            seed: [0; 32],
        }
    }

    #[test]
    fn constructs_an_atomic_session() {
        let session = valid_session();
        let acceptance = acceptance_for(&session.generation, SHARD_ROWS as u64);
        QuerySession::from_session(session, &acceptance).expect("valid session");
    }

    #[test]
    fn accepts_a_wallet_bound_generation_within_the_local_budget() {
        let session = valid_session();
        acceptance_for(&session.generation, SHARD_ROWS as u64)
            .validate(&session.generation)
            .expect("valid generation");
    }

    #[test]
    fn rejects_malformed_public_parameter_base64() {
        let mut session = valid_session();
        let acceptance = acceptance_for(&session.generation, SHARD_ROWS as u64);
        session.public_params_base64 = "not base64***".to_string();
        assert!(matches!(
            QuerySession::from_session(session, &acceptance),
            Err(ClientError::PublicParamsBase64(_))
        ));
    }

    #[test]
    fn rejects_a_public_parameter_digest_mismatch() {
        let mut session = valid_session();
        let acceptance = acceptance_for(&session.generation, SHARD_ROWS as u64);
        session.generation.public_params_sha256 = "00".repeat(32);
        assert!(matches!(
            QuerySession::from_session(session, &acceptance),
            Err(ClientError::Generation(message)) if message == "public parameter digest mismatch"
        ));
    }

    #[test]
    fn rejects_each_generation_discriminator() {
        let mut mutations: Vec<Box<dyn FnOnce(&mut EnhanceGeneration)>> = vec![
            Box::new(|generation| generation.schema_version += 1),
            Box::new(|generation| generation.protocol_revision.push_str("-wrong")),
            Box::new(|generation| generation.network = "test".to_string()),
            Box::new(|generation| generation.pool = "orchard".to_string()),
        ];

        for mutate in mutations.drain(..) {
            let mut session = valid_session();
            mutate(&mut session.generation);
            assert_generation_error(session, "wrong schema, protocol, network, or pool");
        }
    }

    #[test]
    fn rejects_the_wrong_setup_seed_and_malformed_anchor_hash() {
        let mut wrong_seed = valid_session();
        wrong_seed.generation.setup_seed ^= 1;
        assert_generation_error(wrong_seed, "setup seed does not match Enhance PIR");

        let mut malformed_anchor = valid_session();
        malformed_anchor.generation.anchor_block_hash = "not-a-hash".to_string();
        let acceptance = GenerationAcceptance::new(
            AcceptedAnchor::new(
                malformed_anchor.generation.anchor_height,
                [0; 32],
                malformed_anchor.generation.ironwood_tree_size,
            ),
            ClientResourceLimits::new(SHARD_ROWS as u64),
        );
        assert!(matches!(
            QuerySession::from_session(malformed_anchor, &acceptance),
            Err(ClientError::Generation(message)) if message == "invalid anchor block hash"
        ));
    }

    #[test]
    fn rejects_parameter_epoch_and_public_parameter_length_mismatches() {
        let mut wrong_params = valid_session();
        wrong_params.params.query_bits += 1;
        assert_generation_error(wrong_params, "parameters do not match the pinned generator");

        let mut wrong_epoch = valid_session();
        wrong_epoch.generation.public_params_epoch = "00".repeat(8);
        assert_generation_error(wrong_epoch, "public parameter epoch mismatch");

        for delta in [-1isize, 1] {
            let mut session = valid_session();
            let mut public_params = BASE64_STANDARD
                .decode(&session.public_params_base64)
                .unwrap();
            if delta < 0 {
                public_params.pop();
            } else {
                public_params.push(0);
            }
            set_public_params(&mut session, public_params);
            let expected_len = BASE64_STANDARD
                .decode(valid_session().public_params_base64)
                .unwrap()
                .len();
            let actual_len = (expected_len as isize + delta) as usize;
            assert_generation_error(
                session,
                &format!("public parameters have {actual_len} bytes, expected {expected_len}"),
            );
        }
    }

    #[test]
    fn rejects_each_unaccepted_anchor_field() {
        let session = valid_session();
        let mut wrong_height = acceptance_for(&session.generation, SHARD_ROWS as u64);
        wrong_height.anchor.height += 1;
        let mut wrong_hash = acceptance_for(&session.generation, SHARD_ROWS as u64);
        wrong_hash.anchor.block_hash[0] ^= 1;
        let mut wrong_tree_size = acceptance_for(&session.generation, SHARD_ROWS as u64);
        wrong_tree_size.anchor.ironwood_tree_size += 1;

        for acceptance in [wrong_height, wrong_hash, wrong_tree_size] {
            assert!(matches!(
                acceptance.validate(&session.generation),
                Err(ClientError::Generation(message))
                    if message == "generation anchor is not accepted by the wallet"
            ));
        }
    }

    #[test]
    fn rejects_the_reported_unbounded_generation_before_decoding_parameters() {
        let mut session = valid_session();
        session.generation.ironwood_tree_size = 9 * (1_u64 << 32);
        session.generation.used_rows = 1_u64 << 32;
        session.generation.logical_rows = 1_u64 << 32;
        session.public_params_base64 = "not base64***".to_string();
        let acceptance = acceptance_for(&session.generation, 1_u64 << 20);

        assert!(matches!(
            QuerySession::from_session(session, &acceptance),
            Err(ClientError::Generation(message))
                if message.contains("exceeding the local limit")
        ));
    }

    #[test]
    fn rejects_noncanonical_server_padding() {
        let mut session = valid_session();
        let acceptance = acceptance_for(&session.generation, 2 * SHARD_ROWS as u64);
        session.generation.logical_rows *= 2;

        assert!(matches!(
            acceptance.validate(&session.generation),
            Err(ClientError::Generation(message)) if message == "invalid database geometry"
        ));
    }

    #[test]
    fn rejects_generation_geometry_overflow() {
        let mut session = valid_session();
        session.generation.ironwood_tree_size = u64::MAX;
        session.generation.used_rows = u64::MAX;
        session.generation.logical_rows = 1_u64 << 63;
        let acceptance = acceptance_for(&session.generation, u64::MAX);

        assert!(matches!(
            acceptance.validate(&session.generation),
            Err(ClientError::Generation(message)) if message == "database geometry overflows"
        ));
    }

    #[test]
    fn rejects_wire_length_overflow() {
        assert!(matches!(
            checked_generation_product(usize::MAX, 2, "test"),
            Err(ClientError::Generation(message)) if message == "test overflows usize"
        ));
        assert!(matches!(
            checked_response_product(usize::MAX, 2, "test"),
            Err(ClientError::Response(message)) if message == "test overflows usize"
        ));
    }

    #[test]
    fn maps_position_boundaries_and_rejects_out_of_range_rows() {
        let mut session = valid_session();
        session.generation.ironwood_tree_size = 10;
        session.generation.used_rows = 2;
        let acceptance = acceptance_for(&session.generation, SHARD_ROWS as u64);
        let query_session = QuerySession::from_session(session, &acceptance).unwrap();

        for (position, expected) in [(0, (0, 0)), (8, (0, 8)), (9, (1, 0))] {
            let (query, slot) = query_session.prepare_position(position).unwrap();
            assert_eq!((query.row(), slot), expected);
        }
        assert!(matches!(
            query_session.prepare_position(10),
            Err(ClientError::OutsideCoverage(10))
        ));
        assert!(matches!(
            query_session.prepare_row(query_session.params().db_rows),
            Err(ClientError::OutsideCoverage(position))
                if position == query_session.params().db_rows as u64
        ));
    }

    #[test]
    fn rejects_response_header_and_length_mismatches_independently() {
        let session = valid_session();
        let acceptance = acceptance_for(&session.generation, SHARD_ROWS as u64);
        let query_session = QuerySession::from_session(session, &acceptance).unwrap();

        for length in [0, 7, 8, 15] {
            let response = vec![0; length];
            assert!(matches!(
                query_session.decode(prepared_query(), &response),
                Err(ClientError::Response(message)) if message == "generation mismatch"
            ));
        }

        let mut wrong_epoch = query_session.generation.generation.to_le_bytes().to_vec();
        wrong_epoch.extend_from_slice(&[0; 8]);
        assert!(matches!(
            query_session.decode(prepared_query(), &wrong_epoch),
            Err(ClientError::Response(message)) if message == "public parameter epoch mismatch"
        ));

        let d = query_session.client.rlwe_params().d;
        let blocks = query_session.params().db_cols / d;
        let expected_len = 16 + blocks * response_body_len(d, query_session.params().q_prime_1);
        for length in [16, expected_len - 1, expected_len + 1] {
            let mut response = query_session.generation.generation.to_le_bytes().to_vec();
            response.extend_from_slice(&query_session.epoch);
            response.resize(length, 0);
            assert!(matches!(
                query_session.decode(prepared_query(), &response),
                Err(ClientError::Response(message))
                    if message == format!("response has {length} bytes, expected {expected_len}")
            ));
        }

        let mut wrong_generation = query_session
            .generation
            .generation
            .wrapping_add(1)
            .to_le_bytes()
            .to_vec();
        wrong_generation.extend_from_slice(&query_session.epoch);
        wrong_generation.resize(expected_len, 0);
        assert!(matches!(
            query_session.decode(prepared_query(), &wrong_generation),
            Err(ClientError::Response(message)) if message == "generation mismatch"
        ));
    }

    #[test]
    fn end_to_end_query_returns_the_known_record() {
        let rlwe = RlweParams::new(
            8,
            12289,
            256,
            0.1,
            GadgetParams {
                bits_per: 3,
                ell: 5,
            },
        )
        .unwrap();
        let db_cols = ROW_BYTES.next_multiple_of(rlwe.d);
        let ypir = YpirSchemeParams {
            num_items: 8,
            item_size_bits: (db_cols * 8) as u64,
            poly_len: rlwe.d,
            db_dim_1: 0,
            db_dim_2: 1,
            instances: db_cols / rlwe.d,
            db_rows: 8,
            db_cols,
            p: 256,
            q_prime_1: rlwe.q,
            q_prime_2: rlwe.q,
            q2_bits: 14,
            t_exp_left: 3,
            t_exp_right: 2,
            query_bits: 14,
        };
        let client = IPIRClient::new(&rlwe, &ypir);
        let setup = client.generate_public_query_setup_simplepir_from_seed(setup_seed_bytes());

        let expected_record = EnhanceRecord([0x5a; RECORD_BYTES]);
        let target_position = RECORDS_PER_ROW as u64 + 3;
        let target_row = 1;
        let target_slot = 3;
        let mut database = vec![0u16; ypir.db_rows * ypir.db_cols];
        let record_start = target_row * ypir.db_cols + target_slot * RECORD_BYTES;
        for (dst, src) in database[record_start..record_start + RECORD_BYTES]
            .iter_mut()
            .zip(expected_record.as_bytes())
        {
            *dst = u16::from(*src);
        }

        let server = IPIRServer::new(ypir.clone(), database.into_iter(), false, true);
        let offline = server.perform_offline_precomputation_simplepir(&rlwe, &setup);
        let preprocessed = build_pack_preprocessed_blocks(&rlwe, &offline.crs_blocks).unwrap();
        let top_keys = TopKeyImages::build(&rlwe);
        let public_params = published_c1_rows(&preprocessed, rlwe.q);
        let published_c1 =
            recover_published_c1(&public_params, rlwe.d, ypir.db_cols / rlwe.d, rlwe.q);
        let query_session = QuerySession {
            generation: EnhanceGeneration {
                schema_version: SCHEMA_VERSION,
                protocol_revision: PROTOCOL_REVISION.to_string(),
                network: NETWORK.to_string(),
                pool: POOL.to_string(),
                anchor_height: 1,
                anchor_block_hash: "00".repeat(32),
                ironwood_tree_size: RECORDS_PER_ROW as u64 * 2,
                generation: 7,
                record_bytes: RECORD_BYTES as u32,
                records_per_row: RECORDS_PER_ROW as u32,
                row_bytes: ROW_BYTES as u32,
                shard_rows: SHARD_ROWS as u32,
                used_rows: 2,
                logical_rows: ypir.db_rows as u64,
                parameter_id: "known-answer".to_string(),
                setup_seed: ENHANCE_SETUP_SEED,
                public_params_epoch: String::new(),
                public_params_sha256: String::new(),
                shards: vec![],
            },
            ypir,
            client,
            setup,
            published_c1,
            epoch: [9; 8],
        };

        let (query, slot) = query_session.prepare_position(target_position).unwrap();
        assert_eq!((query.row(), slot), (target_row, target_slot));
        assert_eq!(
            u64::from_le_bytes(query.body()[..8].try_into().unwrap()),
            query_session.generation.generation
        );
        let keys_len = serialized_packing_keys_len(&rlwe);
        let keys = deserialize_packing_keys(&rlwe, &query.body()[8..8 + keys_len]).unwrap();
        let response_body = server
            .perform_full_online_computation_simplepir_measured(
                &rlwe,
                &query.body()[8 + keys_len..],
                &keys,
                &top_keys,
                &preprocessed,
            )
            .unwrap()
            .0;
        let mut response = query_session.generation.generation.to_le_bytes().to_vec();
        response.extend_from_slice(&query_session.epoch);
        response.extend_from_slice(&response_body);

        let row = query_session.decode(query, &response).unwrap();
        assert_eq!(record_in_row(&row, slot), expected_record);
    }
}
