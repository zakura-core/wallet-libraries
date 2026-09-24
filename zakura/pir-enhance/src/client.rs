use crate::types::EnhanceRecord;
use crate::types::{
    HEADER_BYTES, ITEM_SIZE_BITS, Manifest, QueryBinding, QueryShard, RECORD_BYTES, ROW_BYTES,
    ShardSession, parameters, setup_seed,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ipir_sp::modulus_switch::{published_c1_len, recover_published_c1, response_body_len};
use ipir_sp::serialize::serialize_packing_keys;
use ipir_sp::{IPIRClient, SimplePirProfile, YpirSchemeParams};
use rand::{Rng, rngs::OsRng};
use sha2::{Digest, Sha256};

/// Locally scanned chain state to which a manifest must be bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedAnchor {
    pub height: u64,
    /// Display order, as encoded in the manifest's hexadecimal hash.
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

/// Application selected bounds for one shard setup and the number of cached setups.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientResourceLimits {
    pub max_shard_rows: u64,
    pub max_cached_shards: usize,
}
impl ClientResourceLimits {
    pub const fn new(max_shard_rows: u64) -> Self {
        Self {
            max_shard_rows,
            max_cached_shards: 1,
        }
    }
    pub const fn with_cache(max_shard_rows: u64, max_cached_shards: usize) -> Self {
        Self {
            max_shard_rows,
            max_cached_shards,
        }
    }
}

/// Wallet-owned inputs. An application must recreate this after every manifest refresh.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerationAcceptance {
    pub network: String,
    pub activation_height: u64,
    pub anchor: AcceptedAnchor,
    pub limits: ClientResourceLimits,
}
impl GenerationAcceptance {
    pub fn new(
        network: impl Into<String>,
        activation_height: u64,
        anchor: AcceptedAnchor,
        limits: ClientResourceLimits,
    ) -> Self {
        Self {
            network: network.into(),
            activation_height,
            anchor,
            limits,
        }
    }
    pub fn validate(&self, manifest: &Manifest) -> Result<(), ClientError> {
        manifest.validate().map_err(ClientError::Generation)?;
        if self.network != "main" || manifest.network != self.network {
            return Err(ClientError::Generation(
                "v6 is only defined for mainnet".into(),
            ));
        }
        if manifest.anchor_height < self.activation_height {
            return Err(ClientError::Generation(
                "anchor precedes wallet activation".into(),
            ));
        }
        let hash: [u8; 32] = hex::decode(&manifest.anchor_block_hash)
            .map_err(|_| ClientError::Generation("invalid anchor hash".into()))?
            .try_into()
            .map_err(|_| ClientError::Generation("invalid anchor hash".into()))?;
        if manifest.anchor_height != self.anchor.height
            || hash != self.anchor.block_hash
            || manifest.coverage.records != self.anchor.ironwood_tree_size
        {
            return Err(ClientError::Generation(
                "manifest anchor is not accepted by the wallet".into(),
            ));
        }
        if self.limits.max_cached_shards == 0
            || manifest
                .coverage
                .shards
                .iter()
                .any(|s| s.logical_rows > self.limits.max_shard_rows)
        {
            return Err(ClientError::Generation(
                "shard setup exceeds application resource limits".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("row batch must not be empty")]
    EmptyBatch,
    #[error("row batch contains multiple transaction IDs")]
    MixedTxid,
    #[error("row batch spans multiple PIR rows")]
    CrossRowBatch,
    #[error("batch exceeds the local limit of {max_items} input items")]
    BatchTooLarge { max_items: usize },
    #[error("row query failed: {0}")]
    Row(#[source] std::sync::Arc<ClientError>),
    #[error("request cancelled")]
    Cancelled,
    #[error("transport error: {0}")]
    Transport(String),
    #[error("HTTP status {0}")]
    HttpStatus(u16),
    #[cfg(feature = "https-client")]
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid public parameters base64: {0}")]
    PublicParamsBase64(#[from] base64::DecodeError),
    #[error("incompatible manifest or session: {0}")]
    Generation(String),
    #[error("position {0} is outside advertised coverage")]
    OutsideCoverage(u64),
    #[error("PIR error: {0}")]
    Pir(String),
    #[error("malformed PIR response: {0}")]
    Response(String),
}
impl ClientError {
    pub fn http_status(&self) -> Option<u16> {
        match self {
            Self::HttpStatus(s) => Some(*s),
            Self::Row(e) => e.http_status(),
            _ => None,
        }
    }
}

pub struct QuerySession {
    binding: QueryBinding,
    shard: QueryShard,
    routes: Vec<crate::types::Route>,
    records: u64,
    params: YpirSchemeParams,
    client: IPIRClient,
    setup: ipir_sp::PublicQuerySetup,
    public: Vec<Vec<u64>>,
}
pub struct PreparedQuery {
    binding: QueryBinding,
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
    pub fn session_id(&self) -> [u8; 32] {
        self.binding.session_id
    }

    /// Only the routing binding changes; the content-bound PIR material is reused.
    pub fn rebind(&mut self, manifest: &Manifest) -> Result<(), ClientError> {
        manifest.validate().map_err(ClientError::Generation)?;
        if manifest
            .session_id(self.shard.id)
            .map_err(ClientError::Generation)?
            != self.binding.session_id
        {
            return Err(ClientError::Generation("session content changed".into()));
        }
        self.binding.generation = manifest.generation;
        self.binding.recovery_epoch = manifest.recovery_epoch;
        self.binding.anchor_hash = hex::decode(&manifest.anchor_block_hash)
            .map_err(|e| ClientError::Generation(e.to_string()))?
            .try_into()
            .map_err(|_| ClientError::Generation("anchor length".into()))?;
        self.routes = manifest
            .coverage
            .routes
            .iter()
            .filter(|r| r.domain_id == self.shard.id)
            .cloned()
            .collect();
        self.records = manifest.coverage.records;
        Ok(())
    }

    /// Caller must validate wallet acceptance before the expanded PIR setup is allocated.
    pub fn from_session(
        manifest: &Manifest,
        session: ShardSession,
        acceptance: &GenerationAcceptance,
    ) -> Result<Self, ClientError> {
        acceptance.validate(manifest)?;
        let shard = manifest
            .coverage
            .shards
            .iter()
            .find(|s| s.id == session.shard_id)
            .ok_or_else(|| ClientError::Generation("unknown shard".into()))?
            .clone();
        let reference = manifest
            .sessions
            .iter()
            .find(|s| s.shard_id == shard.id)
            .ok_or_else(|| ClientError::Generation("missing session reference".into()))?;
        if session.session_id
            != hex::encode(
                manifest
                    .session_id(shard.id)
                    .map_err(ClientError::Generation)?,
            )
            || session.params != parameters(shard.logical_rows).map_err(ClientError::Generation)?
        {
            return Err(ClientError::Generation(
                "session binding or parameters mismatch".into(),
            ));
        }
        let (rlwe, expected) = ipir_sp::params_for_simplepir_profile(
            shard.logical_rows,
            ITEM_SIZE_BITS,
            SimplePirProfile::P16Q48,
        )
        .map_err(|e| ClientError::Pir(e.to_string()))?;
        if session.params != expected || expected.db_cols % rlwe.d != 0 {
            return Err(ClientError::Generation("invalid PIR parameters".into()));
        }
        let blocks = expected.db_cols / rlwe.d;
        let expected_len = blocks
            .checked_mul(published_c1_len(rlwe.d, rlwe.q))
            .ok_or_else(|| ClientError::Generation("public material length overflow".into()))?;
        let encoded_len = expected_len
            .checked_add(2)
            .and_then(|n| n.checked_div(3))
            .and_then(|n| n.checked_mul(4))
            .ok_or_else(|| ClientError::Generation("base64 length overflow".into()))?;
        if session.public_params_base64.len() != encoded_len {
            return Err(ClientError::Generation(
                "public material base64 length mismatch".into(),
            ));
        }
        let bytes = BASE64_STANDARD.decode(session.public_params_base64)?;
        if bytes.len() != expected_len
            || hex::encode(Sha256::digest(&bytes)) != reference.public_params_sha256
        {
            return Err(ClientError::Generation(
                "public material digest or length mismatch".into(),
            ));
        }
        let hash = Sha256::digest(&bytes);
        let binding = QueryBinding {
            generation: manifest.generation,
            shard_id: shard.id,
            epoch: hash[..8].try_into().unwrap(),
            recovery_epoch: manifest.recovery_epoch,
            session_id: manifest
                .session_id(shard.id)
                .map_err(ClientError::Generation)?,
            request_id: [0; 16],
            anchor_hash: hex::decode(&manifest.anchor_block_hash)
                .map_err(|e| ClientError::Generation(e.to_string()))?
                .try_into()
                .map_err(|_| ClientError::Generation("anchor length".into()))?,
        };
        let client =
            IPIRClient::from_profile(shard.logical_rows, ITEM_SIZE_BITS, SimplePirProfile::P16Q48)
                .map_err(|e| ClientError::Pir(e.to_string()))?;
        let setup = client.generate_public_query_setup_simplepir_from_seed(setup_seed(shard.id));
        let public = recover_published_c1(&bytes, rlwe.d, blocks, rlwe.q);
        Ok(Self {
            binding,
            routes: manifest
                .coverage
                .routes
                .iter()
                .filter(|r| r.domain_id == shard.id)
                .cloned()
                .collect(),
            records: manifest.coverage.records,
            shard,
            params: expected,
            client,
            setup,
            public,
        })
    }
    pub fn shard_id(&self) -> u64 {
        self.shard.id
    }
    pub fn manifest_generation(&self) -> u64 {
        self.binding.generation
    }
    pub fn prepare_position(&self, position: u64) -> Result<(PreparedQuery, usize), ClientError> {
        if position >= self.records {
            return Err(ClientError::OutsideCoverage(position));
        }
        let global = position / 33;
        let route = self
            .routes
            .iter()
            .find(|r| r.global_start <= global && global < r.global_end)
            .ok_or(ClientError::OutsideCoverage(position))?;
        let row = (route.local_start + global - route.global_start) as usize;
        let slot = (position % 33) as usize;
        Ok((self.prepare_row(row)?, slot))
    }
    pub fn prepare_dummy(&self) -> Result<PreparedQuery, ClientError> {
        self.prepare_row(OsRng.gen_range(0..self.params.db_rows))
    }
    pub fn prepare_row(&self, row: usize) -> Result<PreparedQuery, ClientError> {
        if row >= self.params.db_rows {
            return Err(ClientError::OutsideCoverage(row as u64));
        }
        let (query, keys, seed) = self.client.generate_fresh_query_simplepir(&self.setup, row);
        let mut binding = self.binding;
        binding.request_id = OsRng.r#gen();
        let mut body = binding.encode();
        body.extend(
            serialize_packing_keys(self.client.rlwe_params(), &keys)
                .map_err(|e| ClientError::Pir(e.to_string()))?,
        );
        body.extend(query.to_switched_bytes(self.client.rlwe_params().q, self.params.query_bits));
        Ok(PreparedQuery {
            binding,
            row,
            body,
            seed,
        })
    }
    pub fn decode(&self, query: PreparedQuery, response: &[u8]) -> Result<Vec<u8>, ClientError> {
        let binding = QueryBinding::decode(response).map_err(ClientError::Response)?;
        let d = self.client.rlwe_params().d;
        if !self.params.db_cols.is_multiple_of(d) {
            return Err(ClientError::Response("invalid PIR dimensions".into()));
        }
        let size = (self.params.db_cols / d)
            .checked_mul(response_body_len(d, self.params.q_prime_1))
            .and_then(|n| n.checked_add(HEADER_BYTES))
            .ok_or_else(|| ClientError::Response("response length overflow".into()))?;
        if binding != query.binding
            || binding.session_id != self.binding.session_id
            || binding.anchor_hash != self.binding.anchor_hash
            || response.len() != size
        {
            return Err(ClientError::Response(
                "PIR response binding or length mismatch".into(),
            ));
        }
        let decoded = self.client.decode_response_simplepir(
            query.seed,
            &self.public,
            &response[HEADER_BYTES..],
        );
        decoded
            .get(..ROW_BYTES)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| ClientError::Response("short row".into()))
    }
}

pub fn record_in_row(row: &[u8], slot: usize) -> Result<EnhanceRecord, ClientError> {
    let start = slot
        .checked_mul(RECORD_BYTES)
        .ok_or_else(|| ClientError::Response("record offset overflow".into()))?;
    let end = start
        .checked_add(RECORD_BYTES)
        .ok_or_else(|| ClientError::Response("record offset overflow".into()))?;
    let bytes: [u8; RECORD_BYTES] = row
        .get(start..end)
        .ok_or_else(|| ClientError::Response("record slot outside decoded row".into()))?
        .try_into()
        .expect("fixed record length");
    EnhanceRecord::from_bytes(bytes).map_err(|e| ClientError::Response(e.to_string()))
}

#[cfg(feature = "https-client")]
pub struct EnhancePirClient {
    http: crate::transport::ReqwestTransport,
    inner: crate::transport::Client,
}
#[cfg(feature = "https-client")]
pub struct PendingEnhancePirClient {
    http: crate::transport::ReqwestTransport,
    inner: crate::transport::PendingClient,
}
#[cfg(feature = "https-client")]
impl PendingEnhancePirClient {
    pub fn manifest(&self) -> &Manifest {
        self.inner.manifest()
    }
    pub fn generation(&self) -> &Manifest {
        self.inner.manifest()
    }
    pub async fn connect(
        self,
        acceptance: &GenerationAcceptance,
    ) -> Result<EnhancePirClient, ClientError> {
        Ok(EnhancePirClient {
            http: self.http,
            inner: self.inner.accept(acceptance)?,
        })
    }
}
#[cfg(feature = "https-client")]
impl EnhancePirClient {
    pub fn refresh_due(&self) -> bool {
        self.inner.refresh_due()
    }

    pub async fn fetch_routing(&self) -> Result<crate::transport::PendingClient, ClientError> {
        crate::transport::PendingClient::fetch(&self.http, &self.inner.base_url).await
    }

    pub fn accept_routing(
        &mut self,
        pending: crate::transport::PendingClient,
        acceptance: &GenerationAcceptance,
    ) -> Result<(), ClientError> {
        self.inner.accept_routing(pending, acceptance)
    }

    pub async fn query_positions_with_cover(
        &mut self,
        positions: &[u64],
        birthday_first_position: u64,
    ) -> Result<Vec<EnhanceRecord>, ClientError> {
        self.inner
            .query_positions_with_cover(&self.http, positions, birthday_first_position)
            .await
    }

    pub async fn fetch_session(base_url: &str) -> Result<PendingEnhancePirClient, ClientError> {
        let http = crate::transport::ReqwestTransport::new()?;
        let inner = crate::transport::PendingClient::fetch(&http, base_url).await?;
        Ok(PendingEnhancePirClient { http, inner })
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
    pub fn manifest(&self) -> &Manifest {
        self.inner.manifest()
    }
    pub fn generation(&self) -> &Manifest {
        self.inner.manifest()
    }
    pub fn query_batch(
        &mut self,
        positions: impl IntoIterator<Item = u64>,
    ) -> Result<impl futures_util::Stream<Item = crate::transport::PositionResult> + '_, ClientError>
    {
        self.inner.query_batch(&self.http, positions)
    }
    pub fn query_batch_with_limit(
        &mut self,
        positions: impl IntoIterator<Item = u64>,
        max_items: usize,
    ) -> Result<impl futures_util::Stream<Item = crate::transport::PositionResult> + '_, ClientError>
    {
        self.inner
            .query_batch_with_limit(&self.http, positions, max_items)
    }
    /// Queries one row for one transaction, preserving captured wallet identities.
    #[cfg(feature = "wallet")]
    pub async fn query_row_requests(
        &mut self,
        requests: &[zcash_client_backend::data_api::enhance_pir::EnhancePirRequest],
    ) -> Result<crate::wallet::RowQueryResult, ClientError> {
        self.inner.query_row_requests(&self.http, requests).await
    }

    pub async fn query_position(&mut self, position: u64) -> Result<EnhanceRecord, ClientError> {
        use futures_util::StreamExt;
        let stream = self.query_batch([position])?;
        futures_util::pin_mut!(stream);
        stream.next().await.expect("one position").record
    }
    pub async fn query_dummy(&mut self, shard_id: u64) -> Result<(), ClientError> {
        self.inner.query_dummy(&self.http, shard_id).await
    }
}
