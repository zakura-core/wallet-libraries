use crate::types::EnhanceRecord;
use crate::types::{
    HEADER_BYTES, Manifest, QueryBinding, QueryShard, RECORD_BYTES, ROW_BYTES, ShardSession,
    parameters, response_len, session_public_len,
};
#[cfg(not(feature = "native-reinspiring"))]
use crate::types::{ITEM_SIZE_BITS, setup_seed};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ipir_sp::YpirSchemeParams;
#[cfg(not(feature = "native-reinspiring"))]
use ipir_sp::modulus_switch::recover_published_c1;
#[cfg(not(feature = "native-reinspiring"))]
use ipir_sp::serialize::serialize_packing_keys;
#[cfg(not(feature = "native-reinspiring"))]
use ipir_sp::{IPIRClient, SimplePirProfile};
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
                "v7 is only defined for mainnet".into(),
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
    #[cfg(not(feature = "native-reinspiring"))]
    client: IPIRClient,
    #[cfg(not(feature = "native-reinspiring"))]
    setup: ipir_sp::PublicQuerySetup,
    #[cfg(not(feature = "native-reinspiring"))]
    public: Vec<Vec<u64>>,
    /// Published two-mask material plus the shard's expanded query masks.
    #[cfg(feature = "native-reinspiring")]
    native: crate::native::NativeSession,
}
pub struct PreparedQuery {
    binding: QueryBinding,
    row: usize,
    body: Vec<u8>,
    #[cfg(not(feature = "native-reinspiring"))]
    seed: ipir_sp::IPIRSeed,
    /// Fresh per query; never reused across requests.
    #[cfg(feature = "native-reinspiring")]
    secret: reinspiring::native::NativeSecret,
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

    /// Reuse content-bound PIR material after independently accepting the new anchor.
    /// Returns an error without changing the session if wallet acceptance fails or
    /// the manifest requires different session material.
    pub fn rebind(
        &mut self,
        manifest: &Manifest,
        acceptance: &GenerationAcceptance,
    ) -> Result<(), ClientError> {
        acceptance.validate(manifest)?;
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
        let expected = parameters(shard.logical_rows).map_err(ClientError::Generation)?;
        if session.params != expected || !expected.db_cols.is_multiple_of(expected.poly_len) {
            return Err(ClientError::Generation("invalid PIR parameters".into()));
        }
        let expected_len =
            session_public_len(shard.logical_rows).map_err(ClientError::Generation)?;
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
        #[cfg(not(feature = "native-reinspiring"))]
        let (client, setup, public) = {
            let (rlwe, _) = ipir_sp::params_for_simplepir_profile(
                shard.logical_rows,
                ITEM_SIZE_BITS,
                SimplePirProfile::P16Q48,
            )
            .map_err(|e| ClientError::Pir(e.to_string()))?;
            let blocks = expected.db_cols / rlwe.d;
            let client = IPIRClient::from_profile(
                shard.logical_rows,
                ITEM_SIZE_BITS,
                SimplePirProfile::P16Q48,
            )
            .map_err(|e| ClientError::Pir(e.to_string()))?;
            let setup =
                client.generate_public_query_setup_simplepir_from_seed(setup_seed(shard.id));
            let public = recover_published_c1(&bytes, rlwe.d, blocks, rlwe.q);
            (client, setup, public)
        };
        #[cfg(feature = "native-reinspiring")]
        let native = crate::native::NativeSession::new(shard.id, expected.db_rows, bytes)
            .map_err(ClientError::Generation)?;
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
            #[cfg(not(feature = "native-reinspiring"))]
            client,
            #[cfg(not(feature = "native-reinspiring"))]
            setup,
            #[cfg(not(feature = "native-reinspiring"))]
            public,
            #[cfg(feature = "native-reinspiring")]
            native,
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
        let mut binding = self.binding;
        binding.request_id = OsRng.r#gen();
        let mut body = binding.encode();
        #[cfg(feature = "native-reinspiring")]
        {
            let (secret, payload) = self.native.prepare(row).map_err(ClientError::Pir)?;
            body.extend(payload);
            Ok(PreparedQuery {
                binding,
                row,
                body,
                secret,
            })
        }
        #[cfg(not(feature = "native-reinspiring"))]
        {
            let (query, keys, seed) = self.client.generate_fresh_query_simplepir(&self.setup, row);
            body.extend(
                serialize_packing_keys(self.client.rlwe_params(), &keys)
                    .map_err(|e| ClientError::Pir(e.to_string()))?,
            );
            body.extend(
                query.to_switched_bytes(self.client.rlwe_params().q, self.params.query_bits),
            );
            Ok(PreparedQuery {
                binding,
                row,
                body,
                seed,
            })
        }
    }
    pub fn decode(&self, query: PreparedQuery, response: &[u8]) -> Result<Vec<u8>, ClientError> {
        let binding = QueryBinding::decode(response).map_err(ClientError::Response)?;
        let size = response_len(self.shard.logical_rows).map_err(ClientError::Response)?;
        if binding != query.binding
            || binding.session_id != self.binding.session_id
            || binding.anchor_hash != self.binding.anchor_hash
            || response.len() != size
        {
            return Err(ClientError::Response(
                "PIR response binding or length mismatch".into(),
            ));
        }
        #[cfg(feature = "native-reinspiring")]
        let decoded = self
            .native
            .decode(&query.secret, &response[HEADER_BYTES..])
            .map_err(ClientError::Pir)?;
        #[cfg(not(feature = "native-reinspiring"))]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::synthetic_manifest;
    use crate::types::{RECORDS_PER_ROW, parameter_id, session_public_len};

    /// A session over zero public material for a manifest whose first shard
    /// spans `logical_rows` rows.
    pub(crate) fn zero_session(logical_rows: u64) -> QuerySession {
        let records = logical_rows * RECORDS_PER_ROW as u64;
        let mut manifest = synthetic_manifest(
            records,
            |shard| {
                let public = vec![0u8; session_public_len(shard.logical_rows).unwrap()];
                hex::encode(Sha256::digest(&public))
            },
            &"00".repeat(32),
        );
        manifest.anchor_height = 3_428_143;
        manifest.anchor_block_hash = "42".repeat(32);
        let shard = &manifest.coverage.shards[0];
        assert_eq!(shard.logical_rows, logical_rows);
        let public = vec![0u8; session_public_len(logical_rows).unwrap()];
        let session = ShardSession {
            session_id: hex::encode(manifest.session_id(0).unwrap()),
            generation: manifest.generation,
            shard_id: 0,
            params: parameters(logical_rows).unwrap(),
            public_params_base64: BASE64_STANDARD.encode(public),
        };
        let acceptance = GenerationAcceptance::new(
            "main",
            3_428_143,
            AcceptedAnchor::new(3_428_143, [0x42; 32], records),
            ClientResourceLimits::new(32_768),
        );
        QuerySession::from_session(&manifest, session, &acceptance).unwrap()
    }

    /// The v7 wire contract must not move when the native feature is off:
    /// protocol identifier, parameter identity and exact request length.
    #[cfg(not(feature = "native-reinspiring"))]
    #[test]
    fn v7_wire_contract_is_pinned() {
        assert_eq!(crate::PROTOCOL_REVISION, "ironwood-enhance-pir-v7");
        let id = parameter_id(32768).unwrap();
        println!("v7 parameter_id(32768) = {id}");
        let session = zero_session(32768);
        let query = session.prepare_row(7).unwrap();
        println!("v7 request length (32768 rows) = {}", query.body().len());
        println!(
            "v7 session public length (32768 rows) = {}",
            session_public_len(32768).unwrap()
        );
        println!(
            "v7 response length (32768 rows) = {}",
            crate::types::response_len(32768).unwrap()
        );
        assert_eq!(
            id,
            "ironwood-enhance-pir-v7/b731a410f932c354abd6a01a05b32865d327b287e021a8d9769190d28c08290c"
        );
        assert_eq!(query.body().len(), 282_740);
        assert_eq!(session_public_len(32768).unwrap(), 86_016);
        assert_eq!(crate::types::response_len(32768).unwrap(), 30_836);
        assert_eq!(session.params.query_bits, 48);
    }

    /// The native profile's identifiers and exact lengths, so a server and
    /// wallet built from different trees can be compared without a network.
    #[cfg(feature = "native-reinspiring")]
    #[test]
    fn v9_native_wire_contract_is_pinned() {
        use crate::native::{COLS, KEY_BYTES, public_len};
        assert_eq!(
            crate::PROTOCOL_REVISION,
            "ironwood-enhance-pir-v9-native-two-mask-m29"
        );
        let id = parameter_id(32768).unwrap();
        println!("v9 parameter_id(32768) = {id}");
        assert!(id.starts_with("ironwood-enhance-pir-v9-native-two-mask-m29/"));
        let session = zero_session(32768);
        assert_eq!(session.params.query_bits, 49);
        assert_eq!(session.params.q_prime_1, 1 << 22);
        assert_eq!(session_public_len(32768).unwrap(), public_len(COLS));
        assert_eq!(session_public_len(32768).unwrap(), 89_088);
        assert_eq!(KEY_BYTES, 27_648);
        let query = session.prepare_row(7).unwrap();
        assert_eq!(
            query.body().len(),
            crate::types::request_len(32768).unwrap()
        );
        assert_eq!(
            query.body().len(),
            HEADER_BYTES + KEY_BYTES + (32768usize * 49).div_ceil(8)
        );
        println!("v9 request length (32768 rows) = {}", query.body().len());
        let response_len = crate::types::response_len(32768).unwrap();
        assert_eq!(response_len, HEADER_BYTES + (COLS * 22).div_ceil(8));
        println!("v9 response length = {response_len}");
        // An all-zero database decodes to an all-zero row under zero masks.
        let mut response = query.body()[..HEADER_BYTES].to_vec();
        response.resize(response_len, 0);
        let row = session.decode(query, &response).unwrap();
        assert_eq!(row, vec![0; ROW_BYTES]);
    }
}
