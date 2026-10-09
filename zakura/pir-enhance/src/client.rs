use crate::types::EnhanceRecord;
use crate::types::{
    HEADER_BYTES, Manifest, QueryBinding, QueryShard, RECORD_BYTES, ROW_BYTES, ShardSession,
    parameters, response_len, session_public_len,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ipir_sp::YpirSchemeParams;
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
                "Enhance PIR is only defined for mainnet".into(),
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
    /// Published two-mask material plus the shard's expanded query masks.
    native: crate::native::NativeSession,
}
pub struct PreparedQuery {
    binding: QueryBinding,
    row: usize,
    body: Vec<u8>,
    /// Fresh per query; never reused across requests.
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
        // Queries select over only the rows the domain's units can hold, under
        // the leading full-shape masks; the count is bound by the session ID.
        let query_rows = shard
            .query_rows(manifest.geometry)
            .map_err(ClientError::Generation)?;
        let native = crate::native::NativeSession::new(shard.id, query_rows as usize, bytes)
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
    /// Rows every query to this session selects over; see
    /// [`QueryShard::query_rows`].
    pub fn query_rows(&self) -> usize {
        self.native.rows()
    }
    /// A cover query, the same length as every real one to this session.
    pub fn prepare_dummy(&self) -> Result<PreparedQuery, ClientError> {
        self.prepare_row(OsRng.gen_range(0..self.query_rows()))
    }
    pub fn prepare_row(&self, row: usize) -> Result<PreparedQuery, ClientError> {
        if row >= self.query_rows() {
            return Err(ClientError::OutsideCoverage(row as u64));
        }
        let mut binding = self.binding;
        binding.request_id = OsRng.r#gen();
        let mut body = binding.encode();
        let (secret, payload) = self.native.prepare(row).map_err(ClientError::Pir)?;
        body.extend(payload);
        Ok(PreparedQuery {
            binding,
            row,
            body,
            secret,
        })
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
        let decoded = self
            .native
            .decode(&query.secret, &response[HEADER_BYTES..])
            .map_err(ClientError::Pir)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::synthetic_manifest;
    use crate::types::{RECORDS_PER_ROW, parameter_id, session_public_len};

    /// A session over zero public material for a manifest whose first shard
    /// spans `logical_rows` rows.
    pub(crate) fn zero_session(logical_rows: u64) -> QuerySession {
        let session = growing_session(logical_rows * RECORDS_PER_ROW as u64);
        assert_eq!(session.shard.logical_rows, logical_rows);
        session
    }

    /// A session over zero public material for a manifest whose first shard
    /// holds `records`.
    fn growing_session(records: u64) -> QuerySession {
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
        let logical_rows = manifest.coverage.shards[0].logical_rows;
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

    /// A growing domain's queries, real and cover, select over only the
    /// blocks its data can occupy, all at one length, and never past them.
    #[test]
    fn growing_domain_queries_share_one_prefix_length() {
        use crate::native::KEY_BYTES;
        let session = growing_session(18_313 * RECORDS_PER_ROW as u64 - 5);
        assert_eq!(session.shard.logical_rows, 32768);
        assert_eq!(session.query_rows(), 18_432);
        let len = crate::types::request_len(18_432).unwrap();
        assert_eq!(len, HEADER_BYTES + KEY_BYTES + 112_896);
        for row in [0, 1, 18_312, 18_431] {
            assert_eq!(session.prepare_row(row).unwrap().body().len(), len);
        }
        for _ in 0..4 {
            assert_eq!(session.prepare_dummy().unwrap().body().len(), len);
        }
        let (query, _) = session.prepare_position(18_313 * 33 - 6).unwrap();
        assert_eq!(query.body().len(), len);
        assert!(matches!(
            session.prepare_row(18_432),
            Err(ClientError::OutsideCoverage(18_432))
        ));
    }

    /// The native profile's identifiers and exact lengths, so a server and
    /// wallet built from different trees can be compared without a network.
    #[test]
    fn v9_native_wire_contract_is_pinned() {
        use crate::native::{COLS, KEY_BYTES, public_len};
        use crate::types::unit_parameter_id;
        assert_eq!(
            crate::PROTOCOL_REVISION,
            "ironwood-enhance-pir-v9-native-two-mask-m29"
        );
        let id = parameter_id(32768).unwrap();
        println!("v9 parameter_id(32768) = {id}");
        // Frozen against wallet-pir's server crate; both bind every native
        // packing parameter into the identity.
        assert_eq!(
            id,
            "ironwood-enhance-pir-v9-native-two-mask-m29/04612c53c821f0c235e8dd44036ac43cbf605bebd8012742a3d71bda18ec13f6"
        );
        assert_eq!(
            unit_parameter_id(8192).unwrap(),
            "ironwood-enhance-pir-v9-native-two-mask-m29/unit/0ce2b7a68ec0ea3bc9cbee600eb8a300bb2f06d121a2cc9caca7f6673537e070"
        );
        assert_eq!(
            unit_parameter_id(4096).unwrap(),
            "ironwood-enhance-pir-v9-native-two-mask-m29/unit/ac16d8451fb2cb1c523ec4b6a8ad17b20ba67c58b367b2ae40ba1783ddfc29f1"
        );
        assert_eq!(
            unit_parameter_id(2048).unwrap(),
            "ironwood-enhance-pir-v9-native-two-mask-m29/unit/2e03e17451928e9498fa614db9077f27709feda2d5a45c40ef2c4f0643dc478a"
        );
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
