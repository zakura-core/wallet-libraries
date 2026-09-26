//! Public v7 shard geometry and wire representations.
pub use zakura_pir_enhance_types::{
    EnhanceRecord, EnhanceRecordParts, EnhanceTransactionMetadata, FLAG_HAS_TRANSPARENT_INPUTS,
    FLAG_HAS_TRANSPARENT_OUTPUTS, InvalidEnhanceRecord, KNOWN_FLAGS, RECORD_BYTES,
    RECORD_CV_NET_OFFSET, RECORD_ENC_CIPHERTEXT_SUFFIX_OFFSET, RECORD_FLAGS_OFFSET,
    RECORD_OUT_CIPHERTEXT_OFFSET,
};

pub const POOL: &str = "ironwood";
pub const RECORDS_PER_ROW: usize = 33;
pub const ROW_BYTES: usize = RECORD_BYTES * RECORDS_PER_ROW;
pub const ITEM_SIZE_BITS: u64 = (ROW_BYTES * 8) as u64;

/// The same public setup seed used by the v4 server.
pub const ENHANCE_SETUP_SEED: u64 = 0xa4d6_9bc2_317e_085f;

pub fn setup_seed_bytes() -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&ENHANCE_SETUP_SEED.to_le_bytes());
    bytes
}
// Schema-11 records, v7 routing and session identities.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Frozen schema-11 wallet limit, independent of worker placement density.
pub const MAX_QUERY_SHARDS: u64 = 24;
pub const SCHEMA_VERSION: u16 = 11;
#[cfg(not(feature = "native-reinspiring"))]
pub const PROTOCOL_REVISION: &str = "ironwood-enhance-pir-v7";
#[cfg(feature = "native-reinspiring")]
pub const PROTOCOL_REVISION: &str = "ironwood-enhance-pir-v9-native-two-mask-m29";
pub const RETAINED_GENERATIONS: usize = 5;
pub const HEADER_BYTES: usize = 116;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Geometry {
    pub max_shard_rows: u64,
    pub min_shard_rows: u64,
    pub max_mutable_unit_rows: u64,
    pub min_mutable_unit_rows: u64,
}

impl Default for Geometry {
    fn default() -> Self {
        Self {
            max_shard_rows: 32768,
            min_shard_rows: 4096,
            max_mutable_unit_rows: 8192,
            min_mutable_unit_rows: 2048,
        }
    }
}

impl Geometry {
    /// Only the geometry family exercised by the qualification suite is accepted.
    pub fn validate(self) -> Result<(), String> {
        if self.max_shard_rows != 32768
            || self.min_shard_rows != 4096
            || self.max_mutable_unit_rows != 8192
            || self.min_mutable_unit_rows != 2048
        {
            return Err("unqualified geometry".into());
        }
        Ok(())
    }

    pub fn logical_rows(self, records: u64) -> Result<u64, String> {
        self.validate()?;
        if records == 0 || records > self.max_shard_rows * RECORDS_PER_ROW as u64 {
            return Err("empty or oversized query shard".into());
        }
        Ok(records
            .div_ceil(RECORDS_PER_ROW as u64)
            .max(self.min_shard_rows)
            .next_power_of_two())
    }

    pub fn units(self, records: u64) -> Result<Vec<MutableUnit>, String> {
        self.logical_rows(records)?;
        let used = records.div_ceil(RECORDS_PER_ROW as u64);
        let mut units = Vec::new();
        let mut start = 0;
        while start < used {
            let rows = (used - start).min(self.max_mutable_unit_rows);
            let allocated = rows.max(self.min_mutable_unit_rows).next_power_of_two();
            units.push(MutableUnit {
                local_row_start: start,
                used_rows: rows,
                allocated_rows: allocated,
            });
            start += rows;
        }
        Ok(units)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MutableUnit {
    pub local_row_start: u64,
    pub used_rows: u64,
    pub allocated_rows: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ShardState {
    Growing,
    Provisional,
    Sealed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct QueryShard {
    pub id: u64,
    pub global_row_start: u64,
    pub records: u64,
    pub logical_rows: u64,
    pub state: ShardState,
    pub units: Vec<MutableUnit>,
}

impl QueryShard {
    pub fn locate(&self, position: u64) -> Option<(usize, usize)> {
        let first = self.global_row_start.checked_mul(RECORDS_PER_ROW as u64)?;
        let relative = position.checked_sub(first)?;
        (relative < self.records).then_some((
            (relative / RECORDS_PER_ROW as u64) as usize,
            (relative % RECORDS_PER_ROW as u64) as usize,
        ))
    }
}

/// Persisted fixed-range identities; confirmation is decided from canonical blocks.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Lifecycle {
    pub identities: Vec<u64>,
    pub next_id: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub global_start: u64,
    pub global_end: u64,
    pub domain_id: u64,
    pub local_start: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    pub records: u64,
    pub shards: Vec<QueryShard>,
    pub routes: Vec<Route>,
}

impl QueryShard {
    pub fn composed(&self) -> bool {
        self.id > 0
            && self.records.div_ceil(RECORDS_PER_ROW as u64) < Geometry::default().min_shard_rows
    }

    pub fn expected_units(&self, geometry: Geometry) -> Result<Vec<MutableUnit>, String> {
        let mut units = geometry.units(self.records)?;
        if self.composed() {
            units.push(MutableUnit {
                local_row_start: geometry.min_shard_rows,
                used_rows: geometry.min_shard_rows,
                allocated_rows: geometry.min_shard_rows,
            });
        }
        Ok(units)
    }

    pub fn expected_logical_rows(&self, geometry: Geometry) -> Result<u64, String> {
        if self.composed() {
            Ok(2 * geometry.min_shard_rows)
        } else {
            geometry.logical_rows(self.records)
        }
    }
}

impl Lifecycle {
    /// Build one complete fixed-range view. Full ranges are provisional until
    /// their completing block is confirmed by the canonical controller.
    pub fn coverage(&mut self, records: u64, geometry: Geometry) -> Result<Coverage, String> {
        geometry.validate()?;
        let span = geometry.max_shard_rows * RECORDS_PER_ROW as u64;
        let count = records.div_ceil(span);
        if count == 0 || count > MAX_QUERY_SHARDS {
            return Err("unsupported coverage".into());
        }
        if self.next_id > MAX_QUERY_SHARDS {
            return Err("invalid persisted identity ceiling".into());
        }
        self.next_id = self.next_id.max(count);
        self.identities = (0..self.next_id).collect();
        let mut shards = Vec::new();
        let mut routes = Vec::new();
        for id in 0..count {
            let n = (records - id * span).min(span);
            let mut shard = QueryShard {
                id,
                global_row_start: id * geometry.max_shard_rows,
                records: n,
                logical_rows: 0,
                state: if n == span {
                    ShardState::Provisional
                } else {
                    ShardState::Growing
                },
                units: Vec::new(),
            };
            shard.logical_rows = shard.expected_logical_rows(geometry)?;
            shard.units = shard.expected_units(geometry)?;
            if shard.composed() {
                let previous: &mut Route = routes.last_mut().ok_or("missing predecessor")?;
                previous.global_end -= geometry.min_shard_rows;
                routes.push(Route {
                    global_start: shard.global_row_start - geometry.min_shard_rows,
                    global_end: shard.global_row_start,
                    domain_id: id,
                    local_start: geometry.min_shard_rows,
                });
            }
            routes.push(Route {
                global_start: shard.global_row_start,
                global_end: shard.global_row_start + n.div_ceil(RECORDS_PER_ROW as u64),
                domain_id: id,
                local_start: 0,
            });
            shards.push(shard);
        }
        Ok(Coverage {
            records,
            shards,
            routes,
        })
    }
}

impl Coverage {
    pub fn validate(&self, geometry: Geometry) -> Result<(), String> {
        let expected = Lifecycle::default().coverage(self.records, geometry)?;
        if self.routes != expected.routes || self.shards.len() != expected.shards.len() {
            return Err("noncanonical routing coverage".into());
        }
        for (actual, mut expected) in self.shards.iter().zip(expected.shards) {
            if actual.state == ShardState::Sealed && expected.state == ShardState::Provisional {
                expected.state = ShardState::Sealed;
            }
            if actual != &expected {
                return Err("invalid fixed domain geometry".into());
            }
        }
        Ok(())
    }

    pub fn locate(&self, position: u64) -> Option<(&QueryShard, usize, usize)> {
        if position >= self.records {
            return None;
        }
        let row = position / RECORDS_PER_ROW as u64;
        let route = self
            .routes
            .iter()
            .find(|r| r.global_start <= row && row < r.global_end)?;
        let shard = self.shards.iter().find(|s| s.id == route.domain_id)?;
        Some((
            shard,
            (route.local_start + row - route.global_start) as usize,
            (position % RECORDS_PER_ROW as u64) as usize,
        ))
    }
}

/// Canonical JSON u64 encoding avoids loss through JavaScript numbers.
pub mod decimal_u64 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(n: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&n.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        let text = String::deserialize(d)?;
        let n: u64 = text.parse().map_err(serde::de::Error::custom)?;
        if n.to_string() != text {
            return Err(serde::de::Error::custom("noncanonical u64"));
        }
        Ok(n)
    }
}

/// All fields participate in cache identity, including the shard-local setup slice.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnitIdentity {
    #[serde(with = "decimal_u64")]
    pub recovery_epoch: u64,
    pub table: String,
    pub shard_id: u64,
    pub local_row_start: u64,
    pub allocated_rows: u64,
    pub setup_sha256: String,
    pub parameter_id: String,
    pub content_sha256: String,
}

impl UnitIdentity {
    pub fn digest(&self) -> String {
        digest(self)
    }
}

pub fn digest(value: &impl Serialize) -> String {
    hex::encode(Sha256::digest(
        serde_json::to_vec(value).expect("serializable protocol value"),
    ))
}

/// Deterministic public setup domain separation; this is public material, not a key.
pub fn setup_seed(shard_id: u64) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"ironwood-enhance-pir-v4/main/ironwood/setup\0");
    hash.update(setup_seed_bytes());
    hash.update(shard_id.to_le_bytes());
    hash.finalize().into()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryBinding {
    /// The routing revision, not the lifetime of the session material.
    pub generation: u64,
    pub shard_id: u64,
    pub epoch: [u8; 8],
    pub recovery_epoch: u64,
    pub session_id: [u8; 32],
    pub request_id: [u8; 16],
    pub anchor_hash: [u8; 32],
}

impl QueryBinding {
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = b"EPQ7".to_vec();
        bytes.extend(self.generation.to_le_bytes());
        bytes.extend(self.shard_id.to_le_bytes());
        bytes.extend(self.epoch);
        bytes.extend(self.recovery_epoch.to_le_bytes());
        bytes.extend(self.session_id);
        bytes.extend(self.request_id);
        bytes.extend(self.anchor_hash);
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < HEADER_BYTES || &bytes[..4] != b"EPQ7" {
            return Err("invalid v7 query framing".into());
        }
        Ok(Self {
            generation: u64::from_le_bytes(bytes[4..12].try_into().unwrap()),
            shard_id: u64::from_le_bytes(bytes[12..20].try_into().unwrap()),
            epoch: bytes[20..28].try_into().unwrap(),
            recovery_epoch: u64::from_le_bytes(bytes[28..36].try_into().unwrap()),
            session_id: bytes[36..68].try_into().unwrap(),
            request_id: bytes[68..84].try_into().unwrap(),
            anchor_hash: bytes[84..116].try_into().unwrap(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionRef {
    pub shard_id: u64,
    pub public_params_sha256: String,
    pub parameter_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    #[serde(with = "decimal_u64")]
    pub recovery_epoch: u64,
    pub placement_revision: u64,
    pub domain_recovery_epochs: std::collections::BTreeMap<u64, String>,
    pub schema_version: u16,
    pub protocol_revision: String,
    pub network: String,
    pub pool: String,
    pub generation: u64,
    pub anchor_height: u64,
    pub anchor_block_hash: String,
    pub geometry: Geometry,
    pub coverage: Coverage,
    pub sessions: Vec<SessionRef>,
    pub unit_identities: std::collections::BTreeMap<u64, Vec<UnitIdentity>>,
}

impl Manifest {
    /// Hash ordered padded unit commitments, geometry and packing material.
    /// Unit hashes commit to every stored byte; gaps are prescribed zero padding.
    pub fn session_id(&self, id: u64) -> Result<[u8; 32], String> {
        let shard = self
            .coverage
            .shards
            .iter()
            .find(|s| s.id == id)
            .ok_or("unknown domain")?;
        let reference = self
            .sessions
            .iter()
            .find(|s| s.shard_id == id)
            .ok_or("missing session")?;
        let epoch = self
            .domain_recovery_epochs
            .get(&id)
            .ok_or("missing domain epoch")?;
        let number: u64 = epoch.parse().map_err(|_| "invalid domain epoch")?;
        if number.to_string() != *epoch || number > self.recovery_epoch {
            return Err("invalid domain epoch".into());
        }
        let units = self.unit_identities.get(&id).ok_or("missing units")?;
        let mut hash = Sha256::new();
        hash.update(b"enhance-pir/v7/session\0");
        hash.update((PROTOCOL_REVISION.len() as u64).to_le_bytes());
        hash.update(PROTOCOL_REVISION.as_bytes());
        for n in [
            id,
            number,
            shard.logical_rows,
            shard.records,
            units.len() as u64,
        ] {
            hash.update(n.to_le_bytes());
        }
        for unit in units {
            hash.update(unit.recovery_epoch.to_le_bytes());
            hash.update(unit.local_row_start.to_le_bytes());
            hash.update(unit.allocated_rows.to_le_bytes());
            for value in [&unit.content_sha256, &unit.setup_sha256, &unit.parameter_id] {
                hash.update((value.len() as u64).to_le_bytes());
                hash.update(value.as_bytes());
            }
        }
        for value in [&reference.parameter_id, &reference.public_params_sha256] {
            hash.update((value.len() as u64).to_le_bytes());
            hash.update(value.as_bytes());
        }
        Ok(hash.finalize().into())
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != SCHEMA_VERSION
            || self.protocol_revision != PROTOCOL_REVISION
            || self.network != "main"
            || self.pool != "ironwood"
            || self.generation == 0
            || self.anchor_block_hash.len() != 64
            || !canonical_hash(&self.anchor_block_hash)
        {
            return Err("incompatible manifest".into());
        }
        self.coverage.validate(self.geometry)?;
        if self.domain_recovery_epochs.len() != self.coverage.shards.len()
            || self.sessions.len() != self.coverage.shards.len()
            || self.unit_identities.len() != self.coverage.shards.len()
        {
            return Err("incomplete sessions".into());
        }
        for (shard, session) in self.coverage.shards.iter().zip(&self.sessions) {
            self.session_id(shard.id)?;
            let units = self
                .unit_identities
                .get(&shard.id)
                .ok_or("missing unit identities")?;
            if units.len() != shard.units.len() {
                return Err("incomplete unit identities".into());
            }
            for (identity, unit) in units.iter().zip(&shard.units) {
                if identity.recovery_epoch.to_string() != self.domain_recovery_epochs[&shard.id]
                    || identity.shard_id != shard.id
                    || identity.table != "enhance"
                    || identity.local_row_start != unit.local_row_start
                    || identity.allocated_rows != unit.allocated_rows
                    || identity.parameter_id != unit_parameter_id(unit.allocated_rows)?
                    || identity.content_sha256.len() != 64
                    || !canonical_hash(&identity.content_sha256)
                    || identity.setup_sha256 != hex::encode(Sha256::digest(setup_seed(shard.id)))
                {
                    return Err("invalid unit identity".into());
                }
            }
            if session.shard_id != shard.id
                || session.parameter_id != parameter_id(shard.logical_rows)?
                || session.public_params_sha256.len() != 64
                || !canonical_hash(&session.public_params_sha256)
            {
                return Err("invalid shard session reference".into());
            }
        }
        Ok(())
    }
}

pub fn canonical_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn parameters(logical_rows: u64) -> Result<ipir_sp::YpirSchemeParams, String> {
    if !matches!(logical_rows, 4096 | 8192 | 16384 | 32768) {
        return Err("unqualified logical rows".into());
    }
    ipir_sp::params_for_simplepir_profile(
        logical_rows,
        (RECORD_BYTES * RECORDS_PER_ROW * 8) as u64,
        ipir_sp::SimplePirProfile::P16Q48,
    )
    .map(|(_, p)| {
        #[cfg(feature = "native-reinspiring")]
        {
            let mut p = p;
            p.query_bits = crate::native::QUERY_BITS;
            p.q_prime_1 = 1 << crate::native::RESPONSE_BITS;
            p
        }
        #[cfg(not(feature = "native-reinspiring"))]
        {
            p
        }
    })
    .map_err(|e| e.to_string())
}

/// Exact length of a shard's public session material for `logical_rows`.
/// v7 publishes one switched `c1` block per RLWE column block; the native
/// profile publishes two rounded masks per column.
pub fn session_public_len(logical_rows: u64) -> Result<usize, String> {
    let params = parameters(logical_rows)?;
    if !params.db_cols.is_multiple_of(params.poly_len) {
        return Err("invalid PIR dimensions".into());
    }
    #[cfg(feature = "native-reinspiring")]
    {
        if params.db_cols != crate::native::COLS {
            return Err("unqualified native column count".into());
        }
        Ok(crate::native::public_len(crate::native::COLS))
    }
    #[cfg(not(feature = "native-reinspiring"))]
    {
        let (rlwe, _) = ipir_sp::params_for_simplepir_profile(
            logical_rows,
            ITEM_SIZE_BITS,
            ipir_sp::SimplePirProfile::P16Q48,
        )
        .map_err(|e| e.to_string())?;
        (params.db_cols / rlwe.d)
            .checked_mul(ipir_sp::modulus_switch::published_c1_len(rlwe.d, rlwe.q))
            .ok_or_else(|| "public material length overflow".into())
    }
}

/// Exact length of a query response for `logical_rows`, including the
/// [`HEADER_BYTES`] echoed binding.
pub fn response_len(logical_rows: u64) -> Result<usize, String> {
    let params = parameters(logical_rows)?;
    if !params.db_cols.is_multiple_of(params.poly_len) {
        return Err("invalid PIR dimensions".into());
    }
    #[cfg(feature = "native-reinspiring")]
    {
        if params.db_cols != crate::native::COLS {
            return Err("unqualified native column count".into());
        }
        Ok(HEADER_BYTES + crate::native::response_len(crate::native::COLS))
    }
    #[cfg(not(feature = "native-reinspiring"))]
    {
        (params.db_cols / params.poly_len)
            .checked_mul(ipir_sp::modulus_switch::response_body_len(
                params.poly_len,
                params.q_prime_1,
            ))
            .and_then(|n| n.checked_add(HEADER_BYTES))
            .ok_or_else(|| "response length overflow".into())
    }
}

/// Exact length of a native query request for `logical_rows`, including the
/// [`HEADER_BYTES`] binding: one uploaded `K_g` key and a 49-bit selection.
#[cfg(feature = "native-reinspiring")]
pub fn request_len(logical_rows: u64) -> Result<usize, String> {
    let params = parameters(logical_rows)?;
    Ok(HEADER_BYTES + crate::native::request_len(params.db_rows))
}

pub fn parameter_id(logical_rows: u64) -> Result<String, String> {
    Ok(format!(
        "{PROTOCOL_REVISION}/{}",
        digest(&parameters(logical_rows)?)
    ))
}

pub fn unit_parameter_id(rows: u64) -> Result<String, String> {
    if !matches!(rows, 2048 | 4096 | 8192) {
        return Err("unqualified unit size".into());
    }
    let (_, params) = ipir_sp::params_for_simplepir_profile(
        rows,
        ITEM_SIZE_BITS,
        ipir_sp::SimplePirProfile::P16Q48,
    )
    .map_err(|e| e.to_string())?;
    Ok(format!("{PROTOCOL_REVISION}/unit/{}", digest(&params)))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShardSession {
    pub session_id: String,
    pub generation: u64,
    pub shard_id: u64,
    pub params: ipir_sp::YpirSchemeParams,
    pub public_params_base64: String,
}

pub const ROW_PAYLOAD_BYTES: usize = ROW_BYTES;
