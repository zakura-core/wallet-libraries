//! Public v5 shard geometry and wire representations.
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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SCHEMA_VERSION: u16 = 11;
pub const PROTOCOL_REVISION: &str = "ironwood-enhance-pir-v5";
pub const RETAINED_GENERATIONS: usize = 5;
pub const HEADER_BYTES: usize = 28;

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
    /// Only the geometry family exercised by the v4 qualification suite is accepted.
    pub fn validate(self) -> Result<(), String> {
        if self.max_shard_rows != 32768
            || self.min_shard_rows != 4096
            || self.max_mutable_unit_rows != 8192
            || self.min_mutable_unit_rows != 2048
        {
            return Err("unqualified v4 geometry".into());
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
    Lending,
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Loan {
    pub lender: u64,
    pub borrower: u64,
    pub row_start: u64,
    pub row_end: u64,
    pub return_at_records: u64,
}

/// Persist this identity registry with the publication decision. Entries survive reorgs.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Lifecycle {
    pub identities: Vec<u64>,
    pub next_id: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    pub records: u64,
    pub shards: Vec<QueryShard>,
    pub loan: Option<Loan>,
}

impl Lifecycle {
    /// Derive the final state for complete canonical coverage, including crossing-block excess.
    /// This deliberately does not publish intermediate threshold states.
    pub fn coverage(&mut self, records: u64, geometry: Geometry) -> Result<Coverage, String> {
        geometry.validate()?;
        if records == 0 {
            return Err("cannot publish empty coverage".into());
        }
        let per_row = RECORDS_PER_ROW as u64;
        let span = geometry.max_shard_rows * per_row;
        let loan_records = geometry.min_shard_rows * per_row;
        let complete = records / span;
        let remainder = records % span;
        let count = complete.checked_add(1).ok_or("shard count overflow")?;
        // The fleet ceiling is four groups of six shards. Reject absurd input before allocation.
        if count > 24 {
            return Err("coverage exceeds the four-group fleet ceiling".into());
        }
        while self.identities.len() < count as usize {
            let id = self.next_id;
            self.next_id = id.checked_add(1).ok_or("shard identity exhausted")?;
            self.identities.push(id);
        }
        let borrowing = complete > 0 && remainder < loan_records;
        let mut shards = Vec::new();
        for index in 0..count {
            let (start, n, state) = if index < complete {
                let lending = borrowing && index + 1 == complete;
                (
                    index * geometry.max_shard_rows,
                    span - if lending { loan_records } else { 0 },
                    if lending {
                        ShardState::Lending
                    } else {
                        ShardState::Sealed
                    },
                )
            } else {
                (
                    index * geometry.max_shard_rows
                        - if borrowing {
                            geometry.min_shard_rows
                        } else {
                            0
                        },
                    remainder + if borrowing { loan_records } else { 0 },
                    ShardState::Growing,
                )
            };
            shards.push(QueryShard {
                id: self.identities[index as usize],
                global_row_start: start,
                records: n,
                logical_rows: geometry.logical_rows(n)?,
                state,
                units: geometry.units(n)?,
            });
        }
        let loan = borrowing.then(|| Loan {
            lender: self.identities[complete as usize - 1],
            borrower: self.identities[complete as usize],
            row_start: complete * geometry.max_shard_rows - geometry.min_shard_rows,
            row_end: complete * geometry.max_shard_rows,
            return_at_records: complete * span + loan_records,
        });
        Ok(Coverage {
            records,
            shards,
            loan,
        })
    }
}

impl Coverage {
    pub fn validate(&self, geometry: Geometry) -> Result<(), String> {
        geometry.validate()?;
        let mut ids = std::collections::BTreeSet::new();
        let mut end = 0u64;
        for shard in &self.shards {
            if !ids.insert(shard.id)
                || shard.global_row_start.checked_mul(RECORDS_PER_ROW as u64) != Some(end)
                || shard.logical_rows != geometry.logical_rows(shard.records)?
                || shard.units != geometry.units(shard.records)?
            {
                return Err("invalid shard coverage or geometry".into());
            }
            end = end
                .checked_add(shard.records)
                .ok_or("record coverage overflow")?;
        }
        if end == 0 || end != self.records {
            return Err("incomplete record coverage".into());
        }
        // Compare lifecycle semantics as well as ranges, independent of assigned stable IDs.
        let mut lifecycle = Lifecycle {
            identities: self.shards.iter().map(|s| s.id).collect(),
            next_id: 0,
        };
        let expected = lifecycle.coverage(self.records, geometry)?;
        if &expected != self {
            return Err("invalid loan or lifecycle state".into());
        }
        Ok(())
    }

    pub fn locate(&self, position: u64) -> Option<(&QueryShard, usize, usize)> {
        self.shards
            .iter()
            .find_map(|s| s.locate(position).map(|(r, p)| (s, r, p)))
    }
}

/// All fields participate in cache identity, including the shard-local setup slice.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnitIdentity {
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
    pub generation: u64,
    pub shard_id: u64,
    pub epoch: [u8; 8],
}

impl QueryBinding {
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = b"EPQ4".to_vec();
        bytes.extend(self.generation.to_le_bytes());
        bytes.extend(self.shard_id.to_le_bytes());
        bytes.extend(self.epoch);
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < HEADER_BYTES || &bytes[..4] != b"EPQ4" {
            return Err("invalid v4 framing".into());
        }
        Ok(Self {
            generation: u64::from_le_bytes(bytes[4..12].try_into().unwrap()),
            shard_id: u64::from_le_bytes(bytes[12..20].try_into().unwrap()),
            epoch: bytes[20..28].try_into().unwrap(),
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
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != SCHEMA_VERSION
            || self.protocol_revision != PROTOCOL_REVISION
            || self.network != "main"
            || self.pool != "ironwood"
            || self.generation == 0
            || self.anchor_block_hash.len() != 64
            || hex::decode(&self.anchor_block_hash).is_err()
        {
            return Err("incompatible v5 manifest".into());
        }
        self.coverage.validate(self.geometry)?;
        if self.sessions.len() != self.coverage.shards.len()
            || self.unit_identities.len() != self.coverage.shards.len()
        {
            return Err("incomplete sessions".into());
        }
        for (shard, session) in self.coverage.shards.iter().zip(&self.sessions) {
            let units = self
                .unit_identities
                .get(&shard.id)
                .ok_or("missing unit identities")?;
            if units.len() != shard.units.len() {
                return Err("incomplete unit identities".into());
            }
            for (identity, unit) in units.iter().zip(&shard.units) {
                if identity.shard_id != shard.id
                    || identity.table != "enhance"
                    || identity.local_row_start != unit.local_row_start
                    || identity.allocated_rows != unit.allocated_rows
                    || identity.parameter_id != unit_parameter_id(unit.allocated_rows)?
                    || identity.content_sha256.len() != 64
                    || hex::decode(&identity.content_sha256).is_err()
                    || identity.setup_sha256 != hex::encode(Sha256::digest(setup_seed(shard.id)))
                {
                    return Err("invalid unit identity".into());
                }
            }
            if session.shard_id != shard.id
                || session.parameter_id != parameter_id(shard.logical_rows)?
                || session.public_params_sha256.len() != 64
                || hex::decode(&session.public_params_sha256).is_err()
            {
                return Err("invalid shard session reference".into());
            }
        }
        Ok(())
    }
}

pub fn parameters(logical_rows: u64) -> Result<ipir_sp::YpirSchemeParams, String> {
    if !matches!(logical_rows, 4096 | 8192 | 16384 | 32768) {
        return Err("unqualified logical rows".into());
    }
    ipir_sp::params_for_simplepir_profile(
        logical_rows,
        (RECORD_BYTES * RECORDS_PER_ROW * 8) as u64,
        ipir_sp::SimplePirProfile::P16Q46,
    )
    .map(|(_, p)| p)
    .map_err(|e| e.to_string())
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
        ipir_sp::SimplePirProfile::P16Q46,
    )
    .map_err(|e| e.to_string())?;
    Ok(format!("{PROTOCOL_REVISION}/unit/{}", digest(&params)))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShardSession {
    pub generation: u64,
    pub shard_id: u64,
    pub params: ipir_sp::YpirSchemeParams,
    pub public_params_base64: String,
}

pub const ROW_PAYLOAD_BYTES: usize = ROW_BYTES;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_layout_is_653_bytes() {
        let record = EnhanceRecord::from_parts(EnhanceRecordParts {
            enc_ciphertext_suffix: [2; 528],
            cv_net: [3; 32],
            out_ciphertext: [4; 80],
            has_transparent_inputs: true,
            has_transparent_outputs: false,
            metadata: EnhanceTransactionMetadata::new(0, Some(0)).unwrap(),
        });
        assert_eq!(RECORD_BYTES, 653);
        assert_eq!(ROW_BYTES, 21_549);
        assert_eq!(record.enc_ciphertext_suffix(), &[2; 528]);
        assert!(record.has_transparent_inputs());
    }

    #[test]
    fn loan_and_return_coverage_map_to_local_rows() {
        let g = Geometry::default();
        let span = 32_768 * RECORDS_PER_ROW as u64;
        let loan = 4_096 * RECORDS_PER_ROW as u64;
        let mut state = Lifecycle::default();
        for n in [1, span - 1, span, span + 1, span + loan - 1, span + loan] {
            let coverage = state.coverage(n, g).unwrap();
            coverage.validate(g).unwrap();
            assert!(coverage.locate(n).is_none());
            for p in [0, n / 2, n - 1] {
                let (shard, row, slot) = coverage.locate(p).unwrap();
                assert_eq!(shard.locate(p), Some((row, slot)));
                assert_eq!(
                    shard.global_row_start * 33 + row as u64 * 33 + slot as u64,
                    p
                );
            }
        }
        let during = state.coverage(span, g).unwrap();
        assert_eq!(during.shards[0].state, ShardState::Lending);
        assert_eq!(during.shards[1].global_row_start, 32_768 - 4_096);
        assert_eq!(during.shards[1].logical_rows, 4_096);
        let after = state.coverage(span + loan, g).unwrap();
        assert!(after.loan.is_none());
        assert_eq!(after.shards[1].global_row_start, 32_768);
    }

    #[test]
    fn geometry_rejects_invalid_units_and_coverage() {
        let g = Geometry::default();
        for (records, rows) in [
            (1, 4_096),
            (4_096 * 33 + 1, 8_192),
            (8_192 * 33 + 1, 16_384),
            (16_384 * 33 + 1, 32_768),
        ] {
            assert_eq!(g.logical_rows(records).unwrap(), rows);
        }
        assert!(g.logical_rows(0).is_err());
        assert!(g.logical_rows(32_768 * 33 + 1).is_err());
        let mut state = Lifecycle::default();
        let mut coverage = state.coverage(32_768 * 33, g).unwrap();
        coverage.loan = None;
        assert!(coverage.validate(g).is_err());
    }

    #[test]
    fn query_binding_has_exact_header_fields() {
        let binding = QueryBinding {
            generation: 0x0102030405060708,
            shard_id: 0x1112131415161718,
            epoch: [0xa5; 8],
        };
        let encoded = binding.encode();
        assert_eq!(encoded.len(), HEADER_BYTES);
        assert_eq!(&encoded[..4], b"EPQ4");
        assert_eq!(&encoded[4..12], &[8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(QueryBinding::decode(&encoded).unwrap(), binding);
        assert!(QueryBinding::decode(&encoded[..27]).is_err());
        let mut wrong = encoded;
        wrong[0] = b'X';
        assert!(QueryBinding::decode(&wrong).is_err());
    }

    #[test]
    fn shard_setup_seed_uses_server_domain() {
        assert_eq!(
            hex::encode(setup_seed(0)),
            "38d2a05f33de9281da5efac0ab38e35386df6458b816cccfa8a13ac7d50fe7fb"
        );
        assert_eq!(
            hex::encode(setup_seed(1)),
            "f448c40881f2d017a6a063ed77439de7a39bbe5f2f0d5ad6e4a452c24e9d1eae"
        );
    }

    #[test]
    fn manifest_rejects_incompatible_versions_and_identity_changes() {
        let geometry = Geometry::default();
        let coverage = Lifecycle::default().coverage(1, geometry).unwrap();
        let shard = &coverage.shards[0];
        let shard_id = shard.id;
        let logical_rows = shard.logical_rows;
        let unit_identities = std::collections::BTreeMap::from([(
            shard.id,
            shard
                .units
                .iter()
                .map(|unit| UnitIdentity {
                    table: "enhance".into(),
                    shard_id: shard.id,
                    local_row_start: unit.local_row_start,
                    allocated_rows: unit.allocated_rows,
                    setup_sha256: hex::encode(Sha256::digest(setup_seed(shard.id))),
                    parameter_id: unit_parameter_id(unit.allocated_rows).unwrap(),
                    content_sha256: "00".repeat(32),
                })
                .collect(),
        )]);
        let manifest = Manifest {
            schema_version: SCHEMA_VERSION,
            protocol_revision: PROTOCOL_REVISION.into(),
            network: "main".into(),
            pool: POOL.into(),
            generation: 1,
            anchor_height: 3_428_143,
            anchor_block_hash: "00".repeat(32),
            geometry,
            coverage,
            sessions: vec![SessionRef {
                shard_id,
                public_params_sha256: "00".repeat(32),
                parameter_id: parameter_id(logical_rows).unwrap(),
            }],
            unit_identities,
        };
        manifest.validate().unwrap();
        let mut bad = manifest.clone();
        bad.schema_version = 7;
        assert!(bad.validate().is_err());
        let mut bad = manifest.clone();
        bad.network = "test".into();
        assert!(bad.validate().is_err());
        let mut bad = manifest.clone();
        bad.unit_identities.get_mut(&shard_id).unwrap()[0].setup_sha256 = "00".repeat(32);
        assert!(bad.validate().is_err());
        let mut json = serde_json::to_value(&manifest).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("old_v2_field".into(), serde_json::Value::Null);
        assert!(serde_json::from_value::<Manifest>(json).is_err());
    }
}
