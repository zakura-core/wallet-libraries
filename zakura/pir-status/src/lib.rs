//! Status-PIR wire contract and private client. No transaction payload API.
pub mod transport;
use ipir_sp::{IPIRClient, IPIRSeed, PublicQuerySetup, SimplePirProfile};
use rand::{Rng, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ROWS: usize = 8192;
pub const SLOTS: usize = 256;
pub const SLOT_BYTES: usize = 40;
pub const ROW_BYTES: usize = 12288;
pub const ITEM_BITS: u64 = (ROW_BYTES * 8) as u64;
pub const MAX_ENTRIES: usize = ROWS * SLOTS * 3 / 4;
pub const PROTOCOL: &str = "status-pir-v2-q48";
pub const HEADER_BYTES: usize = 52;
pub const MAX_AGE_MS: u64 = 20_000;
pub type Hash = [u8; 32];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("malformed status data")]
    Malformed,
    #[error("unsupported status protocol")]
    Unsupported,
    #[error("status coverage incomplete")]
    CoverageIncomplete,
    #[error("status observation stale")]
    Stale,
    #[error("status capacity exceeded")]
    Capacity,
    #[error("status service unavailable")]
    Unavailable,
    #[error("status lookup timed out")]
    Timeout,
    #[error("status lookup cancelled")]
    Cancelled,
    #[error("status PIR operation failed")]
    Pir,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Observation {
    NotFound,
    Mempool,
    Mined(u32),
    Forked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub txid: Hash,
    pub tag: u8,
    pub height: u32,
}

impl Record {
    pub fn validate(&self) -> Result<(), Error> {
        match self.tag {
            1 if self.height == 0 => Ok(()),
            2 | 3 if self.height > 0 => Ok(()),
            _ => Err(Error::Malformed),
        }
    }
    pub fn encode(&self) -> Result<[u8; SLOT_BYTES], Error> {
        self.validate()?;
        let mut out = [0; SLOT_BYTES];
        out[..32].copy_from_slice(&self.txid);
        out[32] = self.tag;
        out[36..40].copy_from_slice(&self.height.to_le_bytes());
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Option<Self>, Error> {
        if bytes.len() != SLOT_BYTES {
            return Err(Error::Malformed);
        }
        if bytes.iter().all(|b| *b == 0) {
            return Ok(None);
        }
        if bytes[33..36].iter().any(|b| *b != 0) {
            return Err(Error::Malformed);
        }
        let r = Self {
            txid: bytes[..32].try_into().unwrap(),
            tag: bytes[32],
            height: u32::from_le_bytes(bytes[36..40].try_into().unwrap()),
        };
        r.validate()?;
        Ok(Some(r))
    }
    pub fn observation(&self) -> Result<Observation, Error> {
        self.validate()?;
        Ok(match self.tag {
            1 => Observation::Mempool,
            2 => Observation::Mined(self.height),
            _ => Observation::Forked,
        })
    }
    /// Mined and forked observations must lie in the published window.
    /// Records carry no inclusion proof; the manifest anchor is checked separately.
    pub fn consistent_with(&self, manifest: &Manifest) -> bool {
        self.tag == 1
            || (self.height >= manifest.coverage_start && self.height <= manifest.anchor_height)
    }
}

pub fn bucket(network: &Hash, salt: &Hash, txid: &Hash) -> usize {
    let mut h = Sha256::new();
    h.update(b"status-pir/v2/bucket\0");
    h.update(network);
    h.update(salt);
    h.update(txid);
    let d = h.finalize();
    usize::from(u16::from_le_bytes([d[0], d[1]])) & (ROWS - 1)
}

pub fn setup_seed(network: &Hash, salt: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update(b"status-pir/v2/setup\0");
    h.update(network);
    h.update(salt);
    h.finalize().into()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub protocol: String,
    pub network: Hash,
    pub salt: Hash,
    pub generation: u64,
    pub recovery_epoch: u64,
    pub coverage_start: u32,
    pub anchor_height: u32,
    pub anchor_hash: Hash,
    pub observed_ms: u64,
    pub entries: usize,
    pub rows_digest: Hash,
    pub public_digest: Hash,
}

impl Manifest {
    /// Canonical fixed-width identity commits to coverage and observation time too.
    pub fn id(&self) -> Hash {
        let mut h = Sha256::new();
        h.update(b"status-pir/v2/manifest\0");
        h.update((self.protocol.len() as u64).to_le_bytes());
        h.update(self.protocol.as_bytes());
        h.update(self.network);
        h.update(self.salt);
        h.update(self.generation.to_le_bytes());
        h.update(self.recovery_epoch.to_le_bytes());
        h.update(self.coverage_start.to_le_bytes());
        h.update(self.anchor_height.to_le_bytes());
        h.update(self.anchor_hash);
        h.update(self.observed_ms.to_le_bytes());
        h.update((self.entries as u64).to_le_bytes());
        h.update(self.rows_digest);
        h.update(self.public_digest);
        h.finalize().into()
    }
    pub fn validate(&self) -> Result<(), Error> {
        if self.protocol != PROTOCOL {
            return Err(Error::Unsupported);
        }
        if self.coverage_start == 0
            || self.coverage_start > self.anchor_height
            || self.anchor_hash == [0; 32]
            || self.generation == 0
        {
            return Err(Error::Malformed);
        }
        if self.entries > MAX_ENTRIES {
            return Err(Error::Capacity);
        }
        Ok(())
    }
    pub fn fresh(&self, now_ms: u64) -> Result<(), Error> {
        self.validate()?;
        // No future timestamp tolerance in the synthetic backend.
        match now_ms.checked_sub(self.observed_ms) {
            Some(age) if age <= MAX_AGE_MS => Ok(()),
            Some(_) => Err(Error::Stale),
            None => Err(Error::Malformed),
        }
    }
}

/// Supplied by wallet chain verification, never copied from server metadata.
pub struct AcceptedAnchor {
    pub network: Hash,
    pub height: u32,
    pub hash: Hash,
}

/// Wallet-held evidence. Neither bound is sent to the PIR service.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LocalCoverageContext {
    /// A conservative lower bound established from transaction creation or
    /// broadcast history. Unknown imported transactions use `None`. A matching
    /// mined or forked record below this bound is rejected as malformed.
    pub earliest_possible_inclusion: Option<u32>,
    /// The chain height that a caller's absence decision must cover.
    pub required_through: Option<u32>,
}

impl LocalCoverageContext {
    pub fn validate(self, manifest: &Manifest) -> Result<(), Error> {
        if self
            .required_through
            .is_some_and(|height| height > manifest.anchor_height)
        {
            return Err(Error::CoverageIncomplete);
        }
        Ok(())
    }
}

/// Validates the whole row before returning the observation for `txid`. The row
/// is malformed if it holds more records than the manifest, is unsorted or
/// sparse, holds a record from another bucket or one inconsistent with the
/// accepted anchor, or matches `txid` below `earliest`.
pub fn decode_row(
    manifest: &Manifest,
    txid: &Hash,
    earliest: Option<u32>,
    row: &[u8],
) -> Result<Observation, Error> {
    if row.len() != ROW_BYTES || row[SLOTS * SLOT_BYTES..].iter().any(|b| *b != 0) {
        return Err(Error::Malformed);
    }
    let mut found = None;
    let mut previous = None;
    let mut empty = false;
    let mut records = 0;
    for bytes in row[..SLOTS * SLOT_BYTES].chunks_exact(SLOT_BYTES) {
        match Record::decode(bytes)? {
            None => empty = true,
            Some(r) => {
                records += 1;
                if empty
                    || records > manifest.entries
                    || previous.is_some_and(|p| p >= r.txid)
                    || bucket(&manifest.network, &manifest.salt, &r.txid)
                        != bucket(&manifest.network, &manifest.salt, txid)
                    || !r.consistent_with(manifest)
                {
                    return Err(Error::Malformed);
                }
                previous = Some(r.txid);
                if r.txid == *txid {
                    if r.tag != 1 && earliest.is_some_and(|e| r.height < e) {
                        return Err(Error::Malformed);
                    }
                    found = Some(r.observation()?);
                }
            }
        }
    }
    if let Some(value) = found {
        return Ok(value);
    }
    match earliest {
        Some(h) if h >= manifest.coverage_start && h <= manifest.anchor_height => {
            Ok(Observation::NotFound)
        }
        _ => Err(Error::CoverageIncomplete),
    }
}

/// `body` may be moved into the transport; decoding uses the retained header.
pub struct Query {
    pub body: Vec<u8>,
    header: [u8; HEADER_BYTES],
    seed: IPIRSeed,
    txid: Hash,
    earliest: Option<u32>,
}

pub struct Client {
    pub manifest: Manifest,
    client: IPIRClient,
    setup: PublicQuerySetup,
    public: Vec<Vec<u64>>,
}

impl Client {
    pub fn new(
        manifest: Manifest,
        public: &[u8],
        accepted: &AcceptedAnchor,
    ) -> Result<Self, Error> {
        manifest.validate()?;
        if manifest.network != accepted.network
            || manifest.anchor_height != accepted.height
            || manifest.anchor_hash != accepted.hash
        {
            return Err(Error::Malformed);
        }
        let client = IPIRClient::from_profile(ROWS as u64, ITEM_BITS, SimplePirProfile::P16Q48)
            .map_err(|_| Error::Pir)?;
        let (rlwe, params) =
            ipir_sp::params_for_simplepir_profile(ROWS as u64, ITEM_BITS, SimplePirProfile::P16Q48)
                .map_err(|_| Error::Pir)?;
        let blocks = params.db_cols / rlwe.d;
        if public.len() != blocks * ipir_sp::modulus_switch::published_c1_len(rlwe.d, rlwe.q)
            || Hash::from(Sha256::digest(public)) != manifest.public_digest
        {
            return Err(Error::Malformed);
        }
        let setup = client.generate_public_query_setup_simplepir_from_seed(setup_seed(
            &manifest.network,
            &manifest.salt,
        ));
        let public = ipir_sp::modulus_switch::recover_published_c1(public, rlwe.d, blocks, rlwe.q);
        Ok(Self {
            manifest,
            client,
            setup,
            public,
        })
    }
    pub fn prepare(
        &self,
        txid: &[u8],
        coverage: LocalCoverageContext,
        now_ms: u64,
    ) -> Result<Query, Error> {
        let txid: Hash = txid.try_into().map_err(|_| Error::Malformed)?;
        self.manifest.fresh(now_ms)?;
        coverage.validate(&self.manifest)?;
        let row = bucket(&self.manifest.network, &self.manifest.salt, &txid);
        let (query, keys, seed) = self.client.generate_fresh_query_simplepir(&self.setup, row);
        let mut body = b"SPQ2".to_vec();
        body.extend(self.manifest.id());
        body.extend(OsRng.r#gen::<[u8; 16]>());
        body.extend(
            ipir_sp::serialize::serialize_packing_keys(self.client.rlwe_params(), &keys)
                .map_err(|_| Error::Pir)?,
        );
        body.extend(query.to_switched_bytes(self.client.rlwe_params().q, 48));
        Ok(Query {
            header: body[..HEADER_BYTES].try_into().unwrap(),
            body,
            seed,
            txid,
            earliest: coverage.earliest_possible_inclusion,
        })
    }
    /// A query prepared under another manifest is `Stale`, even when that
    /// manifest shares this client's public setup.
    pub fn decode(&self, query: Query, response: &[u8], now_ms: u64) -> Result<Observation, Error> {
        self.manifest.fresh(now_ms)?;
        if query.header[4..36] != self.manifest.id() {
            return Err(Error::Stale);
        }
        let (rlwe, params) =
            ipir_sp::params_for_simplepir_profile(ROWS as u64, ITEM_BITS, SimplePirProfile::P16Q48)
                .map_err(|_| Error::Pir)?;
        let len = params.db_cols / rlwe.d
            * ipir_sp::modulus_switch::response_body_len(rlwe.d, params.q_prime_1);
        if response.len() != HEADER_BYTES + len || response[..HEADER_BYTES] != query.header {
            return Err(Error::Malformed);
        }
        let row = self.client.decode_response_simplepir(
            query.seed,
            &self.public,
            &response[HEADER_BYTES..],
        );
        decode_row(&self.manifest, &query.txid, query.earliest, &row)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn manifest() -> Manifest {
        Manifest {
            protocol: PROTOCOL.into(),
            network: [1; 32],
            salt: [2; 32],
            generation: 1,
            recovery_epoch: 0,
            coverage_start: 10,
            anchor_height: 20,
            anchor_hash: [3; 32],
            observed_ms: 1000,
            entries: 1,
            rows_digest: [4; 32],
            public_digest: [5; 32],
        }
    }
    #[test]
    fn v2_geometry_and_v1_rejection() {
        assert_eq!((ROWS, SLOTS, SLOT_BYTES, ROW_BYTES), (8192, 256, 40, 12288));
        assert_eq!(ROWS * ROW_BYTES, 96 * 1024 * 1024);
        let mut m = manifest();
        m.protocol = "status-pir-v1-q48".into();
        assert_eq!(m.validate(), Err(Error::Unsupported));
        assert_eq!(Record::decode(&[0; 80]), Err(Error::Malformed));
    }
    #[test]
    fn independent_python_hash_vector() {
        let txid = std::array::from_fn(|i| i as u8);
        assert_eq!(bucket(&[1; 32], &[2; 32], &txid), 6818);
        assert_eq!(
            hex::encode(setup_seed(&[1; 32], &[2; 32])),
            "44ada24f0ddb452f8d8a6902d2c32d02fe64fde4088e71e60a81c453d81e9ea8"
        );
    }
    #[test]
    fn slot_codec_rejects_reserved_bytes_empty_garbage_and_invalid_states() {
        for (tag, height) in [(1, 0), (2, 10), (3, 10)] {
            let r = Record {
                txid: [4; 32],
                tag,
                height,
            };
            let bytes = r.encode().unwrap();
            assert_eq!(Record::decode(&bytes), Ok(Some(r)));
            let mut bad = bytes;
            bad[33] = 1;
            assert_eq!(Record::decode(&bad), Err(Error::Malformed));
            let mut bad = bytes;
            bad[32] = 4;
            assert_eq!(Record::decode(&bad), Err(Error::Malformed));
        }
        let mut empty = [0; SLOT_BYTES];
        empty[0] = 1;
        assert_eq!(Record::decode(&empty), Err(Error::Malformed));
        assert!(
            Record {
                txid: [0; 32],
                tag: 1,
                height: 1,
            }
            .encode()
            .is_err()
        );
        assert!(
            Record {
                txid: [0; 32],
                tag: 2,
                height: 0,
            }
            .encode()
            .is_err()
        );
    }
    #[test]
    fn freshness_coverage_and_binding_are_separate() {
        let m = manifest();
        let row = vec![0; ROW_BYTES];
        assert_eq!(m.fresh(21_000), Ok(()));
        assert_eq!(m.fresh(21_001), Err(Error::Stale));
        assert_eq!(m.fresh(999), Err(Error::Malformed));
        assert_eq!(
            LocalCoverageContext {
                earliest_possible_inclusion: Some(10),
                required_through: Some(21),
            }
            .validate(&m),
            Err(Error::CoverageIncomplete)
        );
        assert_eq!(
            LocalCoverageContext {
                earliest_possible_inclusion: None,
                required_through: Some(20),
            }
            .validate(&m),
            Ok(())
        );
        for earliest in [None, Some(9), Some(21)] {
            assert_eq!(
                decode_row(&m, &[9; 32], earliest, &row),
                Err(Error::CoverageIncomplete)
            );
        }
        assert_eq!(
            decode_row(&m, &[9; 32], Some(10), &row),
            Ok(Observation::NotFound)
        );
        let id = m.id();
        let mut changed = m.clone();
        changed.observed_ms += 1;
        assert_ne!(changed.id(), id);
        let mut changed = m.clone();
        changed.recovery_epoch += 1;
        assert_ne!(changed.id(), id);
        let mut changed = m.clone();
        changed.coverage_start += 1;
        assert_ne!(changed.id(), id);
        let mut changed = m;
        changed.protocol = "other".into();
        assert_eq!(changed.validate(), Err(Error::Unsupported));
    }
    #[test]
    fn complete_row_is_validated_even_after_a_match() {
        let m = manifest();
        let txid = [9; 32];
        let r = Record {
            txid,
            tag: 2,
            height: 11,
        };
        let mut row = vec![0; ROW_BYTES];
        row[..SLOT_BYTES].copy_from_slice(&r.encode().unwrap());
        assert_eq!(
            decode_row(&m, &txid, None, &row),
            Ok(Observation::Mined(11))
        );
        row[ROW_BYTES - 1] = 1;
        assert_eq!(decode_row(&m, &txid, None, &row), Err(Error::Malformed));
        row[ROW_BYTES - 1] = 0;
        row[SLOT_BYTES..SLOT_BYTES * 2].copy_from_slice(&r.encode().unwrap());
        assert_eq!(decode_row(&m, &txid, None, &row), Err(Error::Malformed));
    }
    fn single(tag: u8, height: u32) -> Vec<u8> {
        let mut row = vec![0; ROW_BYTES];
        let r = Record {
            txid: [9; 32],
            tag,
            height,
        };
        row[..SLOT_BYTES].copy_from_slice(&r.encode().unwrap());
        row
    }
    #[test]
    fn row_cannot_hold_more_records_than_the_manifest() {
        let mut m = manifest();
        let row = single(2, 11);
        assert_eq!(
            decode_row(&m, &[9; 32], None, &row),
            Ok(Observation::Mined(11))
        );
        m.entries = 0;
        assert_eq!(decode_row(&m, &[9; 32], None, &row), Err(Error::Malformed));
    }
    #[test]
    fn records_at_the_anchor_are_status_observations() {
        let m = manifest();
        for (tag, expected) in [
            (2, Ok(Observation::Mined(20))),
            (3, Ok(Observation::Forked)),
        ] {
            let row = single(tag, m.anchor_height);
            assert_eq!(decode_row(&m, &[9; 32], None, &row), expected);
        }
    }

    #[test]
    fn match_below_local_inclusion_bound_is_malformed() {
        let m = manifest();
        for (tag, height, earliest, expected) in [
            (2, 11, Some(15), Err(Error::Malformed)),
            (2, 11, Some(11), Ok(Observation::Mined(11))),
            (3, 11, Some(15), Err(Error::Malformed)),
            (1, 0, Some(15), Ok(Observation::Mempool)),
        ] {
            let row = single(tag, height);
            assert_eq!(decode_row(&m, &[9; 32], earliest, &row), expected);
        }
    }
    #[test]
    fn oversized_snapshot_is_a_capacity_error() {
        let mut m = manifest();
        m.entries = MAX_ENTRIES;
        assert_eq!(m.validate(), Ok(()));
        m.entries += 1;
        assert_eq!(m.validate(), Err(Error::Capacity));
    }
    fn client(m: &Manifest) -> Client {
        let (rlwe, params) =
            ipir_sp::params_for_simplepir_profile(ROWS as u64, ITEM_BITS, SimplePirProfile::P16Q48)
                .unwrap();
        let blocks = params.db_cols / rlwe.d;
        let public = vec![0; blocks * ipir_sp::modulus_switch::published_c1_len(rlwe.d, rlwe.q)];
        let mut m = m.clone();
        m.public_digest = Sha256::digest(&public).into();
        let accepted = AcceptedAnchor {
            network: m.network,
            height: m.anchor_height,
            hash: m.anchor_hash,
        };
        Client::new(m, &public, &accepted).unwrap()
    }
    fn response_len() -> usize {
        let (rlwe, params) =
            ipir_sp::params_for_simplepir_profile(ROWS as u64, ITEM_BITS, SimplePirProfile::P16Q48)
                .unwrap();
        HEADER_BYTES
            + params.db_cols / rlwe.d
                * ipir_sp::modulus_switch::response_body_len(rlwe.d, params.q_prime_1)
    }
    #[test]
    fn decode_uses_the_retained_header_after_body_is_moved() {
        let c = client(&manifest());
        let mut query = c
            .prepare(&[9; 32], LocalCoverageContext::default(), 1000)
            .unwrap();
        let header = query.body[..HEADER_BYTES].to_vec();
        drop(std::mem::take(&mut query.body));
        let mut response = vec![0; response_len()];
        response[..HEADER_BYTES].copy_from_slice(&header);
        response[HEADER_BYTES - 1] ^= 1;
        assert_eq!(c.decode(query, &response, 1000), Err(Error::Malformed));
    }
    #[test]
    fn query_from_another_manifest_is_stale() {
        let a = manifest();
        let mut b = a.clone();
        b.generation += 1;
        let (a, b) = (client(&a), client(&b));
        let query = a
            .prepare(&[9; 32], LocalCoverageContext::default(), 1000)
            .unwrap();
        let mut response = vec![0; response_len()];
        response[..HEADER_BYTES].copy_from_slice(&query.body[..HEADER_BYTES]);
        assert_eq!(b.decode(query, &response, 1000), Err(Error::Stale));
    }
}
