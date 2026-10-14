//! Status-PIR wire contract and private client. No transaction payload API.
//!
//! The client speaks the native two-mask protocol
//! `status-pir-v3-native-two-mask-m29`: one uploaded `K_g` packing key and a
//! selection query dithered to 44 bits per request, answered under two
//! published 29-bit masks. Servers also accept the protocol's original 49-bit
//! selection and tell the two apart by length. The q48 profile
//! (`status-pir-v2-q48`) is no longer supported; the row format, bucket hash
//! and manifest identity are unchanged from v2.
//!
//! Observations are available only through [`transport::StatusPirClient`], so
//! every query runs under a manifest bound to the wallet's accepted anchor. The
//! low-level client is not public:
//!
//! ```compile_fail
//! use zakura_pir_status::Client;
//! ```
pub mod transport;
use rand::{Rng, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ROWS: usize = 8192;
pub const SLOTS: usize = 256;
pub const SLOT_BYTES: usize = 40;
pub const ROW_BYTES: usize = 12288;
pub const ITEM_BITS: u64 = (ROW_BYTES * 8) as u64;
pub const MAX_ENTRIES: usize = ROWS * SLOTS * 3 / 4;
pub const PROTOCOL: &str = "status-pir-v3-native-two-mask-m29";
/// First four bytes of every query body and echoed response header.
pub const QUERY_MAGIC: &[u8; 4] = b"SPN1";
/// Plaintext u16 coefficients per row.
pub const COLS: usize = ROW_BYTES / 2;
pub const HEADER_BYTES: usize = 52;
pub const MAX_AGE_MS: u64 = 20_000;
/// A manifest observed this far ahead of the wallet clock is treated as
/// observed now; anything further ahead is malformed rather than fresh.
pub const MAX_FUTURE_SKEW_MS: u64 = 5_000;
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
    pub(crate) fn observation(&self) -> Result<Observation, Error> {
        self.validate()?;
        Ok(match self.tag {
            1 => Observation::Mempool,
            2 => Observation::Mined(self.height),
            _ => Observation::Forked,
        })
    }
    /// Mined and forked observations must lie in the published window.
    /// Records carry no inclusion proof; the manifest anchor is checked separately.
    pub(crate) fn consistent_with(&self, manifest: &Manifest) -> bool {
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

/// First-dimension query-mask domain, distinct from the retired q48 setup
/// (`status-pir/v2/setup`) and from every Enhance setup.
pub fn native_setup_seed(network: &Hash, salt: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update(b"status-pir/v3/native-setup\0");
    h.update(network);
    h.update(salt);
    h.finalize().into()
}

/// Packing key-switching setup domain for the native profile.
pub fn native_packing_seed(network: &Hash, salt: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update(b"status-pir/v3/native-packing\0");
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
    /// Fresh while `observed_ms` is at most [`MAX_AGE_MS`] behind `now_ms`.
    /// Up to [`MAX_FUTURE_SKEW_MS`] of clock skew ahead of the wallet counts
    /// as age zero; a manifest further in the future is `Malformed`.
    pub fn fresh(&self, now_ms: u64) -> Result<(), Error> {
        self.validate()?;
        let age = match now_ms.checked_sub(self.observed_ms) {
            Some(age) => age,
            None if self.observed_ms - now_ms <= MAX_FUTURE_SKEW_MS => 0,
            None => return Err(Error::Malformed),
        };
        if age <= MAX_AGE_MS {
            Ok(())
        } else {
            Err(Error::Stale)
        }
    }
}

/// Decides whether a manifest anchor is one the wallet has verified itself.
/// Implementations must be built from the wallet's own chain state, never
/// from server metadata: the manifest's `anchor_height` and `anchor_hash` are
/// assertions until this trait accepts them.
pub trait AnchorVerifier {
    fn network(&self) -> Hash;
    fn accepts(&self, height: u32, hash: &Hash) -> bool;
}

impl<T: AnchorVerifier + ?Sized> AnchorVerifier for &T {
    fn network(&self) -> Hash {
        (**self).network()
    }
    fn accepts(&self, height: u32, hash: &Hash) -> bool {
        (**self).accepts(height, hash)
    }
}

/// Supplied by wallet chain verification, never copied from server metadata.
/// Accepts exactly one anchor.
pub struct AcceptedAnchor {
    pub network: Hash,
    pub height: u32,
    pub hash: Hash,
}

impl AnchorVerifier for AcceptedAnchor {
    fn network(&self) -> Hash {
        self.network
    }
    fn accepts(&self, height: u32, hash: &Hash) -> bool {
        self.height == height && self.hash == *hash
    }
}

/// A window of wallet-verified `(height, hash)` anchors, so a manifest a few
/// blocks behind the wallet tip is still acceptable. An empty window accepts
/// nothing.
pub struct AcceptedAnchors {
    pub network: Hash,
    pub known: Vec<(u32, Hash)>,
}

impl AnchorVerifier for AcceptedAnchors {
    fn network(&self) -> Hash {
        self.network
    }
    fn accepts(&self, height: u32, hash: &Hash) -> bool {
        self.known.iter().any(|(h, x)| *h == height && x == hash)
    }
}

/// The manifest anchor must be verified by the wallet, not asserted by the server.
pub(crate) fn anchor_accepted(manifest: &Manifest, accepted: &dyn AnchorVerifier) -> bool {
    manifest.network == accepted.network()
        && accepted.accepts(manifest.anchor_height, &manifest.anchor_hash)
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
pub(crate) fn decode_row(
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
    for bytes in row[..SLOTS * SLOT_BYTES].as_chunks::<SLOT_BYTES>().0 {
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

/// Exact length of the public session material: both 29-bit masks per column.
pub(crate) fn session_len() -> Result<usize, Error> {
    Ok(zakura_pir_native::public_len(COLS))
}
/// Exact length of a query response, including the echoed header.
pub(crate) fn response_len() -> Result<usize, Error> {
    Ok(HEADER_BYTES + zakura_pir_native::response_len(COLS))
}
/// Exact length of a query body, including the header: one uploaded key and a
/// selection dithered to [`zakura_pir_native::DITHERED_QUERY_BITS`].
#[cfg(test)]
pub(crate) fn request_len() -> usize {
    HEADER_BYTES + zakura_pir_native::request_len_bits(ROWS, zakura_pir_native::DITHERED_QUERY_BITS)
}
/// `body` may be moved into the transport; decoding uses the retained header.
pub(crate) struct Query {
    pub(crate) body: Vec<u8>,
    header: [u8; HEADER_BYTES],
    secret: zakura_pir_native::NativeSecret,
    txid: Hash,
    earliest: Option<u32>,
}
pub(crate) struct Client {
    manifest: Manifest,
    packing: zakura_pir_native::NativeSetup,
    masks: Vec<Vec<u64>>,
    public: Vec<u8>,
}
impl Client {
    /// The manifest accepted by [`Client::new`]; it cannot be replaced without
    /// repeating anchor acceptance and setup.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    /// Checks shared by every profile before the row selector is encrypted.
    fn envelope(
        &self,
        txid: &[u8],
        coverage: LocalCoverageContext,
        now_ms: u64,
    ) -> Result<(Hash, Vec<u8>), Error> {
        let txid: Hash = txid.try_into().map_err(|_| Error::Malformed)?;
        self.manifest.fresh(now_ms)?;
        coverage.validate(&self.manifest)?;
        let mut body = QUERY_MAGIC.to_vec();
        body.extend(self.manifest.id());
        body.extend(OsRng.r#gen::<[u8; 16]>());
        Ok((txid, body))
    }
    /// Checks shared by every profile before the response body is decrypted.
    /// A query prepared under another manifest is `Stale`, even when that
    /// manifest shares this client's public setup.
    fn check_response(
        &self,
        header: &[u8; HEADER_BYTES],
        response: &[u8],
        now_ms: u64,
    ) -> Result<(), Error> {
        self.manifest.fresh(now_ms)?;
        if header[4..36] != self.manifest.id() {
            return Err(Error::Stale);
        }
        if response.len() != response_len()? || response[..HEADER_BYTES] != header[..] {
            return Err(Error::Malformed);
        }
        Ok(())
    }
}
impl Client {
    pub fn new(
        manifest: Manifest,
        public: &[u8],
        accepted: &dyn AnchorVerifier,
    ) -> Result<Self, Error> {
        manifest.validate()?;
        if !anchor_accepted(&manifest, accepted) {
            return Err(Error::Malformed);
        }
        if public.len() != session_len()?
            || Hash::from(Sha256::digest(public)) != manifest.public_digest
        {
            return Err(Error::Malformed);
        }
        Ok(Self {
            packing: zakura_pir_native::packing_setup(native_packing_seed(
                &manifest.network,
                &manifest.salt,
            )),
            masks: zakura_pir_native::public_query_masks(
                native_setup_seed(&manifest.network, &manifest.salt),
                ROWS,
                COLS,
            ),
            public: public.to_vec(),
            manifest,
        })
    }
    pub fn prepare(
        &self,
        txid: &[u8],
        coverage: LocalCoverageContext,
        now_ms: u64,
    ) -> Result<Query, Error> {
        let (txid, mut body) = self.envelope(txid, coverage, now_ms)?;
        let row = bucket(&self.manifest.network, &self.manifest.salt, &txid);
        let (secret, payload) =
            zakura_pir_native::prepare_dithered(&self.packing, &self.masks, ROWS, row)
                .map_err(|_| Error::Pir)?;
        body.extend(payload);
        Ok(Query {
            header: body[..HEADER_BYTES].try_into().unwrap(),
            body,
            secret,
            txid,
            earliest: coverage.earliest_possible_inclusion,
        })
    }
    pub fn decode(&self, query: Query, response: &[u8], now_ms: u64) -> Result<Observation, Error> {
        self.check_response(&query.header, response, now_ms)?;
        let row = zakura_pir_native::decode_cols(
            &query.secret,
            &self.public,
            &response[HEADER_BYTES..],
            COLS,
        )
        .map_err(|_| Error::Pir)?;
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
    fn row_geometry_and_retired_protocol_rejection() {
        assert_eq!((ROWS, SLOTS, SLOT_BYTES, ROW_BYTES), (8192, 256, 40, 12288));
        assert_eq!(ROWS * ROW_BYTES, 96 * 1024 * 1024);
        let mut m = manifest();
        for retired in ["status-pir-v1-q48", "status-pir-v2-q48"] {
            m.protocol = retired.into();
            assert_eq!(m.validate(), Err(Error::Unsupported));
        }
        assert_eq!(Record::decode(&[0; 80]), Err(Error::Malformed));
    }
    #[test]
    fn native_setup_domains_match_independent_python_vectors() {
        assert_eq!(
            hex::encode(native_setup_seed(&[1; 32], &[2; 32])),
            "c8cb85010ef6544f65566f275551a3c62616692e6f0a88429176fb83a16aeccf"
        );
        assert_eq!(
            hex::encode(native_packing_seed(&[1; 32], &[2; 32])),
            "7f99c2ef04dab7c859432bb188475a9e2680b06f8cd7eae099ed24f9a0698af5"
        );
        assert_ne!(
            native_setup_seed(&[1; 32], &[2; 32]),
            native_packing_seed(&[1; 32], &[2; 32])
        );
    }
    #[test]
    fn native_wire_identity_and_exact_lengths() {
        assert_eq!(PROTOCOL, "status-pir-v3-native-two-mask-m29");
        assert_eq!(QUERY_MAGIC, b"SPN1");
        assert_eq!(COLS, 6144);
        // Two 29-bit masks per column.
        assert_eq!(session_len(), Ok(44_544));
        // Echoed header plus 6144 22-bit coefficients.
        assert_eq!(response_len(), Ok(HEADER_BYTES + 16_896));
        // Header, one uploaded key and a 44-bit dithered selection over 8192
        // rows; servers also accept the 49-bit selection, so the two lengths
        // must differ.
        assert_eq!(zakura_pir_native::KEY_BYTES, 27_648);
        assert_eq!(zakura_pir_native::DITHERED_QUERY_BITS, 44);
        assert_eq!(request_len(), HEADER_BYTES + 27_648 + 45_056);
        assert_eq!(request_len(), 72_756);
        assert_eq!(zakura_pir_native::request_len(ROWS), 27_648 + 50_176);
    }
    #[test]
    fn independent_python_hash_vector() {
        let txid = std::array::from_fn(|i| i as u8);
        assert_eq!(bucket(&[1; 32], &[2; 32], &txid), 6818);
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
    fn missing_reconfirmation_record_requires_creation_evidence_and_retained_coverage() {
        let mut snapshot = manifest();
        snapshot.coverage_start = 15;
        let empty_row = vec![0; ROW_BYTES];
        // Previously observed inclusion at 12 is now outside the retained window.
        // It is not a trustworthy creation bound and cannot turn missing history into absence.
        assert_eq!(
            decode_row(&snapshot, &[9; 32], None, &empty_row),
            Err(Error::CoverageIncomplete)
        );
        assert_eq!(
            decode_row(&snapshot, &[9; 32], Some(12), &empty_row),
            Err(Error::CoverageIncomplete)
        );
        // Only actual conservative creation evidence covered by the snapshot supports absence.
        assert_eq!(
            decode_row(&snapshot, &[9; 32], Some(15), &empty_row),
            Ok(Observation::NotFound)
        );
        assert_eq!(
            LocalCoverageContext {
                earliest_possible_inclusion: Some(15),
                required_through: Some(snapshot.anchor_height + 1)
            }
            .validate(&snapshot),
            Err(Error::CoverageIncomplete)
        );
    }

    #[test]
    fn freshness_coverage_and_binding_are_separate() {
        let m = manifest();
        let row = vec![0; ROW_BYTES];
        assert_eq!(m.fresh(21_000), Ok(()));
        assert_eq!(m.fresh(21_001), Err(Error::Stale));
        assert_eq!(m.fresh(999), Ok(()));
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
        for earliest in [10, 20] {
            assert_eq!(
                decode_row(&m, &[9; 32], Some(earliest), &row),
                Ok(Observation::NotFound)
            );
        }
        for through in [19, 20] {
            assert_eq!(
                LocalCoverageContext {
                    earliest_possible_inclusion: Some(10),
                    required_through: Some(through)
                }
                .validate(&m),
                Ok(())
            );
        }
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
    fn freshness_tolerates_bounded_future_skew() {
        let mut m = manifest();
        m.observed_ms = 10_000;
        assert_eq!(m.fresh(10_000 - 4_000), Ok(()));
        assert_eq!(m.fresh(10_000 - MAX_FUTURE_SKEW_MS), Ok(()));
        assert_eq!(
            m.fresh(10_000 - MAX_FUTURE_SKEW_MS - 1),
            Err(Error::Malformed)
        );
        assert_eq!(m.fresh(10_000 - 6_000), Err(Error::Malformed));
        assert_eq!(m.fresh(10_000 + MAX_AGE_MS), Ok(()));
        assert_eq!(m.fresh(10_000 + 20_001), Err(Error::Stale));
    }
    #[test]
    fn anchor_verifiers_bind_network_height_and_hash() {
        let m = manifest();
        let exact = AcceptedAnchor {
            network: m.network,
            height: m.anchor_height,
            hash: m.anchor_hash,
        };
        assert!(anchor_accepted(&m, &exact));
        assert!(!anchor_accepted(
            &m,
            &AcceptedAnchor {
                height: m.anchor_height - 1,
                ..exact
            }
        ));
        assert!(!anchor_accepted(
            &m,
            &AcceptedAnchor {
                hash: [7; 32],
                ..exact
            }
        ));
        assert!(!anchor_accepted(
            &m,
            &AcceptedAnchor {
                network: [8; 32],
                ..exact
            }
        ));
        let window = AcceptedAnchors {
            network: m.network,
            known: vec![(19, [9; 32]), (20, m.anchor_hash), (21, [10; 32])],
        };
        assert!(anchor_accepted(&m, &window));
        assert!(anchor_accepted(&m, &&window));
        let mut other = m.clone();
        other.anchor_height = 19;
        other.anchor_hash = [9; 32];
        assert!(anchor_accepted(&other, &window));
        other.anchor_hash = m.anchor_hash;
        assert!(!anchor_accepted(&other, &window));
        let wrong_network = AcceptedAnchors {
            network: [8; 32],
            known: window.known.clone(),
        };
        assert!(!anchor_accepted(&m, &wrong_network));
        let empty = AcceptedAnchors {
            network: m.network,
            known: Vec::new(),
        };
        assert!(!anchor_accepted(&m, &empty));
        let public = vec![0; session_len().unwrap()];
        let mut m = m;
        m.public_digest = Sha256::digest(&public).into();
        assert!(Client::new(m.clone(), &public, &window).is_ok());
        assert_eq!(
            Client::new(m, &public, &empty).err(),
            Some(Error::Malformed)
        );
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
        let public = vec![0; session_len().unwrap()];
        let mut m = m.clone();
        m.public_digest = Sha256::digest(&public).into();
        let accepted = AcceptedAnchor {
            network: m.network,
            height: m.anchor_height,
            hash: m.anchor_hash,
        };
        Client::new(m, &public, &accepted).unwrap()
    }
    #[test]
    fn decode_uses_the_retained_header_after_body_is_moved() {
        let c = client(&manifest());
        let mut query = c
            .prepare(&[9; 32], LocalCoverageContext::default(), 1000)
            .unwrap();
        let header = query.body[..HEADER_BYTES].to_vec();
        drop(std::mem::take(&mut query.body));
        let mut response = vec![0; response_len().unwrap()];
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
        let mut response = vec![0; response_len().unwrap()];
        response[..HEADER_BYTES].copy_from_slice(&query.body[..HEADER_BYTES]);
        assert_eq!(b.decode(query, &response, 1000), Err(Error::Stale));
    }
}
