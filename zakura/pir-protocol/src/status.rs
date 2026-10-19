//! Status publication contract and accepted chain evidence.
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
pub fn anchor_accepted(manifest: &Manifest, accepted: &dyn AnchorVerifier) -> bool {
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
