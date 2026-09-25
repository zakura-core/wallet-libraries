use zcash_address::ZcashAddress;
use zcash_keys::address::Address;
use zcash_protocol::consensus::NetworkType;

const MAGIC: &[u8; 5] = b"\xffZSWP";
const ADDRESS_START: usize = 17;
const MAX_ADDRESS_LEN: usize = 512 - ADDRESS_START;

/// An invalid or unsupported refund recovery record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoError {
    /// Keep this record pending until its version can be interpreted.
    UnsupportedVersion(u8),
    /// Version one only stores refund indices in funding memos.
    InvalidPurpose(u8),
    /// The address must occupy between 1 and 495 bytes.
    InvalidLength,
    /// The address is not valid ASCII, a supported address, or for this network.
    InvalidAddress,
    /// Bytes after the address must all be zero.
    NonzeroPadding,
}

impl core::fmt::Display for MemoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => write!(f, "unsupported swap memo version {v}"),
            Self::InvalidPurpose(p) => write!(f, "invalid swap memo purpose {p}"),
            Self::InvalidLength => f.write_str("invalid swap memo address length"),
            Self::InvalidAddress => f.write_str("invalid swap memo deposit address or network"),
            Self::NonzeroPadding => f.write_str("nonzero swap memo padding"),
        }
    }
}

impl std::error::Error for MemoError {}

/// A v1 refund index and its exact NEAR deposit address.
///
/// Decoding does not establish provenance. Accept a record only after
/// authenticating an ordinary internal note and verifying that its transaction
/// was the wallet's own send. Process zero-value and spent notes too.
#[derive(Clone, PartialEq, Eq)]
pub struct RefundMemo {
    index: u64,
    deposit_address: String,
}

impl core::fmt::Debug for RefundMemo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RefundMemo").finish_non_exhaustive()
    }
}

impl RefundMemo {
    /// Validates the deposit address for the funding transaction's network.
    pub fn new(network: NetworkType, index: u64, deposit_address: &str) -> Result<Self, MemoError> {
        if deposit_address.is_empty() || deposit_address.len() > MAX_ADDRESS_LEN {
            return Err(MemoError::InvalidLength);
        }
        // The generic address parser trims whitespace. Recovery must preserve
        // the exact provider lookup address, not silently normalize its bytes.
        if !deposit_address.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(MemoError::InvalidAddress);
        }
        let address = ZcashAddress::try_from_encoded(deposit_address)
            .map_err(|_| MemoError::InvalidAddress)?;
        address
            .convert_if_network::<Address>(network)
            .map_err(|_| MemoError::InvalidAddress)?;
        Ok(Self {
            index,
            deposit_address: deposit_address.to_owned(),
        })
    }

    /// The index in the refund sequence, not a globally unique operation ID.
    pub fn index(&self) -> u64 {
        self.index
    }

    /// The exact address used for the funding deposit and provider status lookup.
    pub fn deposit_address(&self) -> &str {
        &self.deposit_address
    }

    /// Encodes the fixed 512-byte binary memo, including zero padding.
    pub fn encode(&self) -> [u8; 512] {
        let mut bytes = [0; 512];
        bytes[..5].copy_from_slice(MAGIC);
        bytes[5] = 1;
        bytes[6] = 0;
        bytes[7..15].copy_from_slice(&self.index.to_le_bytes());
        bytes[15..17].copy_from_slice(&(self.deposit_address.len() as u16).to_le_bytes());
        bytes[ADDRESS_START..ADDRESS_START + self.deposit_address.len()]
            .copy_from_slice(self.deposit_address.as_bytes());
        bytes
    }

    /// Decodes a record, returning `None` only for a memo without our discriminator.
    ///
    /// Unsupported versions are errors so callers cannot silently mark their
    /// recovery work complete. Preserve those raw memos for a future decoder.
    pub fn decode(network: NetworkType, bytes: &[u8; 512]) -> Result<Option<Self>, MemoError> {
        if &bytes[..5] != MAGIC {
            return Ok(None);
        }
        if bytes[5] != 1 {
            return Err(MemoError::UnsupportedVersion(bytes[5]));
        }
        if bytes[6] != 0 {
            return Err(MemoError::InvalidPurpose(bytes[6]));
        }
        let len = u16::from_le_bytes(bytes[15..17].try_into().expect("two-byte length")) as usize;
        if len == 0 || len > MAX_ADDRESS_LEN {
            return Err(MemoError::InvalidLength);
        }
        let end = ADDRESS_START + len;
        if bytes[end..].iter().any(|b| *b != 0) {
            return Err(MemoError::NonzeroPadding);
        }
        let index = u64::from_le_bytes(bytes[7..15].try_into().expect("eight-byte index"));
        let address = core::str::from_utf8(&bytes[ADDRESS_START..end])
            .map_err(|_| MemoError::InvalidAddress)?;
        Self::new(network, index, address).map(Some)
    }
}
