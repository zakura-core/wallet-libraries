use core::fmt;

/// Invalid key-lifecycle input or failed signature verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A wallet seed must contain 32 through 64 bytes.
    InvalidSeedLength(usize),
    /// An encoded origin must contain exactly [`crate::ORIGIN_BYTES`] bytes.
    InvalidOriginLength(usize),
    /// The origin uses an unimplemented derivation version.
    UnsupportedVersion(u8),
    /// The origin uses an unassigned network code.
    UnsupportedNetwork(u8),
    /// The origin uses an unassigned receiving/change branch code.
    UnsupportedBranch(u8),
    /// A public key must contain exactly [`crate::PUBLIC_KEY_BYTES`] bytes.
    InvalidPublicKeyLength(usize),
    /// A signature must contain exactly [`crate::SIGNATURE_BYTES`] bytes.
    InvalidSignatureLength(usize),
    /// A Pure SLH-DSA context cannot exceed 255 bytes.
    ContextTooLong(usize),
    /// The signature does not authenticate the supplied key, message, and context.
    InvalidSignature,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSeedLength(length) => {
                write!(f, "wallet seed length {length} is outside 32..=64 bytes")
            }
            Self::InvalidOriginLength(length) => write!(f, "invalid key origin length: {length}"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported PQ derivation version: {version}")
            }
            Self::UnsupportedNetwork(network) => {
                write!(f, "unsupported PQ network code: {network}")
            }
            Self::UnsupportedBranch(branch) => write!(f, "unsupported PQ branch code: {branch}"),
            Self::InvalidPublicKeyLength(length) => {
                write!(f, "invalid PQ public key length: {length}")
            }
            Self::InvalidSignatureLength(length) => {
                write!(f, "invalid PQ signature length: {length}")
            }
            Self::ContextTooLong(length) => {
                write!(f, "SLH-DSA context exceeds 255 bytes: {length}")
            }
            Self::InvalidSignature => f.write_str("invalid SLH-DSA signature"),
        }
    }
}

impl core::error::Error for Error {}
