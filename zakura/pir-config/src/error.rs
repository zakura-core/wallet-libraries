//! Why a wallet PIR config was rejected.

use thiserror::Error;
use zakura_service_config::{ResolveError, SourceError};

use crate::schema::WalletPirNetwork;
use crate::server::{InvalidServerBase, ServerBase};

/// A static source, static document, dynamic document or snapshot that cannot
/// be used. Messages name the offending field and are suitable for logs.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum WalletPirConfigError {
    /// Source parsing, pin mismatch, JSON decoding or attestation failed.
    #[error(transparent)]
    Resolve(#[from] ResolveError),
    /// Wallet PIR static sources must carry `checksum=sha256:<hex>`.
    #[error("static config source must be pinned with checksum=sha256:<hex>")]
    UnpinnedSource,
    /// [`crate::pin_static_config_source`] was given a source that already
    /// has a pin.
    #[error("static config source is already pinned")]
    SourceAlreadyPinned,
    #[error("static_config_version {found} is not supported; expected 1")]
    UnsupportedStaticVersion { found: u32 },
    #[error("dynamic config_version {found} is not supported; expected 1")]
    UnsupportedDynamicVersion { found: u32 },
    /// The static document serves another network than the wallet's.
    #[error("static config network is {found}, expected {expected}")]
    StaticNetworkMismatch {
        expected: WalletPirNetwork,
        found: WalletPirNetwork,
    },
    /// The dynamic document serves another network than its static document.
    #[error("dynamic config network is {found}, expected {expected}")]
    DynamicNetworkMismatch {
        expected: WalletPirNetwork,
        found: WalletPirNetwork,
    },
    #[error("dynamic_config_urls must contain at least one mirror")]
    NoMirrors,
    #[error("dynamic_config_urls[{index}] {url:?} is not a plain https URL")]
    InvalidMirrorUrl { index: usize, url: String },
    #[error("dynamic_config_urls[{index}] {url:?} duplicates an earlier mirror")]
    DuplicateMirrorUrl { index: usize, url: String },
    /// Dynamic bytes were attributed to a URL the static document does not
    /// list. Only declared mirrors may supply a dynamic config.
    #[error("dynamic config URL {url:?} is not declared by the static config")]
    UndeclaredMirror { url: String },
    #[error("servers[{index}].label must not be blank")]
    BlankServerLabel { index: usize },
    #[error("servers[{index}].url {url:?} is invalid: {reason}")]
    InvalidServerUrl {
        index: usize,
        url: String,
        reason: InvalidServerBase,
    },
    /// Two entries normalize to the same base URL.
    #[error("servers[{index}].url duplicates an earlier server {base}")]
    DuplicateServer { index: usize, base: ServerBase },
    /// A persisted snapshot was taken under another static source or pin.
    #[error("config snapshot belongs to another static config source")]
    SnapshotSourceChanged,
}

impl From<SourceError> for WalletPirConfigError {
    fn from(error: SourceError) -> Self {
        Self::Resolve(ResolveError::Source(error))
    }
}
