//! Turning fetched bytes into a resolved wallet PIR config.
//!
//! Phases: static source and document → static anchor; declared mirror and
//! dynamic document → resolved config. A persisted snapshot replays both
//! phases from its exact bytes under the application's current source.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use zakura_pir_protocol::endpoint::Endpoint;
use zakura_service_config::{
    AttestationSelection, Attested, CandidateRank, ConfigSource, MirrorAttempt, MirrorError,
    MirrorResolution, ResolveError, TransportAuthenticated, fingerprint_bytes, resolve_dynamic,
    resolve_from_mirrors, resolve_static,
};

use crate::error::WalletPirConfigError;
use crate::profile::{WalletPirConfigProfile, WalletPirConfigScope};
use crate::schema::{
    DYNAMIC_CONFIG_VERSION, STATIC_CONFIG_VERSION, WalletPirDynamicConfig, WalletPirNetwork,
    WalletPirStaticConfig,
};
use crate::server::{AdvertisedServer, ServerBase};

const SHA256_PIN_QUERY_ITEM: &str = "checksum=sha256:";

/// A static document that matched its source's SHA-256 pin, serves the
/// wallet's network and passed schema checks.
///
/// Dynamic configs are resolved against an anchor; it decides which mirrors
/// may supply them and which attestation method authenticates them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletPirStaticAnchor {
    source: ConfigSource,
    source_fingerprint: String,
    document: WalletPirStaticConfig,
    static_config_json: String,
}

impl WalletPirStaticAnchor {
    /// The pinned source the static document was fetched from.
    pub fn source(&self) -> &ConfigSource {
        &self.source
    }

    /// [`ConfigSource::fingerprint`] of [`Self::source`], covering its pin.
    pub fn source_fingerprint(&self) -> &str {
        &self.source_fingerprint
    }

    pub fn network(&self) -> WalletPirNetwork {
        self.document.network
    }

    /// The declared dynamic config mirrors, in preference order. Fetch only
    /// these URLs.
    pub fn dynamic_config_urls(&self) -> &[String] {
        &self.document.dynamic_config_urls
    }

    pub fn attestation(&self) -> &AttestationSelection {
        &self.document.attestation
    }

    pub fn document(&self) -> &WalletPirStaticConfig {
        &self.document
    }
}

/// A dynamic config fetched from a declared mirror that validated and
/// attested under a static anchor.
///
/// An empty [`Self::servers`] list is a valid inactive config: the wallet
/// must send no private PIR traffic until a later config advertises a server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedWalletPirConfig<V = TransportAuthenticated> {
    pub(crate) scope: WalletPirConfigScope,
    network: WalletPirNetwork,
    pub(crate) servers: Vec<AdvertisedServer>,
    dynamic_config_fingerprint: String,
    attestation: Attested<V>,
    snapshot: WalletPirConfigSnapshot,
}

impl<V> ResolvedWalletPirConfig<V> {
    pub fn scope(&self) -> &WalletPirConfigScope {
        &self.scope
    }

    pub fn network(&self) -> WalletPirNetwork {
        self.network
    }

    /// Advertised servers in config order, each with a distinct base.
    pub fn servers(&self) -> &[AdvertisedServer] {
        &self.servers
    }

    /// Whether any server is advertised.
    pub fn is_active(&self) -> bool {
        !self.servers.is_empty()
    }

    /// The declared mirror the dynamic document was attributed to.
    pub fn dynamic_config_url(&self) -> &str {
        &self.snapshot.dynamic_config_url
    }

    /// Lowercase hex SHA-256 of the exact dynamic document bytes.
    pub fn dynamic_config_fingerprint(&self) -> &str {
        &self.dynamic_config_fingerprint
    }

    pub fn attestation(&self) -> &Attested<V> {
        &self.attestation
    }

    /// The exact inputs this config was resolved from, for persistence.
    pub fn snapshot(&self) -> &WalletPirConfigSnapshot {
        &self.snapshot
    }
}

/// The exact documents behind a resolved config, for an application to
/// persist as its last good config.
///
/// A snapshot is never trusted as stored: [`resolve_config_snapshot`]
/// re-runs every check, including the pin and attestation, under the
/// application's current source, network and profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletPirConfigSnapshot {
    /// The pinned static source string.
    pub source: String,
    pub static_config_json: String,
    /// The declared mirror the dynamic document came from.
    pub dynamic_config_url: String,
    pub dynamic_config_json: String,
}

/// Resolves a static document fetched from `source`.
///
/// `source` must be an HTTPS URL pinned with `checksum=sha256:<hex>`, and
/// `static_bytes` must hash to the pin. The document must have
/// `static_config_version` 1, serve `expected_network`, and declare a
/// non-empty list of distinct HTTPS mirrors without credentials, query or
/// fragment. The attestation selection is checked against the profile when a
/// dynamic document is resolved.
pub fn resolve_static_config(
    source: &str,
    static_bytes: &[u8],
    expected_network: WalletPirNetwork,
) -> Result<WalletPirStaticAnchor, WalletPirConfigError> {
    if ConfigSource::parse(source)?.sha256.is_none() {
        return Err(WalletPirConfigError::UnpinnedSource);
    }
    let resolved = resolve_static::<WalletPirStaticConfig>(source, static_bytes)?;
    let document = resolved.document;
    if document.static_config_version != STATIC_CONFIG_VERSION {
        return Err(WalletPirConfigError::UnsupportedStaticVersion {
            found: document.static_config_version,
        });
    }
    if document.network != expected_network {
        return Err(WalletPirConfigError::StaticNetworkMismatch {
            expected: expected_network,
            found: document.network,
        });
    }
    validate_mirror_urls(&document.dynamic_config_urls)?;
    Ok(WalletPirStaticAnchor {
        source: resolved.source,
        source_fingerprint: resolved.source_fingerprint,
        document,
        static_config_json: utf8_json(static_bytes, ResolveError::StaticDecode)?,
    })
}

/// Resolves a dynamic document the application fetched from
/// `dynamic_config_url`.
///
/// The URL must be one the anchor declares, compared exactly; bytes are never
/// accepted on their own as proof of where they came from. The document must
/// have `config_version` 1, serve the anchor's network, and list servers with
/// non-blank labels and distinct normalized HTTPS bases. It is then
/// authenticated with the attestation method the static document selected,
/// which must be one the profile accepts.
pub fn resolve_dynamic_config<V>(
    profile: &WalletPirConfigProfile<V>,
    anchor: &WalletPirStaticAnchor,
    dynamic_config_url: &str,
    dynamic_bytes: &[u8],
) -> Result<ResolvedWalletPirConfig<V>, WalletPirConfigError> {
    if !anchor
        .dynamic_config_urls()
        .iter()
        .any(|declared| declared == dynamic_config_url)
    {
        return Err(WalletPirConfigError::UndeclaredMirror {
            url: dynamic_config_url.to_string(),
        });
    }
    let resolved = resolve_dynamic(profile, anchor, dynamic_bytes)?;
    // Schema checks already passed inside `resolve_dynamic`; this pass only
    // keeps the normalized servers they produced.
    let servers = validate_dynamic_document(anchor, &resolved.document)?;
    Ok(ResolvedWalletPirConfig {
        scope: profile.scope(anchor),
        network: anchor.network(),
        servers,
        dynamic_config_fingerprint: resolved.fingerprint,
        attestation: resolved.attestation,
        snapshot: WalletPirConfigSnapshot {
            source: anchor.source.raw.clone(),
            static_config_json: anchor.static_config_json.clone(),
            dynamic_config_url: dynamic_config_url.to_string(),
            dynamic_config_json: utf8_json(dynamic_bytes, ResolveError::DynamicDecode)?,
        },
    })
}

/// Resolves the first mirror attempt that yields a valid config.
///
/// The application fetches the anchor's [`dynamic_config_urls`] in order,
/// with its own transport, deadlines and cancellation, and reports each
/// outcome. Attempts for undeclared URLs are rejected like invalid documents.
///
/// [`dynamic_config_urls`]: WalletPirStaticAnchor::dynamic_config_urls
pub fn resolve_config_from_attempts<V>(
    profile: &WalletPirConfigProfile<V>,
    anchor: &WalletPirStaticAnchor,
    attempts: impl IntoIterator<Item = MirrorAttempt>,
) -> Result<MirrorResolution<ResolvedWalletPirConfig<V>>, MirrorError<WalletPirConfigError>> {
    resolve_from_mirrors(
        attempts,
        |url, bytes| resolve_dynamic_config(profile, anchor, url, bytes),
        |_| CandidateRank::Preferred,
    )
}

/// Re-resolves a persisted snapshot under the application's current `source`
/// and `expected_network`.
///
/// Fails with [`WalletPirConfigError::SnapshotSourceChanged`] when the
/// snapshot was taken under another source or pin, so a config from an old
/// source is never reused; otherwise every resolution check runs again on the
/// stored bytes.
pub fn resolve_config_snapshot<V>(
    profile: &WalletPirConfigProfile<V>,
    snapshot: &WalletPirConfigSnapshot,
    source: &str,
    expected_network: WalletPirNetwork,
) -> Result<ResolvedWalletPirConfig<V>, WalletPirConfigError> {
    let snapshot_source = ConfigSource::parse(&snapshot.source)?;
    if snapshot_source.fingerprint() != ConfigSource::parse(source)?.fingerprint() {
        return Err(WalletPirConfigError::SnapshotSourceChanged);
    }
    let anchor = resolve_static_config(
        source,
        snapshot.static_config_json.as_bytes(),
        expected_network,
    )?;
    resolve_dynamic_config(
        profile,
        &anchor,
        &snapshot.dynamic_config_url,
        snapshot.dynamic_config_json.as_bytes(),
    )
}

/// Pins `source_url` to the SHA-256 of `static_bytes`, producing the source
/// string an application ships.
///
/// The URL must be HTTPS and not already pinned. Other query items are kept.
pub fn pin_static_config_source(
    source_url: &str,
    static_bytes: &[u8],
) -> Result<ConfigSource, WalletPirConfigError> {
    let source_url = source_url.trim();
    if ConfigSource::parse(source_url)?.sha256.is_some() {
        return Err(WalletPirConfigError::SourceAlreadyPinned);
    }
    let separator = if source_url.contains('?') { '&' } else { '?' };
    let pinned = format!(
        "{source_url}{separator}{SHA256_PIN_QUERY_ITEM}{}",
        fingerprint_bytes(static_bytes)
    );
    Ok(ConfigSource::parse(&pinned)?)
}

/// Checks a dynamic document against its anchor and returns its servers.
pub(crate) fn validate_dynamic_document(
    anchor: &WalletPirStaticAnchor,
    document: &WalletPirDynamicConfig,
) -> Result<Vec<AdvertisedServer>, WalletPirConfigError> {
    if document.config_version != DYNAMIC_CONFIG_VERSION {
        return Err(WalletPirConfigError::UnsupportedDynamicVersion {
            found: document.config_version,
        });
    }
    if document.network != anchor.network() {
        return Err(WalletPirConfigError::DynamicNetworkMismatch {
            expected: anchor.network(),
            found: document.network,
        });
    }
    let mut servers: Vec<AdvertisedServer> = Vec::with_capacity(document.servers.len());
    for (index, entry) in document.servers.iter().enumerate() {
        if entry.label.trim().is_empty() {
            return Err(WalletPirConfigError::BlankServerLabel { index });
        }
        let base = ServerBase::parse(&entry.url).map_err(|reason| {
            WalletPirConfigError::InvalidServerUrl {
                index,
                url: entry.url.clone(),
                reason,
            }
        })?;
        if servers.iter().any(|earlier| earlier.base == base) {
            return Err(WalletPirConfigError::DuplicateServer { index, base });
        }
        servers.push(AdvertisedServer {
            label: entry.label.clone(),
            base,
        });
    }
    Ok(servers)
}

/// Mirrors use the same strict endpoint syntax as servers, and must be
/// distinct after normalization.
fn validate_mirror_urls(urls: &[String]) -> Result<(), WalletPirConfigError> {
    if urls.is_empty() {
        return Err(WalletPirConfigError::NoMirrors);
    }
    let mut normalized = BTreeSet::new();
    for (index, url) in urls.iter().enumerate() {
        let invalid = || WalletPirConfigError::InvalidMirrorUrl {
            index,
            url: url.clone(),
        };
        let endpoint = Endpoint::parse(url).map_err(|_| invalid())?;
        // Exact-string attribution would be ambiguous for a URL that only
        // matches after trimming.
        if !endpoint.is_https() || url.trim() != url {
            return Err(invalid());
        }
        if !normalized.insert(endpoint.join("/").map_err(|_| invalid())?) {
            return Err(WalletPirConfigError::DuplicateMirrorUrl {
                index,
                url: url.clone(),
            });
        }
    }
    Ok(())
}

/// Keeps the exact document text; JSON that decoded is always UTF-8.
fn utf8_json(
    bytes: &[u8],
    decode_error: fn(String) -> ResolveError,
) -> Result<String, WalletPirConfigError> {
    String::from_utf8(bytes.to_vec())
        .map_err(|_| decode_error("document is not UTF-8".to_string()).into())
}
