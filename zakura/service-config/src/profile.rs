//! Application profiles and the static-then-dynamic resolution steps.

use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::{
    attestation::{AttestationError, AttestationPolicy, AttestationSelection, Attested},
    fingerprint::fingerprint_bytes,
    source::{ConfigSource, PinCheck, PinMismatch, SourceError},
};

/// One application's dynamic config schema and authentication rules.
///
/// `Anchor` is whatever the application keeps from its resolved static
/// document to authenticate dynamic documents with (trusted keys, a network
/// identity, an attestation selection). Implementations add their own schema
/// checks in [`Self::validate_dynamic`]; generic decoding, attestation and
/// fingerprinting happen in [`resolve_dynamic`].
pub trait ConfigProfile {
    type Anchor;
    type Dynamic: DeserializeOwned;
    type Verdict;
    /// Application error; generic failures arrive through `From<ResolveError>`.
    type Error: From<ResolveError>;

    /// The attestation methods this application accepts.
    fn attestation(&self) -> &AttestationPolicy<Self::Anchor, Self::Dynamic, Self::Verdict>;

    /// The method the static document selected, if its schema has one.
    /// `None` uses the policy's default method.
    fn attestation_selection<'a>(
        &self,
        anchor: &'a Self::Anchor,
    ) -> Option<&'a AttestationSelection> {
        let _ = anchor;
        None
    }

    /// Application schema checks, run after decoding and before attestation.
    fn validate_dynamic(
        &self,
        anchor: &Self::Anchor,
        document: &Self::Dynamic,
    ) -> Result<(), Self::Error> {
        let _ = (anchor, document);
        Ok(())
    }
}

/// Generic resolution failures. The messages are suitable for users and logs.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ResolveError {
    #[error(transparent)]
    Source(#[from] SourceError),
    #[error("static config {0}")]
    PinMismatch(#[from] PinMismatch),
    #[error("static config decode failed: {0}")]
    StaticDecode(String),
    #[error("dynamic config decode failed: {0}")]
    DynamicDecode(String),
    #[error(transparent)]
    Attestation(#[from] AttestationError),
}

/// A static document whose source parsed and whose bytes matched the pin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedStatic<S> {
    pub source: ConfigSource,
    /// [`ConfigSource::fingerprint`] of `source`.
    pub source_fingerprint: String,
    pub pin: PinCheck,
    pub document: S,
}

/// A dynamic document that decoded, validated and attested.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedDynamic<D, V> {
    pub document: D,
    /// Fingerprint of the exact fetched bytes.
    pub fingerprint: String,
    pub attestation: Attested<V>,
}

/// Parses `source`, checks `bytes` against its pin and decodes the JSON
/// static document.
///
/// The pin is checked before decoding, so a tampered document is reported as
/// a pin mismatch rather than a decode error. Schema checks beyond JSON shape
/// are the caller's.
pub fn resolve_static<S: DeserializeOwned>(
    source: &str,
    bytes: &[u8],
) -> Result<ResolvedStatic<S>, ResolveError> {
    let source = ConfigSource::parse(source)?;
    let pin = source.verify_pin(bytes)?;
    let document =
        serde_json::from_slice(bytes).map_err(|e| ResolveError::StaticDecode(e.to_string()))?;
    Ok(ResolvedStatic {
        source_fingerprint: source.fingerprint(),
        source,
        pin,
        document,
    })
}

/// Decodes, validates and attests one dynamic document.
///
/// Steps run in order and stop at the first failure: JSON decode,
/// [`ConfigProfile::validate_dynamic`], then the selected (or default)
/// attestation method, which sees both `bytes` and the decoded document.
pub fn resolve_dynamic<P: ConfigProfile>(
    profile: &P,
    anchor: &P::Anchor,
    bytes: &[u8],
) -> Result<ResolvedDynamic<P::Dynamic, P::Verdict>, P::Error> {
    let document: P::Dynamic =
        serde_json::from_slice(bytes).map_err(|e| ResolveError::DynamicDecode(e.to_string()))?;
    profile.validate_dynamic(anchor, &document)?;
    let attestation = profile
        .attestation()
        .verify(
            profile.attestation_selection(anchor),
            anchor,
            bytes,
            &document,
        )
        .map_err(ResolveError::from)?;
    Ok(ResolvedDynamic {
        document,
        fingerprint: fingerprint_bytes(bytes),
        attestation,
    })
}
