//! A small application profile used by the integration tests: a static
//! document naming dynamic mirrors and an optional attestation selection, and
//! a dynamic document advertising labeled servers.

#![allow(dead_code)]

use serde::Deserialize;
use sha2::{Digest, Sha256};
use zakura_service_config::{
    AttestationError, AttestationMethod, AttestationPolicy, AttestationSelection,
    AttestationSubject, AttestationVerifier, ConfigProfile, HttpsTransport, LabeledEndpoint,
    ResolveError, validate_labeled_endpoints,
};

#[derive(Debug, Deserialize)]
pub struct StaticDocument {
    pub network: String,
    pub dynamic_config_urls: Vec<String>,
    #[serde(default)]
    pub attestation: Option<AttestationSelection>,
}

#[derive(Debug, Deserialize)]
pub struct DynamicDocument {
    pub network: String,
    pub servers: Vec<LabeledEndpoint>,
}

/// What both test methods establish, so they can share one policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Transport,
    DigestMatched,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AppError {
    Generic(ResolveError),
    WrongNetwork,
    Servers(String),
}

impl From<ResolveError> for AppError {
    fn from(error: ResolveError) -> Self {
        Self::Generic(error)
    }
}

/// Accepts a dynamic document whose raw bytes hash to the hex digest given as
/// trust data. Exercises verifier access to raw bytes and trust data.
pub struct DigestAttestation;

pub const DIGEST_METHOD: &str = "test-digest";

impl AttestationVerifier<StaticDocument, DynamicDocument> for DigestAttestation {
    type Verdict = Verdict;

    fn verify(
        &self,
        subject: AttestationSubject<'_, StaticDocument, DynamicDocument>,
    ) -> Result<Verdict, AttestationError> {
        let method = AttestationMethod::new(DIGEST_METHOD)?;
        let expected =
            subject
                .trust
                .as_str()
                .ok_or_else(|| AttestationError::InvalidTrustData {
                    method: method.clone(),
                    message: "expected a hex digest string".to_string(),
                })?;
        if hex::encode(Sha256::digest(subject.raw)) == expected {
            Ok(Verdict::DigestMatched)
        } else {
            Err(AttestationError::Rejected {
                method,
                message: "digest mismatch".to_string(),
            })
        }
    }
}

/// [`HttpsTransport`] mapped to the shared verdict type.
pub struct Transport;

impl AttestationVerifier<StaticDocument, DynamicDocument> for Transport {
    type Verdict = Verdict;

    fn verify(
        &self,
        subject: AttestationSubject<'_, StaticDocument, DynamicDocument>,
    ) -> Result<Verdict, AttestationError> {
        AttestationVerifier::<StaticDocument, DynamicDocument>::verify(&HttpsTransport, subject)
            .map(|_| Verdict::Transport)
    }
}

pub struct TestProfile {
    pub policy: AttestationPolicy<StaticDocument, DynamicDocument, Verdict>,
}

impl TestProfile {
    /// HTTPS transport by default, with the digest method selectable.
    pub fn new() -> Self {
        let policy = AttestationPolicy::new()
            .allow(HttpsTransport::method(), Transport)
            .unwrap()
            .allow(
                AttestationMethod::new(DIGEST_METHOD).unwrap(),
                DigestAttestation,
            )
            .unwrap()
            .with_default(HttpsTransport::method())
            .unwrap();
        Self { policy }
    }
}

impl ConfigProfile for TestProfile {
    type Anchor = StaticDocument;
    type Dynamic = DynamicDocument;
    type Verdict = Verdict;
    type Error = AppError;

    fn attestation(&self) -> &AttestationPolicy<StaticDocument, DynamicDocument, Verdict> {
        &self.policy
    }

    fn attestation_selection<'a>(
        &self,
        anchor: &'a StaticDocument,
    ) -> Option<&'a AttestationSelection> {
        anchor.attestation.as_ref()
    }

    fn validate_dynamic(
        &self,
        anchor: &StaticDocument,
        document: &DynamicDocument,
    ) -> Result<(), AppError> {
        if anchor.network != document.network {
            return Err(AppError::WrongNetwork);
        }
        validate_labeled_endpoints(&document.servers, "servers")
            .map_err(|e| AppError::Servers(e.to_string()))
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub const STATIC_JSON: &str = r#"{"network":"main","dynamic_config_urls":["https://a.example/d.json","https://b.example/d.json"]}"#;

pub const DYNAMIC_JSON: &str = r#"{"network":"main","servers":[{"label":"Primary","url":"https://pir1.example"},{"label":"Backup","url":"https://pir2.example"}]}"#;

pub fn static_document(attestation: Option<&str>) -> StaticDocument {
    let json = match attestation {
        Some(selection) => format!(
            r#"{{"network":"main","dynamic_config_urls":["https://a.example/d.json"],"attestation":{selection}}}"#
        ),
        None => STATIC_JSON.to_string(),
    };
    serde_json::from_str(&json).unwrap()
}
