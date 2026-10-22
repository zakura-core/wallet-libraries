//! Pluggable authentication of dynamic config documents.
//!
//! An *attestation method* is a named way of deciding that a dynamic document
//! is authentic, such as "signed entries under keys in the static config" or
//! "fetched over HTTPS from a pinned static source". The application registers
//! the methods it accepts; the static document can select one by name and
//! carry its public trust data, but cannot enable an unregistered method.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Registered name of an attestation method, such as `https-transport`.
///
/// Names are non-empty and use lowercase ASCII letters, digits, `-` and `.`,
/// so they compare and log unambiguously.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AttestationMethod(String);

impl AttestationMethod {
    /// Validates a method name.
    pub fn new(name: impl Into<String>) -> Result<Self, AttestationError> {
        let name = name.into();
        let valid = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.');
        if valid {
            Ok(Self(name))
        } else {
            Err(AttestationError::InvalidMethodName { name })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AttestationMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for AttestationMethod {
    type Error = AttestationError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        Self::new(name)
    }
}

impl From<AttestationMethod> for String {
    fn from(method: AttestationMethod) -> Self {
        method.0
    }
}

/// The attestation a static document asks for.
///
/// Serialized as `{"method": "...", "trust": ...}`. `trust` is public material
/// interpreted only by the selected method's verifier (keys, key ids, expected
/// origins); it defaults to `null` for methods that need none.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationSelection {
    pub method: AttestationMethod,
    #[serde(default)]
    pub trust: Value,
}

/// Everything a verifier may inspect for one dynamic document.
#[derive(Debug)]
pub struct AttestationSubject<'a, A, D> {
    /// The application's resolved static trust anchor.
    pub anchor: &'a A,
    /// Public trust data from the selection, or `null` for a default method.
    pub trust: &'a Value,
    /// The dynamic document bytes exactly as fetched.
    pub raw: &'a [u8],
    /// The decoded dynamic document.
    pub document: &'a D,
}

/// One attestation method's verification logic.
///
/// `A` is the static trust anchor, `D` the decoded dynamic document and
/// `Verdict` what a successful verification establishes. A verdict may be
/// partial (for example, the subset of entries whose signatures verified);
/// returning an error rejects the whole document.
pub trait AttestationVerifier<A, D>: Send + Sync {
    type Verdict;

    fn verify(
        &self,
        subject: AttestationSubject<'_, A, D>,
    ) -> Result<Self::Verdict, AttestationError>;
}

/// A successful attestation and the method that produced it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attested<V> {
    pub method: AttestationMethod,
    pub verdict: V,
}

/// Attestation configuration or verification failures.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AttestationError {
    #[error("invalid attestation method name {name:?}")]
    InvalidMethodName { name: String },
    /// The application registered the same method twice.
    #[error("attestation method {method} is already registered")]
    DuplicateMethod { method: AttestationMethod },
    /// The static document selected a method the application does not accept.
    #[error("attestation method {method} is not allowed; allowed: {}", allowed.join(","))]
    UnsupportedMethod {
        method: AttestationMethod,
        allowed: Vec<String>,
    },
    /// No method was selected and the policy has no default.
    #[error("static config selects no attestation method and the application has no default")]
    MissingSelection,
    /// The selection's trust data does not fit the method.
    #[error("attestation method {method} trust data is invalid: {message}")]
    InvalidTrustData {
        method: AttestationMethod,
        message: String,
    },
    /// The verifier rejected the document.
    #[error("attestation method {method} rejected the document: {message}")]
    Rejected {
        method: AttestationMethod,
        message: String,
    },
}

type BoxedVerifier<A, D, V> = Box<dyn AttestationVerifier<A, D, Verdict = V>>;

/// The attestation methods an application accepts, and its default.
///
/// The default applies to static documents that select no method, which lets
/// an existing config schema without an attestation field keep its original
/// authentication rule.
pub struct AttestationPolicy<A, D, V> {
    verifiers: BTreeMap<AttestationMethod, BoxedVerifier<A, D, V>>,
    default_method: Option<AttestationMethod>,
}

impl<A, D, V> Default for AttestationPolicy<A, D, V> {
    fn default() -> Self {
        Self {
            verifiers: BTreeMap::new(),
            default_method: None,
        }
    }
}

impl<A, D, V> fmt::Debug for AttestationPolicy<A, D, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttestationPolicy")
            .field("methods", &self.verifiers.keys().collect::<Vec<_>>())
            .field("default_method", &self.default_method)
            .finish()
    }
}

impl<A, D, V> AttestationPolicy<A, D, V> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accepts `method`, verified by `verifier`.
    pub fn allow(
        mut self,
        method: AttestationMethod,
        verifier: impl AttestationVerifier<A, D, Verdict = V> + 'static,
    ) -> Result<Self, AttestationError> {
        if self.verifiers.contains_key(&method) {
            return Err(AttestationError::DuplicateMethod { method });
        }
        self.verifiers.insert(method, Box::new(verifier));
        Ok(self)
    }

    /// Uses `method`, which must already be allowed, when a static document
    /// selects none.
    pub fn with_default(mut self, method: AttestationMethod) -> Result<Self, AttestationError> {
        if !self.verifiers.contains_key(&method) {
            return Err(self.unsupported(method));
        }
        self.default_method = Some(method);
        Ok(self)
    }

    /// Allowed method names, in sorted order.
    pub fn allowed_methods(&self) -> impl Iterator<Item = &AttestationMethod> {
        self.verifiers.keys()
    }

    /// Verifies a dynamic document with the selected method, or the default
    /// when `selection` is `None`.
    ///
    /// # Errors
    ///
    /// [`AttestationError::UnsupportedMethod`] when the selection names an
    /// unregistered method, [`AttestationError::MissingSelection`] when nothing
    /// is selected and there is no default, or the verifier's own error.
    pub fn verify(
        &self,
        selection: Option<&AttestationSelection>,
        anchor: &A,
        raw: &[u8],
        document: &D,
    ) -> Result<Attested<V>, AttestationError> {
        const NO_TRUST: Value = Value::Null;
        let (method, trust) = match selection {
            Some(selection) => (&selection.method, &selection.trust),
            None => (
                self.default_method
                    .as_ref()
                    .ok_or(AttestationError::MissingSelection)?,
                &NO_TRUST,
            ),
        };
        let verifier = self
            .verifiers
            .get(method)
            .ok_or_else(|| self.unsupported(method.clone()))?;
        let verdict = verifier.verify(AttestationSubject {
            anchor,
            trust,
            raw,
            document,
        })?;
        Ok(Attested {
            method: method.clone(),
            verdict,
        })
    }

    fn unsupported(&self, method: AttestationMethod) -> AttestationError {
        AttestationError::UnsupportedMethod {
            method,
            allowed: self.verifiers.keys().map(|m| m.to_string()).collect(),
        }
    }
}

/// Verdict of [`HttpsTransport`]: the document is trusted because it arrived
/// over TLS from a URL named by the (optionally pinned) static document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportAuthenticated;

/// Accepts a dynamic document on the strength of its HTTPS transport alone.
///
/// The application must fetch only `https://` URLs taken from the resolved
/// static document; this verifier adds no cryptographic check of its own. It
/// takes no trust data and rejects a selection that supplies any, so a
/// misconfigured static document fails loudly instead of being ignored.
#[derive(Clone, Copy, Debug, Default)]
pub struct HttpsTransport;

impl HttpsTransport {
    /// Registered name of this method.
    pub const METHOD: &'static str = "https-transport";

    pub fn method() -> AttestationMethod {
        AttestationMethod(Self::METHOD.to_string())
    }
}

impl<A, D> AttestationVerifier<A, D> for HttpsTransport {
    type Verdict = TransportAuthenticated;

    fn verify(
        &self,
        subject: AttestationSubject<'_, A, D>,
    ) -> Result<TransportAuthenticated, AttestationError> {
        if subject.trust.is_null() {
            Ok(TransportAuthenticated)
        } else {
            Err(AttestationError::InvalidTrustData {
                method: Self::method(),
                message: "https-transport takes no trust data".to_string(),
            })
        }
    }
}
