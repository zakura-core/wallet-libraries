//! The wallet PIR attestation policy and the scope a config is valid in.

use serde::{Deserialize, Serialize};
use zakura_service_config::{
    AttestationMethod, AttestationPolicy, AttestationSelection, ConfigProfile, HttpsTransport,
    TransportAuthenticated, fingerprint_json,
};

use crate::error::WalletPirConfigError;
use crate::resolve::{WalletPirStaticAnchor, validate_dynamic_document};
use crate::schema::{WalletPirDynamicConfig, WalletPirNetwork};

/// The attestation methods a wallet accepts for dynamic wallet PIR configs.
///
/// A static document must select one of these methods; it can never enable
/// another, and there is no default when it selects none. `V` is what a
/// successful attestation establishes.
pub struct WalletPirConfigProfile<V = TransportAuthenticated> {
    attestation: AttestationPolicy<WalletPirStaticAnchor, WalletPirDynamicConfig, V>,
}

impl WalletPirConfigProfile<TransportAuthenticated> {
    /// Accepts only [`HttpsTransport`]: a dynamic document is trusted because
    /// the application fetched it over HTTPS from a mirror the hash-pinned
    /// static document declares.
    pub fn https_transport() -> Self {
        let attestation = AttestationPolicy::new()
            .allow(HttpsTransport::method(), HttpsTransport)
            .expect("a new policy has no method registered yet");
        Self { attestation }
    }
}

impl Default for WalletPirConfigProfile<TransportAuthenticated> {
    fn default() -> Self {
        Self::https_transport()
    }
}

impl<V> WalletPirConfigProfile<V> {
    /// Accepts the methods registered in `attestation`, for applications that
    /// authenticate dynamic documents differently (for example with signed
    /// entries). A default method on the policy is never used, because the
    /// wallet PIR static schema always selects one.
    pub fn with_attestation_policy(
        attestation: AttestationPolicy<WalletPirStaticAnchor, WalletPirDynamicConfig, V>,
    ) -> Self {
        Self { attestation }
    }

    /// The scope configs and selections resolved under `anchor` belong to.
    pub fn scope(&self, anchor: &WalletPirStaticAnchor) -> WalletPirConfigScope {
        #[derive(Serialize)]
        struct ScopeIdentity<'a> {
            source_fingerprint: &'a str,
            network: WalletPirNetwork,
            allowed_attestation_methods: Vec<&'a AttestationMethod>,
        }
        WalletPirConfigScope(fingerprint_json(&ScopeIdentity {
            source_fingerprint: anchor.source_fingerprint(),
            network: anchor.network(),
            allowed_attestation_methods: self.attestation.allowed_methods().collect(),
        }))
    }
}

impl<V> ConfigProfile for WalletPirConfigProfile<V> {
    type Anchor = WalletPirStaticAnchor;
    type Dynamic = WalletPirDynamicConfig;
    type Verdict = V;
    type Error = WalletPirConfigError;

    fn attestation(&self) -> &AttestationPolicy<WalletPirStaticAnchor, WalletPirDynamicConfig, V> {
        &self.attestation
    }

    fn attestation_selection<'a>(
        &self,
        anchor: &'a WalletPirStaticAnchor,
    ) -> Option<&'a AttestationSelection> {
        Some(anchor.attestation())
    }

    fn validate_dynamic(
        &self,
        anchor: &WalletPirStaticAnchor,
        document: &WalletPirDynamicConfig,
    ) -> Result<(), WalletPirConfigError> {
        validate_dynamic_document(anchor, document).map(drop)
    }
}

/// Identity of the trust context a config was resolved in: the static source
/// with its pin, the wallet network and the accepted attestation methods.
///
/// A persisted config or server selection is only reused under the same
/// scope, so changing the source, pin, network or policy starts afresh. The
/// policy is identified by its method names; changing a verifier's behavior
/// under an existing name does not change the scope.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WalletPirConfigScope(String);

impl WalletPirConfigScope {
    /// Lowercase hex fingerprint of the scope.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
