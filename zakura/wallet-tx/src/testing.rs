//! Helpers for exercising the spend path.

use orchard::circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey};

/// The circuit this wallet proves against.
///
/// Orchard and Ironwood share it: the circuit is pool-agnostic from NU6.3, so
/// one key serves both bundles and building it twice would only cost time.
const CIRCUIT: OrchardCircuitVersion = OrchardCircuitVersion::PostNu6_3;

/// Returns the proving key, built once per process.
///
/// Building it takes seconds, and every test that proves anything needs the
/// same one.
pub fn proving_key() -> &'static ProvingKey {
    use std::sync::OnceLock;
    static PK: OnceLock<ProvingKey> = OnceLock::new();
    PK.get_or_init(|| ProvingKey::build(CIRCUIT))
}

/// Returns the verifying key, built once per process.
pub fn verifying_key() -> &'static VerifyingKey {
    use std::sync::OnceLock;
    static VK: OnceLock<VerifyingKey> = OnceLock::new();
    VK.get_or_init(|| VerifyingKey::build(CIRCUIT))
}
