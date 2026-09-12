//! The proving and verifying keys, and the circuit they belong to.
//!
//! These are not test scaffolding: every spend needs the proving key, so a
//! release build has to be able to reach it. They live here rather than in
//! `testing` for that reason, and `testing` re-exports them so the test suite
//! keeps its existing spelling.
//!
//! Building either takes seconds and a lot of memory, so each is built once per
//! process and then shared. A caller that cares when that cost is paid — a
//! wallet on a phone, where it must not land on the first send — should call
//! [`proving_key`] from a background thread at startup and discard the result;
//! the second call returns the key already built.

use std::sync::OnceLock;

use orchard::circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey};

/// The circuit this wallet proves against.
///
/// Orchard and Ironwood share it: the circuit is pool-agnostic from NU6.3, so
/// one key serves both bundles and building it twice would only cost time.
pub const CIRCUIT: OrchardCircuitVersion = OrchardCircuitVersion::PostNu6_3;

/// Returns the proving key, built once per process.
pub fn proving_key() -> &'static ProvingKey {
    static PK: OnceLock<ProvingKey> = OnceLock::new();
    PK.get_or_init(|| ProvingKey::build(CIRCUIT))
}

/// Returns the verifying key, built once per process.
pub fn verifying_key() -> &'static VerifyingKey {
    static VK: OnceLock<VerifyingKey> = OnceLock::new();
    VK.get_or_init(|| VerifyingKey::build(CIRCUIT))
}
