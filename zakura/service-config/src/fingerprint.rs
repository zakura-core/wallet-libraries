//! Stable fingerprints for comparing config material across runs.

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Lowercase hex SHA-256 of `bytes`.
pub fn fingerprint_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Lowercase hex SHA-256 of the compact JSON encoding of `value`.
///
/// The fingerprint is stable as long as the type's serialized field order is,
/// so persisted fingerprints compare equal across builds.
///
/// # Panics
///
/// Panics if `value` cannot be serialized to JSON, which for config types
/// (plain structs, strings, sequences and string-keyed maps) cannot happen.
pub fn fingerprint_json<T: Serialize + ?Sized>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("config values serialize to JSON");
    fingerprint_bytes(&bytes)
}
