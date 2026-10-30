//! Deterministic, privately derived SLH-DSA-SHA2-128f and SHA2-192s wallet keys.
//!
//! This unpublished experiment implements the key lifecycle only. It does not
//! issue addresses, allocate indices, count signatures, or authorize transactions.
//! The caller preserves the seed and [`KeyOrigin`] and owns those wallet policies.
//! The exact derivation and security assumptions are specified in the crate README.
//!
//! ```
//! use transparent_pq_keys::{Branch, KeyOrigin, Network, ParameterSet, WalletSeed};
//!
//! // Public example material. A real seed must come from a secure entropy source.
//! let seed = WalletSeed::from_bytes(&[0x42; 32])?;
//! let origin = KeyOrigin::new(ParameterSet::Sha2_128f, Network::Testnet, 0, Branch::Receive, 7);
//! let key = seed.derive_key(origin);
//! let public_key = key.public_key();
//! let message = b"key lifecycle example";
//! let context = b"transparent-pq-keys/example";
//! let signature = key.sign(message, context)?;
//! public_key.verify(message, context, &signature)?;
//! # Ok::<(), transparent_pq_keys::Error>(())
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

mod derivation;
mod error;
mod origin;
mod parameters;
mod signing;

pub use derivation::WalletSeed;
pub use error::Error;
pub use origin::{Branch, DERIVATION_VERSION, KeyOrigin, Network, ORIGIN_BYTES};
pub use parameters::ParameterSet;
pub use signing::{DerivedSigningKey, PublicKey};
