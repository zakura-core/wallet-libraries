//! *A crate for implementing Zcash light clients.*
//!
//! `zcash_client_backend` contains Rust structs and traits for creating shielded Zcash
//! light clients.
//!
//! # Design
//!
//! ## Wallet sync
//!
//! The APIs in the [`data_api::chain`] module can be used to implement the following
//! synchronization flow:
//!
//! ```text
//!                          ┌─────────────┐  ┌─────────────┐
//!                          │Get required │  │   Update    │
//!                          │subtree root │─▶│subtree roots│
//!                          │    range    │  └─────────────┘
//!                          └─────────────┘         │
//!                                                  ▼
//!                                             ┌─────────┐
//!                                             │ Update  │
//!           ┌────────────────────────────────▶│chain tip│◀──────┐
//!           │                                 └─────────┘       │
//!           │                                      │            │
//!           │                                      ▼            │
//!    ┌─────────────┐        ┌────────────┐  ┌─────────────┐     │
//!    │  Truncate   │        │Split range │  │Get suggested│     │
//!    │  wallet to  │        │into batches│◀─│ scan ranges │     │
//!    │rewind height│        └────────────┘  └─────────────┘     │
//!    └─────────────┘               │                            │
//!           ▲                     ╱│╲                           │
//!           │      ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─              │
//!      ┌────────┐         ┌───────────────┐       │             │
//!      │ Choose │  │      │Download blocks│                     │
//!      │ rewind │         │   to cache    │       │             │
//!      │ height │  │      └───────────────┘           .───────────────────.
//!      └────────┘                 │               │  ( Scan ranges updated )
//!           ▲      │              ▼                   `───────────────────'
//!           │               ┌───────────┐         │             ▲
//!  .───────────────┴─.      │Scan cached│    .─────────.        │
//! ( Continuity error  )◀────│  blocks   │──▶(  Success  )───────┤
//!  `───────────────┬─'      └───────────┘    `─────────'        │
//!                                 │               │             │
//!                  │       ┌──────┴───────┐                     │
//!                          ▼              ▼       │             ▼
//!                  │┌─────────────┐┌─────────────┐  ┌──────────────────────┐
//!                   │Delete blocks││   Enhance   ││ │Update wallet balance │
//!                  ││ from cache  ││transactions │  │  and sync progress   │
//!                   └─────────────┘└─────────────┘│ └──────────────────────┘
//!                  └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
//! ```
//!
//! ## Feature flags
#![doc = document_features::document_features!()]
//!

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, doc(auto_cfg))]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]

pub mod data_api;
mod decrypt;
pub mod fees;
pub mod proposal;
pub mod proto;
pub mod scan;
pub mod scanning;
pub mod wallet;

#[cfg(any(feature = "sync", feature = "sync-decryptor"))]
pub mod sync;

#[cfg(feature = "unstable-serialization")]
pub mod serialization;

#[cfg(feature = "sync-decryptor")]
mod task;

#[cfg(feature = "tor")]
pub mod tor;

pub use decrypt::{DecryptedOutput, TransferType, decrypt_transaction};

/// Starts process-lifetime Orchard proving-key warm-up if it has not started.
///
/// Returns immediately. A proof requested before warm-up completes blocks on
/// the same cache used by the transaction builder, so this is a latency
/// optimization rather than a correctness requirement.
///
/// Each [`orchard::circuit::OrchardCircuitVersion`] is warmed at most once.
/// Callers should derive the version from the target transaction's consensus
/// branch instead of assuming the latest version.
pub fn start_orchard_proving_key_warmup(circuit_version: orchard::circuit::OrchardCircuitVersion) {
    use orchard::circuit::OrchardCircuitVersion;
    use std::sync::atomic::AtomicBool;

    static INSECURE_PRE_NU6_2: AtomicBool = AtomicBool::new(false);
    static FIXED_POST_NU6_2: AtomicBool = AtomicBool::new(false);
    static POST_NU6_3: AtomicBool = AtomicBool::new(false);

    let started = match circuit_version {
        OrchardCircuitVersion::InsecurePreNu6_2 => &INSECURE_PRE_NU6_2,
        OrchardCircuitVersion::FixedPostNu6_2 => &FIXED_POST_NU6_2,
        OrchardCircuitVersion::PostNu6_3 => &POST_NU6_3,
    };

    start_orchard_proving_key_warmup_with(circuit_version, started, |task| {
        std::thread::Builder::new()
            .name("orchard-proving-key-warmup".to_string())
            .spawn(task)
            .map(|_| ())
    });
}

fn start_orchard_proving_key_warmup_with(
    circuit_version: orchard::circuit::OrchardCircuitVersion,
    started: &std::sync::atomic::AtomicBool,
    spawn: impl FnOnce(Box<dyn FnOnce() + Send>) -> std::io::Result<()>,
) {
    use std::sync::atomic::Ordering;

    if started
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }

    if let Err(error) = spawn(Box::new(move || {
        let _ = zcash_primitives::transaction::builder::cached_orchard_proving_key(circuit_version);
    })) {
        started.store(false, Ordering::Release);
        tracing::warn!(
            %error,
            "Orchard proving-key warmup spawn failed; proving will build the key inline if needed"
        );
    }
}

#[deprecated(note = "This module is deprecated; use `::zcash_keys::address` instead.")]
pub mod address {
    pub use zcash_keys::address::*;
}
#[deprecated(note = "This module is deprecated; use `::zcash_keys::encoding` instead.")]
pub mod encoding {
    pub use zcash_keys::encoding::*;
}
#[deprecated(note = "This module is deprecated; use `::zcash_keys::keys` instead.")]
pub mod keys {
    pub use zcash_keys::keys::*;
}
#[deprecated(note = "use ::zcash_protocol::PoolType instead")]
pub type PoolType = zcash_protocol::PoolType;
#[deprecated(note = "use ::zcash_protocol::ShieldedPool instead")]
pub type ShieldedPool = zcash_protocol::ShieldedPool;
#[deprecated(note = "This module is deprecated; use the `zip321` crate instead.")]
pub mod zip321 {
    pub use zip321::*;
}

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

#[cfg(test)]
mod tests {
    use core::ptr;
    use std::sync::atomic::{AtomicBool, Ordering};

    use orchard::circuit::OrchardCircuitVersion;
    use zcash_primitives::transaction::builder::cached_orchard_proving_key;

    use super::{start_orchard_proving_key_warmup, start_orchard_proving_key_warmup_with};

    #[test]
    fn orchard_proving_key_warmup_retries_after_spawn_failure() {
        let started = AtomicBool::new(false);
        let circuit_version = OrchardCircuitVersion::PostNu6_3;

        start_orchard_proving_key_warmup_with(circuit_version, &started, |_| {
            Err(std::io::Error::other("simulated spawn failure"))
        });
        assert!(!started.load(Ordering::Acquire));

        start_orchard_proving_key_warmup_with(circuit_version, &started, |_| Ok(()));
        assert!(started.load(Ordering::Acquire));

        start_orchard_proving_key_warmup_with(circuit_version, &started, |_| {
            panic!("warm-up spawned more than once")
        });
    }

    #[test]
    fn orchard_proving_key_warmup_reuses_the_builder_cache() {
        let circuit_version = OrchardCircuitVersion::PostNu6_3;

        start_orchard_proving_key_warmup(circuit_version);
        start_orchard_proving_key_warmup(circuit_version);
        let warmed = cached_orchard_proving_key(circuit_version);

        assert!(ptr::eq(warmed, cached_orchard_proving_key(circuit_version)));
    }
}
