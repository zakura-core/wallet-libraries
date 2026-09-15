//! One name for two stacks.
//!
//! A crate that has to build for both Gemini and Vizor cannot name
//! `zcash_client_backend` or `zakura-client-backend` directly: one of them is
//! absent in either build. It depends on this crate instead and reaches the
//! selected family through these re-exports:
//!
//! ```ignore
//! use zakura_wallet_lib::{client_backend, orchard};
//! ```
//!
//! The two families are API-compatible today — the Zakura forks differ only in
//! package name — so a consumer needs no `cfg` of its own. Where a fork later
//! diverges, the `cfg` for it belongs here, behind a shared signature, and not
//! in every consumer.
//!
//! # Selecting a backend
//!
//! `zakura` is the default and resolves to the complete fork capability set.
//! Gemini selects the equivalent upstream LRZ stack explicitly:
//!
//! ```toml
//! zakura-wallet-lib = { version = "0.1", default-features = false, features = ["lrz"] }
//! ```
//!
//! `zakura` and `lrz` select the backend. The additive `zakura-pir-enhance`
//! feature selects Zakura and enables its private Ironwood enhancement APIs.
//!
//! The two are mutually exclusive. Cargo features are additive, so that cannot
//! be stated in the manifest and is enforced below instead: a graph that
//! enables both — usually an LRZ dependency that forgot `default-features = false` —
//! fails to compile rather than silently resolving two copies of the crypto
//! stack.
//!
//! Being buildable is not the whole guarantee. A consumer can still reach
//! around this crate and depend on an upstream package directly, which puts
//! both families in one binary; `scripts/verify-zakura-graph.sh` is what
//! catches that, and it belongs in the consumer's CI as well as this one's.

#![no_std]

#[cfg(all(feature = "lrz", feature = "zakura"))]
compile_error!(
    "`lrz` and `zakura` are mutually exclusive: pass `default-features = false` \
     when selecting `lrz`"
);

#[cfg(not(any(feature = "lrz", feature = "zakura")))]
compile_error!("select a backend: enable either the `lrz` or the `zakura` feature");

// The upstream family is declared under renamed keys, so it is reached by
// those keys.
#[cfg(feature = "lrz")]
mod backend {
    pub use ::lrz_client_backend as client_backend;
    pub use ::lrz_client_sqlite as client_sqlite;
    pub use ::lrz_keys as keys;
    pub use ::lrz_orchard as orchard;
    pub use ::lrz_pczt as pczt;
    pub use ::lrz_primitives as primitives;
}

// The default Zakura family is declared under the clean upstream names. Only
// the package names were changed by the fork; every library target still calls
// itself what it always did, which is what lets the vendored sources stay
// untouched — and it shows up here as `zcash_client_backend` resolving to
// `zakura-client-backend`.
#[cfg(feature = "zakura")]
mod backend {
    pub use ::orchard;
    pub use ::pczt;
    pub use ::zcash_client_backend as client_backend;
    pub use ::zcash_client_sqlite as client_sqlite;
    pub use ::zcash_keys as keys;
    pub use ::zcash_primitives as primitives;
}

#[cfg(any(feature = "lrz", feature = "zakura"))]
pub use backend::*;

/// Which family this build selected. Useful in logs and in a consumer's own
/// tests, where asserting the expected backend is cheaper than reading a
/// dependency tree.
pub const BACKEND: &str = if cfg!(feature = "zakura") {
    "zakura"
} else {
    "lrz"
};
