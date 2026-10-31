//! The Zakura wallet stack under stable import names.
//!
//! ```
//! use zakura_wallet_lib::{client_backend, client_sqlite, keys, orchard, pczt,
//!     primitives};
//! assert_eq!(zakura_wallet_lib::BACKEND, "zakura");
//! ```
//!
//! The default `zakura` feature enables the complete wallet capability set,
//! including Orchard. Consumers disabling default features must explicitly
//! enable `zakura`. The re-exports retain the identities of the Zakura packages;
//! applications should use the same dependency family throughout their graph.
//!
//! `scripts/verify-wallet-lib-modes.sh` checks the supported feature selections,
//! fresh consumer resolution and the minimum supported Rust version.

#![no_std]

#[cfg(not(feature = "zakura"))]
compile_error!("enable the `zakura` feature when disabling default features");

// Keep the established facade names for the Zakura dependency family.
#[cfg(feature = "zakura")]
mod backend {
    pub use ::orchard;
    pub use ::pczt;
    pub use ::zcash_client_backend as client_backend;
    pub use ::zcash_client_sqlite as client_sqlite;
    pub use ::zcash_keys as keys;
    pub use ::zcash_primitives as primitives;
}

#[cfg(feature = "zakura")]
pub use backend::*;

/// The wallet dependency family exposed by this facade.
pub const BACKEND: &str = "zakura";
