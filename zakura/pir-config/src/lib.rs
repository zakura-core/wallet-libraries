//! The wallet PIR configuration profile.
//!
//! A wallet ships one hash-pinned static config source per network. The static
//! document names the dynamic config mirrors and the attestation method; the
//! dynamic document lists wallet PIR servers, each a single base URL serving
//! all four products (enhance, status, transparent and receiver).
//!
//! ```text
//!   pinned source + static bytes ──resolve_static_config──▶ WalletPirStaticAnchor
//!                                                                │
//!   declared mirror + dynamic bytes ──resolve_dynamic_config──▶ ResolvedWalletPirConfig
//!   (or ordered MirrorAttempts ──resolve_config_from_attempts──▶)  │
//!                                                                ▼
//!   persisted ServerSelection ──reconcile_selection──▶ ServerSelectionOutcome
//! ```
//!
//! Resolution is built on `zakura-service-config` and performs no I/O. The
//! application owns transport, cancellation, refresh scheduling and durable
//! state: it persists a [`WalletPirConfigSnapshot`] as its last good config
//! (re-validated by [`resolve_config_snapshot`] on reload) and the user's
//! [`ServerSelection`]. A failed refresh never replaces an accepted config; use
//! [`zakura_service_config::LastGoodConfig`] for that rule.
//!
//! Server selection is explicit. The first advertised server is chosen only
//! when the scope has no prior selection; a selected server that a later
//! config removes requires a new user choice, and nothing here fails over to
//! another server.

mod error;
mod profile;
mod resolve;
mod schema;
mod selection;
mod server;

pub use error::WalletPirConfigError;
pub use profile::{WalletPirConfigProfile, WalletPirConfigScope};
pub use resolve::{
    ResolvedWalletPirConfig, WalletPirConfigSnapshot, WalletPirStaticAnchor,
    pin_static_config_source, resolve_config_from_attempts, resolve_config_snapshot,
    resolve_dynamic_config, resolve_static_config,
};
pub use schema::{
    DYNAMIC_CONFIG_VERSION, STATIC_CONFIG_VERSION, UnknownNetwork, WalletPirDynamicConfig,
    WalletPirNetwork, WalletPirStaticConfig,
};
pub use selection::{SelectionError, ServerSelection, ServerSelectionOutcome};
pub use server::{AdvertisedServer, InvalidServerBase, ServerBase};
