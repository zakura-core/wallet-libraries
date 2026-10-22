//! The static and dynamic wallet PIR config documents, exactly as published.
//!
//! These types only describe JSON shape. Version, network, mirror and server
//! rules are enforced during resolution, so a decoded document is not yet a
//! usable config.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zakura_service_config::{AttestationSelection, LabeledEndpoint};

/// The only `static_config_version` this crate accepts.
pub const STATIC_CONFIG_VERSION: u32 = 1;

/// The only dynamic `config_version` this crate accepts.
pub const DYNAMIC_CONFIG_VERSION: u32 = 1;

/// The Zcash network a config serves, serialized as `mainnet`, `testnet` or
/// `regtest`.
///
/// Staging configs bind `testnet`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WalletPirNetwork {
    Mainnet,
    Testnet,
    Regtest,
}

impl WalletPirNetwork {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Regtest => "regtest",
        }
    }
}

impl fmt::Display for WalletPirNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A network name other than `mainnet`, `testnet` or `regtest`.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("unknown network {0:?}; expected mainnet, testnet or regtest")]
pub struct UnknownNetwork(pub String);

impl FromStr for WalletPirNetwork {
    type Err = UnknownNetwork;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            "regtest" => Ok(Self::Regtest),
            _ => Err(UnknownNetwork(name.to_string())),
        }
    }
}

/// The hash-pinned static document an application ships the source of.
///
/// ```json
/// {"static_config_version":1,"network":"mainnet",
///  "dynamic_config_urls":["https://mirror.example/dynamic-wallet-pir-config.json"],
///  "attestation":{"method":"https-transport","trust":null}}
/// ```
///
/// `attestation` is mandatory: a document without it is rejected rather than
/// given a default method. Unknown fields are rejected; a schema change needs
/// a new version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletPirStaticConfig {
    pub static_config_version: u32,
    pub network: WalletPirNetwork,
    /// Mirrors serving copies of the same dynamic document, in preference order.
    pub dynamic_config_urls: Vec<String>,
    pub attestation: AttestationSelection,
}

/// The dynamic document listing wallet PIR servers.
///
/// ```json
/// {"config_version":1,"network":"mainnet",
///  "servers":[{"label":"Example server","url":"https://server.example"}]}
/// ```
///
/// Each server `url` is a base serving all four PIR products (enhance,
/// status, transparent and receiver); product routes are appended by the
/// clients, never configured here. An empty `servers` list is a valid
/// inactive config: no server is selectable and no private queries are sent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletPirDynamicConfig {
    pub config_version: u32,
    pub network: WalletPirNetwork,
    pub servers: Vec<LabeledEndpoint>,
}
