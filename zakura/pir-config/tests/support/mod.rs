//! Documents and resolution shortcuts shared by the behavior tests.
#![allow(dead_code)]

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zakura_pir_config::{
    ResolvedWalletPirConfig, WalletPirConfigProfile, WalletPirNetwork, WalletPirStaticAnchor,
    resolve_dynamic_config, resolve_static_config,
};

pub const SOURCE_URL: &str = "https://config.example/static-wallet-pir-config.json";
pub const MIRROR_A: &str = "https://mirror-a.example/dynamic-wallet-pir-config.json";
pub const MIRROR_B: &str = "https://mirror-b.example/dynamic-wallet-pir-config.json";

pub fn static_json(network: &str) -> Value {
    json!({
        "static_config_version": 1,
        "network": network,
        "dynamic_config_urls": [MIRROR_A, MIRROR_B],
        "attestation": {"method": "https-transport", "trust": null},
    })
}

/// A dynamic document advertising `(label, url)` servers.
pub fn dynamic_json(network: &str, servers: &[(&str, &str)]) -> Value {
    json!({
        "config_version": 1,
        "network": network,
        "servers": servers
            .iter()
            .map(|(label, url)| json!({"label": label, "url": url}))
            .collect::<Vec<_>>(),
    })
}

pub fn bytes(document: &Value) -> Vec<u8> {
    serde_json::to_vec_pretty(document).unwrap()
}

/// `SOURCE_URL` pinned to `static_bytes`.
pub fn pinned_source(static_bytes: &[u8]) -> String {
    format!(
        "{SOURCE_URL}?checksum=sha256:{}",
        hex::encode(Sha256::digest(static_bytes))
    )
}

pub fn anchor_for(static_document: &Value) -> WalletPirStaticAnchor {
    let static_bytes = bytes(static_document);
    resolve_static_config(
        &pinned_source(&static_bytes),
        &static_bytes,
        WalletPirNetwork::Mainnet,
    )
    .unwrap()
}

pub fn mainnet_anchor() -> WalletPirStaticAnchor {
    anchor_for(&static_json("mainnet"))
}

/// Resolves a mainnet config advertising `servers` from `MIRROR_A`.
pub fn mainnet_config(servers: &[(&str, &str)]) -> ResolvedWalletPirConfig {
    resolve_dynamic_config(
        &WalletPirConfigProfile::https_transport(),
        &mainnet_anchor(),
        MIRROR_A,
        &bytes(&dynamic_json("mainnet", servers)),
    )
    .unwrap()
}
