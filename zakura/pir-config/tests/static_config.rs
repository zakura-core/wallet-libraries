//! Static document resolution: pins, versions, networks and mirrors.

mod support;

use serde_json::json;
use support::{MIRROR_A, SOURCE_URL, bytes, pinned_source, static_json};
use zakura_pir_config::{
    WalletPirConfigError, WalletPirNetwork, pin_static_config_source, resolve_static_config,
};
use zakura_service_config::{PinCheck, ResolveError};

fn resolve(document: &serde_json::Value) -> Result<(), WalletPirConfigError> {
    let static_bytes = bytes(document);
    resolve_static_config(
        &pinned_source(&static_bytes),
        &static_bytes,
        WalletPirNetwork::Mainnet,
    )
    .map(drop)
}

#[test]
fn accepts_a_pinned_document_for_the_expected_network() {
    let static_bytes = bytes(&static_json("mainnet"));
    let anchor = resolve_static_config(
        &pinned_source(&static_bytes),
        &static_bytes,
        WalletPirNetwork::Mainnet,
    )
    .unwrap();
    assert_eq!(anchor.network(), WalletPirNetwork::Mainnet);
    assert_eq!(anchor.dynamic_config_urls()[0], MIRROR_A);
    assert_eq!(anchor.attestation().method.as_str(), "https-transport");
    assert_eq!(
        anchor.source().verify_pin(&static_bytes),
        Ok(PinCheck::Verified)
    );
}

#[test]
fn requires_a_matching_sha256_pin() {
    let static_bytes = bytes(&static_json("mainnet"));
    assert_eq!(
        resolve_static_config(SOURCE_URL, &static_bytes, WalletPirNetwork::Mainnet),
        Err(WalletPirConfigError::UnpinnedSource)
    );
    let other_pin = pinned_source(b"other document");
    assert!(matches!(
        resolve_static_config(&other_pin, &static_bytes, WalletPirNetwork::Mainnet),
        Err(WalletPirConfigError::Resolve(ResolveError::PinMismatch(_)))
    ));
}

#[test]
fn binds_the_wallet_network_and_version_one() {
    let static_bytes = bytes(&static_json("testnet"));
    assert_eq!(
        resolve_static_config(
            &pinned_source(&static_bytes),
            &static_bytes,
            WalletPirNetwork::Mainnet,
        ),
        Err(WalletPirConfigError::StaticNetworkMismatch {
            expected: WalletPirNetwork::Mainnet,
            found: WalletPirNetwork::Testnet,
        })
    );

    let mut document = static_json("mainnet");
    document["static_config_version"] = json!(2);
    assert_eq!(
        resolve(&document),
        Err(WalletPirConfigError::UnsupportedStaticVersion { found: 2 })
    );
}

#[test]
fn rejects_unknown_networks_missing_attestation_and_unknown_fields() {
    let mut unknown_network = static_json("mainnet");
    unknown_network["network"] = json!("main");
    let mut no_attestation = static_json("mainnet");
    no_attestation
        .as_object_mut()
        .unwrap()
        .remove("attestation");
    let mut extra_field = static_json("mainnet");
    extra_field["servers"] = json!([]);
    for document in [unknown_network, no_attestation, extra_field] {
        assert!(
            matches!(
                resolve(&document),
                Err(WalletPirConfigError::Resolve(ResolveError::StaticDecode(_)))
            ),
            "{document}"
        );
    }
}

#[test]
fn requires_distinct_plain_https_mirrors() {
    let with_mirrors = |mirrors: serde_json::Value| {
        let mut document = static_json("mainnet");
        document["dynamic_config_urls"] = mirrors;
        resolve(&document)
    };
    assert_eq!(
        with_mirrors(json!([])),
        Err(WalletPirConfigError::NoMirrors)
    );
    for bad in [
        "http://mirror.example/dynamic.json",
        "https://user@mirror.example/dynamic.json",
        "https://mirror.example/dynamic.json?ref=main",
        "https://mirror.example/dynamic.json#latest",
        " https://mirror.example/dynamic.json",
        "mirror.example/dynamic.json",
    ] {
        assert_eq!(
            with_mirrors(json!([MIRROR_A, bad])),
            Err(WalletPirConfigError::InvalidMirrorUrl {
                index: 1,
                url: bad.to_string()
            }),
            "{bad}"
        );
    }
    let same_after_normalization =
        "HTTPS://Mirror-A.example:443/x/../dynamic-wallet-pir-config.json";
    assert_eq!(
        with_mirrors(json!([MIRROR_A, same_after_normalization])),
        Err(WalletPirConfigError::DuplicateMirrorUrl {
            index: 1,
            url: same_after_normalization.to_string()
        })
    );
}

#[test]
fn pins_sources_reproducibly() {
    let static_bytes = bytes(&static_json("mainnet"));
    let pinned = pin_static_config_source(SOURCE_URL, &static_bytes).unwrap();
    assert_eq!(pinned.raw, pinned_source(&static_bytes));
    assert_eq!(
        pinned,
        pin_static_config_source(SOURCE_URL, &static_bytes).unwrap()
    );
    assert_eq!(pinned.url, SOURCE_URL);

    assert_eq!(
        pin_static_config_source(&pinned.raw, &static_bytes),
        Err(WalletPirConfigError::SourceAlreadyPinned)
    );
    assert_eq!(
        pin_static_config_source("https://config.example/static.json#v1", &static_bytes),
        Err(WalletPirConfigError::SourceUrlHasFragment)
    );
    assert!(pin_static_config_source("http://config.example/static.json", &static_bytes).is_err());
    let with_query =
        pin_static_config_source("https://config.example/s.json?ref=main", &static_bytes).unwrap();
    assert_eq!(with_query.url, "https://config.example/s.json?ref=main");
    assert!(with_query.sha256.is_some());
}
