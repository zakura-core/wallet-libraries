//! Keeping the last good config across failed refreshes and restarts.

mod support;

use support::{
    MIRROR_A, SOURCE_URL, bytes, dynamic_json, mainnet_anchor, mainnet_config, pinned_source,
    static_json,
};
use zakura_pir_config::{
    WalletPirConfigError, WalletPirConfigProfile, WalletPirConfigSnapshot, WalletPirNetwork,
    resolve_config_snapshot, resolve_dynamic_config,
};
use zakura_service_config::{LastGoodConfig, RefreshOutcome};

fn current_source() -> String {
    pinned_source(&bytes(&static_json("mainnet")))
}

/// Persists and reloads a snapshot the way an application would.
fn restart(snapshot: &WalletPirConfigSnapshot) -> WalletPirConfigSnapshot {
    serde_json::from_slice(&serde_json::to_vec(snapshot).unwrap()).unwrap()
}

#[test]
fn a_snapshot_reloads_to_the_same_config() {
    let config = mainnet_config(&[("A", "https://a.example")]);
    let reloaded = resolve_config_snapshot(
        &WalletPirConfigProfile::https_transport(),
        &restart(config.snapshot()),
        &current_source(),
        WalletPirNetwork::Mainnet,
    )
    .unwrap();
    assert_eq!(reloaded, config);
}

#[test]
fn a_snapshot_is_not_reused_under_another_source_or_network() {
    let config = mainnet_config(&[("A", "https://a.example")]);
    let profile = WalletPirConfigProfile::https_transport();
    let other_pin = pinned_source(b"next static document");
    assert_eq!(
        resolve_config_snapshot(
            &profile,
            config.snapshot(),
            &other_pin,
            WalletPirNetwork::Mainnet
        ),
        Err(WalletPirConfigError::SnapshotSourceChanged)
    );
    let other_url = current_source().replace(SOURCE_URL, "https://config.example/other.json");
    assert_eq!(
        resolve_config_snapshot(
            &profile,
            config.snapshot(),
            &other_url,
            WalletPirNetwork::Mainnet
        ),
        Err(WalletPirConfigError::SnapshotSourceChanged)
    );
    assert!(matches!(
        resolve_config_snapshot(
            &profile,
            config.snapshot(),
            &current_source(),
            WalletPirNetwork::Testnet
        ),
        Err(WalletPirConfigError::StaticNetworkMismatch { .. })
    ));
}

#[test]
fn a_tampered_snapshot_is_rejected() {
    let config = mainnet_config(&[("A", "https://a.example")]);
    let profile = WalletPirConfigProfile::https_transport();

    let mut static_edited = config.snapshot().clone();
    static_edited.static_config_json = static_edited
        .static_config_json
        .replace("mirror-b", "mirror-c");
    assert!(matches!(
        resolve_config_snapshot(
            &profile,
            &static_edited,
            &current_source(),
            WalletPirNetwork::Mainnet
        ),
        Err(WalletPirConfigError::Resolve(_))
    ));

    let mut undeclared_mirror = config.snapshot().clone();
    undeclared_mirror.dynamic_config_url = "https://evil.example/d.json".to_string();
    assert!(matches!(
        resolve_config_snapshot(
            &profile,
            &undeclared_mirror,
            &current_source(),
            WalletPirNetwork::Mainnet
        ),
        Err(WalletPirConfigError::UndeclaredMirror { .. })
    ));

    let mut invalid_servers = config.snapshot().clone();
    invalid_servers.dynamic_config_json =
        serde_json::to_string(&dynamic_json("mainnet", &[("A", "http://a.example")])).unwrap();
    assert!(matches!(
        resolve_config_snapshot(
            &profile,
            &invalid_servers,
            &current_source(),
            WalletPirNetwork::Mainnet
        ),
        Err(WalletPirConfigError::InvalidServerUrl { .. })
    ));
}

#[test]
fn an_invalid_candidate_never_replaces_the_accepted_config() {
    let accepted = mainnet_config(&[("A", "https://a.example")]);
    let mut last_good = LastGoodConfig::new(Some(accepted.clone()));

    let invalid = resolve_dynamic_config(
        &WalletPirConfigProfile::https_transport(),
        &mainnet_anchor(),
        MIRROR_A,
        &bytes(&dynamic_json("testnet", &[("B", "https://b.example")])),
    );
    assert!(matches!(
        last_good.refresh(invalid),
        RefreshOutcome::KeptPrevious { .. }
    ));
    assert_eq!(last_good.accepted(), Some(&accepted));

    let fetch_failed: Result<_, String> = Err("all mirrors timed out".to_string());
    assert!(matches!(
        last_good.refresh(fetch_failed),
        RefreshOutcome::KeptPrevious { .. }
    ));
    assert_eq!(
        last_good.refresh(Ok::<_, String>(mainnet_config(&[(
            "A",
            "https://a.example"
        )]))),
        RefreshOutcome::Unchanged
    );
    assert_eq!(
        last_good.refresh(Ok::<_, String>(mainnet_config(&[(
            "B",
            "https://b.example"
        )]))),
        RefreshOutcome::Accepted
    );
}
