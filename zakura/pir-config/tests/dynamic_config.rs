//! Dynamic document resolution: networks, servers, attestation and mirrors.

mod support;

use serde_json::json;
use support::{MIRROR_A, MIRROR_B, anchor_for, bytes, dynamic_json, mainnet_anchor, static_json};
use zakura_pir_config::{
    InvalidServerBase, ResolvedWalletPirConfig, ServerBase, WalletPirConfigError,
    WalletPirConfigProfile, WalletPirDynamicConfig, WalletPirNetwork, WalletPirStaticAnchor,
    resolve_config_from_attempts, resolve_dynamic_config,
};
use zakura_service_config::{
    AttestationError, AttestationMethod, AttestationPolicy, AttestationSubject,
    AttestationVerifier, MirrorAttempt, MirrorError, ResolveError,
};

fn resolve(document: &serde_json::Value) -> Result<ResolvedWalletPirConfig, WalletPirConfigError> {
    resolve_dynamic_config(
        &WalletPirConfigProfile::https_transport(),
        &mainnet_anchor(),
        MIRROR_A,
        &bytes(document),
    )
}

fn servers(entries: &[(&str, &str)]) -> Result<ResolvedWalletPirConfig, WalletPirConfigError> {
    resolve(&dynamic_json("mainnet", entries))
}

#[test]
fn an_empty_server_list_is_a_valid_inactive_config() {
    let config = servers(&[]).unwrap();
    assert!(!config.is_active());
    assert!(config.servers().is_empty());
    assert_eq!(config.network(), WalletPirNetwork::Mainnet);
    assert_eq!(config.dynamic_config_url(), MIRROR_A);
}

#[test]
fn binds_the_static_network_and_version_one() {
    assert_eq!(
        resolve(&dynamic_json("testnet", &[])),
        Err(WalletPirConfigError::DynamicNetworkMismatch {
            expected: WalletPirNetwork::Mainnet,
            found: WalletPirNetwork::Testnet,
        })
    );
    let mut document = dynamic_json("mainnet", &[]);
    document["config_version"] = json!(2);
    assert_eq!(
        resolve(&document),
        Err(WalletPirConfigError::UnsupportedDynamicVersion { found: 2 })
    );
    let mut per_product_url = dynamic_json("mainnet", &[]);
    per_product_url["enhance_url"] = json!("https://server.example/enhance");
    assert!(matches!(
        resolve(&per_product_url),
        Err(WalletPirConfigError::Resolve(ResolveError::DynamicDecode(
            _
        )))
    ));
}

#[test]
fn normalizes_server_bases() {
    let config = servers(&[
        ("A", "  HTTPS://Server-A.Example:443/pir/../wallet/  "),
        ("B", "https://server-b.example:8443"),
        ("C", "https://[2001:0db8::1]/"),
    ])
    .unwrap();
    let bases: Vec<_> = config.servers().iter().map(|s| s.base.as_str()).collect();
    assert_eq!(
        bases,
        [
            "https://server-a.example/wallet",
            "https://server-b.example:8443",
            "https://[2001:db8::1]",
        ]
    );
    assert_eq!(
        config.servers()[0]
            .base
            .endpoint()
            .join("/enhance/v1")
            .unwrap(),
        "https://server-a.example/wallet/enhance/v1"
    );
}

#[test]
fn rejects_malformed_server_urls() {
    for (url, reason) in [
        ("http://server.example", Some(InvalidServerBase::NotHttps)),
        ("http://localhost:8080", Some(InvalidServerBase::NotHttps)),
        (
            "https://server.example//evil.example",
            Some(InvalidServerBase::EmptyPathSegment),
        ),
        ("https://user:pass@server.example", None),
        ("https://server.example?route=enhance", None),
        ("https://server.example/#enhance", None),
        ("https://server.example\\@evil.example", None),
        ("https://bücher.example", None),
        ("https://%73erver.example", None),
        ("https://0x7f000001", None),
        ("server.example", None),
        ("", None),
    ] {
        match servers(&[("Server", url)]) {
            Err(WalletPirConfigError::InvalidServerUrl {
                index: 0,
                url: rejected,
                reason: actual,
            }) => {
                assert_eq!(rejected, url);
                if let Some(reason) = reason {
                    assert_eq!(actual, reason, "{url}");
                }
            }
            other => panic!("{url:?} resolved to {other:?}"),
        }
    }
}

#[test]
fn rejects_duplicates_by_normalized_base_and_blank_labels() {
    assert_eq!(
        servers(&[
            ("Primary", "https://server.example/pir"),
            ("Same server", "HTTPS://SERVER.EXAMPLE:443/pir/"),
        ]),
        Err(WalletPirConfigError::DuplicateServer {
            index: 1,
            base: ServerBase::parse("https://server.example/pir").unwrap(),
        })
    );
    assert_eq!(
        servers(&[
            ("Primary", "https://a.example"),
            ("  ", "https://b.example")
        ]),
        Err(WalletPirConfigError::BlankServerLabel { index: 1 })
    );
}

#[test]
fn rejects_attestation_methods_the_profile_does_not_accept() {
    let mut static_document = static_json("mainnet");
    static_document["attestation"] = json!({"method": "signed-entries", "trust": {"keys": []}});
    let anchor = anchor_for(&static_document);
    let result = resolve_dynamic_config(
        &WalletPirConfigProfile::https_transport(),
        &anchor,
        MIRROR_A,
        &bytes(&dynamic_json("mainnet", &[])),
    );
    assert!(matches!(
        result,
        Err(WalletPirConfigError::Resolve(ResolveError::Attestation(
            AttestationError::UnsupportedMethod { .. }
        )))
    ));

    let mut https_with_trust = static_json("mainnet");
    https_with_trust["attestation"]["trust"] = json!({"origin": "https://mirror-a.example"});
    let result = resolve_dynamic_config(
        &WalletPirConfigProfile::https_transport(),
        &anchor_for(&https_with_trust),
        MIRROR_A,
        &bytes(&dynamic_json("mainnet", &[])),
    );
    assert!(matches!(
        result,
        Err(WalletPirConfigError::Resolve(ResolveError::Attestation(
            AttestationError::InvalidTrustData { .. }
        )))
    ));
}

/// Accepts documents whose servers the static trust data lists by label.
struct LabelAllowlist;

impl AttestationVerifier<WalletPirStaticAnchor, WalletPirDynamicConfig> for LabelAllowlist {
    type Verdict = usize;

    fn verify(
        &self,
        subject: AttestationSubject<'_, WalletPirStaticAnchor, WalletPirDynamicConfig>,
    ) -> Result<usize, AttestationError> {
        let allowed = subject.trust["labels"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if subject
            .document
            .servers
            .iter()
            .all(|server| allowed.contains(&json!(server.label)))
        {
            Ok(subject.document.servers.len())
        } else {
            Err(AttestationError::Rejected {
                method: AttestationMethod::new("label-allowlist").unwrap(),
                message: "unlisted server".to_string(),
            })
        }
    }
}

#[test]
fn applications_can_supply_their_own_attestation_policy() {
    let method = AttestationMethod::new("label-allowlist").unwrap();
    let profile = WalletPirConfigProfile::with_attestation_policy(
        AttestationPolicy::new()
            .allow(method.clone(), LabelAllowlist)
            .unwrap(),
    );
    let mut static_document = static_json("mainnet");
    static_document["attestation"] =
        json!({"method": "label-allowlist", "trust": {"labels": ["A"]}});
    let anchor = anchor_for(&static_document);

    let config = resolve_dynamic_config(
        &profile,
        &anchor,
        MIRROR_A,
        &bytes(&dynamic_json("mainnet", &[("A", "https://a.example")])),
    )
    .unwrap();
    assert_eq!(config.attestation().method, method);
    assert_eq!(config.attestation().verdict, 1);
    assert_ne!(
        config.scope(),
        &WalletPirConfigProfile::https_transport().scope(&anchor),
        "the policy is part of the scope"
    );

    assert!(
        resolve_dynamic_config(
            &profile,
            &anchor,
            MIRROR_A,
            &bytes(&dynamic_json("mainnet", &[("B", "https://b.example")])),
        )
        .is_err()
    );
}

#[test]
fn only_declared_mirrors_may_supply_the_dynamic_config() {
    let profile = WalletPirConfigProfile::https_transport();
    let anchor = mainnet_anchor();
    let document = bytes(&dynamic_json("mainnet", &[("A", "https://a.example")]));
    for undeclared in [
        "https://evil.example/dynamic-wallet-pir-config.json",
        "https://MIRROR-A.example/dynamic-wallet-pir-config.json",
        "https://mirror-a.example/dynamic-wallet-pir-config.json?x",
    ] {
        assert_eq!(
            resolve_dynamic_config(&profile, &anchor, undeclared, &document),
            Err(WalletPirConfigError::UndeclaredMirror {
                url: undeclared.to_string()
            })
        );
    }

    let only_undeclared = resolve_config_from_attempts(
        &profile,
        &anchor,
        [MirrorAttempt::fetched(
            "https://evil.example/d.json",
            document.clone(),
        )],
    );
    assert!(matches!(
        only_undeclared,
        Err(MirrorError::Exhausted { .. })
    ));
}

#[test]
fn mirror_attempts_fall_through_to_the_next_declared_mirror() {
    let profile = WalletPirConfigProfile::https_transport();
    let anchor = mainnet_anchor();
    let resolution = resolve_config_from_attempts(
        &profile,
        &anchor,
        [
            MirrorAttempt::failed(MIRROR_A, "timed out"),
            MirrorAttempt::fetched(
                MIRROR_B,
                bytes(&dynamic_json("mainnet", &[("A", "https://a.example")])),
            ),
        ],
    )
    .unwrap();
    assert_eq!(resolution.url, MIRROR_B);
    assert_eq!(resolution.value.dynamic_config_url(), MIRROR_B);
    assert_eq!(resolution.passed_over.len(), 1);
    assert_eq!(resolution.value.servers().len(), 1);
}
