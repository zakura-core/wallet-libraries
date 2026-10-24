//! Dynamic resolution through a profile and its attestation policy.

mod support;

use support::{
    AppError, DIGEST_METHOD, DYNAMIC_JSON, DigestAttestation, TestProfile, Verdict, sha256_hex,
    static_document,
};
use zakura_service_config::{
    AttestationError, AttestationMethod, AttestationPolicy, HttpsTransport, ResolveError,
    fingerprint_bytes, resolve_dynamic,
};

#[test]
fn default_method_applies_when_the_static_document_selects_none() {
    let profile = TestProfile::new();
    let resolved =
        resolve_dynamic(&profile, &static_document(None), DYNAMIC_JSON.as_bytes()).unwrap();
    assert_eq!(resolved.attestation.method, HttpsTransport::method());
    assert_eq!(resolved.attestation.verdict, Verdict::Transport);
    assert_eq!(
        resolved.fingerprint,
        fingerprint_bytes(DYNAMIC_JSON.as_bytes())
    );
    assert_eq!(resolved.document.servers[1].label, "Backup");
}

#[test]
fn static_selection_with_trust_data_reaches_the_verifier_with_raw_bytes() {
    let profile = TestProfile::new();
    let selection = format!(
        r#"{{"method":"{DIGEST_METHOD}","trust":"{}"}}"#,
        sha256_hex(DYNAMIC_JSON.as_bytes())
    );
    let anchor = static_document(Some(&selection));
    let resolved = resolve_dynamic(&profile, &anchor, DYNAMIC_JSON.as_bytes()).unwrap();
    assert_eq!(resolved.attestation.verdict, Verdict::DigestMatched);

    let tampered = DYNAMIC_JSON.replace("Primary", "Primary ");
    let error = resolve_dynamic(&profile, &anchor, tampered.as_bytes()).unwrap_err();
    assert!(matches!(
        error,
        AppError::Generic(ResolveError::Attestation(AttestationError::Rejected { .. }))
    ));
}

#[test]
fn a_method_the_application_did_not_register_is_rejected() {
    let profile = TestProfile::new();
    let anchor = static_document(Some(r#"{"method":"full-document-ed25519"}"#));
    let error = resolve_dynamic(&profile, &anchor, DYNAMIC_JSON.as_bytes()).unwrap_err();
    let AppError::Generic(ResolveError::Attestation(AttestationError::UnsupportedMethod {
        method,
        allowed,
    })) = error
    else {
        panic!("expected unsupported method, got {error:?}");
    };
    assert_eq!(method.as_str(), "full-document-ed25519");
    assert_eq!(
        allowed,
        vec!["https-transport".to_string(), DIGEST_METHOD.to_string()]
    );
}

#[test]
fn https_transport_refuses_trust_data_it_would_ignore() {
    let profile = TestProfile::new();
    let anchor = static_document(Some(r#"{"method":"https-transport","trust":{"keys":[]}}"#));
    let error = resolve_dynamic(&profile, &anchor, DYNAMIC_JSON.as_bytes()).unwrap_err();
    assert!(matches!(
        error,
        AppError::Generic(ResolveError::Attestation(
            AttestationError::InvalidTrustData { .. }
        ))
    ));
}

#[test]
fn invalid_method_names_are_rejected_when_decoding_a_selection() {
    let parsed: Result<support::StaticDocument, _> = serde_json::from_str(
        r#"{"network":"main","dynamic_config_urls":[],"attestation":{"method":"Bad Name"}}"#,
    );
    assert!(parsed.is_err());
}

#[test]
fn profile_validation_runs_before_attestation() {
    let profile = TestProfile::new();
    let other_network = DYNAMIC_JSON.replace(r#""network":"main""#, r#""network":"test""#);
    assert_eq!(
        resolve_dynamic(&profile, &static_document(None), other_network.as_bytes()).unwrap_err(),
        AppError::WrongNetwork
    );

    let duplicate_labels = DYNAMIC_JSON.replace("Backup", "Primary");
    let error = resolve_dynamic(
        &profile,
        &static_document(None),
        duplicate_labels.as_bytes(),
    )
    .unwrap_err();
    assert_eq!(
        error,
        AppError::Servers("servers[1].label is a duplicate: Primary".to_string())
    );
}

#[test]
fn malformed_dynamic_json_is_a_dynamic_decode_error() {
    let profile = TestProfile::new();
    let error = resolve_dynamic(&profile, &static_document(None), b"[]").unwrap_err();
    assert!(matches!(
        error,
        AppError::Generic(ResolveError::DynamicDecode(_))
    ));
}

#[test]
fn a_policy_without_a_default_requires_a_selection() {
    let profile = TestProfile {
        policy: AttestationPolicy::new()
            .allow(
                AttestationMethod::new(DIGEST_METHOD).unwrap(),
                DigestAttestation,
            )
            .unwrap(),
    };
    let error =
        resolve_dynamic(&profile, &static_document(None), DYNAMIC_JSON.as_bytes()).unwrap_err();
    assert_eq!(
        error,
        AppError::Generic(ResolveError::Attestation(
            AttestationError::MissingSelection
        ))
    );
}

#[test]
fn policies_refuse_duplicate_methods_and_unregistered_defaults() {
    let duplicate = AttestationPolicy::<(), (), _>::new()
        .allow(HttpsTransport::method(), HttpsTransport)
        .unwrap()
        .allow(HttpsTransport::method(), HttpsTransport)
        .unwrap_err();
    assert!(matches!(
        duplicate,
        AttestationError::DuplicateMethod { .. }
    ));

    let unregistered = AttestationPolicy::<(), (), _>::new()
        .allow(HttpsTransport::method(), HttpsTransport)
        .unwrap()
        .with_default(AttestationMethod::new("other").unwrap())
        .unwrap_err();
    assert!(matches!(
        unregistered,
        AttestationError::UnsupportedMethod { .. }
    ));
}
