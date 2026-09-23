//! Wallet-only v6 wire fixtures; legacy v4 server fixtures must be rejected.
use serde::Deserialize;
use zakura_pir_enhance::{
    AcceptedAnchor, ClientResourceLimits, GenerationAcceptance, HEADER_BYTES, Manifest,
    QuerySession, RECORD_BYTES, RECORDS_PER_ROW, ROW_BYTES, ShardSession,
    client::ClientError,
    types::{QueryBinding, setup_seed},
};

#[derive(Deserialize)]
struct Fixture {
    provenance: String,
    ipir_sp_revision: String,
    manifest: Manifest,
    session: ShardSession,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!("fixtures/wallet-schema11.json")).unwrap()
}

fn acceptance() -> GenerationAcceptance {
    GenerationAcceptance::new(
        "main",
        3_428_143,
        AcceptedAnchor::new(3_428_143, [0x42; 32], 67),
        ClientResourceLimits::new(4_096),
    )
}

#[test]
fn synthetic_wallet_manifest_and_session_are_accepted() {
    let fixture = fixture();
    assert!(fixture.provenance.starts_with("Synthetic wallet"));
    assert_eq!(
        fixture.ipir_sp_revision,
        "b1c540f90f62e112c834a0f57f025e3c605e55d1"
    );
    assert_eq!(fixture.manifest.schema_version, 11);
    assert_eq!(
        fixture.manifest.protocol_revision,
        "ironwood-enhance-pir-v6"
    );
    assert_eq!(RECORD_BYTES, 653);
    assert_eq!(RECORDS_PER_ROW, 33);
    assert_eq!(ROW_BYTES, 21_549);
    assert_eq!(
        fixture.manifest.sessions[0].parameter_id,
        "ironwood-enhance-pir-v6/374a9b116e59a537ee883c763ff5e60b2b044e710419360fe8d4516f3181c8b9"
    );
    assert_eq!(
        fixture.manifest.sessions[0].public_params_sha256,
        "793dd18194116ab34ab06e753faefa8d882fb962beba46dbf4256264c74c5006"
    );
    assert_eq!(fixture.session.public_params_base64.len(), 114688);
    fixture.manifest.validate().unwrap();
    let query_session =
        QuerySession::from_session(&fixture.manifest, fixture.session, &acceptance()).unwrap();
    let (query, slot) = query_session.prepare_position(66).unwrap();
    assert_eq!(slot, 0);
    assert_eq!(query.row(), 2);
    let binding = QueryBinding::decode(query.body()).unwrap();
    assert_eq!(binding.generation, 7);
    assert_eq!(binding.shard_id, 0);
    assert_eq!(&query.body()[..4], b"EPQ4");
    assert!(query.body().len() > HEADER_BYTES);
}

#[test]
fn pinned_contract_rejects_old_or_unaccepted_chain_state() {
    let mut fixture = fixture();
    fixture.manifest.schema_version = 7;
    assert!(fixture.manifest.validate().is_err());
    fixture.manifest.schema_version = 11;
    fixture.manifest.protocol_revision = "ironwood-enhance-pir-v2".into();
    assert!(fixture.manifest.validate().is_err());
    fixture.manifest.protocol_revision = "ironwood-enhance-pir-v6".into();
    let wrong_anchor = GenerationAcceptance::new(
        "main",
        3_428_143,
        AcceptedAnchor::new(3_428_143, [0x41; 32], 67),
        ClientResourceLimits::new(4_096),
    );
    assert!(matches!(
        wrong_anchor.validate(&fixture.manifest),
        Err(ClientError::Generation(_))
    ));
    let unscanned = GenerationAcceptance::new(
        "main",
        3_428_143,
        AcceptedAnchor::new(3_428_142, [0x42; 32], 67),
        ClientResourceLimits::new(4_096),
    );
    assert!(unscanned.validate(&fixture.manifest).is_err());
    let too_small = GenerationAcceptance::new(
        "main",
        3_428_143,
        AcceptedAnchor::new(3_428_143, [0x42; 32], 67),
        ClientResourceLimits::new(2_048),
    );
    assert!(too_small.validate(&fixture.manifest).is_err());
}

#[test]
fn shard_setup_seed_is_pinned() {
    assert_eq!(
        hex::encode(setup_seed(0)),
        "38d2a05f33de9281da5efac0ab38e35386df6458b816cccfa8a13ac7d50fe7fb"
    );
    assert_eq!(
        hex::encode(setup_seed(1)),
        "f448c40881f2d017a6a063ed77439de7a39bbe5f2f0d5ad6e4a452c24e9d1eae"
    );
}

#[test]
fn malformed_response_bindings_and_length_are_rejected() {
    let fixture = fixture();
    let session =
        QuerySession::from_session(&fixture.manifest, fixture.session, &acceptance()).unwrap();
    let (query, _) = session.prepare_position(33).unwrap();
    let mut binding = QueryBinding::decode(query.body()).unwrap();
    let response = binding.encode();
    assert!(session.decode(query, &response).is_err()); // Exact packed-body length.

    for altered in 0..4 {
        let (query, _) = session.prepare_position(33).unwrap();
        binding = QueryBinding::decode(query.body()).unwrap();
        let mut response = match altered {
            0 => {
                let mut bytes = binding.encode();
                bytes[0] = b'X';
                bytes
            }
            1 => {
                binding.generation += 1;
                binding.encode()
            }
            2 => {
                binding.shard_id += 1;
                binding.encode()
            }
            _ => {
                binding.epoch[0] ^= 1;
                binding.encode()
            }
        };
        response.extend([0; 4]);
        assert!(
            session.decode(query, &response).is_err(),
            "altered {altered}"
        );
    }
}

#[test]
fn malformed_shard_setup_is_rejected_before_expansion() {
    let fixture = fixture();
    let mut wrong_params = fixture.session.clone();
    wrong_params.params.db_rows += 1;
    assert!(QuerySession::from_session(&fixture.manifest, wrong_params, &acceptance()).is_err());
    let mut wrong_hash = fixture.manifest.clone();
    wrong_hash.sessions[0].public_params_sha256 = "00".repeat(32);
    assert!(
        QuerySession::from_session(&wrong_hash, fixture.session.clone(), &acceptance()).is_err()
    );
    let mut wrong_length = fixture.session;
    wrong_length.public_params_base64.pop();
    assert!(QuerySession::from_session(&fixture.manifest, wrong_length, &acceptance()).is_err());
}

#[test]
fn legacy_server_schema_is_rejected() {
    let legacy: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/upstream-session.json")).unwrap();
    let manifest: Manifest = serde_json::from_value(legacy["manifest"].clone()).unwrap();
    assert!(acceptance().validate(&manifest).is_err());
}

#[test]
fn q46_schema11_manifest_and_session_are_rejected() {
    let legacy: Fixture =
        serde_json::from_str(include_str!("fixtures/wallet-schema11-v5.json")).unwrap();
    assert!(legacy.manifest.validate().is_err());
    let current = fixture();
    assert!(QuerySession::from_session(&current.manifest, legacy.session, &acceptance()).is_err());
}
