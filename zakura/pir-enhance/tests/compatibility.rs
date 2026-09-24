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
        "611a29284264d844bf4dba00de2874c5b762f8c2"
    );
    assert_eq!(fixture.manifest.schema_version, 11);
    assert_eq!(
        fixture.manifest.protocol_revision,
        "ironwood-enhance-pir-v7"
    );
    assert_eq!(RECORD_BYTES, 653);
    assert_eq!(RECORDS_PER_ROW, 33);
    assert_eq!(ROW_BYTES, 21_549);
    assert_eq!(
        fixture.manifest.sessions[0].parameter_id,
        "ironwood-enhance-pir-v7/6ef480a31bd6a76c6403288ba1a0f0aeefbbe1805ba35168a85ccb2b07bd1c7b"
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
    assert_eq!(&query.body()[..4], b"EPQ7");
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
    fixture.manifest.protocol_revision = "ironwood-enhance-pir-v7".into();
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
        QuerySession::from_session(&fixture.manifest, fixture.session.clone(), &acceptance())
            .unwrap();
    let (query, _) = session.prepare_position(33).unwrap();
    let binding = QueryBinding::decode(query.body()).unwrap();
    let response = binding.encode();
    assert!(session.decode(query, &response).is_err()); // Exact packed-body length.

    let params = &fixture.session.params;
    let response_len = HEADER_BYTES
        + params.db_cols / params.poly_len
            * ipir_sp::modulus_switch::response_body_len(params.poly_len, params.q_prime_1);
    for altered in 0..8 {
        let (query, _) = session.prepare_position(33).unwrap();
        let mut response = query.body()[..HEADER_BYTES].to_vec();
        response.resize(response_len, 0);
        // Magic and every binding field, with a valid body length in every case.
        response[[0, 4, 12, 20, 28, 36, 68, 84][altered]] ^= 1;
        assert!(
            session.decode(query, &response).is_err(),
            "altered {altered}"
        );
    }
    let (query, _) = session.prepare_position(33).unwrap();
    let mut response = query.body()[..HEADER_BYTES].to_vec();
    response.resize(response_len, 0);
    assert!(session.decode(query, &response).is_ok());
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
    assert!(serde_json::from_value::<Manifest>(legacy["manifest"].clone()).is_err());
}

#[test]
fn q46_schema11_manifest_and_session_are_rejected() {
    assert!(
        serde_json::from_str::<Fixture>(include_str!("fixtures/wallet-schema11-v5.json")).is_err()
    );
    let current = fixture();
    let mut session = current.session;
    session.params.query_bits = 46;
    assert!(QuerySession::from_session(&current.manifest, session, &acceptance()).is_err());
}

#[test]
fn q48_rejects_other_query_precisions_even_with_v6_manifest() {
    for bits in [46, 47, 49] {
        let mut current = fixture();
        current.session.params.query_bits = bits;
        assert!(
            QuerySession::from_session(&current.manifest, current.session, &acceptance()).is_err()
        );
    }
}

#[test]
fn rebinding_requires_fresh_wallet_acceptance_and_preserves_state_on_failure() {
    let mut fixture = fixture();
    let mut session =
        QuerySession::from_session(&fixture.manifest, fixture.session, &acceptance()).unwrap();
    let id = session.session_id();
    let old_generation = session.manifest_generation();
    fixture.manifest.generation += 1;
    fixture.manifest.anchor_height += 1;
    fixture.manifest.anchor_block_hash = "43".repeat(32);
    assert!(session.rebind(&fixture.manifest, &acceptance()).is_err());
    assert_eq!(session.manifest_generation(), old_generation);
    let (query, _) = session.prepare_position(0).unwrap();
    assert_eq!(
        QueryBinding::decode(query.body()).unwrap().anchor_hash,
        [0x42; 32]
    );
    let mut accepted = acceptance();
    accepted.anchor.height += 1;
    accepted.anchor.block_hash = [0x43; 32];
    session.rebind(&fixture.manifest, &accepted).unwrap();
    assert_eq!(session.session_id(), id);
    assert_eq!(session.manifest_generation(), fixture.manifest.generation);
    let (query, _) = session.prepare_position(0).unwrap();
    assert_eq!(
        QueryBinding::decode(query.body()).unwrap().anchor_hash,
        [0x43; 32]
    );
    fixture.manifest.unit_identities.get_mut(&0).unwrap()[0].content_sha256 = "ab".repeat(32);
    assert!(session.rebind(&fixture.manifest, &accepted).is_err());
    assert_eq!(session.session_id(), id);
}
