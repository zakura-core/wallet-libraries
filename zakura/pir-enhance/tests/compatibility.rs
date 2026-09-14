//! Conformance to Enhance PIR 8c86d1b and its pinned ipir-sp server primitives.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use inspiring::TopKeyImages;
use ipir_sp::{
    IPIRClient,
    serialize::{deserialize_packing_keys, serialized_packing_keys_len},
    server::{IPIRServer, build_pack_preprocessed_blocks, published_c1_rows},
};
use sha2::{Digest, Sha256};
use zakura_pir_enhance::{
    AcceptedAnchor, ClientResourceLimits, EnhanceSession, GenerationAcceptance, QuerySession,
    RECORD_BYTES, RECORDS_PER_ROW, ROW_BYTES, SHARD_POSITIONS, SHARD_ROWS,
    client::record_in_row,
    types::{RECORD_FLAGS_OFFSET, setup_seed_bytes},
};

fn fixture() -> EnhanceSession {
    serde_json::from_str(include_str!("fixtures/upstream-session.json")).unwrap()
}

fn acceptance() -> GenerationAcceptance {
    // Independent, synthetic wallet metadata; never accept an anchor by copying server fields.
    GenerationAcceptance::new(
        "main",
        3_428_143,
        AcceptedAnchor::new(3_428_143, [0x42; 32], 73_728),
        ClientResourceLimits::new(8_192),
    )
}

#[test]
fn upstream_session_contract_is_accepted_and_round_trips() {
    let wire: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/upstream-session.json")).unwrap();
    let session = fixture();
    assert_eq!(serde_json::to_value(&session).unwrap(), wire);
    let query_session = QuerySession::from_session(session, &acceptance()).unwrap();
    assert_eq!(query_session.params().instances, 2);
    assert_eq!(query_session.params().db_cols, 4_096);
    assert_eq!(
        query_session.generation().shards[0].worker,
        "opaque-group-a"
    );
}

/// Full production geometry is intentionally opt-in locally and mandatory in release-mode CI.
#[test]
#[ignore = "full-shard cryptography; run with --release -- --ignored"]
fn full_shard_production_round_trip() {
    let mut session = fixture();
    let (rlwe, params) = ipir_sp::params_for_simplepir(
        session.generation.logical_rows,
        u64::from(session.generation.row_bytes) * 8,
    )
    .unwrap();
    assert_eq!(params, session.params);
    let setup = IPIRClient::new(&rlwe, &params)
        .generate_public_query_setup_simplepir_from_seed(setup_seed_bytes());

    // Position-dependent bytes catch row/slot swaps, 14-bit packing errors, and truncation.
    let mut rows = vec![0u8; SHARD_ROWS * ROW_BYTES];
    for position in 0..SHARD_POSITIONS {
        let record = &mut rows[position * RECORD_BYTES..(position + 1) * RECORD_BYTES];
        for (offset, byte) in record.iter_mut().enumerate() {
            *byte = (position.wrapping_mul(37) ^ (position >> 8) ^ offset) as u8;
        }
        record[RECORD_FLAGS_OFFSET] = (position % 4) as u8;
    }
    session.generation.shards[0].rows_sha256 = hex::encode(Sha256::digest(&rows));
    // Matches Enhance server's RowCoefficientIter: each row is independently packed into p.
    let plaintext_bits = params.p.ilog2() as usize;
    let coefficients = rows.chunks_exact(ROW_BYTES).flat_map(|row| {
        (0..params.db_cols).map(move |column| {
            ipir_sp::bits::read_bits(row, column * plaintext_bits, plaintext_bits) as u16
        })
    });
    let server = IPIRServer::new(params.clone(), coefficients, false, true);
    let offline = server.perform_offline_precomputation_simplepir(&rlwe, &setup);
    let preprocessed = build_pack_preprocessed_blocks(&rlwe, &offline.crs_blocks).unwrap();
    let top_keys = TopKeyImages::build(&rlwe);
    let public_params = published_c1_rows(&preprocessed, rlwe.q);
    let digest = Sha256::digest(&public_params);
    session.generation.public_params_epoch = hex::encode(&digest[..8]);
    session.generation.public_params_sha256 = hex::encode(digest);
    session.public_params_base64 = STANDARD.encode(public_params);
    let generation = session.generation.generation;
    let query_session = QuerySession::from_session(session, &acceptance()).unwrap();

    let answer = |body: &[u8]| {
        assert_eq!(&body[..8], &generation.to_le_bytes());
        let keys_len = serialized_packing_keys_len(&rlwe);
        let keys = deserialize_packing_keys(&rlwe, &body[8..8 + keys_len]).unwrap();
        let payload = server
            .perform_full_online_computation_simplepir_measured(
                &rlwe,
                &body[8 + keys_len..],
                &keys,
                &top_keys,
                &preprocessed,
            )
            .unwrap()
            .0;
        let mut response = generation.to_le_bytes().to_vec();
        response.extend_from_slice(&digest[..8]);
        response.extend_from_slice(&payload);
        response
    };
    for position in [0, RECORDS_PER_ROW - 1, RECORDS_PER_ROW, SHARD_POSITIONS - 1] {
        let (query, slot) = query_session.prepare_position(position as u64).unwrap();
        let response = answer(query.body());
        let decoded = query_session.decode(query, &response).unwrap();
        assert_eq!(
            record_in_row(&decoded, slot).unwrap().as_bytes().as_slice(),
            &rows[position * RECORD_BYTES..(position + 1) * RECORD_BYTES],
            "position {position}"
        );
    }
    assert!(
        query_session
            .prepare_position(SHARD_POSITIONS as u64)
            .is_err()
    );
    let dummy = query_session.prepare_dummy().unwrap();
    let row = dummy.row();
    let response = answer(dummy.body());
    assert_eq!(
        query_session.decode(dummy, &response).unwrap(),
        rows[row * ROW_BYTES..(row + 1) * ROW_BYTES]
    );
}
