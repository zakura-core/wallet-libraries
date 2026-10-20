//! Pinned bytes for what receiver PIR adds to the shared `pir-native` profile (seeds,
//! session ID, framing and row placement), from a request built without `Client`; a
//! change that alters one needs a new protocol name, not a new pin.
mod common;
use common::{manifest, receiver, record};
use ipir_sp::bits::u64s_to_contiguous_bytes;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use receiver_directory::snapshot::{lookup_row, row_for, Snapshot, MIN_ROWS, ROW_BYTES};
use receiver_pir::{server::Server, AcceptedCoverage, Client, HEADER_BYTES, MAGIC, PROTOCOL};
use sha2::{Digest, Sha256};
use zakura_pir_client::native::{NativeKeys, NativeSecret, NativeSetup, D, Q, QUERY_BITS, Q_BITS};

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A profile seed: SHA-256 of the protocol, `/`, the purpose, a zero byte and the
/// little-endian row count.
fn seed(purpose: &[u8], rows: u32) -> [u8; 32] {
    Sha256::new()
        .chain_update(PROTOCOL)
        .chain_update(b"/")
        .chain_update(purpose)
        .chain_update(b"\0")
        .chain_update(rows.to_le_bytes())
        .finalize()
        .into()
}

/// Rounds `x` modulo `Q` to its top `bits` bits, as `pir-native` switches a request.
fn round(x: u64, bits: usize) -> u64 {
    (((x as u128 * (1u128 << bits) + (Q / 2) as u128) / Q as u128) as u64) & ((1 << bits) - 1)
}

#[test]
fn the_protocol_reproduces_its_pinned_bytes() {
    let records = [record(0, 2), record(1, 2)];
    let snapshot = Snapshot::build(manifest(MIN_ROWS), &records, &[]).unwrap();
    let (rows, cols) = (MIN_ROWS as usize, ROW_BYTES / 2);
    let target = row_for(&snapshot.manifest, &receiver(), 1).unwrap();
    let server = Server::new(snapshot.clone()).unwrap();
    let id = server.manifest().id().unwrap();

    // `RPQ1`, the session ID, a nonce, then the packing key and the selection.
    let masks = zakura_pir_client::native::P16
        .public_query_masks(seed(b"query-masks", MIN_ROWS), rows, cols)
        .unwrap();
    let setup = NativeSetup::new(
        zakura_pir_client::native::params(),
        seed(b"packing-setup", MIN_ROWS),
    );
    let mut rng = ChaCha20Rng::from_seed([21; 32]);
    let secret = NativeSecret::sample(&zakura_pir_client::native::params(), &mut rng);
    let keys = NativeKeys::generate_one_key(&setup, &secret, &mut rng).unwrap();
    let selection = secret
        .encrypt_selection(&masks[..rows / D], target, &mut rng)
        .unwrap();
    let mut request = MAGIC.to_vec();
    request.extend(id);
    request.extend([22; 16]);
    request.extend(u64s_to_contiguous_bytes(&keys.kg_words(), Q_BITS));
    let switched: Vec<_> = selection.iter().map(|&x| round(x, QUERY_BITS)).collect();
    request.extend(u64s_to_contiguous_bytes(&switched, QUERY_BITS));

    let response = server.respond(&request).unwrap();
    assert_eq!(response[..HEADER_BYTES], request[..HEADER_BYTES]);
    let row = zakura_pir_client::native::decode_cols(
        &secret,
        server.public(),
        &response[HEADER_BYTES..],
        cols,
    )
    .unwrap();
    assert_eq!(
        row,
        snapshot.data[target * ROW_BYTES..(target + 1) * ROW_BYTES]
    );
    assert_eq!(
        lookup_row(&snapshot.manifest, &receiver(), 1, &row).unwrap(),
        Some(records[1].clone())
    );

    // `Client` frames its own fresh query the same way.
    let accepted = AcceptedCoverage {
        genesis: [1; 32],
        required_start: 100,
        height: 101,
        hash: [3; 32],
    };
    let client = Client::new(server.manifest().clone(), server.public(), accepted).unwrap();
    let query = client.prepare(receiver(), 1).unwrap();
    assert_eq!(query.body().len(), request.len());
    assert_eq!(query.body()[..36], request[..36]);
    let answer = server.respond(query.body()).unwrap();
    assert_eq!(
        client.decode(query, &answer).unwrap(),
        Some(records[1].clone())
    );

    let got = [
        ("row index", target.to_string()),
        ("session", hex::encode(id)),
        ("public", digest(server.public())),
        ("request", digest(&request)),
        ("response", digest(&response)),
        ("row", digest(&row)),
    ];
    // The correction revision changes the session header and its framed digests only.
    // Native setup, row placement and row bytes retain their independent golden values.
    let want = [
        ("row index", "2600"),
        (
            "session",
            "fdcdbb7ac3303d82a516050f036ef25aeab02e75e614de7bdcb8248996367c35",
        ),
        (
            "public",
            "f373884d2da8d24661a99793f5624739c4bfe90feedb7f8e4ed6f1042faa35e1",
        ),
        (
            "request",
            "f93ef6e515eae32680ca7e50567d8b9bf31ace8b2005e53a3fea02e07ca7b16d",
        ),
        (
            "response",
            "8b00631bc12b1dab1c4218ad36bd19af96a76db206606faac086a91defe1ce92",
        ),
        (
            "row",
            "6ac822f39e11fac5980508721afdd3fa8f3774ec01cdc7a2eb2e265a7cd82f44",
        ),
    ];
    for ((name, got), (_, want)) in got.iter().zip(want) {
        assert_eq!(got, want, "{name}");
    }
}

/// Sharing public preprocessing must not share a session, skip validation, or
/// answer changed rows with the previous publication's database.
#[test]
fn reused_rows_keep_fresh_sessions_and_changed_rows_rebuild() {
    let records = [record(0, 2), record(1, 2)];
    let snapshot = Snapshot::build(manifest(MIN_ROWS), &records, &[]).unwrap();
    let original = Server::new(snapshot.clone()).unwrap();
    let accepted = AcceptedCoverage {
        genesis: [1; 32],
        required_start: 100,
        height: 101,
        hash: [3; 32],
    };
    let old_client = Client::new(original.manifest().clone(), original.public(), accepted).unwrap();
    let old_query = old_client.prepare(receiver(), 1).unwrap();
    let mut advanced = snapshot.clone();
    advanced.manifest.end_height = 102;
    advanced.manifest.end_hash = [4; 32];
    let reused = Server::new_reusing_rows(advanced.clone(), &original).unwrap();
    assert!(std::ptr::eq(
        original.public().as_ptr(),
        reused.public().as_ptr()
    ));
    assert_ne!(original.id(), reused.id());
    assert!(matches!(
        reused.respond(old_query.body()),
        Err(receiver_pir::Error::Revision)
    ));
    let fresh = Server::new(advanced).unwrap();
    assert_eq!(reused.public(), fresh.public());
    let accepted = AcceptedCoverage {
        height: 102,
        hash: [4; 32],
        ..accepted
    };
    let client = Client::new(reused.manifest().clone(), reused.public(), accepted).unwrap();
    let query = client.prepare(receiver(), 1).unwrap();
    let response = reused.respond(query.body()).unwrap();
    assert_eq!(response, fresh.respond(query.body()).unwrap());
    assert_eq!(
        client.decode(query, &response).unwrap(),
        Some(records[1].clone())
    );

    let mut changed_records = records;
    changed_records[1].payment.txid[0] ^= 0x80;
    let changed = Snapshot::build(manifest(MIN_ROWS), &changed_records, &[]).unwrap();
    let rebuilt = Server::new_reusing_rows(changed, &original).unwrap();
    assert!(!std::ptr::eq(
        original.public().as_ptr(),
        rebuilt.public().as_ptr()
    ));
    let accepted = AcceptedCoverage {
        height: 101,
        hash: [3; 32],
        ..accepted
    };
    let client = Client::new(rebuilt.manifest().clone(), rebuilt.public(), accepted).unwrap();
    let query = client.prepare(receiver(), 1).unwrap();
    let response = rebuilt.respond(query.body()).unwrap();
    assert_eq!(
        client.decode(query, &response).unwrap(),
        Some(changed_records[1].clone())
    );
    let mut corrupt = snapshot.clone();
    corrupt.data[0] ^= 1;
    assert!(Server::new_reusing_rows(corrupt, &original).is_err());
    let mut corrupt = snapshot;
    corrupt.filters.push(1);
    assert!(Server::new_reusing_rows(corrupt, &original).is_err());
}
