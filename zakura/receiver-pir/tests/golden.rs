//! Pinned bytes for what receiver PIR adds to the shared `pir-native` profile (seeds,
//! session ID, framing and row placement), from a request built without `Client`; a
//! manifest-only changes alter session framing but preserve native setup and rows.
mod common;
use common::{manifest, receiver, record};
use ipir_sp::bits::u64s_to_contiguous_bytes;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use receiver_directory::snapshot::{lookup_row, row_for, Snapshot, MIN_ROWS, ROW_BYTES};
use receiver_pir::{
    server::{Server, WitnessServer},
    AcceptedCoverage, Client, Publication, WitnessClient, HEADER_BYTES, MAGIC, PROTOCOL,
};
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
    let snapshot = Snapshot::build(manifest(MIN_ROWS), &records).unwrap();
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
    // The 289-byte record with its witness ordinal changes the row bytes, so the public
    // setup, session and framed digests. Native setup and row placement are unchanged.
    let want = [
        ("row index", "2600"),
        (
            "session",
            "dfef4a80bc698477eb33fed0147973a6a44a7177f9c726862c059ddeff53582f",
        ),
        (
            "public",
            "9e381bd348e26d914d073535b99c548cfe49613aa3428c8fbfea00a550e5edc2",
        ),
        (
            "request",
            "105648f0abe4d5b4a76e4e766b4abd2cfd6c059f59492a8ed80fda5119a33095",
        ),
        (
            "response",
            "b385ab684031e348ea954da2bf452107710f987f794d184643bbb440def6acd3",
        ),
        (
            "row",
            "48713abae152674088b49f320f09aadaa9c3adbd8288e0a73832cd0f1d66aa88",
        ),
    ];
    assert_eq!(got, want.map(|(name, value)| (name, value.to_owned())));
}

/// A companion witness session answers an ordinal's payload under its own session ID,
/// bound to exactly one payment session, and refuses the payment session's queries.
#[test]
fn witness_sessions_answer_ordinals_and_bind_their_payment_table() {
    use receiver_directory::witness::{Manifest, Table, PAYLOAD_BYTES, PROFILE};
    let records = [record(0, 2), record(1, 2)];
    let payments = Server::new(Snapshot::build(manifest(MIN_ROWS), &records).unwrap()).unwrap();
    let directory = &payments.manifest().directory;
    let table = |tree_height: u32| Manifest {
        profile: PROFILE.into(),
        genesis: directory.genesis,
        history_revision: directory.history_revision,
        payments: directory.revision().unwrap(),
        payloads: 0,
        rows: MIN_ROWS,
        tree_height,
        tree_hash: if tree_height == directory.end_height {
            directory.end_hash
        } else {
            [9; 32]
        },
        tree_size: directory.end_position,
        data_sha256: [0; 32],
    };
    let payloads = [[0x11; PAYLOAD_BYTES], [0x22; PAYLOAD_BYTES]];
    let witnesses = WitnessServer::new(
        Table::build(table(directory.end_height), &payloads).unwrap(),
        &payments,
    )
    .unwrap();
    let publication = Publication {
        payments: payments.manifest().clone(),
        witnesses: witnesses.manifest().clone(),
    };
    publication.validate().unwrap();
    assert_eq!(
        hex::encode(witnesses.id()),
        "c024b19ad537bf88414d54b4d602a319800665ef9633a9f1693278050bdf9300"
    );
    let client = WitnessClient::new(witnesses.manifest().clone(), witnesses.public()).unwrap();
    for (ordinal, payload) in payloads.iter().enumerate() {
        let query = client.prepare(ordinal as u32).unwrap();
        assert!(matches!(
            payments.respond(query.body()),
            Err(receiver_pir::Error::Revision)
        ));
        let answer = witnesses.respond(query.body()).unwrap();
        assert_eq!(client.decode(query, &answer).unwrap(), *payload);
    }
    assert!(client.prepare(2).is_err());
    // A witness-only replacement is a new witness session over the same payment session.
    let replaced = WitnessServer::new(
        Table::build(table(directory.end_height + 1), &payloads).unwrap(),
        &payments,
    )
    .unwrap();
    assert_ne!(replaced.id(), witnesses.id());
    Publication {
        payments: payments.manifest().clone(),
        witnesses: replaced.manifest().clone(),
    }
    .validate()
    .unwrap();
    // Another payment table's companion is refused.
    let other = Server::new(Snapshot::build(manifest(MIN_ROWS), &records[..0]).unwrap()).unwrap();
    assert!(WitnessServer::new(
        Table::build(table(directory.end_height), &payloads).unwrap(),
        &other
    )
    .is_err());
    let mut mixed = publication;
    mixed.payments = other.manifest().clone();
    assert!(mixed.validate().is_err());
}
