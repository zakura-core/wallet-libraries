//! Pinned bytes for what receiver PIR adds to the shared `pir-native` P8 profile (seeds,
//! session IDs, framing and the directory row a lookup selects), from a request built
//! without `Client`.
mod common;
use common::receiver;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use zakura_pir_client::native::{D, NativeSetup, P8, ProfileClientExt as _};
use zakura_pir_client::receiver::{
    Client, Coverage, DIRECTORY_ROWS, Kind, Payment, ROW_BYTES, SCHEMA, Tree, choose_row,
    decode_choice, initial_salt, lookup_entry, lookup_slot,
    native::{COLS, MAGIC, profile},
    session::{Error, HEADER_BYTES},
    slot_row, tag,
    wire::PAYLOAD_BYTES,
};
use zakura_pir_publisher::receiver::{OPEN_SEED_ATTEMPTS, Paid, Projection, build};
use zakura_pir_query_server::receiver::server::Server;

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A profile seed: SHA-256 of the schema, `/native-p8/`, the purpose, a zero byte, the
/// table kind, a zero byte and the little-endian row count.
fn seed(purpose: &[u8], kind: &str, rows: u32) -> [u8; 32] {
    Sha256::new()
        .chain_update(SCHEMA)
        .chain_update(b"/native-p8/")
        .chain_update(purpose)
        .chain_update(b"\0")
        .chain_update(kind)
        .chain_update(b"\0")
        .chain_update(rows.to_le_bytes())
        .finalize()
        .into()
}

#[test]
fn the_protocol_reproduces_its_pinned_bytes() {
    let coverage = Coverage {
        genesis: [1; 32],
        history_revision: 0,
        start_height: 100,
        start_parent: [2; 32],
        start_position: 200,
        end_height: 101,
        end_hash: [3; 32],
        end_position: 300,
    };
    let paid: Vec<Paid> = (0..3u32)
        .map(|i| {
            let payment = Payment {
                height: 101,
                block_hash: [3; 32],
                txid: [4; 32],
                tx_index: 1,
                action_index: i,
                position: 200 + u64::from(i),
                action_nullifier: [5; 32],
                cmx: [6; 32],
                ephemeral_key: [7; 32],
                ciphertext_prefix: [8; 52],
            };
            let to = if i < 2 { receiver() } else { [9; 43] };
            (to, payment, [0; PAYLOAD_BYTES])
        })
        .collect();
    let mut projection = Projection::new(initial_salt(&coverage.start_parent, 0));
    let receivers: Vec<_> = paid.iter().map(|p| p.0).collect();
    projection.project(&receivers, &[3; 32]).unwrap();
    let tree = Tree {
        height: 101,
        hash: [3; 32],
        size: 300,
    };
    let segment = build(
        &projection,
        coverage,
        &[10; 32],
        OPEN_SEED_ATTEMPTS,
        2048,
        tree,
        &paid,
    )
    .unwrap();
    let (d, choice, data) = (
        segment.directory.manifest.clone(),
        segment.directory.choice.clone(),
        segment.directory.data.clone(),
    );
    let (directory, entries) = Server::directory(segment.directory).unwrap();
    let companion = Server::companion(segment.companion, &d, &entries).unwrap();
    let t = tag(&d.salt, &receiver());
    let target = choose_row(&d.salt, &decode_choice(&d, &choice).unwrap(), &t);

    // `RPQ1`, the session ID, a nonce, then the packing key and the dithered selection.
    let rows = DIRECTORY_ROWS as usize;
    let masks = P8
        .public_query_masks(
            seed(b"query-masks", "directory", DIRECTORY_ROWS),
            rows,
            COLS,
        )
        .unwrap();
    let setup = NativeSetup::new(
        P8.params(),
        seed(b"packing-setup", "directory", DIRECTORY_ROWS),
    );
    assert_eq!(
        masks,
        profile(Kind::Directory, DIRECTORY_ROWS).unwrap().masks
    );
    let mut rng = ChaCha20Rng::from_seed([21; 32]);
    let (secret, upload) = P8
        .prepare_dithered_with(&setup, &masks[..rows / D], rows, target as usize, &mut rng)
        .unwrap();
    let request = [&MAGIC[..], &directory.id(), &[22; 16], &upload].concat();
    let response = directory.respond(&request).unwrap();
    assert_eq!(response[..HEADER_BYTES], request[..HEADER_BYTES]);
    let row = P8
        .decode_cols(&secret, directory.public(), &response[HEADER_BYTES..], COLS)
        .unwrap();
    let at = target as usize * ROW_BYTES;
    assert_eq!(row, data[at..at + ROW_BYTES]);
    let entry = lookup_entry(&d, &row, &t).unwrap().unwrap();
    assert_eq!((entry.count, entry.last), (2, 1));

    // `Client` frames its own fresh query the same way, and a companion session answers a
    // slot under its own ID while refusing the directory's queries.
    let public = Arc::new(directory.public().to_vec());
    let client = Client::new(directory.session().clone(), public).unwrap();
    let query = client.prepare(target).unwrap();
    assert_eq!(query.body().len(), request.len());
    assert_eq!(query.body()[..36], request[..36]);
    assert!(matches!(
        companion.respond(query.body()),
        Err(Error::Revision)
    ));
    let answer = directory.respond(query.body()).unwrap();
    assert_eq!(client.decode(query, &answer).unwrap(), row);
    let public = Arc::new(companion.public().to_vec());
    let slots = Client::new(companion.session().clone(), public).unwrap();
    let query = slots.prepare(slot_row(entry.first + 1)).unwrap();
    let answer = companion.respond(query.body()).unwrap();
    let slot = slots.decode(query, &answer).unwrap();
    let c = &companion.session().manifest;
    let (record, payload) = lookup_slot(&d, c, &entry, entry.first + 1, &slot).unwrap();
    assert_eq!((record.page, payload), (1, paid[1].2));

    let got = [
        ("row index", target.to_string()),
        ("session", hex::encode(directory.id())),
        ("companion", hex::encode(companion.id())),
        ("public", digest(directory.public())),
        ("request", digest(&request)),
        ("response", digest(&response)),
        ("row", digest(&row)),
    ];
    let want = [
        ("row index", "468"),
        (
            "session",
            "cebccdf8e740de49ec9663dda690719e81382baf53d0cd7c14ce542139309da3",
        ),
        (
            "companion",
            "e14e6dbad3fac3de839e94c446ea9d8acf0483509cbfd54f79ce67e92bf9d02c",
        ),
        (
            "public",
            "4b24d5237a55c7b65df816a08390c2bfdb404bdc5258a37cdc9b50adb5be5ea6",
        ),
        (
            "request",
            "c83e85894acd3150ca72113428162b302c6017f385e30d02e90322c578c3fe65",
        ),
        (
            "response",
            "4516de869456fafe91cd74c24c3c2f23f562da0006530a05d814229ea223c99b",
        ),
        (
            "row",
            "525350321965ed90a8b13c21aa7aa9b5e4ccb8d0288a5b25f3ec26982436ecde",
        ),
    ];
    assert_eq!(got, want.map(|(name, value)| (name, value.to_owned())));
}
