//! Pinned bytes for what receiver PIR adds to the shared `pir-native` profile (seeds,
//! session ID, framing and row placement), from a request built without `Client`; a
//! change that alters one needs a new protocol name, not a new pin.
#[path = "../../receiver-directory/tests/common/mod.rs"]
mod common;
use common::{manifest, receiver, record};
use ipir_sp::bits::u64s_to_contiguous_bytes;
use pir_native::{NativeKeys, NativeSecret, NativeSetup, D, Q, QUERY_BITS, Q_BITS};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use receiver_directory::snapshot::{lookup_row, row_for, Snapshot, MIN_ROWS, ROW_BYTES};
use receiver_pir::{server::Server, AcceptedCoverage, Client, HEADER_BYTES, MAGIC, PROTOCOL};
use sha2::{Digest, Sha256};

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
    let masks = pir_native::public_query_masks(seed(b"query-masks", MIN_ROWS), rows, cols).unwrap();
    let setup = NativeSetup::new(pir_native::params(), seed(b"packing-setup", MIN_ROWS));
    let mut rng = ChaCha20Rng::from_seed([21; 32]);
    let secret = NativeSecret::sample(&pir_native::params(), &mut rng);
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
    let row =
        pir_native::decode_cols(&secret, server.public(), &response[HEADER_BYTES..], cols).unwrap();
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
    let want = [
        ("row index", "2600"),
        (
            "session",
            "1ff67e1b137866eed28623586925a7e258af335857854f38909f915f410e8945",
        ),
        (
            "public",
            "f373884d2da8d24661a99793f5624739c4bfe90feedb7f8e4ed6f1042faa35e1",
        ),
        (
            "request",
            "37c8a73cdd1f943da9ff2e202133d960bcd063af91626d5574c866f81114ef66",
        ),
        (
            "response",
            "9c52cf1169e5fc4dc6bcb5c4d3e99ebb906977a6f13260bccdd1d03cd0b4572c",
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
