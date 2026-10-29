//! The evaluator's admission: full and trimmed companion queries, an
//! untrimmed directory, and the zero suffix checked at preparation.
use super::*;
use zakura_pir_protocol::receiver::{
    Payment,
    native::{query_bytes, response_bytes},
    wire::PAYLOAD_BYTES,
};
use zakura_pir_publisher::receiver::{OPEN_SEED_ATTEMPTS, Paid, Projection, build};

/// A segment paying `payments` receivers once each at height 100, with a
/// companion of `rows` rows.
fn segment(payments: u32, rows: u32) -> (DirectoryTable, CompanionTable) {
    let coverage = Coverage {
        genesis: [1; 32],
        history_revision: 0,
        start_height: 100,
        start_parent: [2; 32],
        start_position: 0,
        end_height: 100,
        end_hash: [3; 32],
        end_position: 1000,
    };
    let paid: Vec<Paid> = (0..payments)
        .map(|i| {
            let payment = Payment {
                height: 100,
                block_hash: [3; 32],
                txid: [4; 32],
                tx_index: 1,
                action_index: i,
                position: i.into(),
                action_nullifier: [5; 32],
                cmx: [6; 32],
                ephemeral_key: [7; 32],
                ciphertext_prefix: [8; 52],
            };
            ([i as u8; 43], payment, [0; PAYLOAD_BYTES])
        })
        .collect();
    let mut projection = Projection::new(initial_salt(&coverage.start_parent, 0));
    let receivers: Vec<_> = paid.iter().map(|p| p.0).collect();
    projection.project(&receivers, &[3; 32]).unwrap();
    let tree = Tree {
        height: 100,
        hash: [3; 32],
        size: 1000,
    };
    let segment = build(
        &projection,
        coverage,
        &[3; 32],
        OPEN_SEED_ATTEMPTS,
        rows,
        tree,
        &paid,
    );
    let segment = segment.unwrap();
    (segment.directory, segment.companion)
}

/// Both servers of a segment.
fn servers(payments: u32, rows: u32) -> (Server<Directory>, Server<Companion>) {
    let (directory, companion) = segment(payments, rows);
    let manifest = directory.manifest.clone();
    let (directory, entries) = Server::directory(directory).unwrap();
    (
        directory,
        Server::companion(companion, &manifest, &entries).unwrap(),
    )
}

/// A request of `len` bytes framed for `id`, its upload arbitrary. Any bytes
/// parse as a key and a selection, so only the length decides admission.
fn request(id: &Hash, len: usize) -> Vec<u8> {
    let mut body: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
    body[..4].copy_from_slice(MAGIC);
    body[4..36].copy_from_slice(id);
    body
}

/// A companion takes its full length or exactly its `query_rows` prefix, and
/// refuses any other prefix, another session and another magic.
#[test]
fn companions_accept_full_and_trimmed_queries_only() {
    let (_, companion) = servers(3, 6144);
    assert_eq!(companion.session().manifest.query_rows, 2048);
    let id = companion.id();
    for rows in [6144, 2048] {
        let response = companion.respond(&request(&id, query_bytes(rows))).unwrap();
        assert_eq!(response.len(), response_bytes(), "{rows} rows");
    }
    for len in [
        query_bytes(4096),
        query_bytes(2048) - 1,
        query_bytes(6144) + 1,
    ] {
        assert!(matches!(
            companion.respond(&request(&id, len)),
            Err(Error::Malformed)
        ));
    }
    let foreign = request(&[0; 32], query_bytes(2048));
    assert!(matches!(companion.respond(&foreign), Err(Error::Revision)));
    let mut magic = request(&id, query_bytes(2048));
    magic[..4].copy_from_slice(b"RPQ9");
    assert!(matches!(companion.respond(&magic), Err(Error::Malformed)));
}

/// A directory is answered only over all of its rows. At 2,048 rows no whole
/// block prefix exists, so a shorter or companion-shaped upload is refused.
#[test]
fn directories_are_never_trimmed() {
    let (directory, _) = servers(3, 2048);
    let id = directory.id();
    let response = directory
        .respond(&request(&id, query_bytes(DIRECTORY_ROWS)))
        .unwrap();
    assert_eq!(response.len(), response_bytes());
    for len in [query_bytes(4096), query_bytes(DIRECTORY_ROWS) - 1] {
        assert!(matches!(
            directory.respond(&request(&id, len)),
            Err(Error::Malformed)
        ));
    }
}

/// An empty companion has one zero block, and its one query shape is 2,048
/// rows.
#[test]
fn empty_companions_take_one_block_queries() {
    let (directory, companion) = servers(0, 2048);
    assert_eq!(companion.session().manifest.query_rows, 2048);
    assert!(
        companion
            .respond(&request(&companion.id(), query_bytes(2048)))
            .is_ok()
    );
    assert!(
        directory
            .respond(&request(&directory.id(), query_bytes(2048)))
            .is_ok()
    );
}

/// Preparation refuses a companion with a nonzero byte in a row a trimmed
/// query omits, even with its digest rebound.
#[test]
fn preparation_refuses_a_nonzero_omitted_row() {
    let (directory, mut companion) = segment(3, 4096);
    companion.data[2048 * ROW_BYTES + 7] = 1;
    companion.manifest.data_sha256 = Sha256::digest(&companion.data).into();
    let manifest = directory.manifest.clone();
    let (_, entries) = Server::directory(directory).unwrap();
    assert!(Server::companion(companion, &manifest, &entries).is_err());
}

/// Served sessions form a valid publication; another segment's companion
/// does not.
#[test]
fn served_sessions_form_a_publication() {
    let (directory, companion) = servers(3, 2048);
    let (_, other) = servers(2, 2048);
    let publication = |companion: &Server<Companion>| Publication {
        directory: directory.session().clone(),
        companion: companion.session().clone(),
    };
    publication(&companion).validate().unwrap();
    assert!(publication(&other).validate().is_err());
    assert_ne!(directory.id(), companion.id());
}

#[test]
fn native_scan_matches_previous_provider_fixtures() {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("../../../testdata/previous_provider_scans.json"))
            .unwrap();
    for rows in [DIRECTORY_ROWS as usize, 2 * DIRECTORY_ROWS as usize] {
        let data: Vec<u8> = (0..rows * COLS)
            .map(|i| (i as u8).wrapping_mul(157).wrapping_add(19))
            .collect();
        let database = Database::new(rows, &data).unwrap();
        let fixture = &fixtures[rows.to_string()];
        assert_eq!(hex::encode(Sha256::digest(&database.values)), fixture["database"]);
        for (index, query) in [
            vec![0; rows],
            vec![Q - 1; rows],
            (0..rows)
                .map(|i| (i as u64).wrapping_mul(Q / 3) & (Q - 1))
                .collect(),
        ]
        .into_iter()
        .enumerate()
        {
            let actual = database.multiply(&query).unwrap();
            let mut hash = Sha256::new();
            for value in &actual {
                hash.update(value.to_le_bytes());
            }
            assert_eq!(hex::encode(hash.finalize()), fixture["scans"][index]);
            for col in [0, COLS / 2, COLS - 1] {
                let exact: u128 = (0..rows)
                    .map(|row| u128::from(data[row * COLS + col]) * u128::from(query[row]))
                    .sum();
                assert_eq!(actual[col], (exact % u128::from(Q)) as u64);
            }
        }
        assert!(database.multiply(&vec![0; rows - 1]).is_err());
        assert!(database.multiply(&vec![Q; rows]).is_err());
    }
}

#[test]
fn native_database_handles_partial_tiles() {
    let rows = 35;
    let data: Vec<u8> = (0..rows * COLS).map(|i| (i % 251) as u8).collect();
    let database = Database::new(rows, &data).unwrap();
    for row in 0..rows {
        for col in 0..COLS {
            assert_eq!(database.values[col * rows + row], data[row * COLS + col]);
        }
    }
}
