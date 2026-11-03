//! Receiver lookups through real P8 queries: a directory row chosen by the
//! choice object, then companion slots read with trimmed and full queries,
//! including slots in a row's second packing block.
use zakura_pir_client::native::{D, P8, ProfileClientExt as _};
use zakura_pir_protocol::receiver::{
    Hash, Payment,
    native::{COLS, MAGIC, profile},
    session::HEADER_BYTES,
    wire::PAYLOAD_BYTES,
    *,
};
use zakura_pir_publisher::receiver::{OPEN_SEED_ATTEMPTS, Paid, Projection, build};
use zakura_pir_query_server::receiver::server::Server;

/// Reads row `row` of a served table through PIR, with a query over its first
/// `sent` rows.
fn read<M: Table>(server: &Server<M>, kind: Kind, rows: u32, sent: u32, row: u32) -> Vec<u8> {
    let profile = profile(kind, rows).unwrap();
    let masks = &profile.masks[..sent as usize / D];
    let (secret, upload) = P8
        .prepare(&profile.setup, masks, sent as usize, row as usize)
        .unwrap();
    let body = [&MAGIC[..], &server.id(), &[0; 16], &upload].concat();
    let response = server.respond(&body).unwrap();
    assert_eq!(response[..HEADER_BYTES], body[..HEADER_BYTES]);
    P8.decode_cols(&secret, server.public(), &response[HEADER_BYTES..], COLS)
        .unwrap()
}

#[test]
fn lookups_read_entries_and_slots_through_pir() {
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
    let paid: Vec<Paid> = (0..7u32)
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
                ciphertext_prefix: [i as u8 + 1; 52],
            };
            ([u8::from(i > 4); 43], payment, [0; PAYLOAD_BYTES])
        })
        .collect();
    let receivers: Vec<_> = paid.iter().map(|p| p.0).collect();
    let mut projection = Projection::new(initial_salt(&coverage.start_parent, 0));
    projection.project(&receivers, &[3; 32]).unwrap();
    let tree = Tree {
        height: 100,
        hash: [3; 32],
        size: 1000,
    };
    let seed: Hash = [9; 32];
    let segment = build(
        &projection,
        coverage,
        &seed,
        OPEN_SEED_ATTEMPTS,
        4096,
        tree,
        &paid,
    )
    .unwrap();
    let (d, choice) = (
        segment.directory.manifest.clone(),
        segment.directory.choice.clone(),
    );
    let (directory, entries) = Server::directory(segment.directory).unwrap();
    let companion = Server::companion(segment.companion, &d, &entries).unwrap();
    let c = companion.session().manifest.clone();
    assert_eq!((c.rows, c.query_rows), (4096, 2048));

    let choice = decode_choice(&d, &choice).unwrap();
    for receiver in [[0; 43], [1; 43]] {
        let t = tag(&d.salt, &receiver);
        let row = read(
            &directory,
            Kind::Directory,
            DIRECTORY_ROWS,
            DIRECTORY_ROWS,
            choose_row(&d.salt, &choice, &t),
        );
        let entry = lookup_entry(&d, &row, &t).unwrap().unwrap();
        for slot in entry.slots() {
            for sent in [c.query_rows, c.rows] {
                let row = read(&companion, Kind::Companion, c.rows, sent, slot_row(slot));
                assert!(slot_row(slot) > 0 || row[2048..].iter().any(|b| *b != 0));
                let (record, _) = lookup_slot(&d, &c, &entry, slot, &row).unwrap();
                let expected = paid
                    .iter()
                    .filter(|p| p.0 == receiver)
                    .nth(record.page as usize);
                assert_eq!(
                    (record.receiver, Some(&record.payment)),
                    (receiver, expected.map(|p| &p.1))
                );
            }
        }
    }
}
