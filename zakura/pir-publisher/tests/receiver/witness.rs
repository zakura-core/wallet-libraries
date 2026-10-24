//! Companion witness tables: binding to their payment table, layout and bounds.
mod common;
use common::{manifest, record};
use zakura_pir_publisher::receiver::{
    Error,
    snapshot::{ROW_BYTES, Snapshot, SnapshotPublisherExt},
    witness::{
        Manifest, PAYLOAD_BYTES, PAYLOADS, PROFILE, Table, TablePublisherExt, capacity, lookup_row,
        slot_for,
    },
};

/// A companion manifest for `payments`, built at its end.
fn companion(payments: &Snapshot) -> Manifest {
    let m = &payments.manifest;
    Manifest {
        profile: PROFILE.into(),
        genesis: m.genesis,
        history_revision: m.history_revision,
        payments: m.revision().unwrap(),
        payloads: 0,
        rows: 8,
        tree_height: m.end_height,
        tree_hash: m.end_hash,
        tree_size: m.end_position,
        data_sha256: [0; 32],
    }
}

/// `n` distinct payloads.
fn payloads(n: u8) -> Vec<[u8; PAYLOAD_BYTES]> {
    (0..n).map(|i| [i + 1; PAYLOAD_BYTES]).collect()
}

#[test]
fn ordinals_select_row_and_slot() {
    assert_eq!(PAYLOADS, 8);
    assert_eq!(slot_for(0), (0, 0));
    assert_eq!(slot_for(9), (1, 1));
    assert_eq!(capacity(8).unwrap(), 64);
    assert!(capacity(3).is_err());
    let payments = Snapshot::build(manifest(8), &[record(0, 2), record(1, 2)]).unwrap();
    let table = Table::build(companion(&payments), &payloads(2)).unwrap();
    table.validate().unwrap();
    assert_eq!(table.manifest.payloads, 2);
    table.manifest.check_payments(&payments.manifest).unwrap();
    let row = &table.data[..ROW_BYTES];
    assert_eq!(
        lookup_row(&table.manifest, 1, row).unwrap(),
        [2; PAYLOAD_BYTES]
    );
    assert!(matches!(
        lookup_row(&table.manifest, 2, row),
        Err(Error::Malformed)
    ));
    assert!(matches!(
        lookup_row(&table.manifest, 0, &row[1..]),
        Err(Error::Malformed)
    ));
}

/// The manifest binds one payment table: another revision, record count, network,
/// correction or a tree before its coverage is refused.
#[test]
fn a_companion_serves_exactly_its_payment_table() {
    let payments = Snapshot::build(manifest(8), &[record(0, 1)]).unwrap();
    let good = Table::build(companion(&payments), &payloads(1))
        .unwrap()
        .manifest;
    good.check_payments(&payments.manifest).unwrap();
    let edits: [&dyn Fn(&mut Manifest); 7] = [
        &|m| m.payments[0] ^= 1,
        &|m| m.payloads += 1,
        &|m| m.genesis[0] ^= 1,
        &|m| m.history_revision += 1,
        &|m| m.tree_height -= 1,
        &|m| m.tree_size -= 1,
        &|m| m.tree_hash[0] ^= 1,
    ];
    for (i, edit) in edits.iter().enumerate() {
        let mut m = good.clone();
        edit(&mut m);
        assert!(m.check_payments(&payments.manifest).is_err(), "{i}");
        assert_ne!(m.revision().unwrap(), good.revision().unwrap(), "{i}");
    }
    // A later construction tree is a valid witness-only replacement.
    let mut later = good.clone();
    (later.tree_height, later.tree_hash, later.tree_size) = (900, [7; 32], 400);
    later.check_payments(&payments.manifest).unwrap();
    let json = serde_json::to_value(&good).unwrap();
    let mut added = json;
    added["added"] = 1.into();
    assert!(serde_json::from_value::<Manifest>(added).is_err());
}

#[test]
fn supplied_tables_are_bounded_and_digest_checked() {
    let payments = Snapshot::build(manifest(8), &[record(0, 1)]).unwrap();
    assert!(matches!(
        Table::build(companion(&payments), &vec![[1; PAYLOAD_BYTES]; 65]),
        Err(Error::Capacity)
    ));
    let table = Table::build(companion(&payments), &payloads(1)).unwrap();
    let mut stale = table.clone();
    stale.data[0] ^= 1;
    assert!(stale.validate().is_err());
    let mut extra = table.clone();
    extra.data[PAYLOAD_BYTES] = 1;
    use sha2::{Digest, Sha256};
    extra.manifest.data_sha256 = Sha256::digest(&extra.data).into();
    assert!(
        extra.validate().is_err(),
        "slots past the payloads stay zero"
    );
    let mut short = table;
    short.data.pop();
    assert!(short.validate().is_err());
}
