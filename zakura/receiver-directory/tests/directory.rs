mod common;
use common::{manifest, receiver, record};
use receiver_directory::{
    snapshot::{lookup_row, row_for, Snapshot, MAX_ROWS, MIN_ROWS, ROW_BYTES, SLOTS},
    Error, RawRecord, ReceiverBytes, RECORD_BYTES,
};

fn row<'a>(s: &'a Snapshot, r: &ReceiverBytes, page: u32) -> &'a [u8] {
    let n = row_for(&s.manifest, r, page).unwrap();
    &s.data[n * ROW_BYTES..(n + 1) * ROW_BYTES]
}

#[test]
fn wire_layout_and_strict_empty_slots() {
    let r = record(0, 1);
    let b = r.encode().unwrap();
    assert_eq!(b.len(), 285);
    assert_eq!(&b[129..137], &200u64.to_le_bytes());
    assert_eq!(RawRecord::decode(&b).unwrap(), Some(r));
    assert!(RawRecord::decode(&[0; RECORD_BYTES]).unwrap().is_none());
    let mut corrupt = [0; RECORD_BYTES];
    corrupt[284] = 1;
    assert!(RawRecord::decode(&corrupt).is_err());
    assert!(RawRecord::decode(&b[..284]).is_err());
}

/// The directory parses structure only. Cryptographically invalid receiver and
/// Action bytes pass through a build, a lookup and a supplied publication unchanged:
/// the publisher refuses them before storing, and every wallet before crediting.
#[test]
fn records_are_carried_without_cryptographic_checks() {
    let mut r = record(0, 1);
    r.receiver = [255; 43];
    let p = &mut r.payment;
    (p.action_nullifier, p.cmx, p.ephemeral_key) = ([255; 32], [255; 32], [255; 32]);
    let s = Snapshot::build(manifest(8), &[r.clone()], &[]).unwrap();
    s.validate().unwrap();
    assert_eq!(
        lookup_row(&s.manifest, &r.receiver, 0, row(&s, &r.receiver, 0)).unwrap(),
        Some(r)
    );
}

/// A manifest with a field this version does not know is refused, and the revision
/// binds every field, including each set's optional ones.
#[test]
fn manifests_refuse_unknown_fields_and_bind_every_field() {
    use receiver_directory::snapshot::Manifest;
    let s = Snapshot::build(manifest(8), &[record(0, 1)], &[]).unwrap();
    let json = serde_json::to_value(&s.manifest).unwrap();
    let read: Manifest = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(read.revision().unwrap(), s.manifest.revision().unwrap());
    let mut added = json.clone();
    added["added"] = 1.into();
    assert!(serde_json::from_value::<Manifest>(added).is_err());
    let mut nested = json;
    nested["filters"][0]["note"] = "later".into();
    assert!(serde_json::from_value::<Manifest>(nested).is_err());
    let mut other = s.manifest.clone();
    other.records += 1;
    assert_ne!(other.revision().unwrap(), s.manifest.revision().unwrap());
    let mut catalog = s.manifest.clone();
    catalog.catalog_sha256[0] ^= 1;
    assert_ne!(catalog.revision().unwrap(), s.manifest.revision().unwrap());
}

#[test]
fn pages_share_one_revision_and_build_order_is_stable() {
    let records = [record(0, 2), record(1, 2)];
    let s = Snapshot::build(manifest(8), &records, &[]).unwrap();
    let reversed =
        Snapshot::build(manifest(8), &[records[1].clone(), records[0].clone()], &[]).unwrap();
    assert_eq!(
        s.manifest.revision().unwrap(),
        reversed.manifest.revision().unwrap()
    );
    for r in &records {
        assert_eq!(
            lookup_row(
                &s.manifest,
                &r.receiver,
                r.page,
                row(&s, &r.receiver, r.page)
            )
            .unwrap(),
            Some(r.clone())
        );
    }
    let empty = Snapshot::build(manifest(8), &[], &[]).unwrap();
    assert!(lookup_row(
        &empty.manifest,
        &records[0].receiver,
        0,
        row(&empty, &records[0].receiver, 0)
    )
    .unwrap()
    .is_none());
    assert!(matches!(
        lookup_row(
            &empty.manifest,
            &records[0].receiver,
            1,
            row(&empty, &records[0].receiver, 1)
        ),
        Err(Error::MissingPage)
    ));
    assert!(Snapshot::build(manifest(8), &records[..1], &[]).is_err());
    assert!(Snapshot::build(manifest(8), &records[1..], &[]).is_err());
    assert!(Snapshot::build(manifest(8), &[record(0, 1), record(1, 2)], &[]).is_err());
    assert!(Snapshot::build(manifest(8), &[record(0, 1), record(0, 1)], &[]).is_err());
}

/// Valid Ironwood receivers, pinned in `fixtures/receivers.json` (see
/// [`common::seeded_receiver`]): `other` and `third` from spending keys of bytes 3 and
/// 4 at external index zero, and `spread` from the spending key of bytes 5 at external
/// indices 0 to 15.
fn pinned(key: &str) -> Vec<ReceiverBytes> {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/receivers.json")).unwrap();
    let values = match &fixture[key] {
        serde_json::Value::Array(values) => values.clone(),
        value => vec![value.clone()],
    };
    values
        .iter()
        .map(|v| {
            hex::decode(v.as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        })
        .collect()
}

/// A valid receiver other than [`receiver`].
fn other_receiver() -> ReceiverBytes {
    pinned("other")[0]
}

#[test]
fn publications_commit_to_their_filters() {
    use receiver_directory::{
        filter::{Filters, PAID},
        snapshot::ProviderSet,
    };
    use sha2::{Digest, Sha256};
    let (paid, provider) = (receiver(), other_receiver());
    let sets = [
        ProviderSet {
            label: "near-intents/recent".into(),
            window_secs: Some(86_400),
            since_unix: 1_000,
            until_unix: 90_000,
            receivers: vec![provider],
        },
        ProviderSet {
            label: "near-intents/seen".into(),
            window_secs: None,
            since_unix: 1_000,
            until_unix: 90_000,
            receivers: vec![provider],
        },
    ];
    let s = Snapshot::build(manifest(8), &[record(0, 1)], &sets).unwrap();
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&s.filters)),
        s.manifest.filters_sha256
    );
    let filters = Filters::decode(&s.filters).unwrap();
    s.manifest.check_filters(&filters).unwrap();
    let labels: Vec<_> = s
        .manifest
        .filters
        .iter()
        .map(|f| f.label.as_str())
        .collect();
    assert_eq!(labels, ["near-intents/recent", "near-intents/seen", PAID]);
    assert_eq!(s.manifest.filters[0].window_secs, Some(86_400));
    assert_eq!(s.manifest.filters[0].until_unix, Some(90_000));
    assert_eq!(s.manifest.filters[2].since_unix, None);
    assert_eq!(s.manifest.filters[2].until_unix, None);
    let key = s.manifest.salt;
    let set = |label| filters.get(label).unwrap().matches(&key, &[paid, provider]);
    assert_eq!(set(PAID), [true, false]);
    assert_eq!(set("near-intents/recent"), [false, true]);
    assert_eq!(set("near-intents/seen"), [false, true]);
    // The provider's data is part of the revision.
    let without = Snapshot::build(manifest(8), &[record(0, 1)], &[]).unwrap();
    assert_ne!(
        without.manifest.revision().unwrap(),
        s.manifest.revision().unwrap()
    );
    // A filter file is checked against the sets its manifest declares.
    let only_paid = Filters::decode(&without.filters).unwrap();
    assert!(s.manifest.check_filters(&only_paid).is_err());
    // A recent set must declare its window, labels must be known kinds, and a feed
    // cannot end before it started.
    for (label, window_secs, until_unix) in [
        ("near-intents/recent", None, 90_000),
        ("near-intents/other", None, 90_000),
        ("near-intents/seen", None, 999),
    ] {
        let bad = [ProviderSet {
            label: label.into(),
            window_secs,
            since_unix: 1_000,
            until_unix,
            receivers: vec![provider],
        }];
        assert!(Snapshot::build(manifest(8), &[record(0, 1)], &bad).is_err());
    }
}

#[test]
fn coverage_anchor_and_position_are_required() {
    let m = manifest(8);
    m.accept([1; 32], 100, 101, [3; 32]).unwrap();
    for (network, start, height, hash) in [
        ([9; 32], 100, 101, [3; 32]),
        ([1; 32], 99, 101, [3; 32]),
        ([1; 32], 100, 102, [3; 32]),
        ([1; 32], 100, 101, [9; 32]),
    ] {
        assert!(m.accept(network, start, height, hash).is_err());
    }
    let mut r = record(0, 1);
    r.payment.position = 300;
    assert!(Snapshot::build(m.clone(), &[r], &[]).is_err());
    let mut r = record(0, 1);
    r.payment.block_hash = [9; 32];
    assert!(Snapshot::build(m.clone(), &[r], &[]).is_err());
    // Transaction zero is the coinbase, whose recipients the directory excludes.
    let mut r = record(0, 1);
    r.payment.tx_index = 0;
    assert!(matches!(
        Snapshot::build(m, &[r], &[]),
        Err(Error::Malformed)
    ));
}

/// A manifest cannot claim more records than its span has note positions.
#[test]
fn records_fit_the_covered_positions() {
    let mut m = manifest(MIN_ROWS);
    m.records = m.end_position - m.start_position;
    m.validate().unwrap();
    m.records += 1;
    assert!(matches!(m.validate(), Err(Error::Malformed)));
}

/// A row whose record claims more pages than the publication has records is
/// malformed.
#[test]
fn a_total_beyond_the_record_count_is_malformed() {
    let s = Snapshot::build(manifest(8), &[record(0, 1)], &[]).unwrap();
    let r = receiver();
    let mut b = row(&s, &r, 0).to_vec();
    assert!(lookup_row(&s.manifest, &r, 0, &b).unwrap().is_some());
    let slot = b
        .chunks(RECORD_BYTES)
        .position(|slot| slot.iter().any(|x| *x != 0))
        .unwrap();
    // The total pages field follows the version, receiver and page.
    b[slot * RECORD_BYTES + 48..slot * RECORD_BYTES + 52].copy_from_slice(&2u32.to_le_bytes());
    assert!(RawRecord::decode(&b[slot * RECORD_BYTES..(slot + 1) * RECORD_BYTES]).is_ok());
    assert!(matches!(
        lookup_row(&s.manifest, &r, 0, &b),
        Err(Error::Malformed)
    ));
}

/// The note commitment tree ends at 2^32 positions.
#[test]
fn coverage_ends_within_the_tree() {
    let mut m = manifest(MIN_ROWS);
    m.end_position = 1 << 32;
    m.validate().unwrap();
    m.end_position += 1;
    assert!(m.validate().is_err());
}

#[test]
fn overflow_and_bad_padding_fail_closed() {
    let records: Vec<_> = (0..50).map(|p| record(p, 50)).collect();
    let mut m = manifest(4);
    let overflow = (0..100).any(|i| {
        m.salt[0] = i;
        matches!(
            Snapshot::build(m.clone(), &records, &[]),
            Err(Error::Capacity)
        )
    });
    assert!(overflow);
    let s = Snapshot::build(manifest(8), &[record(0, 1)], &[]).unwrap();
    let r = receiver();
    let mut b = row(&s, &r, 0).to_vec();
    b[ROW_BYTES - 1] = 1;
    assert!(lookup_row(&s.manifest, &r, 0, &b).is_err());
}

/// More records than slots is a capacity failure, found before placement; a bad row
/// count stays malformed.
#[test]
fn records_beyond_the_slots_are_a_capacity_failure() {
    let records = |n: u32| (0..n).map(|p| record(p, n)).collect::<Vec<_>>();
    let full = Snapshot::build(manifest(1), &records(SLOTS as u32), &[]).unwrap();
    assert_eq!(full.manifest.records, SLOTS as u64);
    assert!(matches!(
        Snapshot::build(manifest(1), &records(SLOTS as u32 + 1), &[]),
        Err(Error::Capacity)
    ));
    for rows in [0, 3, MAX_ROWS * 2] {
        assert!(matches!(
            Snapshot::build(manifest(rows), &records(SLOTS as u32 + 1), &[]),
            Err(Error::Malformed)
        ));
    }
    // A supplied manifest claiming more records than slots is malformed, not a
    // capacity failure.
    let mut claimed = full.manifest.clone();
    claimed.records += 1;
    assert!(matches!(claimed.validate(), Err(Error::Malformed)));
    assert!(matches!(
        claimed.accept([1; 32], 100, 101, [3; 32]),
        Err(Error::Malformed)
    ));
    let r = receiver();
    assert!(matches!(
        lookup_row(&claimed, &r, 0, row(&full, &r, 0)),
        Err(Error::Malformed)
    ));
}

/// Recomputes `s`'s digests after an edit, so validation reaches its semantic checks.
fn rehash(s: &mut Snapshot) {
    use sha2::{Digest, Sha256};
    s.manifest.data_sha256 = Sha256::digest(&s.data).into();
    s.manifest.filters_sha256 = Sha256::digest(&s.filters).into();
}

/// The byte offset of `r`'s slot in `s`'s rows.
fn slot_of(s: &Snapshot, r: &RawRecord) -> usize {
    let encoded = r.encode().unwrap();
    (0..s.manifest.rows as usize)
        .flat_map(|row| (0..SLOTS).map(move |slot| row * ROW_BYTES + slot * RECORD_BYTES))
        .find(|offset| s.data[*offset..offset + RECORD_BYTES] == encoded)
        .unwrap()
}

/// Writes `r` into the slot at `offset`, or empties it.
fn put(s: &mut Snapshot, offset: usize, r: Option<&RawRecord>) {
    let bytes = r.map_or([0; RECORD_BYTES], |r| r.encode().unwrap());
    s.data[offset..offset + RECORD_BYTES].copy_from_slice(&bytes);
}

/// No two records, of one receiver or several, share an output or note position, in
/// a build and a supplied publication.
#[test]
fn records_share_no_output_or_position() {
    let (a0, a1) = (record(0, 2), record(1, 2));
    let mut b = record(0, 1);
    b.receiver = other_receiver();
    (b.payment.txid, b.payment.tx_index, b.payment.position) = ([9; 32], 9, 210);
    let records = [a0.clone(), a1, b];
    let valid = Snapshot::build(manifest(8), &records, &[]).unwrap();
    valid.validate().unwrap();
    // `a0`'s output at a later position, by `a0`'s receiver and by `b`'s, and `b` at
    // `a0`'s position.
    let mut own_output = records[1].clone();
    (own_output.payment.txid, own_output.payment.tx_index) = (a0.payment.txid, 5);
    let mut output = records[2].clone();
    output.payment.txid = a0.payment.txid;
    let mut position = records[2].clone();
    position.payment.position = a0.payment.position;
    for (i, repeated) in [(1, own_output), (2, output), (2, position)] {
        let mut edited = records.clone();
        edited[i] = repeated.clone();
        assert!(matches!(
            Snapshot::build(manifest(8), &edited, &[]),
            Err(Error::Malformed)
        ));
        let mut s = valid.clone();
        let offset = slot_of(&s, &records[i]);
        put(&mut s, offset, Some(&repeated));
        rehash(&mut s);
        assert!(matches!(s.validate(), Err(Error::Malformed)));
    }
}

/// A supplied publication is checked as a whole: digests, placement, count, pages,
/// padding, coverage and the paid set, each edit rehashed so the digests
/// alone cannot catch it.
#[test]
fn supplied_publications_are_validated_record_by_record() {
    let (a0, a1) = (record(0, 2), record(1, 2));
    let mut b = record(0, 1);
    b.receiver = other_receiver();
    (b.payment.txid, b.payment.tx_index, b.payment.position) = ([9; 32], 9, 210);
    let valid = Snapshot::build(manifest(8), &[a0.clone(), a1.clone(), b.clone()], &[]).unwrap();
    valid.validate().unwrap();
    Snapshot::build(manifest(8), &[], &[])
        .unwrap()
        .validate()
        .unwrap();
    let refused = |edit: &dyn Fn(&mut Snapshot)| {
        let mut s = valid.clone();
        edit(&mut s);
        rehash(&mut s);
        assert!(matches!(s.validate(), Err(Error::Malformed)));
    };

    // An edit without a matching digest is refused before any record is read.
    let mut stale = valid.clone();
    stale.data[0] ^= 1;
    assert!(matches!(stale.validate(), Err(Error::Malformed)));

    // Page zero stored outside its bucket: a lookup of the right row finds nothing.
    let mut misplaced = valid.clone();
    let from = slot_of(&misplaced, &b);
    let bucket = row_for(&valid.manifest, &b.receiver, 0).unwrap();
    let to = ((bucket + 1) % 8) * ROW_BYTES + (SLOTS - 1) * RECORD_BYTES;
    assert!(misplaced.data[to..to + RECORD_BYTES]
        .iter()
        .all(|x| *x == 0));
    put(&mut misplaced, from, None);
    put(&mut misplaced, to, Some(&b));
    rehash(&mut misplaced);
    assert_eq!(
        lookup_row(
            &misplaced.manifest,
            &b.receiver,
            0,
            row(&misplaced, &b.receiver, 0)
        )
        .unwrap(),
        None
    );
    assert!(matches!(misplaced.validate(), Err(Error::Malformed)));

    // A missing page; the other page faults are tested against a build.
    refused(&|s| {
        put(s, slot_of(s, &a1), None);
        s.manifest.records -= 1;
    });

    // More or fewer records than the manifest declares.
    refused(&|s| s.manifest.records += 1);
    refused(&|s| s.manifest.records -= 1);

    // Nonzero row padding and a payment outside the covered positions.
    refused(&|s| s.data[ROW_BYTES - 1] = 1);
    refused(&|s| {
        let mut outside = b.clone();
        outside.payment.position = s.manifest.end_position;
        put(s, slot_of(s, &b), Some(&outside));
    });

    // A paid set of the declared size but other receivers.
    refused(&|s| {
        use receiver_directory::filter::{Filter, Filters};
        let third = pinned("third")[0];
        let paid = Filter::build(&s.manifest.salt, &[receiver(), third]);
        s.filters = Filters::new(paid, []).unwrap().encode().unwrap();
    });
}

/// `n` distinct valid receivers, at most 16.
fn receivers(n: u32) -> Vec<ReceiverBytes> {
    pinned("spread")[..n as usize].to_vec()
}

/// `pages` payments to each of `receivers`, interleaved in [`manifest`]'s last block,
/// one transaction each, at successive positions from 200.
fn spread(receivers: &[ReceiverBytes], pages: u32) -> Vec<RawRecord> {
    let n = receivers.len() as u32;
    (0..pages)
        .flat_map(|page| {
            receivers.iter().enumerate().map(move |(i, receiver)| {
                let index = page * n + i as u32;
                let mut r = record(0, pages);
                (r.receiver, r.page) = (*receiver, page);
                r.payment.txid = [0; 32];
                r.payment.txid[..4].copy_from_slice(&index.to_le_bytes());
                r.payment.tx_index = index + 1;
                r.payment.position = 200 + u64::from(index);
                r
            })
        })
        .collect()
}

/// Rows match an independent computation of the bucket hash, pinned here.
#[test]
fn rows_are_pinned() {
    let m = manifest(MIN_ROWS);
    let rows: Vec<_> = (0..4)
        .map(|p| row_for(&m, &receiver(), p).unwrap())
        .collect();
    assert_eq!(rows, [3472, 2600, 4604, 7755]);
}

/// A populated table of [`MAX_ROWS`] rows, about two records per row, validates from
/// its own bytes once its source records are gone.
#[test]
fn a_populated_largest_table_validates() {
    let n = 16;
    let pages = 2 * MAX_ROWS / n;
    let mut m = manifest(MAX_ROWS);
    m.end_position = 200 + u64::from(n * pages);
    let records = spread(&receivers(n), pages);
    let s = Snapshot::build(m, &records, &[]).unwrap();
    drop(records);
    assert_eq!(s.manifest.records, u64::from(2 * MAX_ROWS));
    let fullest = s
        .data
        .chunks(ROW_BYTES)
        .map(|row| {
            row.chunks(RECORD_BYTES)
                .filter(|slot| slot.len() == RECORD_BYTES && slot.iter().any(|b| *b != 0))
                .count()
        })
        .max()
        .unwrap();
    assert!(fullest < SLOTS, "{fullest} records share a row");
    s.validate().unwrap();
}

/// Each page continues the last as [`check_next`] requires, which a build and a
/// supplied publication apply.
#[test]
fn pages_continue_in_chain_order() {
    use receiver_directory::{snapshot::check_next, Payment};
    let mut m = manifest(8);
    m.start_height = 98;
    // Below the terminal height, whose hash a record must match anyway, so a
    // disagreement within a block is caught by the continuation alone.
    let mut first = record(0, 2);
    first.payment.height = 100;
    first.payment.block_hash = [10; 32];
    (
        first.payment.txid,
        first.payment.tx_index,
        first.payment.action_index,
    ) = ([1; 32], 2, 1);
    first.payment.position = 200;
    let next = |edit: fn(&mut Payment)| {
        let mut r = record(1, 2);
        r.payment = first.payment.clone();
        r.payment.position = 201;
        edit(&mut r.payment);
        r
    };
    let within_tx = next(|p| p.action_index = 2);
    let valid = Snapshot::build(m.clone(), &[first.clone(), within_tx.clone()], &[]).unwrap();
    valid.validate().unwrap();

    let continuing: [fn(&mut Payment); 3] = [
        |p| p.action_index = 2,
        |p| (p.txid, p.tx_index, p.action_index) = ([2; 32], 3, 0),
        |p| {
            (p.height, p.block_hash, p.txid, p.tx_index, p.action_index) =
                (101, [3; 32], [2; 32], 1, 0)
        },
    ];
    for edit in continuing {
        check_next(&first, &next(edit)).unwrap();
    }

    let broken: [fn(&mut Payment); 5] = [
        // An earlier action in the same transaction.
        |p| p.action_index = 0,
        // An earlier transaction in the same block.
        |p| (p.txid, p.tx_index, p.action_index) = ([2; 32], 1, 5),
        // An earlier block.
        |p| (p.height, p.block_hash, p.txid) = (99, [9; 32], [2; 32]),
        // Another hash for the same block.
        |p| (p.block_hash, p.txid, p.tx_index) = ([11; 32], [2; 32], 3),
        // Another txid for the same transaction.
        |p| (p.txid, p.action_index) = ([2; 32], 2),
    ];
    for edit in broken {
        assert!(matches!(
            check_next(&first, &next(edit)),
            Err(Error::Malformed)
        ));
    }
    // A build and a supplied publication apply the same rule.
    let earlier_action = next(broken[0]);
    assert!(matches!(
        Snapshot::build(m, &[first.clone(), earlier_action.clone()], &[]),
        Err(Error::Malformed)
    ));
    let mut s = valid;
    let offset = slot_of(&s, &within_tx);
    put(&mut s, offset, Some(&earlier_action));
    rehash(&mut s);
    assert!(matches!(s.validate(), Err(Error::Malformed)));

    // The page, total and position conditions hold for the predicate too.
    let mut other = within_tx.clone();
    other.receiver = other_receiver();
    let mut skipped = within_tx.clone();
    (skipped.page, skipped.total) = (2, 3);
    let mut wider = within_tx.clone();
    wider.total = 3;
    let earlier = next(|p| (p.position, p.action_index) = (199, 2));
    for r in [other, skipped, wider, earlier] {
        assert!(matches!(check_next(&first, &r), Err(Error::Malformed)));
    }
}
