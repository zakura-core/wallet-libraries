//! Receiver v2 segments: building, lookup round trips, the S1.2 and S1.7
//! refusals, choice objects and the geometry limits.
mod common;
use sha2::{Digest, Sha256};
use zakura_pir_protocol::directory::choice::{
    ChoiceError, ChoiceTable, SeedPolicy, segment_length,
};
use zakura_pir_publisher::{
    directory::choice_bits,
    receiver::{
        Error, Hash, Payment, RawRecord, ReceiverBytes,
        v2::*,
        wire::{PAYLOAD_BYTES, encode_payload, supplied},
    },
};

const END: u32 = 120;
const SEED_BLOCK: Hash = [9; 32];

fn coverage() -> Coverage {
    Coverage {
        genesis: [1; 32],
        history_revision: 0,
        start_height: 100,
        start_parent: [2; 32],
        start_position: 0,
        end_height: END,
        end_hash: [3; 32],
        end_position: 4096,
    }
}

fn tree() -> Tree {
    Tree {
        height: END,
        hash: [3; 32],
        size: 4096,
    }
}

fn receiver(i: u32) -> ReceiverBytes {
    let mut r = [0xee; 43];
    r[..4].copy_from_slice(&i.to_le_bytes());
    r
}

fn block_hash(height: u32) -> Hash {
    if height == END {
        [3; 32]
    } else {
        [height as u8; 32]
    }
}

/// The chain's payment `n`: four a block from height 100, at position `n`.
fn payment(n: u32) -> Payment {
    let height = 100 + n / 4;
    Payment {
        height,
        block_hash: block_hash(height),
        txid: Sha256::digest(n.to_le_bytes()).into(),
        tx_index: 1 + n % 4,
        action_index: 0,
        position: n.into(),
        action_nullifier: [5; 32],
        cmx: [6; 32],
        ephemeral_key: [7; 32],
        ciphertext_prefix: [8; 52],
    }
}

/// A payload supplying every sibling complete at `size`, each nonzero.
fn payload(position: u64, size: u64) -> [u8; PAYLOAD_BYTES] {
    let siblings = std::array::from_fn(|l| supplied(position, size, l as u8).then_some([0xa5; 32]));
    encode_payload(&siblings, position, size).unwrap()
}

/// Projects `paid` block by block under the segment's initial salt.
fn project(paid: &[Paid]) -> Projection {
    let mut p = Projection::new(initial_salt(&coverage().start_parent, 0));
    for height in 100..=END {
        let block: Vec<_> = paid
            .iter()
            .filter(|p| p.1.height == height)
            .map(|p| p.0)
            .collect();
        p.project(&block, &block_hash(height)).unwrap();
    }
    p
}

/// Receiver `i` paid `counts[i]` times, interleaved in chain order.
fn payments(counts: &[u32]) -> Vec<Paid> {
    let (mut left, mut paid, mut n) = (counts.to_vec(), Vec::new(), 0);
    while left.iter().any(|c| *c > 0) {
        for (i, c) in left.iter_mut().enumerate().filter(|(_, c)| **c > 0) {
            *c -= 1;
            paid.push((
                receiver(i as u32),
                payment(n),
                payload(n.into(), tree().size),
            ));
            n += 1;
        }
    }
    paid
}

fn segment(counts: &[u32], rows: u32) -> Segment {
    let paid = payments(counts);
    build(
        &project(&paid),
        coverage(),
        &SEED_BLOCK,
        OPEN_SEED_ATTEMPTS,
        rows,
        tree(),
        &paid,
    )
    .unwrap()
}

/// A record and its payload as a wallet reads them.
type Read = (RawRecord, [u8; PAYLOAD_BYTES]);

/// What a wallet reads for `r`: one directory row chosen by the choice object,
/// then one companion row per record.
fn find(seg: &Segment, r: &ReceiverBytes) -> Option<(Entry, Vec<Read>)> {
    let d = &seg.directory.manifest;
    let choice = decode_choice(d, &seg.directory.choice).unwrap();
    let t = tag(&d.salt, r);
    let row = choose_row(&d.salt, &choice, &t) as usize * ROW_BYTES;
    let entry = lookup_entry(d, &seg.directory.data[row..row + ROW_BYTES], &t).unwrap()?;
    let records = entry.slots().map(|slot| {
        let row = slot_row(slot) as usize * ROW_BYTES;
        lookup_slot(
            d,
            &seg.companion.manifest,
            &entry,
            slot,
            &seg.companion.data[row..row + ROW_BYTES],
        )
        .unwrap()
    });
    Some((entry, records.collect()))
}

fn check(seg: &Segment) -> Result<(), Error> {
    let entries = seg.directory.validate()?;
    seg.companion.validate(&seg.directory.manifest, &entries)
}

/// Rebinds digests and the companion's directory revision after an edit, so
/// only the rule under test can refuse it.
fn rehash(seg: &mut Segment) {
    let d = &mut seg.directory.manifest;
    d.choice.digest = Sha256::digest(&seg.directory.choice).into();
    d.choice.bytes = seg.directory.choice.len() as u32;
    d.data_sha256 = Sha256::digest(&seg.directory.data).into();
    seg.companion.manifest.data_sha256 = Sha256::digest(&seg.companion.data).into();
    if let Ok(revision) = d.revision() {
        seg.companion.manifest.directory = revision;
    }
}

fn edit_slot(seg: &mut Segment, slot: u32, edit: impl FnOnce(&mut RawRecord)) {
    let at = slot_row(slot) as usize * ROW_BYTES + (slot % ROW_SLOTS) as usize * SLOT_BYTES;
    let bytes = &mut seg.companion.data[at..at + SLOT_BYTES];
    let (mut record, payload) = decode_slot(bytes).unwrap().unwrap();
    edit(&mut record);
    bytes.copy_from_slice(&encode_slot(&record, &payload).unwrap());
    rehash(seg);
}

fn edit_entry(seg: &mut Segment, r: &ReceiverBytes, edit: impl Fn(&mut Entry)) {
    let t = tag(&seg.directory.manifest.salt, r);
    for row in seg.directory.data.as_chunks_mut::<ROW_BYTES>().0 {
        let mut entries = decode_row(row).unwrap();
        if let Some(e) = entries.iter_mut().find(|e| e.tag == t) {
            edit(e);
            *row = encode_row(&entries).unwrap();
        }
    }
    rehash(seg);
}

/// Each receiver's directory entry and records come back whole, with the
/// payments, pages, totals, ordinals and payloads put in, and a companion row
/// holds data in both packing blocks. An unpaid receiver is a miss.
#[test]
fn segments_round_trip_through_lookup() {
    let counts = [7, 1, 3, 1, 1];
    let seg = segment(&counts, 2048);
    check(&seg).unwrap();
    assert_eq!(seg.companion.manifest.query_rows, 2048);
    assert!(seg.companion.data[2048..ROW_BYTES].iter().any(|b| *b != 0));
    let paid = payments(&counts);
    for (i, count) in counts.iter().enumerate() {
        let r = receiver(i as u32);
        let (entry, records) = find(&seg, &r).unwrap();
        assert_eq!(u32::from(entry.count), *count);
        let expected: Vec<_> = paid.iter().filter(|p| p.0 == r).collect();
        for (page, ((record, payload), (_, payment, put))) in
            records.iter().zip(expected).enumerate()
        {
            assert_eq!(
                (record.receiver, record.page, record.total),
                (r, page as u32, *count)
            );
            assert_eq!(
                (record.ordinal, &record.payment, payload),
                (entry.first + page as u32, payment, put)
            );
        }
        assert_eq!(entry.last + 100, records.last().unwrap().0.payment.height);
    }
    assert!(find(&seg, &receiver(99)).is_none());
}

/// Payloads from the kept `ShardPaths` construction build and validate.
#[cfg(feature = "receiver-crypto")]
#[test]
fn shard_path_payloads_build() {
    let mut paid = payments(&[3, 2]);
    let positions: Vec<u64> = paid.iter().map(|p| p.1.position).collect();
    let built =
        zakura_pir_publisher::receiver::witness::payloads(&common::leaves(4096), &positions)
            .unwrap();
    paid.iter_mut()
        .zip(built)
        .for_each(|(p, payload)| p.2 = payload);
    let seg = build(
        &project(&paid),
        coverage(),
        &SEED_BLOCK,
        OPEN_SEED_ATTEMPTS,
        2048,
        tree(),
        &paid,
    )
    .unwrap();
    assert_eq!(find(&seg, &receiver(0)).unwrap().1[2].1, paid[4].2);
}

/// Every S1.2 and S1.7 rule refuses its violation, and a later construction
/// tree is accepted.
#[test]
fn every_segment_rule_refuses_its_violation() {
    let base = segment(&[7, 1, 3], 4096);
    let first = |seg: &Segment, i| find(seg, &receiver(i)).unwrap().0.first;
    type Edit = Box<dyn Fn(&mut Segment)>;
    let malformed: Vec<(&str, Edit)> = vec![
        (
            "bad extent",
            Box::new(|s| edit_entry(s, &receiver(1), |e| e.first += 1)),
        ),
        (
            "wrong count",
            Box::new(|s| edit_entry(s, &receiver(1), |e| e.count += 1)),
        ),
        (
            "wrong total",
            Box::new(|s| edit_slot(s, 0, |r| r.total += 1)),
        ),
        (
            "wrong page",
            Box::new(move |s| edit_slot(s, first(s, 0) + 1, |r| r.page = 2)),
        ),
        (
            "wrong ordinal",
            Box::new(|s| edit_slot(s, 1, |r| r.ordinal = 0)),
        ),
        (
            "foreign tag",
            Box::new(|s| edit_slot(s, 1, |r| r.receiver = receiver(77))),
        ),
        (
            "early last height",
            Box::new(|s| edit_entry(s, &receiver(0), |e| e.last -= 1)),
        ),
        (
            "late last height",
            Box::new(|s| edit_entry(s, &receiver(0), |e| e.last += 1)),
        ),
        (
            "gap",
            Box::new(|s| {
                s.companion.data[2 * SLOT_BYTES..3 * SLOT_BYTES].fill(0);
                rehash(s);
            }),
        ),
        (
            "slot past the payments",
            Box::new(|s| {
                let at = slot_row(11) as usize * ROW_BYTES + (11 % ROW_SLOTS) as usize * SLOT_BYTES;
                s.companion.data.copy_within(..SLOT_BYTES, at);
                rehash(s);
            }),
        ),
        (
            "nonzero row past query_rows",
            Box::new(|s| {
                s.companion.data[2048 * ROW_BYTES] = 1;
                rehash(s);
            }),
        ),
    ];
    for (name, edit) in &malformed {
        let mut seg = base.clone();
        edit(&mut seg);
        assert!(matches!(check(&seg), Err(Error::Malformed)), "{name}");
    }

    let swapped = segment(&[7, 1, 2], 4096).companion;
    let at = |height, hash, size| Tree { height, hash, size };
    let binding: Vec<(&str, Edit)> = vec![
        (
            "swapped companion",
            Box::new(move |s| s.companion = swapped.clone()),
        ),
        (
            "stale tree",
            Box::new(move |s| s.companion.manifest.tree = at(END - 1, [3; 32], 4096)),
        ),
        (
            "other block at the end height",
            Box::new(move |s| s.companion.manifest.tree.hash = [4; 32]),
        ),
        (
            "other size at the end height",
            Box::new(move |s| s.companion.manifest.tree.size = 4097),
        ),
    ];
    for (name, edit) in &binding {
        let mut seg = base.clone();
        edit(&mut seg);
        assert!(matches!(check(&seg), Err(Error::Coverage)), "{name}");
        let publication = Publication {
            directory: Session {
                manifest: seg.directory.manifest.clone(),
                public_digest: [0; 32],
            },
            companion: Session {
                manifest: seg.companion.manifest.clone(),
                public_digest: [0; 32],
            },
        };
        assert!(
            matches!(publication.validate(), Err(Error::Coverage)),
            "{name}"
        );
    }

    let mut later = base.clone();
    later.companion.manifest.tree = at(END + 5, [7; 32], 5000);
    check(&later).unwrap();
    let publication = Publication {
        directory: Session {
            manifest: later.directory.manifest.clone(),
            public_digest: [0; 32],
        },
        companion: Session {
            manifest: later.companion.manifest.clone(),
            public_digest: [0; 32],
        },
    };
    publication.validate().unwrap();
}

/// A repeated tag is refused in a row and in a choice table.
#[test]
fn duplicate_tags_are_refused() {
    let mut seg = segment(&[1, 1], 2048);
    let row = seg
        .directory
        .data
        .as_chunks_mut::<ROW_BYTES>()
        .0
        .iter_mut()
        .find(|r| r.iter().any(|b| *b != 0))
        .unwrap();
    let mut entries = decode_row(row).unwrap();
    entries.push(entries[0]);
    assert!(encode_row(&entries).is_err());
    row[ENTRY_BYTES * entries.len() - ENTRY_BYTES..][..ENTRY_BYTES]
        .copy_from_slice(&entries[0].encode().unwrap());
    rehash(&mut seg);
    assert!(matches!(check(&seg), Err(Error::Malformed)));
    let key: &[u8] = &[1; 14];
    let built = ChoiceTable::build(CHOICE_DOMAIN, &[0; 32], 0..1, &[(key, 0), (key, 1)]);
    assert!(matches!(built, Err(ChoiceError::Duplicate(_))));
}

/// A missing, truncated, extended or malformed choice object fails the
/// segment, as does a reference whose key count or length is off.
#[test]
fn choice_objects_fail_closed() {
    let seg = segment(&[2, 1], 2048);
    let edits: [fn(&mut Vec<u8>); 4] = [
        |c| c.clear(),
        |c| c.truncate(c.len() - 1),
        |c| c.push(0),
        |c| c[0] = 2,
    ];
    for edit in edits {
        let mut bad = seg.clone();
        edit(&mut bad.directory.choice);
        assert!(decode_choice(&bad.directory.manifest, &bad.directory.choice).is_err());
        rehash(&mut bad);
        assert!(matches!(check(&bad), Err(Error::Malformed)));
    }
    let edits: [fn(&mut ChoiceRef); 2] = [|r| r.keys += 1, |r| r.bytes += 1];
    for edit in edits {
        let mut bad = seg.directory.manifest.clone();
        edit(&mut bad.choice);
        assert!(matches!(bad.validate(), Err(Error::Malformed)));
    }
}

/// The tags and rows a built directory holds, for rebuilding its choice table.
fn placed(seg: &Segment) -> (Vec<Tag>, Vec<u32>) {
    let rows = seg
        .directory
        .data
        .as_chunks::<ROW_BYTES>()
        .0
        .iter()
        .enumerate();
    rows.flat_map(|(i, row)| {
        decode_row(row)
            .unwrap()
            .into_iter()
            .map(move |e| (e.tag, i as u32))
    })
    .unzip()
}

/// A table built from seal attempts past 64, with a seed above 63, decodes
/// under Receiver's any-seed policy and routes every lookup. Transparent's
/// bounded policy refuses it.
#[test]
fn drawn_seeds_past_sixty_four_round_trip() {
    let counts = [2, 1, 1, 3];
    let mut seg = segment(&counts, 2048);
    let salt = seg.directory.manifest.salt;
    let (tags, rows) = placed(&seg);
    let keys: Vec<&[u8]> = tags.iter().map(|t| &t[..]).collect();
    let bits = choice_bits(&bucket_salts(&salt), &keys, &rows, DIRECTORY_ROWS.into());
    let seeds = candidate_seeds(&salt, &SEED_BLOCK, 0..SEAL_SEED_ATTEMPTS).skip(64);
    let table = ChoiceTable::build(CHOICE_DOMAIN, &salt, seeds, &bits).unwrap();
    assert!(table.seed() > 63);
    seg.directory.choice = table.encode();
    rehash(&mut seg);
    check(&seg).unwrap();
    assert!(ChoiceTable::decode(&seg.directory.choice, SeedPolicy::Below(64)).is_err());
    for i in 0..counts.len() as u32 {
        assert!(find(&seg, &receiver(i)).is_some());
    }
}

/// Round 6's attack: someone who knows a segment's salt grinds 128 receivers,
/// one pair per seed, whose tags take the same three positions under each of
/// seeds 0 to 63, so no fixed seed peels. Seeds drawn from a later block still
/// build, and every receiver is found with one directory query.
#[test]
fn round_six_attack_set_builds_under_drawn_seeds() {
    let salt = initial_salt(&coverage().start_parent, 0);
    let segment = segment_length(128);
    let positions = |seed: u32, t: &Tag| -> [u64; 3] {
        let digest = Sha256::new()
            .chain_update(CHOICE_DOMAIN)
            .chain_update(salt)
            .chain_update(seed.to_le_bytes())
            .chain_update((t.len() as u32).to_le_bytes())
            .chain_update(t)
            .finalize();
        std::array::from_fn(|i| {
            u64::from_le_bytes(digest[i * 8..i * 8 + 8].try_into().unwrap()) % u64::from(segment)
        })
    };
    let mut attackers = Vec::new();
    for seed in 0..64u32 {
        let mut seen = std::collections::HashMap::new();
        for counter in 0u32.. {
            let mut r = [0xcc; 43];
            r[..4].copy_from_slice(&seed.to_le_bytes());
            r[4..8].copy_from_slice(&counter.to_le_bytes());
            if let Some(other) = seen.insert(positions(seed, &tag(&salt, &r)), r) {
                attackers.extend([other, r]);
                break;
            }
        }
    }
    let paid: Vec<Paid> = attackers
        .iter()
        .enumerate()
        .map(|(n, r)| {
            let mut p = payment(0);
            (p.position, p.action_index) = (n as u64, n as u32);
            (*r, p, [0; PAYLOAD_BYTES])
        })
        .collect();
    let projection = project(&paid);
    assert_eq!(*projection.salt(), salt);
    let seg = build(
        &projection,
        coverage(),
        &SEED_BLOCK,
        OPEN_SEED_ATTEMPTS,
        2048,
        tree(),
        &paid,
    )
    .unwrap();
    let (tags, rows) = placed(&seg);
    let keys: Vec<&[u8]> = tags.iter().map(|t| &t[..]).collect();
    let bits = choice_bits(&bucket_salts(&salt), &keys, &rows, DIRECTORY_ROWS.into());
    let fixed = ChoiceTable::build(CHOICE_DOMAIN, &salt, 0..64, &bits);
    assert_eq!(fixed, Err(ChoiceError::Unpeelable { keys: 128 }));
    for r in &attackers {
        assert_eq!(find(&seg, r).unwrap().1.len(), 1);
    }
}

/// Zero payments give an empty directory and a 2,048-row companion query; a
/// receiver can hold 65,535 payments but not 65,536; a segment refuses more
/// payments than its companion holds; and the last representable height
/// offset builds.
#[test]
fn geometry_limits_hold_at_their_bounds() {
    let empty = build(
        &project(&[]),
        coverage(),
        &SEED_BLOCK,
        OPEN_SEED_ATTEMPTS,
        2048,
        tree(),
        &[],
    )
    .unwrap();
    check(&empty).unwrap();
    let (d, c) = (&empty.directory.manifest, &empty.companion.manifest);
    assert_eq!(
        (
            d.entries,
            d.payments,
            c.query_rows,
            empty.directory.choice.len()
        ),
        (0, 0, 2048, 18)
    );

    let wide = Coverage {
        end_position: 70_000,
        ..coverage()
    };
    let wide_tree = Tree {
        size: 70_000,
        ..tree()
    };
    let many = |n: u32| -> Vec<Paid> {
        (0..n)
            .map(|i| {
                let mut p = payment(80);
                (p.position, p.action_index) = (i.into(), i);
                (receiver(0), p, [0; PAYLOAD_BYTES])
            })
            .collect()
    };
    let paid = many(MAX_RECEIVER_PAYMENTS);
    let seg = build(
        &project(&paid),
        wide.clone(),
        &SEED_BLOCK,
        OPEN_SEED_ATTEMPTS,
        14_336,
        wide_tree,
        &paid,
    )
    .unwrap();
    assert_eq!(find(&seg, &receiver(0)).unwrap().0.count, u16::MAX);
    let over = many(MAX_RECEIVER_PAYMENTS + 1);
    let refused = build(
        &project(&over),
        wide,
        &SEED_BLOCK,
        OPEN_SEED_ATTEMPTS,
        16_384,
        wide_tree,
        &over,
    );
    assert!(matches!(refused, Err(Error::Capacity)));

    let full = many(2048 * ROW_SLOTS + 1);
    let refused = build(
        &project(&full),
        coverage(),
        &SEED_BLOCK,
        OPEN_SEED_ATTEMPTS,
        2048,
        tree(),
        &full,
    );
    assert!(matches!(refused, Err(Error::Capacity)));

    let end = 100 + MAX_HEIGHT_OFFSET;
    let far = Coverage {
        end_height: end,
        ..coverage()
    };
    let mut p = payment(0);
    (p.height, p.block_hash) = (end, [3; 32]);
    let paid = [(receiver(0), p, [0; PAYLOAD_BYTES])];
    let mut projection = Projection::new(initial_salt(&far.start_parent, 0));
    projection.project(&[receiver(0)], &[3; 32]).unwrap();
    let seg = build(
        &projection,
        far,
        &SEED_BLOCK,
        OPEN_SEED_ATTEMPTS,
        2048,
        Tree {
            height: end,
            ..tree()
        },
        &paid,
    )
    .unwrap();
    assert_eq!(find(&seg, &receiver(0)).unwrap().0.last, MAX_HEIGHT_OFFSET);
}

/// A payment whose receiver the projection never placed is refused.
#[test]
fn payments_must_match_the_projection() {
    let paid = payments(&[1, 1]);
    let projection = project(&paid[..1]);
    let built = build(
        &projection,
        coverage(),
        &SEED_BLOCK,
        OPEN_SEED_ATTEMPTS,
        2048,
        tree(),
        &paid,
    );
    assert!(matches!(built, Err(Error::Malformed)));
}

/// A build whose seeds all fail is `Error::Choice`, which the publisher
/// reports as `receiver.choice.failed`, never a table without a choice object.
#[test]
fn exhausted_choice_seeds_fail_the_build() {
    let paid = payments(&[1, 2]);
    let built = build(
        &project(&paid),
        coverage(),
        &SEED_BLOCK,
        0,
        2048,
        tree(),
        &paid,
    );
    assert!(matches!(built, Err(Error::Choice)));
}

/// Rules across records hold whichever receivers the records pay. Each edit
/// keeps tags, pages, totals, ordinals and digests valid and breaks one rule:
/// a position or output shared by two receivers, positions decreasing within
/// an extent, or two receivers naming different blocks at one height or
/// different transactions at one `(height, tx_index)`. The untouched segment,
/// whose tag order differs from both receiver and position order, is valid.
#[test]
fn cross_record_rules_hold_across_receivers() {
    // Receiver 0 has payments 0, 6 and 7; receivers 1 to 5 one each, 1 to 5.
    let mut paid = payments(&[3, 1, 1, 1, 1, 1]);
    for p in &mut paid {
        (p.1.position, p.2) = (p.1.position * 10, [0; PAYLOAD_BYTES]);
    }
    let base = build(
        &project(&paid),
        coverage(),
        &SEED_BLOCK,
        OPEN_SEED_ATTEMPTS,
        2048,
        tree(),
        &paid,
    )
    .unwrap();
    check(&base).unwrap();
    let mut by_tag: Vec<u32> = (0..6).collect();
    by_tag.sort_by_key(|i| find(&base, &receiver(*i)).unwrap().0.first);
    assert_ne!(
        by_tag,
        (0..6).collect::<Vec<_>>(),
        "tag order matches receiver and position order"
    );

    let slot = |seg: &Segment, i: u32, page: u32| find(seg, &receiver(i)).unwrap().0.first + page;
    let of = |n: usize| paid[n].1.clone();
    type Edit<'a> = Box<dyn Fn(&mut Segment) + 'a>;
    let edits: Vec<(&str, Edit)> = vec![
        (
            "position shared across receivers",
            Box::new(|s| edit_slot(s, slot(s, 2, 0), |r| r.payment.position = of(1).position)),
        ),
        (
            "output shared across receivers",
            Box::new(|s| {
                edit_slot(s, slot(s, 2, 0), |r| {
                    (r.payment.txid, r.payment.tx_index) = (of(1).txid, of(1).tx_index)
                })
            }),
        ),
        (
            "decreasing positions in an extent",
            Box::new(|s| {
                edit_slot(s, slot(s, 0, 2), |r| {
                    r.payment.position = of(6).position - 5
                })
            }),
        ),
        (
            "two blocks at one height",
            Box::new(|s| edit_slot(s, slot(s, 2, 0), |r| r.payment.block_hash = [0x77; 32])),
        ),
        (
            "two transactions at one index",
            Box::new(|s| edit_slot(s, slot(s, 2, 0), |r| r.payment.tx_index = of(1).tx_index)),
        ),
    ];
    for (name, edit) in &edits {
        let mut seg = base.clone();
        edit(&mut seg);
        assert!(matches!(check(&seg), Err(Error::Malformed)), "{name}");
    }
}
