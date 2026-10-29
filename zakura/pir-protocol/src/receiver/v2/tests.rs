//! Unit tests for the v2 format: codecs, geometry, salts and seeds, and
//! manifest-level refusals.
use super::*;
use crate::receiver::Payment;

fn entry(tag: u8, first: u32, count: u16, last: u32) -> Entry {
    Entry {
        tag: [tag; TAG_BYTES],
        first,
        count,
        last,
    }
}

/// Entries round-trip at every field's limit, and a field past its width or a
/// zero count is refused.
#[test]
fn entries_round_trip_at_their_limits() {
    for e in [
        entry(1, 0, 1, 0),
        entry(9, (1 << 24) - 1, u16::MAX, MAX_HEIGHT_OFFSET),
    ] {
        assert_eq!(Entry::decode(&e.encode().unwrap()).unwrap(), Some(e));
    }
    assert_eq!(Entry::decode(&[0; ENTRY_BYTES]).unwrap(), None);
    for bad in [
        entry(1, 0, 0, 0),
        entry(1, 1 << 24, 1, 0),
        entry(1, 0, 1, MAX_HEIGHT_OFFSET + 1),
    ] {
        assert!(matches!(bad.encode(), Err(Error::Malformed)));
    }
    let mut zero_count = entry(1, 0, 1, 0).encode().unwrap();
    zero_count[17] = 0;
    assert!(matches!(Entry::decode(&zero_count), Err(Error::Malformed)));
}

/// A full row puts entries in both packing blocks and round-trips. A repeated
/// or unsorted tag, an entry after an empty one, and nonzero padding are refused.
#[test]
fn directory_rows_round_trip_and_refuse_duplicates() {
    let full: Vec<Entry> = (0..ROW_ENTRIES as u8)
        .map(|i| entry(i + 1, u32::from(i), 1, 7))
        .collect();
    let row = encode_row(&full).unwrap();
    assert!(row[2048..ROW_ENTRIES * ENTRY_BYTES].iter().any(|b| *b != 0));
    assert_eq!(decode_row(&row).unwrap(), full);
    let mut over = full.clone();
    over.push(entry(255, 300, 1, 7));
    assert!(matches!(encode_row(&over), Err(Error::Capacity)));

    let repeated = [entry(4, 0, 1, 0), entry(4, 1, 1, 0)];
    assert!(encode_row(&repeated).is_err());
    let mut row = [0; ROW_BYTES];
    row[..ENTRY_BYTES].copy_from_slice(&repeated[0].encode().unwrap());
    row[ENTRY_BYTES..2 * ENTRY_BYTES].copy_from_slice(&repeated[1].encode().unwrap());
    assert!(matches!(decode_row(&row), Err(Error::Malformed)));

    let mut gap = [0; ROW_BYTES];
    gap[ENTRY_BYTES..2 * ENTRY_BYTES].copy_from_slice(&entry(4, 0, 1, 0).encode().unwrap());
    assert!(matches!(decode_row(&gap), Err(Error::Malformed)));
    let mut padded = encode_row(&full[..1]).unwrap();
    padded[ROW_BYTES - 1] = 1;
    assert!(matches!(decode_row(&padded), Err(Error::Malformed)));
}

/// A slot holds a record then its payload; an empty slot is zero, and a
/// payload with no record is malformed.
#[test]
fn companion_slots_round_trip() {
    let record = RawRecord {
        receiver: [7; 43],
        page: 0,
        total: 1,
        payment: Payment {
            height: 5,
            block_hash: [1; 32],
            txid: [2; 32],
            tx_index: 1,
            action_index: 0,
            position: 9,
            action_nullifier: [3; 32],
            cmx: [4; 32],
            ephemeral_key: [5; 32],
            ciphertext_prefix: [6; 52],
        },
        ordinal: 0,
    };
    let slot = encode_slot(&record, &[0xab; wire::PAYLOAD_BYTES]).unwrap();
    assert_eq!(
        decode_slot(&slot).unwrap(),
        Some((record, [0xab; wire::PAYLOAD_BYTES]))
    );
    assert_eq!(decode_slot(&[0; SLOT_BYTES]).unwrap(), None);
    let mut orphan = [0; SLOT_BYTES];
    orphan[SLOT_BYTES - 1] = 1;
    assert!(matches!(decode_slot(&orphan), Err(Error::Malformed)));
}

/// The companion's query prefix is whole 2,048-row blocks over the occupied
/// rows, and 2,048 for an empty companion; its rows are whole blocks up to the
/// policy limit.
#[test]
fn geometry_bounds_query_rows_and_companions() {
    for (payments, rows) in [
        (0, 2048),
        (1, 2048),
        (10_240, 2048),
        (10_241, 4096),
        (CAPACITY, 65_536),
    ] {
        assert_eq!(query_rows(payments), rows, "{payments} payments");
    }
    for rows in [2048, 6144, MAX_COMPANION_ROWS] {
        validate_companion_rows(rows).unwrap();
    }
    for rows in [0, 1024, 3000, MAX_COMPANION_ROWS + QUERY_BLOCK_ROWS] {
        assert!(matches!(
            validate_companion_rows(rows),
            Err(Error::Unsupported)
        ));
    }
    assert_eq!(choice_bytes(CAPACITY), 50_398);
    assert_eq!(choice_bytes(0), 18);
}

/// A segment takes a block up to the companion's capacity, 65,535 payments for
/// one receiver and the last u24 height offset, and seals before one past any.
#[test]
fn block_limits_seal_at_each_bound() {
    let ok = |p, r, h| within_limits(p, r, 100, h);
    assert!(ok(CAPACITY.into(), 65_535, 100 + MAX_HEIGHT_OFFSET));
    assert!(!ok(u64::from(CAPACITY) + 1, 1, 100));
    assert!(!ok(1, 65_536, 100));
    assert!(!ok(1, 1, 101 + MAX_HEIGHT_OFFSET));
    assert!(!ok(1, 1, 99));
}

/// Retry 0 keeps the committed salt; every later one depends on the retry and
/// the forcing block.
#[test]
fn retry_salts_mix_in_the_forcing_block() {
    let committed = initial_salt(&[1; 32], 0);
    assert_ne!(committed, initial_salt(&[1; 32], 1));
    assert_eq!(retry_salt(&committed, 0, &[2; 32]), committed);
    let one = retry_salt(&committed, 1, &[2; 32]);
    assert_ne!(one, committed);
    assert_ne!(one, retry_salt(&committed, 2, &[2; 32]));
    assert_ne!(one, retry_salt(&committed, 1, &[3; 32]));
}

/// Over a seal's 2^16 attempts a 32-bit seed can repeat. The repeat is skipped,
/// so every seed tried is distinct.
#[test]
fn repeated_seeds_are_skipped() {
    let block = [5; 32];
    let found = (0..32u8).find_map(|i| {
        let seeds: Vec<u32> = candidate_seeds(&[i; 32], &block, 0..SEAL_SEED_ATTEMPTS).collect();
        (seeds.len() < SEAL_SEED_ATTEMPTS as usize).then_some(seeds)
    });
    let seeds = found.expect("some salt repeats a seed within 2^16 attempts");
    let distinct: std::collections::HashSet<_> = seeds.iter().collect();
    assert_eq!(distinct.len(), seeds.len());
}

fn coverage() -> Coverage {
    Coverage {
        genesis: [1; 32],
        history_revision: 0,
        start_height: 100,
        start_parent: [2; 32],
        start_position: 0,
        end_height: 110,
        end_hash: [3; 32],
        end_position: 1000,
    }
}

fn directory(entries: u32, payments: u32) -> Directory {
    Directory {
        schema: SCHEMA.into(),
        coverage: coverage(),
        salt: [4; 32],
        entries,
        payments,
        choice: ChoiceRef {
            digest: [0; 32],
            bytes: choice_bytes(entries) as u32,
            keys: entries,
        },
        data_sha256: [0; 32],
    }
}

/// Manifest checks: v1's schema is refused as unsupported, the choice
/// reference must have one key per entry and the formula's exact length,
/// counts must be consistent, and a shard may span at most a u24 offset.
#[test]
fn directory_manifests_bind_their_choice_object_and_limits() {
    directory(2, 3).validate().unwrap();
    directory(0, 0).validate().unwrap();
    let mut v1 = directory(2, 3);
    v1.schema = crate::receiver::snapshot::PROFILE.into();
    assert!(matches!(v1.validate(), Err(Error::Unsupported)));
    let refused = |edit: &dyn Fn(&mut Directory)| {
        let mut d = directory(2, 3);
        edit(&mut d);
        matches!(d.validate(), Err(Error::Malformed))
    };
    assert!(refused(&|d| d.choice.bytes += 1));
    assert!(refused(&|d| d.choice.keys = 3));
    assert!(refused(&|d| d.payments = 1));
    assert!(refused(&|d| d.payments = CAPACITY + 1));
    assert!(refused(
        &|d| d.coverage.end_height = d.coverage.start_height + MAX_HEIGHT_OFFSET + 1
    ));
    let mut last = directory(2, 3);
    last.coverage.end_height = last.coverage.start_height + MAX_HEIGHT_OFFSET;
    last.validate().unwrap();
}

/// A companion's `query_rows` must be the one its payments imply.
#[test]
fn companion_manifests_bind_their_query_prefix() {
    let d = directory(2, 3);
    let companion = Companion {
        schema: SCHEMA.into(),
        coverage: coverage(),
        directory: d.revision().unwrap(),
        rows: 4096,
        query_rows: 2048,
        payments: 3,
        tree: Tree {
            height: 110,
            hash: [3; 32],
            size: 1000,
        },
        data_sha256: [0; 32],
    };
    companion.check_directory(&d).unwrap();
    for query_rows in [4096, 0] {
        let wrong = Companion {
            query_rows,
            ..companion.clone()
        };
        assert!(matches!(wrong.validate(), Err(Error::Malformed)));
    }
}
