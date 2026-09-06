//! End-to-end tests for the apply stage: detection results into storage.
//!
//! These drive the real scanner over a synthetic chain of real encrypted notes,
//! then apply the result, so they exercise the whole path a block takes from
//! the wire to the database.

use assert_matches::assert_matches;
use incrementalmerkletree::Position;
use zakura_wallet_core::{
    DetectedBatch,
    pool::PoolId,
    scanning::{ScanPriority, ScanRange},
};
use zakura_wallet_scan::{
    AccountId, KeyScope, NullifierSnapshot, ScanKeys, TransparentWatch, detect_batch,
    testing::{ChainBuilder, IRONWOOD_ACTIVATION, fvk_from_seed, script, test_params, test_rng},
};
use zakura_wallet_store::{WalletDb, testing::test_db};
use zcash_protocol::consensus::BlockHeight;

const ALICE: AccountId = AccountId(1);

/// The stored address row the watch set reports a hit against.
const ADDRESS_ID: i64 = 1;
const START: u32 = IRONWOOD_ACTIVATION + 10;

fn h(n: u32) -> BlockHeight {
    BlockHeight::from_u32(n)
}

fn alice() -> orchard::keys::FullViewingKey {
    fvk_from_seed(1)
}

fn keys() -> ScanKeys {
    ScanKeys::from_accounts([(ALICE, alice())])
}

/// Detects `chain` against Alice's keys and the given snapshot.
fn detect(chain: &ChainBuilder, nfs: &NullifierSnapshot) -> DetectedBatch {
    detect_batch(
        &test_params(),
        &keys(),
        &TransparentWatch::default(),
        nfs,
        &chain.anchor(),
        chain.blocks(),
    )
    .expect("a well-formed chain detects cleanly")
}

fn apply(db: &mut WalletDb, batch: &DetectedBatch) {
    db.put_batch(&test_params(), batch).expect("the batch applies");
}

/// Counts rows in a cache table.
fn count(db: &WalletDb, table: &str) -> u32 {
    db.connection()
        .query_row(&format!("SELECT COUNT(*) FROM cache.{table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

// ------------------------------------------------------------ storing

#[test]
fn a_scanned_note_is_stored_with_everything_needed_to_spend_it() {
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 55_000);
        });
    });

    let batch = detect(&chain, &NullifierSnapshot::default());
    apply(&mut db, &batch);

    let (pool, value, position, is_change, scope, version, has_nf): (
        u8,
        i64,
        u64,
        bool,
        u8,
        u8,
        bool,
    ) = db
        .connection()
        .query_row(
            "SELECT pool, value, commitment_tree_position, is_change, key_scope,
                    note_version, nf IS NOT NULL
             FROM cache.received_notes",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .unwrap();

    assert_eq!(pool, PoolId::Ironwood.code());
    assert_eq!(value, 55_000);
    assert_eq!(position, 0);
    assert!(!is_change);
    assert_eq!(scope, KeyScope::External.code());
    // Ironwood notes use version 3 plaintexts; storing the lead byte keeps the
    // value meaningful to anything reading the database.
    assert_eq!(version, 0x03);
    assert!(has_nf, "the nullifier must be stored, or the note can never be seen spent");

    // The block and its transaction are recorded, and the transaction is queued
    // for the enhancement that recovers its memo.
    assert_eq!(count(&db, "blocks"), 1);
    assert_eq!(count(&db, "transactions"), 1);
    assert_eq!(count(&db, "retrieval_queue"), 1);
}

#[test]
fn both_pools_are_stored_in_one_table() {
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Orchard, &alice(), KeyScope::External, 1);
            t.receive(PoolId::Ironwood, &alice(), KeyScope::Internal, 2);
        });
    });

    apply(&mut db, &detect(&chain, &NullifierSnapshot::default()));

    let mut stmt = db
        .connection()
        .prepare("SELECT pool, value, is_change FROM cache.received_notes ORDER BY pool")
        .unwrap();
    let rows: Vec<(u8, i64, bool)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();

    assert_eq!(
        rows,
        vec![
            (PoolId::Orchard.code(), 1, false),
            (PoolId::Ironwood.code(), 2, true),
        ]
    );
}

#[test]
fn an_orchard_and_an_ironwood_action_may_share_an_index() {
    // This is the collision that forces the fork to keep two note tables. The
    // `pool` column in the key removes it.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            // Both are action 0 of their respective bundles.
            t.receive(PoolId::Orchard, &alice(), KeyScope::External, 10);
            t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 20);
        });
    });

    apply(&mut db, &detect(&chain, &NullifierSnapshot::default()));

    let indices: Vec<i64> = db
        .connection()
        .prepare("SELECT action_index FROM cache.received_notes")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(indices, vec![0, 0]);
    assert_eq!(count(&db, "received_notes"), 2);
}

#[test]
fn a_spend_of_a_stored_note_is_recorded() {
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    // Scan the receive first so the wallet knows the nullifier.
    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 100);
        });
    });
    let first = detect(&chain, &NullifierSnapshot::default());
    apply(&mut db, &first);
    let nf = first.received_notes().next().unwrap().nullifier;

    // Then a later batch spending it.
    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 100);
        });
    });
    chain.block(|b| {
        b.tx(|t| {
            t.spend(PoolId::Ironwood, nf);
        });
    });
    apply(&mut db, &detect(&chain, &NullifierSnapshot::default()));

    assert_eq!(count(&db, "received_note_spends"), 1);
}

#[test]
fn a_spend_seen_before_its_note_is_linked_when_the_note_arrives() {
    // Descending recovery scans a send before the note that funded it, so the
    // link cannot be made at scan time. Making it at apply time, inside the
    // same transaction, is what stops the spend being lost.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    // Learn the note and its nullifier without storing anything.
    let mut probe = ChainBuilder::new(START);
    probe.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 100);
        });
    });
    let nf = detect(&probe, &NullifierSnapshot::default())
        .received_notes()
        .next()
        .unwrap()
        .nullifier;

    // Apply the *spend* first, with no knowledge of the note. Its anchor
    // carries the tree sizes the server reports at that height, which is what
    // descending recovery uses in place of having scanned the earlier range.
    let mut later = ChainBuilder::with_anchor(
        START + 10,
        zakura_wallet_core::pool::TreeSizes {
            orchard: 0,
            ironwood: 1,
        },
    );
    later.block(|b| {
        b.tx(|t| {
            t.spend(PoolId::Ironwood, nf);
        });
    });
    apply(&mut db, &detect(&later, &NullifierSnapshot::default()));

    assert_eq!(count(&db, "received_note_spends"), 0);
    assert_eq!(
        count(&db, "nullifier_map"),
        1,
        "the unmatched nullifier must be kept, not discarded"
    );

    // Now the note turns up. Applying it must link the spend that was waiting:
    // an actual row in `received_note_spends`, not merely a nullifier that
    // happens to match.
    apply(&mut db, &detect(&probe, &NullifierSnapshot::default()));

    assert_eq!(
        count(&db, "received_note_spends"),
        1,
        "the note must be marked spent by the transaction seen earlier"
    );

    // The spending transaction did not exist as a row until now: nothing in it
    // was visible to the wallet when it was scanned.
    let spent_by: Vec<u32> = db
        .connection()
        .prepare(
            "SELECT t.mined_height FROM cache.received_note_spends s
             JOIN cache.transactions t ON t.id = s.transaction_id",
        )
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(spent_by, vec![START + 10]);
}

#[test]
fn a_note_and_a_spend_in_the_same_batch_are_linked() {
    // The forward direction: the spend arrives when the note is already stored.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let mut probe = ChainBuilder::new(START);
    probe.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 100);
        });
    });
    let nf = detect(&probe, &NullifierSnapshot::default())
        .received_notes()
        .next()
        .unwrap()
        .nullifier;

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 100);
        });
    });
    chain.block(|b| {
        b.tx(|t| {
            t.spend(PoolId::Ironwood, nf);
        });
    });

    apply(&mut db, &detect(&chain, &NullifierSnapshot::default()));
    assert_eq!(count(&db, "received_note_spends"), 1);
}

#[test]
fn an_empty_batch_changes_nothing() {
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let chain = ChainBuilder::new(START);
    apply(&mut db, &detect(&chain, &NullifierSnapshot::default()));

    assert_eq!(count(&db, "blocks"), 0);
    assert!(db.suggest_scan_ranges(ScanPriority::Ignored).unwrap().is_empty());
    assert_eq!(db.block_height_extrema().unwrap(), None);
}

#[test]
fn a_note_beyond_the_first_shard_widens_from_the_previous_shards_end() {
    // A note in shard 1 must have shard 1 scanned, and the widening starts from
    // where shard 0 ended rather than from the wallet's birthday.
    let shard_width = 1u32 << zakura_wallet_store::SHARD_HEIGHT;
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    db.connection()
        .execute(
            "INSERT INTO cache.tree_shards
                (pool, shard_index, subtree_end_height, root_hash, shard_data)
             VALUES (?, 0, ?, NULL, X'0100'), (?, 1, ?, NULL, X'0100')",
            rusqlite::params![
                PoolId::Ironwood.code(),
                START - 5,
                PoolId::Ironwood.code(),
                START + 400
            ],
        )
        .unwrap();

    // An anchor at the start of shard 1 puts the note at position 65536.
    let mut chain = ChainBuilder::with_anchor(
        START,
        zakura_wallet_core::pool::TreeSizes {
            orchard: 0,
            ironwood: shard_width,
        },
    );
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 1);
        });
    });

    let batch = detect(&chain, &NullifierSnapshot::default());
    assert_eq!(
        u64::from(batch.received_notes().next().unwrap().position),
        u64::from(shard_width),
        "the note should sit at the start of shard 1"
    );
    apply(&mut db, &batch);

    let ranges = db.suggest_scan_ranges(ScanPriority::Ignored).unwrap();
    let found: Vec<_> = ranges
        .iter()
        .filter(|r| r.priority() == ScanPriority::FoundNote)
        .collect();
    assert_eq!(found.len(), 1, "{ranges:?}");
    assert_eq!(*found[0].block_range(), h(START + 1)..h(START + 401));
}

#[test]
fn enhance_candidates_are_stored_with_their_funding_accounts() {
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let mut rng = test_rng(31);
    let nf = zakura_wallet_scan::testing::random_nullifier(&mut rng);
    let nfs = NullifierSnapshot::new([(PoolId::Ironwood, nf, ALICE)]);

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.spend(PoolId::Ironwood, nf);
            t.decoy(PoolId::Ironwood, 5);
        });
    });

    apply(&mut db, &detect(&chain, &nfs));

    assert_eq!(count(&db, "enhance_candidates"), 2);
    assert_eq!(count(&db, "enhance_candidate_accounts"), 2);

    let (position, nf_len, cmx_len, epk_len, ct_len): (u64, i64, i64, i64, i64) = db
        .connection()
        .query_row(
            "SELECT commitment_tree_position, length(nullifier), length(cmx),
                    length(ephemeral_key), length(compact_ciphertext)
             FROM cache.enhance_candidates ORDER BY commitment_tree_position LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .unwrap();

    // Keyed by position, never by transaction identifier: the position is the
    // only thing a private lookup may reveal.
    assert_eq!(position, 0);
    assert_eq!((nf_len, cmx_len, epk_len, ct_len), (32, 32, 32, 52));
}

#[test]
fn transparent_activity_is_stored() {
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let watched = script(3);
    // The address must exist before anything can be received at it. There is no
    // trial decryption for transparent outputs: the wallet recognises one only
    // because it derived the address in advance and was watching for it, and
    // the foreign key from the output makes that structural rather than a
    // convention somebody has to remember.
    register_address(&db, ADDRESS_ID, ALICE, &watched);

    let watch = TransparentWatch::new([(watched.clone(), ALICE, ADDRESS_ID)], []);

    let mut chain = ChainBuilder::new(START);
    let mut funding = None;
    chain.block(|b| {
        funding = Some(b.tx(|t| {
            t.transparent_out(watched.clone(), 900);
        }));
    });
    let outpoint = transparent::bundle::OutPoint::new(funding.unwrap().into(), 0);
    chain.block(|b| {
        b.tx(|t| {
            t.transparent_in(outpoint.clone());
        });
    });

    let batch = detect_batch(
        &test_params(),
        &keys(),
        &watch,
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap();
    apply(&mut db, &batch);

    assert_eq!(count(&db, "transparent_received_outputs"), 1);
    assert_eq!(count(&db, "transparent_received_output_spends"), 1);
    // The spend is also recorded independently, so a spend seen before its
    // output can be reconciled later.
    assert_eq!(count(&db, "transparent_spend_map"), 1);
}

// --------------------------------------------------------------- trees

#[test]
fn applying_a_batch_advances_both_trees() {
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 1);
            t.decoy(PoolId::Ironwood, 2);
            t.decoy(PoolId::Orchard, 3);
        });
    });

    apply(&mut db, &detect(&chain, &NullifierSnapshot::default()));

    let ironwood = db
        .with_tree_for(PoolId::Ironwood, |tree| Ok(tree.max_leaf_position(None)?))
        .unwrap();
    let orchard = db
        .with_tree_for(PoolId::Orchard, |tree| Ok(tree.max_leaf_position(None)?))
        .unwrap();
    assert_eq!(ironwood, Some(Position::from(1)));
    assert_eq!(orchard, Some(Position::from(0)));
}

#[test]
fn a_wallet_note_is_witnessable_once_its_batch_is_applied() {
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.decoy(PoolId::Ironwood, 1);
            t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 7);
            t.decoy(PoolId::Ironwood, 2);
        });
    });

    let batch = detect(&chain, &NullifierSnapshot::default());
    let position = batch.received_notes().next().unwrap().position;
    apply(&mut db, &batch);

    let witness = db
        .with_tree_for(PoolId::Ironwood, |tree| {
            Ok(tree.witness_at_checkpoint_id(position, &h(START))?)
        })
        .unwrap();
    assert!(
        witness.is_some(),
        "a note the wallet owns must be marked, or it can never be spent"
    );

    // A decoy is not marked, so no witness is available for it.
    let decoy = db
        .with_tree_for(PoolId::Ironwood, |tree| {
            Ok(tree.witness_at_checkpoint_id(Position::from(0), &h(START)))
        })
        .unwrap();
    assert!(decoy.is_err() || decoy.unwrap().is_none());
}

#[test]
fn every_scanned_block_gets_a_checkpoint_even_with_no_commitments() {
    // A rewind to height `h` needs a checkpoint at `h`. Checkpointing only the
    // blocks that touched a pool would make rewinds land approximately, and an
    // approximate rewind leaves the tree quietly wrong.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.decoy(PoolId::Ironwood, 1);
        });
    });
    chain.empty_blocks(2);
    chain.block(|b| {
        b.tx(|t| {
            t.decoy(PoolId::Ironwood, 2);
        });
    });

    apply(&mut db, &detect(&chain, &NullifierSnapshot::default()));

    for pool in PoolId::ALL {
        let count = db
            .with_tree_for(pool, |tree| {
                Ok(shardtree::store::ShardStore::checkpoint_count(
                    tree.store(),
                )?)
            })
            .unwrap();
        assert_eq!(count, 4, "{pool:?} should have one checkpoint per block");
    }
}

// ---------------------------------------------------------- scan queue

#[test]
fn applying_a_batch_marks_its_range_scanned() {
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let mut chain = ChainBuilder::new(START);
    chain.empty_blocks(3);
    apply(&mut db, &detect(&chain, &NullifierSnapshot::default()));

    let ranges = db.suggest_scan_ranges(ScanPriority::Ignored).unwrap();
    assert_eq!(
        ranges,
        vec![ScanRange::from_parts(
            h(START)..h(START + 3),
            ScanPriority::Scanned
        )]
    );
}

#[test]
fn a_found_note_widens_the_queue_to_cover_its_shard() {
    // This is the check the whole stage exists for. A note whose shard has not
    // been fully scanned has no witness and is silently unspendable, so
    // discovering one must schedule the rest of its shard.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    // Stand in for a downloaded subtree root: shard 0 of the Ironwood tree ends
    // well above the range about to be scanned.
    let shard_end = START + 500;
    db.connection()
        .execute(
            "INSERT INTO cache.tree_shards
                (pool, shard_index, subtree_end_height, root_hash, shard_data)
             VALUES (?, 0, ?, NULL, X'0100')",
            rusqlite::params![PoolId::Ironwood.code(), shard_end],
        )
        .unwrap();

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 1);
        });
    });
    apply(&mut db, &detect(&chain, &NullifierSnapshot::default()));

    let ranges = db.suggest_scan_ranges(ScanPriority::Ignored).unwrap();
    let found: Vec<_> = ranges
        .iter()
        .filter(|r| r.priority() == ScanPriority::FoundNote)
        .collect();

    assert_eq!(found.len(), 1, "expected one widening range, got {ranges:?}");
    assert_eq!(
        *found[0].block_range(),
        h(START + 1)..h(shard_end + 1),
        "the queue must cover the rest of the note's shard"
    );
}

#[test]
fn a_batch_with_no_wallet_notes_does_not_widen_the_queue() {
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();
    db.connection()
        .execute(
            "INSERT INTO cache.tree_shards
                (pool, shard_index, subtree_end_height, root_hash, shard_data)
             VALUES (?, 0, ?, NULL, X'0100')",
            rusqlite::params![PoolId::Ironwood.code(), START + 500],
        )
        .unwrap();

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.decoy(PoolId::Ironwood, 1);
        });
    });
    apply(&mut db, &detect(&chain, &NullifierSnapshot::default()));

    let ranges = db.suggest_scan_ranges(ScanPriority::Ignored).unwrap();
    assert!(
        ranges
            .iter()
            .all(|r| r.priority() != ScanPriority::FoundNote),
        "nothing was found, so nothing needs widening: {ranges:?}"
    );
}

#[test]
fn scan_ranges_are_returned_most_urgent_first() {
    let db = test_db().unwrap();
    db.connection()
        .execute_batch(
            "INSERT INTO cache.scan_queue VALUES (100, 200, 20);
             INSERT INTO cache.scan_queue VALUES (200, 300, 60);
             INSERT INTO cache.scan_queue VALUES (300, 400, 50);",
        )
        .unwrap();

    let ranges = db.suggest_scan_ranges(ScanPriority::Ignored).unwrap();
    let priorities: Vec<_> = ranges.iter().map(|r| r.priority()).collect();
    assert_eq!(
        priorities,
        vec![
            ScanPriority::Verify,
            ScanPriority::ChainTip,
            ScanPriority::Historic
        ]
    );

    // And the caller can ask for only the urgent ones.
    let urgent = db.suggest_scan_ranges(ScanPriority::ChainTip).unwrap();
    assert_eq!(urgent.len(), 2);
}

#[test]
fn an_unknown_priority_code_is_reported_rather_than_guessed() {
    let db = test_db().unwrap();
    db.connection()
        .execute("INSERT INTO cache.scan_queue VALUES (1, 2, 999)", [])
        .unwrap();

    let err = db.suggest_scan_ranges(ScanPriority::Ignored).unwrap_err();
    assert_matches!(err, zakura_wallet_store::Error::Serialization(_));
    assert!(err.to_string().contains("999"), "{err}");
}

#[test]
fn a_stale_snapshot_is_repaired_when_the_batch_is_applied() {
    // Detection runs against an immutable nullifier snapshot, which can go out
    // of date while the batch is in flight. The spend then arrives unmatched
    // even though the wallet does hold the note. Re-checking inside the
    // applying transaction is what stops that losing the spend.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let mut first = ChainBuilder::new(START);
    first.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 100);
        });
    });
    let batch = detect(&first, &NullifierSnapshot::default());
    let nf = batch.received_notes().next().unwrap().nullifier;
    apply(&mut db, &batch);

    // The spend is detected against an *empty* snapshot, so detection reports
    // it as unmatched even though the note is already stored. The range has to
    // genuinely continue from the first one: a second chain anchored on an
    // invented predecessor would be a different chain, and the store rejects
    // that rather than inserting its commitments where the wallet disagrees.
    let mut second = ChainBuilder::continuing_from(&first.end_anchor());
    second.block(|b| {
        b.tx(|t| {
            t.spend(PoolId::Ironwood, nf);
        });
    });
    let stale = detect(&second, &NullifierSnapshot::default());
    assert_eq!(
        stale.spends().count(),
        0,
        "detection could not match it, which is the situation under test"
    );

    apply(&mut db, &stale);
    assert_eq!(
        count(&db, "received_note_spends"),
        1,
        "applying must repair what the stale snapshot missed"
    );
}

#[test]
fn a_buried_note_becomes_stabilized() {
    // A stabilized note is one whose witness a reorg can no longer invalidate,
    // which is what makes it safe to select for spending. It requires the whole
    // containing shard to be scanned and buried.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 1);
        });
    });
    apply(&mut db, &detect(&chain, &NullifierSnapshot::default()));

    // The shard ends at the tip, so it is not buried yet.
    let stabilized: u32 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM cache.received_notes WHERE witness_stabilized = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stabilized, 0, "a note in the tip shard can never be stable");

    // Bury it: the shard ends far below a much later tip.
    db.connection()
        .execute(
            "UPDATE cache.tree_shards SET subtree_end_height = ? WHERE pool = ?",
            rusqlite::params![START, PoolId::Ironwood.code()],
        )
        .unwrap();

    let mut later = ChainBuilder::with_anchor(
        START + 1 + zakura_wallet_store::PRUNING_DEPTH as u32 + 10,
        zakura_wallet_core::pool::TreeSizes {
            orchard: 0,
            ironwood: 1,
        },
    );
    later.empty_blocks(1);
    apply(&mut db, &detect(&later, &NullifierSnapshot::default()));

    let stabilized: u32 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM cache.received_notes WHERE witness_stabilized = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stabilized, 1, "the note's shard is now buried");
}

#[test]
fn every_priority_code_round_trips() {
    // The codes are stored, so a mistake here silently reinterprets a queue.
    let db = test_db().unwrap();
    let all = [
        (0i64, ScanPriority::Ignored),
        (10, ScanPriority::Scanned),
        (20, ScanPriority::Historic),
        (30, ScanPriority::OpenAdjacent),
        (40, ScanPriority::FoundNote),
        (50, ScanPriority::ChainTip),
        (60, ScanPriority::Verify),
    ];

    for (i, (code, _)) in all.iter().enumerate() {
        let start = 1_000 + (i as u32) * 10;
        db.connection()
            .execute(
                "INSERT INTO cache.scan_queue VALUES (?, ?, ?)",
                rusqlite::params![start, start + 5, code],
            )
            .unwrap();
    }

    let ranges = db.suggest_scan_ranges(ScanPriority::Ignored).unwrap();
    let mut seen: Vec<_> = ranges.iter().map(|r| r.priority()).collect();
    seen.sort();
    let mut expected: Vec<_> = all.iter().map(|(_, p)| *p).collect();
    expected.sort();
    assert_eq!(seen, expected);
}

#[test]
fn a_batch_anchored_on_a_different_block_is_rejected() {
    // A batch is inserted into the trees at the absolute position its anchor
    // names, so an anchor the wallet can contradict has to be refused. Here the
    // second range is built on an invented predecessor rather than on the block
    // the wallet actually scanned, which is what a faulty or hostile source
    // looks like from the store's side.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let mut first = ChainBuilder::new(START);
    first.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 100);
        });
    });
    apply(&mut db, &detect(&first, &NullifierSnapshot::default()));

    let mut second = ChainBuilder::with_anchor(
        START + 1,
        zakura_wallet_core::pool::TreeSizes {
            orchard: 0,
            ironwood: 1,
        },
    );
    second.empty_blocks(1);
    let err = db
        .put_batch(&test_params(), &detect(&second, &NullifierSnapshot::default()))
        .expect_err("an anchor naming a block the wallet did not scan must be refused");

    assert_matches!(
        err,
        zakura_wallet_store::TreeError::Store(zakura_wallet_store::Error::AnchorHashMismatch {
            at_height,
        }) if at_height == h(START)
    );
}

#[test]
fn a_batch_whose_anchor_miscounts_the_tree_is_rejected() {
    // The hash agrees, so this is the same chain — but the tree size does not.
    // Accepting it would place every commitment in the batch one position out,
    // and every witness built from that region would be invalid.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let mut first = ChainBuilder::new(START);
    first.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 100);
        });
    });
    apply(&mut db, &detect(&first, &NullifierSnapshot::default()));

    let mut second = ChainBuilder::continuing_from(&first.end_anchor());
    second.empty_blocks(1);
    let mut batch = detect(&second, &NullifierSnapshot::default());
    batch.start_anchor.tree_sizes.ironwood += 1;

    let err = db
        .put_batch(&test_params(), &batch)
        .expect_err("an anchor that miscounts the tree must be refused");

    assert_matches!(
        err,
        zakura_wallet_store::TreeError::Store(zakura_wallet_store::Error::AnchorMismatch {
            pool: PoolId::Ironwood,
            stored: 1,
            claimed: 2,
            ..
        })
    );
}

#[test]
fn a_batch_that_does_not_meet_the_block_above_it_is_rejected() {
    // The seam descending recovery actually exercises: a range is scanned, then
    // a later batch fills in the region beneath it. Nothing is stored *below*
    // the new batch to check its start against, so the check that matters is
    // against the block above its end.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    // Scan the upper range first, as descending recovery does.
    let mut lower = ChainBuilder::new(START);
    lower.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 100);
        });
    });
    let mut upper = ChainBuilder::continuing_from(&lower.end_anchor());
    upper.block(|b| {
        b.tx(|t| {
            t.decoy(PoolId::Ironwood, 5);
        });
    });
    apply(&mut db, &detect(&upper, &NullifierSnapshot::default()));

    // Now the range beneath it, but claiming to end with a tree size that does
    // not continue into the block already stored above.
    let mut batch = detect(&lower, &NullifierSnapshot::default());
    batch.end_anchor.tree_sizes.ironwood += 1;

    let err = db
        .put_batch(&test_params(), &batch)
        .expect_err("a batch that does not meet the block above it must be refused");

    assert_matches!(
        err,
        zakura_wallet_store::TreeError::Store(zakura_wallet_store::Error::AnchorMismatch {
            pool: PoolId::Ironwood,
            ..
        })
    );
}

#[test]
fn a_partly_filled_shard_has_no_end_height() {
    // A shard holds 2^16 leaves. Recording an end height for one a handful of
    // commitments have landed in would tell both consumers — stabilisation and
    // range widening — that the shard is settled when almost none of it has
    // been scanned, which is how a note becomes silently unspendable.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 100);
            t.decoy(PoolId::Ironwood, 7);
        });
    });
    apply(&mut db, &detect(&chain, &NullifierSnapshot::default()));

    let ends: u32 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM cache.tree_shards WHERE subtree_end_height IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        ends, 0,
        "no shard is complete after two commitments, so none may claim an end height"
    );
}

#[test]
fn a_rewind_clears_a_shard_end_height_it_invalidated() {
    // The block that completed the shard has just been discarded, so the end
    // height names a block the wallet no longer holds. Left in place, both
    // consumers would treat the shard as settled on the strength of it.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 100);
        });
    });
    chain.empty_blocks(5);
    apply(&mut db, &detect(&chain, &NullifierSnapshot::default()));

    db.connection()
        .execute(
            "UPDATE cache.tree_shards SET subtree_end_height = ? WHERE pool = ?",
            rusqlite::params![START + 4, PoolId::Ironwood.code()],
        )
        .unwrap();

    db.truncate_to(h(START + 1)).unwrap();

    let remaining: u32 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM cache.tree_shards WHERE subtree_end_height IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        remaining, 0,
        "an end height above the rewind point names a block that no longer exists"
    );
}

#[test]
fn a_grid_boundary_survives_ordinary_pruning() {
    // A ZIP 318 crossing proves against the tree state at a boundary of the
    // shared anchor grid, and it is built long after that boundary has passed.
    // Pruned on the ordinary depth rule, the boundary — and every crossing that
    // would have anchored there — is lost, and it cannot be recovered: the tree
    // state at a passed height is not refetchable once the shard has moved on.
    let grid = zakura_wallet_core::ANCHOR_GRID;
    let interval = u32::from(grid.block_count());

    let start = u32::from(grid.boundary_at_or_above(h(START))) + 1;
    let boundary = u32::from(grid.boundary_at_or_above(h(start)));
    assert!(boundary > start, "the boundary must fall inside the scan");

    // Scan across the boundary and then well past the pruning window.
    let depth = zakura_wallet_store::PRUNING_DEPTH as u32;
    let stop = boundary + depth + 10;

    let mut db = test_db().unwrap();
    db.set_birthday(h(start)).unwrap();

    let mut chain = ChainBuilder::new(start);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Orchard, &alice(), KeyScope::External, 100);
            t.decoy(PoolId::Ironwood, 1);
        });
    });
    chain.empty_blocks((stop - start) as usize);
    apply(&mut db, &detect(&chain, &NullifierSnapshot::default()));

    for pool in PoolId::ALL {
        let retained: u32 = db
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM cache.tree_checkpoints
                 WHERE pool = ? AND checkpoint_id = ? AND retained_for IS NOT NULL",
                rusqlite::params![pool.code(), boundary],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            retained, 1,
            "{pool:?} must still hold the retained boundary at {boundary}, \
             {depth} blocks or more below the scanned tip"
        );
    }

    // And it is the one a crossing would be planned against.
    assert_eq!(
        db.grid_anchor_height().unwrap(),
        Some(h(boundary)),
        "the retained boundary is what a crossing anchors on"
    );

    // A non-boundary checkpoint that deep is not retained, so this is not just
    // "nothing is ever pruned".
    let unretained: u32 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM cache.tree_checkpoints
             WHERE retained_for IS NOT NULL AND checkpoint_id % ? != 0",
            rusqlite::params![interval],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(unretained, 0, "only grid boundaries are retained");
}

#[test]
fn retention_does_not_grow_without_bound() {
    // Retention is bounded by the window in which a crossing's anchor is still
    // usable. Retaining every boundary ever scanned would add rows forever, and
    // — the part that actually costs — would stop the tree pruning the marks
    // beneath them, so a recovering wallet would carry the whole history's worth
    // of retained subtrees.
    let grid = zakura_wallet_core::ANCHOR_GRID;
    let interval = u32::from(grid.block_count());
    let depth = zakura_wallet_core::ANCHOR_RETENTION_DEPTH;

    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    // A batch of old blocks spanning several boundaries, applied while the
    // chain tip is far above them — which is exactly what recovery looks like.
    let start = u32::from(grid.boundary_at_or_above(h(START))) + 1;
    let stop = start + interval * 3;
    let tip = stop + depth + interval;

    db.update_chain_tip(&test_params(), h(tip)).unwrap();

    let mut chain = ChainBuilder::new(start);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Orchard, &alice(), KeyScope::External, 100);
            t.decoy(PoolId::Ironwood, 1);
        });
    });
    chain.empty_blocks((stop - start) as usize);
    apply(&mut db, &detect(&chain, &NullifierSnapshot::default()));

    let retained: u32 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM cache.tree_checkpoints WHERE retained_for IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        retained, 0,
        "boundaries older than the window a crossing could still use are not retained"
    );

    // And there is no grid anchor to offer, which is the honest answer: the
    // wallet holds no boundary a crossing could still be built against.
    assert_eq!(db.grid_anchor_height().unwrap(), None);
}

/// Gives the wallet the `addresses` row a watched script belongs to.
fn register_address(
    db: &zakura_wallet_store::WalletDb,
    address_id: i64,
    account: zakura_wallet_core::AccountId,
    script: &transparent::address::Script,
) {
    db.connection()
        .execute(
            "INSERT INTO cache.addresses
                (id, account_id, key_scope, diversifier_index_be,
                 transparent_child_index, transparent_address, transparent_script)
             VALUES (:id, :account, 0, :div, 0, :address, :script)",
            rusqlite::named_params![
                ":id": address_id,
                ":account": account.0,
                ":div": &[0u8; 11][..],
                ":address": format!("t-test-{address_id}"),
                ":script": script.0.0.clone(),
            ],
        )
        .expect("the fixture address inserts");
}

#[test]
fn a_spend_seen_before_its_output_is_reconciled_when_the_output_arrives() {
    // Not an edge case: this wallet recovers from the tip downwards, so it
    // meets the transaction that spent an output *before* the one that created
    // it more often than not.
    //
    // The spend is recorded against an outpoint the wallet does not yet know,
    // and replayed when the output shows up. Without the replay the output
    // would sit in the balance as though it were still there — money the wallet
    // offers and cannot spend.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let watched = script(9);
    register_address(&db, ADDRESS_ID, ALICE, &watched);
    let watch = TransparentWatch::new([(watched.clone(), ALICE, ADDRESS_ID)], []);

    // The funding block, built first so its transaction identifier is known,
    // but applied second.
    let mut lower = ChainBuilder::new(START);
    let mut funding = None;
    lower.block(|b| {
        funding = Some(b.tx(|t| {
            t.transparent_out(watched.clone(), 700);
        }));
    });
    let outpoint = transparent::bundle::OutPoint::new(funding.unwrap().into(), 0);

    // The spending block, above it, which descending recovery reaches first.
    //
    // The spending transaction also pays the wallet, which is what a real
    // transparent spend looks like — it has to put the remainder somewhere.
    // That is also what makes the wallet keep the transaction at all: a
    // transaction whose only connection to the wallet is an input the wallet
    // cannot yet recognise is indistinguishable from a stranger's, and is
    // dropped. Recovering *that* case needs the UTXO sweep, not the block
    // stream.
    let mut upper = ChainBuilder::new(START + 1);
    upper.block(|b| {
        b.tx(|t| {
            t.transparent_in(outpoint.clone());
            t.transparent_out(watched.clone(), 600);
        });
    });

    let detect = |chain: &ChainBuilder| {
        detect_batch(
            &test_params(),
            &keys(),
            &watch,
            &NullifierSnapshot::default(),
            &chain.anchor(),
            chain.blocks(),
        )
        .unwrap()
    };

    apply(&mut db, &detect(&upper));

    assert_eq!(
        count(&db, "transparent_received_outputs"),
        1,
        "only the change the spending transaction paid back to the wallet"
    );
    assert_eq!(
        count(&db, "transparent_spend_map"),
        1,
        "but the spend is remembered against its outpoint"
    );
    assert_eq!(count(&db, "transparent_received_output_spends"), 0);

    // Now the block below, carrying the output the spend referred to.
    apply(&mut db, &detect(&lower));

    assert_eq!(count(&db, "transparent_received_outputs"), 2);
    assert_eq!(
        count(&db, "transparent_received_output_spends"),
        1,
        "the remembered spend must attach itself to the output when it arrives"
    );
}

// ------------------------------------------------- the discovery back edge

/// Reads the txids queued for a given kind of question.
fn requests(db: &WalletDb, query_type: u8) -> Vec<Vec<u8>> {
    db.connection()
        .prepare("SELECT subject_txid FROM cache.retrieval_queue WHERE kind = ?1 ORDER BY subject_txid")
        .unwrap()
        .query_map([query_type], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn a_spend_found_by_back_linking_asks_for_the_transaction_that_made_it() {
    // The transaction that spends a wallet note but pays the wallet nothing is
    // invisible at scan time: it has no note to decrypt, and under descending
    // recovery the note it spends has not been scanned yet, so its nullifier
    // matches nothing. Detection drops it. The only moment anything learns it
    // is the wallet's is when the funding note arrives and the nullifier links
    // — and if nothing asks for the transaction then, its memo, its recipients
    // and its outgoing data are never recovered at all.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let mut probe = ChainBuilder::new(START);
    probe.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 100);
        });
    });
    let nf = detect(&probe, &NullifierSnapshot::default())
        .received_notes()
        .next()
        .unwrap()
        .nullifier;

    let mut later = ChainBuilder::with_anchor(
        START + 10,
        zakura_wallet_core::pool::TreeSizes {
            orchard: 0,
            ironwood: 1,
        },
    );
    let mut spending = None;
    later.block(|b| {
        spending = Some(b.tx(|t| {
            t.spend(PoolId::Ironwood, nf);
        }));
    });
    let spending = spending.unwrap();

    // Scanned first, and correctly asked about by nobody: at this moment the
    // wallet has no evidence the transaction concerns it.
    apply(&mut db, &detect(&later, &NullifierSnapshot::default()));
    assert!(
        !requests(&db, 1).contains(&spending.as_ref().to_vec()),
        "a transaction with no visible wallet activity must not be fetched"
    );

    // The funding note arrives. Now it is the wallet's send.
    apply(&mut db, &detect(&probe, &NullifierSnapshot::default()));
    assert!(
        requests(&db, 1).contains(&spending.as_ref().to_vec()),
        "linking the spend must queue the transaction that made it"
    );
}

#[test]
fn a_transaction_already_fetched_is_not_asked_for_again() {
    // The guard that makes the back edge terminate. `raw_transactions` is
    // durable and written on every successful enhancement, so a transaction
    // whose bytes are present has been through this path already.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let mut probe = ChainBuilder::new(START);
    probe.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 100);
        });
    });
    let nf = detect(&probe, &NullifierSnapshot::default())
        .received_notes()
        .next()
        .unwrap()
        .nullifier;

    let mut later = ChainBuilder::with_anchor(
        START + 10,
        zakura_wallet_core::pool::TreeSizes {
            orchard: 0,
            ironwood: 1,
        },
    );
    let mut spending = None;
    later.block(|b| {
        spending = Some(b.tx(|t| {
            t.spend(PoolId::Ironwood, nf);
        }));
    });
    let spending = spending.unwrap();
    apply(&mut db, &detect(&later, &NullifierSnapshot::default()));

    // Stand in for a completed enhancement of that transaction.
    db.connection()
        .execute(
            "INSERT INTO main.raw_transactions (txid, bytes) VALUES (?1, ?2)",
            rusqlite::params![spending.as_ref(), &[0u8; 4][..]],
        )
        .unwrap();

    apply(&mut db, &detect(&probe, &NullifierSnapshot::default()));
    assert!(
        !requests(&db, 1).contains(&spending.as_ref().to_vec()),
        "a transaction whose bytes are already stored must not be re-queued"
    );
}

#[test]
fn a_note_learned_only_through_enhancement_can_still_be_seen_spent() {
    // Enhancement can be the first thing that knows about a note: the change of
    // a transaction this wallet broadcast, or any transaction enhanced below
    // the scanned frontier. The nullifier snapshot detection matches spends
    // against is built from stored nullifiers, so a grafted note written
    // without one is invisible to every later scan — it sits in the balance
    // forever, and spending it changes nothing on screen.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    // A real note, and the nullifier its owner derives from it.
    let mut probe = ChainBuilder::new(START);
    let mut note = None;
    probe.block(|b| {
        b.tx(|t| {
            note = Some(t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 100));
        });
    });
    let note = note.unwrap();
    let nf = note.nullifier(&alice());

    let txid = zcash_protocol::TxId::from_bytes([7u8; 32]);
    let enhanced = zakura_wallet_core::enhanced::EnhancedTx {
        txid,
        expiry_height: None,
        outputs: vec![zakura_wallet_core::enhanced::DecryptedOutput {
            pool: PoolId::Ironwood,
            action_index: 0,
            account: ALICE,
            note,
            recipient: alice().address_at(0u32, orchard::keys::Scope::External),
            memo: [0u8; 512],
            transfer_type: zakura_wallet_core::enhanced::TransferType::Incoming,
            nullifier: Some(nf),
        }],
        spent_nullifiers: Vec::new(),
        shielded_value_balance: 0,
        transparent_received: Vec::new(),
        transparent_spends: Vec::new(),
        candidate_spends: Vec::new(),
        is_coinbase: false,
        raw: vec![0u8; 4],
    };

    db.put_enhanced_tx(
        &test_params(),
        &enhanced,
        zakura_wallet_store::enhance::TxMeta {
            mined_height: Some(h(START)),
            ..Default::default()
        },
    )
    .expect("the enhanced transaction stores");

    // The snapshot is the thing that matters: without a nullifier the note is
    // not in it, and nothing downstream can tell the difference between a note
    // that was never spent and one whose spend cannot be recognised.
    let snapshot = db.unspent_nullifiers().unwrap();

    let mut later = ChainBuilder::with_anchor(
        START + 10,
        zakura_wallet_core::pool::TreeSizes {
            orchard: 0,
            ironwood: 1,
        },
    );
    later.block(|b| {
        b.tx(|t| {
            t.spend(PoolId::Ironwood, nf);
        });
    });
    apply(&mut db, &detect(&later, &snapshot));

    assert_eq!(
        count(&db, "received_note_spends"),
        1,
        "the grafted note must be recognised as spent"
    );
}

#[test]
fn candidates_missed_by_descending_recovery_are_recoverable_from_the_block() {
    // The defect this closes: `collect_enhance_candidates` needs to know the
    // transaction is the wallet's, and it learns that from *linked* spends.
    // Under descending recovery the funding note has not been scanned when the
    // send is, so nothing links, and the candidates are not recorded — for
    // exactly the transactions private enhancement exists to serve. Their
    // fields cannot be reconstructed from anything the wallet stores, so
    // without a way back to the block, enabling PIR later means a full rescan.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let mut probe = ChainBuilder::new(START);
    probe.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 100);
        });
    });
    let nf = detect(&probe, &NullifierSnapshot::default())
        .received_notes()
        .next()
        .unwrap()
        .nullifier;

    // The send: it spends the wallet's note and pays out. Its extra action is
    // the one a private enhancement would later have to recover.
    let mut later = ChainBuilder::with_anchor(
        START + 10,
        zakura_wallet_core::pool::TreeSizes {
            orchard: 0,
            ironwood: 1,
        },
    );
    later.block(|b| {
        b.tx(|t| {
            t.spend(PoolId::Ironwood, nf);
            t.decoy(PoolId::Ironwood, 40);
        });
    });

    apply(&mut db, &detect(&later, &NullifierSnapshot::default()));
    assert_eq!(
        count(&db, "enhance_candidates"),
        0,
        "at scan time the wallet cannot yet tell this transaction is its own"
    );

    // The funding note arrives, and the spend links.
    apply(&mut db, &detect(&probe, &NullifierSnapshot::default()));

    // A block request is now queued, naming the height and the hash the wallet
    // itself recorded there — so the answer can be checked rather than trusted.
    let queued: Vec<(u8, Vec<u8>)> = db
        .connection()
        .prepare("SELECT kind, locator FROM cache.retrieval_queue")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let anchor = db.block_anchor(h(START + 10)).unwrap().unwrap();
    let expected = zakura_wallet_core::retrieval::Locator::Block {
        height: h(START + 10),
        hash: anchor.hash,
    };
    assert!(
        queued.contains(&(expected.kind().code(), expected.encode())),
        "linking the spend must queue the block its candidates have to be read from"
    );

    // Re-detecting that one block against the wallet's *current* snapshot is
    // what recovers them: the same pure detection, with the funding now known.
    let snapshot = db.all_nullifiers().unwrap();
    let redetected = detect(&later, &snapshot);
    let stored = db
        .put_rediscovered_candidates(h(START + 10), &anchor.hash, &redetected.blocks[0])
        .expect("the block is the one the wallet scanned");

    assert!(stored > 0, "the re-detection must produce candidates");
    assert!(
        count(&db, "enhance_candidates") > 0,
        "the candidates missed at scan time must now be stored"
    );
}

#[test]
fn a_rediscovered_block_from_the_wrong_height_is_refused() {
    // The block has to come from the same trusted source scanning uses, and
    // comparing a claimed hash does not authenticate compact contents. What
    // this check does buy is that a block for the wrong height, or for a height
    // the wallet has since rewound past, cannot be folded in.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 100);
        });
    });
    let batch = detect(&chain, &NullifierSnapshot::default());
    apply(&mut db, &batch);

    let hash = db.block_anchor(h(START)).unwrap().unwrap().hash;
    assert!(
        db.put_rediscovered_candidates(h(START + 5), &hash, &batch.blocks[0])
            .is_err(),
        "a block must not be applied against a height it did not come from"
    );
}

#[test]
fn a_rewind_drops_the_position_claims_it_invalidated() {
    // A candidate names a tree position the wallet was about to ask about
    // privately. Above a rewind that position may hold somebody else's note, so
    // both the material and the request that names it have to go. A request
    // outliving its material would be one the wallet has nothing left to check
    // the answer against — the state the identity recheck exists to prevent.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 100);
        });
    });
    let batch = detect(&chain, &NullifierSnapshot::default());
    apply(&mut db, &batch);
    let nf = batch.received_notes().next().unwrap().nullifier;

    let mut later = ChainBuilder::continuing_from(&batch.end_anchor);
    later.block(|b| {
        b.tx(|t| {
            t.spend(PoolId::Ironwood, nf);
            t.decoy(PoolId::Ironwood, 40);
        });
    });
    let snapshot = db.unspent_nullifiers().unwrap();
    apply(&mut db, &detect(&later, &snapshot));

    fn actions(db: &WalletDb) -> u32 {
        db.connection()
            .query_row(
                "SELECT COUNT(*) FROM cache.retrieval_queue WHERE kind = 2",
                [],
                |r| r.get(0),
            )
            .unwrap()
    }

    assert!(count(&db, "enhance_candidates") > 0);
    assert!(actions(&db) > 0, "each candidate is queued as a request");

    db.truncate_to(h(START)).unwrap();

    assert_eq!(
        count(&db, "enhance_candidates"),
        0,
        "the material above the rewind is gone"
    );
    assert_eq!(
        actions(&db),
        0,
        "and so are the requests that named those positions"
    );
}

#[test]
fn a_malformed_stored_txid_is_an_error_rather_than_a_panic() {
    // `nullifier_map.txid` is an unconstrained BLOB, and this path runs once
    // per received note inside the apply transaction — on the engine's own
    // thread. A corrupt row must surface as an error the caller can handle, not
    // abort the sync.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let mut probe = ChainBuilder::new(START);
    probe.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 100);
        });
    });
    let probe_batch = detect(&probe, &NullifierSnapshot::default());
    let nf = probe_batch.received_notes().next().unwrap().nullifier;

    let mut later = ChainBuilder::with_anchor(
        START + 10,
        zakura_wallet_core::pool::TreeSizes {
            orchard: 0,
            ironwood: 1,
        },
    );
    later.block(|b| {
        b.tx(|t| {
            t.spend(PoolId::Ironwood, nf);
        });
    });
    apply(&mut db, &detect(&later, &NullifierSnapshot::default()));

    db.connection()
        .execute(
            "UPDATE cache.nullifier_map SET txid = ?1",
            rusqlite::params![&[9u8; 7][..]],
        )
        .unwrap();

    // Applying the funding note links the spend, which is what reads that txid.
    let err = db
        .put_batch(&test_params(), &probe_batch)
        .expect_err("a malformed stored txid must not be accepted");
    assert!(
        format!("{err}").contains("malformed"),
        "the error should name what is wrong, got: {err}"
    );
}

#[test]
fn a_block_request_waits_until_the_wallet_can_anchor_it() {
    // Re-detecting a block needs the chain state at the block *below* it. Until
    // the wallet holds that, the request must not be dispatched: asking for the
    // block anyway reveals which height the wallet cares about, achieves
    // nothing, and would repeat on every tip. Rows that can never be answered
    // would also fill the batch and starve the ones that can.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let mut probe = ChainBuilder::new(START);
    probe.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 100);
        });
    });
    let nf = detect(&probe, &NullifierSnapshot::default())
        .received_notes()
        .next()
        .unwrap()
        .nullifier;

    // The spend sits at START + 10, and START + 9 is not scanned.
    let mut later = ChainBuilder::with_anchor(
        START + 10,
        zakura_wallet_core::pool::TreeSizes {
            orchard: 0,
            ironwood: 1,
        },
    );
    later.block(|b| {
        b.tx(|t| {
            t.spend(PoolId::Ironwood, nf);
            t.decoy(PoolId::Ironwood, 40);
        });
    });
    apply(&mut db, &detect(&later, &NullifierSnapshot::default()));
    apply(&mut db, &detect(&probe, &NullifierSnapshot::default()));

    let everything = zakura_wallet_core::retrieval::LocatorKinds {
        status: true,
        transaction: true,
        action: true,
        block: true,
    };
    let blocks_pending = |db: &WalletDb| -> usize {
        db.pending_requests(
            zakura_wallet_store::retrieval::RequestScope::All,
            everything,
            h(START + 100),
            100,
        )
        .unwrap()
        .into_iter()
        .filter(|r| matches!(r.locator, zakura_wallet_core::retrieval::Locator::Block { .. }))
        .count()
    };

    let queued: u32 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM cache.retrieval_queue WHERE kind = 3",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(queued, 1, "the job is recorded");
    assert_eq!(
        blocks_pending(&db),
        0,
        "but it must not be dispatched while its predecessor is unscanned"
    );

    // Ordinary scanning reaches the block below, and the job becomes
    // dispatchable on its own, with nothing having to re-queue it.
    let mut below = ChainBuilder::with_anchor(
        START + 9,
        zakura_wallet_core::pool::TreeSizes {
            orchard: 0,
            ironwood: 1,
        },
    );
    below.block(|_| {});
    apply(&mut db, &detect(&below, &NullifierSnapshot::default()));

    assert_eq!(
        blocks_pending(&db),
        1,
        "once the predecessor is stored the job is dispatchable"
    );
}
