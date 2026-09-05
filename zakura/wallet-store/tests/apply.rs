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
    assert_eq!(count(&db, "tx_requests"), 1);
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
    let nfs = NullifierSnapshot::new(0, [(PoolId::Ironwood, nf, ALICE)]);

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
    let watch = TransparentWatch::new([(watched.clone(), ALICE)], []);

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
    // it as unmatched even though the note is already stored.
    let mut second = ChainBuilder::with_anchor(
        START + 1,
        zakura_wallet_core::pool::TreeSizes {
            orchard: 0,
            ironwood: 1,
        },
    );
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
