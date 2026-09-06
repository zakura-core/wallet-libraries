//! Tests for chain-tip reconciliation and rewinding.
//!
//! The behaviours here are ported from `zcash_client_sqlite::wallet::scanning`,
//! which is where the priority ladder's meaning actually lives: which range
//! gets which priority as the tip moves is the whole scheduling policy.

use zakura_wallet_core::{
    pool::PoolId,
    scanning::{ScanPriority, ScanRange},
};
use zakura_wallet_scan::{
    KeyScope, NullifierSnapshot, ScanKeys, TransparentWatch, detect_batch,
    testing::{ChainBuilder, IRONWOOD_ACTIVATION, ORCHARD_ACTIVATION, fvk_from_seed, test_params},
};
use zakura_wallet_store::{PRUNING_DEPTH, VERIFY_LOOKAHEAD, WalletDb, testing::test_db};
use zcash_protocol::consensus::BlockHeight;

const START: u32 = IRONWOOD_ACTIVATION + 10;

fn h(n: u32) -> BlockHeight {
    BlockHeight::from_u32(n)
}

fn ranges(db: &WalletDb) -> Vec<ScanRange> {
    db.suggest_scan_ranges(ScanPriority::Ignored).unwrap()
}

/// Records a shard ending at `height`, standing in for a downloaded subtree
/// root.
fn shard_ending_at(db: &WalletDb, pool: PoolId, index: u64, height: u32) {
    db.connection()
        .execute(
            "INSERT INTO cache.tree_shards
                (pool, shard_index, subtree_end_height, root_hash, shard_data)
             VALUES (?, ?, ?, NULL, X'0100')
             ON CONFLICT (pool, shard_index) DO UPDATE SET subtree_end_height = ?3",
            rusqlite::params![pool.code(), index, height],
        )
        .unwrap();
}

/// Scans `count` blocks from `START` into `db`, so it has a scanned tip.
fn scan_blocks(db: &mut WalletDb, count: usize) {
    let keys = ScanKeys::from_accounts([(zakura_wallet_scan::AccountId(1), fvk_from_seed(1))]);
    let mut chain = ChainBuilder::new(START);
    chain.empty_blocks(count);
    let batch = detect_batch(
        &test_params(),
        &keys,
        &TransparentWatch::default(),
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap();
    db.put_batch(&test_params(), &batch).unwrap();
}

// ------------------------------------------------------- update_chain_tip

#[test]
fn a_tip_below_the_first_pools_activation_queues_nothing() {
    // There is nothing this wallet could find down there, so there is nothing
    // to schedule.
    let mut db = test_db().unwrap();
    db.update_chain_tip(&test_params(), h(ORCHARD_ACTIVATION - 1))
        .unwrap();
    assert!(ranges(&db).is_empty());
}

#[test]
fn without_a_birthday_everything_below_the_tip_is_ignored() {
    // No accounts means no keys, so no block can contain anything of ours.
    let mut db = test_db().unwrap();
    db.update_chain_tip(&test_params(), h(START + 100)).unwrap();

    assert_eq!(
        ranges(&db),
        vec![ScanRange::from_parts(
            h(ORCHARD_ACTIVATION)..h(START + 101),
            ScanPriority::Ignored
        )]
    );
}

#[test]
fn with_a_birthday_and_nothing_scanned_the_range_is_historic() {
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();
    db.update_chain_tip(&test_params(), h(START + 100)).unwrap();

    assert_eq!(
        ranges(&db),
        vec![ScanRange::from_parts(
            h(START)..h(START + 101),
            ScanPriority::Historic
        )]
    );
}

#[test]
fn a_tip_below_the_scanned_height_is_ignored() {
    // The caller has caught the chain mid-reorg. Reacting would mean guessing
    // at a chain state that is still changing; the existing ranges will fail
    // their continuity check and the caller will rewind.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();
    scan_blocks(&mut db, 5);

    let before = ranges(&db);
    db.update_chain_tip(&test_params(), h(START)).unwrap();
    assert_eq!(ranges(&db), before);
}

#[test]
fn close_to_the_tip_the_gap_is_chain_tip_priority() {
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();
    scan_blocks(&mut db, 5);
    shard_ending_at(&db, PoolId::Orchard, 0, START + 4);
    shard_ending_at(&db, PoolId::Ironwood, 0, START + 4);

    // The scanned tip is well within the unstable window below the new tip.
    let new_tip = START + 5 + 10;
    db.update_chain_tip(&test_params(), h(new_tip)).unwrap();

    let queued = ranges(&db);
    assert!(
        queued
            .iter()
            .any(|r| r.priority() == ScanPriority::ChainTip
                && r.block_range().end == h(new_tip + 1)),
        "{queued:?}"
    );
}

#[test]
fn far_from_the_tip_a_short_verify_window_is_queued_first() {
    // The scanned tip is stable against the *new* tip but may not have been
    // against the tip it was scanned at, so a short window above it is
    // re-checked before any chain-tip work is trusted.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();
    scan_blocks(&mut db, 5);
    shard_ending_at(&db, PoolId::Orchard, 0, START + 4);
    shard_ending_at(&db, PoolId::Ironwood, 0, START + 4);

    let new_tip = START + 5 + PRUNING_DEPTH as u32 + 50;
    db.update_chain_tip(&test_params(), h(new_tip)).unwrap();

    let queued = ranges(&db);
    let verify = queued
        .iter()
        .find(|r| r.priority() == ScanPriority::Verify)
        .unwrap_or_else(|| panic!("expected a Verify range in {queued:?}"));

    assert_eq!(verify.block_range().start, h(START + 5));
    assert_eq!(
        verify.block_range().end,
        h(START + 5 + VERIFY_LOOKAHEAD),
        "the verify window is bounded by the lookahead"
    );
    // And it sorts above everything else, so it is scanned first.
    assert_eq!(queued[0].priority(), ScanPriority::Verify);
}

#[test]
fn the_tip_shard_range_follows_the_lagging_pool() {
    // Ironwood is sparse after NU6.3, so its last shard can end far below
    // Orchard's. Following the higher tip would leave Ironwood's final shard
    // incomplete, and every Ironwood note in it unwitnessable.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();
    scan_blocks(&mut db, 5);

    shard_ending_at(&db, PoolId::Orchard, 0, START + 900);
    shard_ending_at(&db, PoolId::Ironwood, 0, START + 300);

    db.update_chain_tip(&test_params(), h(START + 1_000))
        .unwrap();

    let queued = ranges(&db);
    let tip_shard = queued
        .iter()
        .find(|r| {
            r.priority() == ScanPriority::ChainTip
                && r.block_range().end == h(START + 1_001)
        })
        .unwrap_or_else(|| panic!("expected a tip-shard range in {queued:?}"));

    assert_eq!(
        tip_shard.block_range().start,
        h(START + 300),
        "the tip-shard range must start at the lagging pool's shard end"
    );
}

#[test]
fn the_tip_shard_range_never_starts_below_the_birthday() {
    // The tip-shard range would otherwise start where the lagging pool's shard
    // ends. Below the birthday the wallet holds no tree information, so
    // scanning there is work that cannot produce anything.
    let birthday = START + 500;
    let mut db = test_db().unwrap();
    db.set_birthday(h(birthday)).unwrap();

    // Both shards end well below the birthday.
    shard_ending_at(&db, PoolId::Orchard, 0, START + 100);
    shard_ending_at(&db, PoolId::Ironwood, 0, START + 100);

    db.update_chain_tip(&test_params(), h(START + 1_000))
        .unwrap();

    let queued = ranges(&db);
    let earliest = queued
        .iter()
        .map(|r| r.block_range().start)
        .min()
        .expect("the queue is not empty");
    assert_eq!(
        earliest,
        h(birthday),
        "nothing below the birthday should be queued: {queued:?}"
    );
}

#[test]
fn without_shard_metadata_the_gap_is_a_plain_historic_range() {
    // No shard information means there is no tip shard to complete, so this is
    // an ordinary linear scan.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();
    scan_blocks(&mut db, 3);

    db.update_chain_tip(&test_params(), h(START + 500)).unwrap();

    let queued = ranges(&db);
    assert!(
        queued
            .iter()
            .any(|r| r.priority() == ScanPriority::Historic
                && r.block_range() == &(h(START + 3)..h(START + 501))),
        "{queued:?}"
    );
}

#[test]
fn the_queue_stays_gapless_across_repeated_tip_updates() {
    // A hole in the queue is a region that silently stops being scanned. The
    // spanning tree fills gaps with `Historic` coverage; this checks that
    // survives repeated updates.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();
    scan_blocks(&mut db, 5);
    shard_ending_at(&db, PoolId::Orchard, 0, START + 4);
    shard_ending_at(&db, PoolId::Ironwood, 0, START + 4);

    for tip in [START + 50, START + 400, START + 900] {
        db.update_chain_tip(&test_params(), h(tip)).unwrap();
    }

    let mut queued = ranges(&db);
    queued.sort_by_key(|r| r.block_range().start);

    for pair in queued.windows(2) {
        assert_eq!(
            pair[0].block_range().end,
            pair[1].block_range().start,
            "gap between {:?} and {:?}",
            pair[0],
            pair[1]
        );
    }
    assert_eq!(queued.last().unwrap().block_range().end, h(START + 901));
}

// ------------------------------------------------------------ truncation

#[test]
fn rewinding_discards_everything_the_chain_can_reproduce() {
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let alice = fvk_from_seed(1);
    let keys = ScanKeys::from_accounts([(zakura_wallet_scan::AccountId(1), alice.clone())]);
    let mut chain = ChainBuilder::new(START);
    for i in 0..4u64 {
        chain.block(|b| {
            b.tx(|t| {
                t.receive(PoolId::Ironwood, &alice, KeyScope::External, 100 + i);
            });
        });
    }
    let batch = detect_batch(
        &test_params(),
        &keys,
        &TransparentWatch::default(),
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap();
    db.put_batch(&test_params(), &batch).unwrap();

    let notes_before: u32 = db
        .connection()
        .query_row("SELECT COUNT(*) FROM cache.received_notes", [], |r| r.get(0))
        .unwrap();
    assert_eq!(notes_before, 4);

    db.truncate_to(h(START + 1)).unwrap();

    let (notes, blocks, txs): (u32, u32, u32) = db
        .connection()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM cache.received_notes),
                    (SELECT COUNT(*) FROM cache.blocks),
                    (SELECT COUNT(*) FROM cache.transactions)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    // These transactions were found by scanning and nothing else, so the chain
    // is their only source and a rescan of the winning chain reproduces them
    // exactly. Deleting them is what keeps a reorged wallet identical to a
    // freshly scanned one.
    assert_eq!((notes, blocks, txs), (2, 2, 2));

    assert_eq!(db.block_height_extrema().unwrap(), Some((h(START), h(START + 1))));

    // The tree came back with it, and the surviving note is still witnessable.
    let max = db
        .with_tree_for(PoolId::Ironwood, |tree| Ok(tree.max_leaf_position(None)?))
        .unwrap();
    assert_eq!(max, Some(incrementalmerkletree::Position::from(1)));

    let witness = db
        .with_tree_for(PoolId::Ironwood, |tree| {
            Ok(tree.witness_at_checkpoint_id(
                incrementalmerkletree::Position::from(0),
                &h(START + 1),
            )?)
        })
        .unwrap();
    assert!(witness.is_some());
}

#[test]
fn rewinding_frees_the_notes_a_purely_scanned_spend_held() {
    // If the spend record outlived the transaction that made it, the note would
    // stay unspendable forever after a reorg.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let alice = fvk_from_seed(1);
    let keys = ScanKeys::from_accounts([(zakura_wallet_scan::AccountId(1), alice.clone())]);

    let mut probe = ChainBuilder::new(START);
    probe.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 100);
        });
    });
    let nf = detect_batch(
        &test_params(),
        &keys,
        &TransparentWatch::default(),
        &NullifierSnapshot::default(),
        &probe.anchor(),
        probe.blocks(),
    )
    .unwrap()
    .received_notes()
    .next()
    .unwrap()
    .nullifier;

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 100);
        });
    });
    chain.block(|b| {
        b.tx(|t| {
            t.spend(PoolId::Ironwood, nf);
        });
    });
    let batch = detect_batch(
        &test_params(),
        &keys,
        &TransparentWatch::default(),
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap();
    db.put_batch(&test_params(), &batch).unwrap();

    let spends: u32 = db
        .connection()
        .query_row("SELECT COUNT(*) FROM cache.received_note_spends", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(spends, 1);

    db.truncate_to(h(START)).unwrap();

    let (spends, notes): (u32, u32) = db
        .connection()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM cache.received_note_spends),
                    (SELECT COUNT(*) FROM cache.received_notes)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    // The spending transaction was known only from the chain that lost, so it
    // goes, and the note it spent is free again. A wallet that kept the spend
    // would hold the note against a transaction it can never prove dead,
    // because nothing outside that discarded chain ever referred to it.
    assert_eq!(spends, 0, "a spend known only from the losing chain goes with it");
    assert_eq!(notes, 1, "the note itself survives the rewind");
}

#[test]
fn rewinding_requeues_the_discarded_range() {
    // A rewind that merely deleted the blocks would leave a hole the queue
    // never revisits: nothing above the rewind point would be scanned again
    // until the tip moved far enough for `update_chain_tip` to notice, and in
    // the meantime the wallet would quietly be missing blocks.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();
    scan_blocks(&mut db, 6);

    db.truncate_to(h(START + 2)).unwrap();

    let queued = ranges(&db);
    assert_eq!(
        queued,
        vec![
            // `Verify` so it is re-checked before anything else, and so it
            // overrides the `Scanned` marking it used to carry.
            ScanRange::from_parts(h(START + 3)..h(START + 6), ScanPriority::Verify),
            ScanRange::from_parts(h(START)..h(START + 3), ScanPriority::Scanned),
        ],
    );
}

#[test]
fn rewinding_below_everything_empties_the_wallet_and_requeues_it_all() {
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();
    scan_blocks(&mut db, 4);

    db.truncate_to(h(START - 1)).unwrap();

    assert_eq!(db.block_height_extrema().unwrap(), None);
    assert_eq!(
        ranges(&db),
        vec![ScanRange::from_parts(
            h(START)..h(START + 4),
            ScanPriority::Verify
        )],
        "everything discarded must come back as work to redo"
    );
    for pool in PoolId::ALL {
        let max = db
            .with_tree_for(pool, |tree| Ok(tree.max_leaf_position(None)?))
            .unwrap();
        assert_eq!(max, None, "{pool:?}");
    }
}

#[test]
fn rewinding_keeps_what_the_chain_cannot_reproduce() {
    // The other half of the rule. A transaction this wallet built, or whose
    // bytes an enhancement stored, holds things scanning can never produce
    // again: the fee, the height it was built for, an outgoing recipient
    // recovered under an outgoing viewing key, a memo. A reorg says the wallet
    // was wrong about *where* that transaction is, not that it never happened,
    // so the row is un-mined rather than deleted.
    //
    // Without this a rewind past a pending payment would erase the payment.
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let alice = fvk_from_seed(1);
    let keys = ScanKeys::from_accounts([(zakura_wallet_scan::AccountId(1), alice.clone())]);
    let mut chain = ChainBuilder::new(START);
    for i in 0..2u64 {
        chain.block(|b| {
            b.tx(|t| {
                t.receive(PoolId::Ironwood, &alice, KeyScope::External, 100 + i);
            });
        });
    }
    let batch = detect_batch(
        &test_params(),
        &keys,
        &TransparentWatch::default(),
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap();
    db.put_batch(&test_params(), &batch).unwrap();

    // Mark the upper transaction as one this wallet built, which is what
    // `target_height` means and what no other installation would ever set.
    let txid: Vec<u8> = db
        .connection()
        .query_row(
            "SELECT txid FROM cache.transactions WHERE mined_height = :h",
            rusqlite::named_params![":h": u32::from(h(START + 1))],
            |r| r.get(0),
        )
        .unwrap();
    db.connection()
        .execute(
            "UPDATE cache.transactions SET target_height = :h, fee = 5000
             WHERE txid = :txid",
            rusqlite::named_params![":h": u32::from(h(START + 2)), ":txid": txid],
        )
        .unwrap();

    db.truncate_to(h(START)).unwrap();

    let (txs, mined, fee, notes, positionless): (u32, u32, Option<i64>, u32, u32) = db
        .connection()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM cache.transactions),
                    (SELECT COUNT(*) FROM cache.transactions WHERE mined_height IS NOT NULL),
                    (SELECT fee FROM cache.transactions WHERE target_height IS NOT NULL),
                    (SELECT COUNT(*) FROM cache.received_notes),
                    (SELECT COUNT(*) FROM cache.received_notes
                     WHERE commitment_tree_position IS NULL)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap();

    assert_eq!(txs, 2, "the locally built transaction survives the rewind");
    assert_eq!(mined, 1, "and is un-mined, leaving only the one below the rewind");
    assert_eq!(fee, Some(5000), "its fee is not something a rescan could recover");
    assert_eq!(notes, 2, "its note keeps its row, and its memo with it");
    assert_eq!(
        positionless, 1,
        "but loses its place in the tree, which a rescan may assign differently"
    );
}

#[test]
fn a_provably_dead_spend_gives_its_note_back() {
    // The failure this prevents is funds locked forever. A wallet builds a
    // payment, it never gets mined, and the notes it named are held against a
    // transaction that can no longer exist.
    //
    // The release has to be earned, though. It happens only once a server has
    // positively said it does not have the transaction, at a height past which
    // the transaction could no longer be mined. Inferring death from the chain
    // tip alone would mean releasing notes the wallet simply had not asked
    // about — and then spending them twice.
    use zakura_wallet_core::enhanced::TransactionStatus;

    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let alice = fvk_from_seed(1);
    let keys = ScanKeys::from_accounts([(zakura_wallet_scan::AccountId(1), alice.clone())]);

    let mut probe = ChainBuilder::new(START);
    probe.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 100);
        });
    });
    let nf = detect_batch(
        &test_params(),
        &keys,
        &TransparentWatch::default(),
        &NullifierSnapshot::default(),
        &probe.anchor(),
        probe.blocks(),
    )
    .unwrap()
    .received_notes()
    .next()
    .unwrap()
    .nullifier;

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 100);
        });
    });
    chain.block(|b| {
        b.tx(|t| {
            t.spend(PoolId::Ironwood, nf);
        });
    });
    let batch = detect_batch(
        &test_params(),
        &keys,
        &TransparentWatch::default(),
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap();
    db.put_batch(&test_params(), &batch).unwrap();

    // Make the spending transaction look like one this wallet sent and that
    // never landed: unmined, with an expiry height it has now passed.
    let spending: Vec<u8> = db
        .connection()
        .query_row(
            "SELECT t.txid FROM cache.transactions t
             JOIN cache.received_note_spends s ON s.transaction_id = t.id",
            [],
            |r| r.get(0),
        )
        .unwrap();
    db.connection()
        .execute(
            "UPDATE cache.transactions
             SET mined_height = NULL, block_height = NULL,
                 target_height = :target, expiry_height = :expiry
             WHERE txid = :txid",
            rusqlite::named_params![
                ":target": START + 2,
                ":expiry": START + 5,
                ":txid": spending,
            ],
        )
        .unwrap();

    let txid = zcash_protocol::TxId::from_bytes(spending.clone().try_into().unwrap());

    // The chain tip is now well past the expiry height — and that alone must
    // not release the note, because the wallet has not asked anybody.
    assert_eq!(
        db.spendable_notes(zakura_wallet_core::AccountId(1), false)
            .unwrap()
            .len(),
        0,
        "passing the expiry height is not proof; the wallet never asked"
    );
    assert!(
        db.has_outstanding_sent_transaction().unwrap(),
        "the wallet is still waiting on this payment"
    );

    // Now a server answers. This is the proof, and it is what releases the note.
    db.set_transaction_status(txid, TransactionStatus::NotFound, h(START + 20))
        .unwrap();

    assert_eq!(
        db.spendable_notes(zakura_wallet_core::AccountId(1), false)
            .unwrap()
            .len(),
        1,
        "a note held by a provably dead transaction must come back"
    );
    assert!(
        !db.has_outstanding_sent_transaction().unwrap(),
        "and the wallet is no longer waiting on it"
    );

    // The attempt stays on record. That is the whole reason spends are a
    // junction table rather than a column on the note.
    let spends: u32 = db
        .connection()
        .query_row("SELECT COUNT(*) FROM cache.received_note_spends", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(spends, 1, "the spend attempt is history, not a mistake to erase");
}

#[test]
fn a_transaction_reported_missing_can_still_be_mined() {
    // The sequence is ordinary, not adversarial: a wallet broadcasts a payment,
    // asks a server about it before the server has seen it, is told it does not
    // exist, and the transaction mines a moment later.
    //
    // `confirmed_unmined_at_height` records proof the transaction was not
    // mined, and the schema forbids holding that alongside a mined height. So
    // whichever write learns the transaction is mined has to retract the proof.
    // Without that, scanning the block carrying it fails a CHECK constraint and
    // the range never finishes — the wallet stops syncing entirely.
    use zakura_wallet_core::enhanced::TransactionStatus;

    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let alice = fvk_from_seed(1);
    let keys = ScanKeys::from_accounts([(zakura_wallet_scan::AccountId(1), alice.clone())]);

    let mut chain = ChainBuilder::new(START);
    let mut txid = None;
    chain.block(|b| {
        txid = Some(b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 100);
        }));
    });
    let txid = zcash_protocol::TxId::from_bytes(txid.unwrap().into());

    // The wallet knows of the transaction before scanning reaches it, and a
    // server says it does not have it.
    db.connection()
        .execute(
            "INSERT INTO cache.transactions (txid, target_height, expiry_height)
             VALUES (:txid, :target, :expiry)",
            rusqlite::named_params![
                ":txid": txid.as_ref(),
                ":target": START,
                ":expiry": START + 40,
            ],
        )
        .unwrap();
    db.set_transaction_status(txid, TransactionStatus::NotFound, h(START))
        .unwrap();

    let recorded: Option<u32> = db
        .connection()
        .query_row(
            "SELECT confirmed_unmined_at_height FROM cache.transactions WHERE txid = :txid",
            rusqlite::named_params![":txid": txid.as_ref()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(recorded, Some(START), "the server's answer was recorded");

    // Now it mines, and scanning finds it.
    let batch = detect_batch(
        &test_params(),
        &keys,
        &TransparentWatch::default(),
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap();
    db.put_batch(&test_params(), &batch)
        .expect("scanning a transaction previously reported missing must not fail");

    let (mined, unmined_proof): (Option<u32>, Option<u32>) = db
        .connection()
        .query_row(
            "SELECT mined_height, confirmed_unmined_at_height
             FROM cache.transactions WHERE txid = :txid",
            rusqlite::named_params![":txid": txid.as_ref()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(mined, Some(START), "it is mined where the chain says");
    assert_eq!(
        unmined_proof, None,
        "and the proof that it was not mined has been retracted"
    );
}
