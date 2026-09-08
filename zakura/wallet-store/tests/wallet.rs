//! The wallet end to end: an account is created, its chain is scanned, and its
//! balance and history come back.
//!
//! Everything below this file has been tested in pieces. This is the check that
//! the pieces are a wallet — that a key derived from a seed finds the notes
//! paid to the address it issues, and that asking what the account is worth
//! gives the right answer.

use zakura_wallet_core::{KeyScope, pool::PoolId};
use zakura_wallet_scan::{
    NullifierSnapshot, ScanKeys, detect_batch,
    testing::{ChainBuilder, IRONWOOD_ACTIVATION, test_params},
};
use zakura_wallet_store::{WalletDb, testing::test_db};
use zcash_protocol::{consensus::BlockHeight, value::Zatoshis};

const START: u32 = IRONWOOD_ACTIVATION + 10;

fn h(n: u32) -> BlockHeight {
    BlockHeight::from_u32(n)
}

/// Creates an account and returns it with the key the chain builder pays to.
fn account_with_keys(db: &mut WalletDb) -> (zakura_wallet_core::AccountId, orchard::keys::FullViewingKey) {
    let id = db
        .create_account(
            &test_params(),
            &[9u8; 32],
            zip32::AccountId::try_from(0).unwrap(),
            h(START),
        )
        .expect("the account is created");
    let fvk = db
        .account(&test_params(), id)
        .unwrap()
        .unwrap()
        .orchard_fvk()
        .unwrap()
        .clone();
    (id, fvk)
}

#[test]
fn an_account_finds_the_notes_paid_to_it_and_reports_them() {
    let mut db = test_db().unwrap();
    let (id, fvk) = account_with_keys(&mut db);

    // The address the account would hand out. Recording it is what lets the
    // wallet know which of its addresses have been exposed.
    let (address, _) = db
        .next_address(&test_params(), id, KeyScope::External, Some(h(START)))
        .unwrap();
    assert!(address.encode(&test_params()).starts_with('u'));

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &fvk, KeyScope::External, 400_000);
        });
        b.tx(|t| {
            t.receive(PoolId::Orchard, &fvk, KeyScope::External, 250_000);
            // Somebody else's note, to be sure the account claims only its own.
            t.decoy(PoolId::Orchard, 999);
        });
    });
    chain.empty_blocks(2);

    let keys = ScanKeys::from_accounts([(id, fvk)]);
    let batch = detect_batch(
        &test_params(),
        &keys,
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .expect("the chain scans");
    db.put_batch(&test_params(), &batch).expect("the batch applies");

    // The account is worth what was paid to it, and nothing else.
    let balance = db.total_balance(id).unwrap();
    assert_eq!(balance.total(), Zatoshis::const_from_u64(650_000));
    assert_eq!(
        db.balance(id, PoolId::Ironwood).unwrap().total(),
        Zatoshis::const_from_u64(400_000)
    );
    assert_eq!(
        db.balance(id, PoolId::Orchard).unwrap().total(),
        Zatoshis::const_from_u64(250_000)
    );

    // Neither note is spendable yet: their shards are not buried, so their
    // witnesses are still reorg-able.
    assert_eq!(balance.spendable, Zatoshis::ZERO);
    assert_eq!(balance.pending, Zatoshis::const_from_u64(650_000));

    // And the history shows both transactions as incoming.
    let history = db.history(id, 10).unwrap();
    assert_eq!(history.len(), 2);
    for entry in &history {
        assert!(entry.net() > 0, "both were payments in");
        assert!(!entry.is_change_only);
        assert_eq!(entry.spent, Zatoshis::ZERO);
        assert_eq!(entry.mined_height, Some(h(START)));
    }
    let received: u64 = history.iter().map(|e| e.received.into_u64()).sum();
    assert_eq!(received, 650_000);
}

#[test]
fn a_spend_shows_in_the_history_as_value_leaving() {
    let mut db = test_db().unwrap();
    let (id, fvk) = account_with_keys(&mut db);

    // Learn the note's nullifier the way the wallet will.
    let mut probe = ChainBuilder::new(START);
    probe.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &fvk, KeyScope::External, 400_000);
        });
    });
    let keys = ScanKeys::from_accounts([(id, fvk.clone())]);
    let nf = detect_batch(
        &test_params(),
        &keys,
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
            t.receive(PoolId::Ironwood, &fvk, KeyScope::External, 400_000);
        });
    });
    chain.block(|b| {
        b.tx(|t| {
            // Spend it, keeping some back as change.
            t.spend(PoolId::Ironwood, nf);
            t.receive(PoolId::Ironwood, &fvk, KeyScope::Internal, 250_000);
        });
    });

    let batch = detect_batch(
        &test_params(),
        &keys,
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap();
    db.put_batch(&test_params(), &batch).unwrap();

    // What is left is the change, not the original note.
    assert_eq!(
        db.total_balance(id).unwrap().total(),
        Zatoshis::const_from_u64(250_000)
    );

    let history = db.history(id, 10).unwrap();
    assert_eq!(history.len(), 2);

    // Most recent first: the spend.
    let spend = &history[0];
    assert_eq!(spend.spent, Zatoshis::const_from_u64(400_000));
    assert_eq!(spend.received, Zatoshis::const_from_u64(250_000));
    assert_eq!(spend.net(), -150_000, "the difference left the wallet");
    assert!(
        spend.is_change_only,
        "everything it returned was change, so this is the wallet paying out"
    );

    let receipt = &history[1];
    assert_eq!(receipt.net(), 400_000);
    assert!(!receipt.is_change_only);
}

#[test]
fn history_is_bounded_and_most_recent_first() {
    let mut db = test_db().unwrap();
    let (id, fvk) = account_with_keys(&mut db);

    let mut chain = ChainBuilder::new(START);
    for i in 0..6u64 {
        chain.block(|b| {
            b.tx(|t| {
                t.receive(PoolId::Ironwood, &fvk, KeyScope::External, 1_000 + i);
            });
        });
    }

    let keys = ScanKeys::from_accounts([(id, fvk)]);
    let batch = detect_batch(
        &test_params(),
        &keys,
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap();
    db.put_batch(&test_params(), &batch).unwrap();

    let all = db.history(id, 100).unwrap();
    assert_eq!(all.len(), 6);
    for pair in all.windows(2) {
        assert!(
            pair[0].mined_height >= pair[1].mined_height,
            "most recent first"
        );
    }

    let recent = db.history(id, 2).unwrap();
    assert_eq!(recent.len(), 2);
    assert_eq!(recent[0], all[0], "the limit takes from the top");
}
