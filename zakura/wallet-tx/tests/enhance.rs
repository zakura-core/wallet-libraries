//! The enhancement round trip, over a real transaction.
//!
//! This is the only place the three arms of the decryption ladder can all be
//! exercised at once, because it is the only crate that can both *build* a
//! proved transaction and decrypt one. `wallet-scan` cannot depend on
//! `wallet-tx` — that would be a cycle through `wallet-store` — so the test
//! lives on this side of it.
//!
//! What it proves is the thing scanning cannot do: the sender recovers what
//! they sent and to whom, from the outgoing ciphertext a compact block omits.

use orchard::keys::{Scope, SpendingKey};
use rand::SeedableRng;
use zakura_wallet_core::{
    AccountId,
    enhanced::TransferType,
    pool::PoolId,
};
use zakura_wallet_scan::{
    ScanKeys, TransparentWatch, enhance::decrypt_transaction,
    testing::{IRONWOOD_ACTIVATION, test_params},
};
use zakura_wallet_tx::{
    Keys, SpendRequest, anchors, payment, select, spendable_notes,
    testing::{proving_key, verifying_key},
    verify_proofs,
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId},
    value::Zatoshis,
};

#[path = "common/mod.rs"]
mod common;

const ALICE: AccountId = AccountId(1);

fn rng() -> rand::rngs::ChaCha20Rng {
    rand::rngs::ChaCha20Rng::seed_from_u64(11)
}

fn keys_from(seed: u8) -> Keys {
    let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([seed; 32]))
        .expect("this seed is a valid spending key");
    Keys::from_spending_key(sk)
}

/// Serialises a transaction the way the wire would carry it.
fn raw(tx: &zcash_primitives::transaction::Transaction) -> Vec<u8> {
    let mut bytes = Vec::new();
    tx.write(&mut bytes).expect("a built transaction serialises");
    bytes
}

#[test]
fn a_sender_recovers_what_they_sent_and_a_recipient_what_they_received() {
    let alice = keys_from(1);
    let bob = keys_from(42);
    let bob_address = bob.fvk.address_at(0u32, Scope::External);

    let mut db = common::funded_wallet(PoolId::Ironwood, 2, 500_000, &alice.fvk);
    let anchors = anchors(&mut db).expect("both trees have a shared anchor");
    let witnesses = spendable_notes(&mut db, ALICE, &alice.fvk, &anchors, false).unwrap();

    let proposal = select(
        witnesses.iter().map(|(n, _)| n.clone()).collect(),
        PoolId::Ironwood,
        Zatoshis::const_from_u64(300_000),
    )
    .unwrap();

    let built = payment(
        &SpendRequest {
            proposal: &proposal,
            witnesses: &witnesses,
            keys: &alice,
            recipient: bob_address,
            anchors: &anchors,
        },
        BranchId::Nu6_3,
        anchors.height + 100,
        proving_key(),
        rng(),
    )
    .expect("an Ironwood payment builds");
    verify_proofs(&built, verifying_key()).expect("the proof verifies");

    let bytes = raw(&built);
    let height = anchors.height + 1;

    // --- The sender's view. ---
    //
    // Alice never received Bob's note and cannot decrypt it with any incoming
    // key. She recovers it with her outgoing viewing key, which reads the
    // outgoing ciphertext — the field compact blocks leave out, and the reason
    // a wallet that only scans can watch money leave without knowing where.
    let alice_keys = ScanKeys::from_accounts([(ALICE, alice.fvk.clone())]);
    let sent = decrypt_transaction(
        &test_params(),
        &alice_keys,
        &TransparentWatch::default(),
        built.txid(),
        height,
        &bytes,
    )
    .expect("the sender decrypts her own transaction");

    let outgoing: Vec<_> = sent
        .outputs
        .iter()
        .filter(|o| o.transfer_type == TransferType::Outgoing)
        .collect();
    assert_eq!(outgoing.len(), 1, "exactly one output left the wallet");
    assert_eq!(
        outgoing[0].recipient, bob_address,
        "outgoing recovery must name who was paid; this is the whole point of \
         enhancement, and no rescan can produce it"
    );
    assert_eq!(
        outgoing[0].note.value().inner(),
        300_000,
        "and how much they were paid"
    );
    assert_eq!(outgoing[0].pool, PoolId::Ironwood);

    let change: Vec<_> = sent
        .outputs
        .iter()
        .filter(|o| o.transfer_type == TransferType::AccountInternal)
        .collect();
    assert_eq!(change.len(), 1, "the remainder came back as change");
    assert!(
        !sent.spent_nullifiers.is_empty(),
        "the transaction reveals the nullifiers of the notes it spent"
    );

    // --- The recipient's view of the very same bytes. ---
    let bob_keys = ScanKeys::from_accounts([(AccountId(2), bob.fvk.clone())]);
    let received = decrypt_transaction(
        &test_params(),
        &bob_keys,
        &TransparentWatch::default(),
        built.txid(),
        height,
        &bytes,
    )
    .expect("the recipient decrypts the transaction paying them");

    let incoming: Vec<_> = received
        .outputs
        .iter()
        .filter(|o| o.transfer_type == TransferType::Incoming)
        .collect();
    assert_eq!(incoming.len(), 1, "Bob sees exactly the payment to him");
    assert_eq!(incoming[0].note.value().inner(), 300_000);
    assert!(
        received
            .outputs
            .iter()
            .all(|o| o.transfer_type != TransferType::Outgoing),
        "Bob did not send this; labelling a receipt as a send would invert the \
         direction of the payment in his history"
    );
    assert!(
        received
            .outputs
            .iter()
            .all(|o| o.transfer_type != TransferType::AccountInternal),
        "Alice's change is not Bob's, and is not decryptable by him"
    );
}

#[test]
fn a_substituted_transaction_is_refused() {
    // A server may say it does not have a transaction. It may not answer with a
    // different one: the wallet would graft this transaction's memos and
    // recipients onto the row it asked about, and nothing downstream could tell.
    let alice = keys_from(1);
    let mut db = common::funded_wallet(PoolId::Ironwood, 2, 500_000, &alice.fvk);
    let anchors = anchors(&mut db).expect("both trees have a shared anchor");
    let witnesses = spendable_notes(&mut db, ALICE, &alice.fvk, &anchors, false).unwrap();
    let proposal = select(
        witnesses.iter().map(|(n, _)| n.clone()).collect(),
        PoolId::Ironwood,
        Zatoshis::const_from_u64(300_000),
    )
    .unwrap();
    let built = payment(
        &SpendRequest {
            proposal: &proposal,
            witnesses: &witnesses,
            keys: &alice,
            recipient: keys_from(42).fvk.address_at(0u32, Scope::External),
            anchors: &anchors,
        },
        BranchId::Nu6_3,
        anchors.height + 100,
        proving_key(),
        rng(),
    )
    .unwrap();

    let keys = ScanKeys::from_accounts([(ALICE, alice.fvk.clone())]);
    let wrong = zcash_protocol::TxId::from_bytes([9u8; 32]);
    let err = decrypt_transaction(
        &test_params(),
        &keys,
        &TransparentWatch::default(),
        wrong,
        anchors.height + 1,
        &raw(&built),
    )
    .expect_err("the wallet must not accept a transaction it did not ask for");

    assert_eq!(
        err,
        zakura_wallet_scan::EnhanceError::TxIdMismatch {
            requested: wrong,
            received: built.txid(),
        }
    );
}

#[test]
fn malformed_bytes_are_an_error_not_a_panic() {
    let alice = keys_from(1);
    let keys = ScanKeys::from_accounts([(ALICE, alice.fvk.clone())]);
    let err = decrypt_transaction(
        &test_params(),
        &keys,
        &TransparentWatch::default(),
        zcash_protocol::TxId::from_bytes([0u8; 32]),
        BlockHeight::from_u32(IRONWOOD_ACTIVATION + 10),
        &[0u8; 8],
    )
    .expect_err("eight zero bytes are not a transaction");
    assert!(matches!(err, zakura_wallet_scan::EnhanceError::Malformed(_)));
}


#[test]
fn enhancement_grafts_the_memo_without_disturbing_the_scan() {
    // The discipline the whole write path rests on. Scanning stored this note
    // already, and knows where it sits in the commitment tree; enhancement
    // knows its memo. Neither may overwrite the other with a null — the memo
    // has no second source, and the position is not derivable from the
    // transaction at all.
    use zakura_wallet_store::enhance::{PutOutcome, TxMeta};

    let alice = keys_from(1);
    let bob = keys_from(42);
    let bob_address = bob.fvk.address_at(0u32, Scope::External);

    let mut db = common::funded_wallet(PoolId::Ironwood, 2, 500_000, &alice.fvk);
    let anchors = anchors(&mut db).expect("both trees have a shared anchor");
    let witnesses = spendable_notes(&mut db, ALICE, &alice.fvk, &anchors, false).unwrap();
    let proposal = select(
        witnesses.iter().map(|(n, _)| n.clone()).collect(),
        PoolId::Ironwood,
        Zatoshis::const_from_u64(300_000),
    )
    .unwrap();
    let built = payment(
        &SpendRequest {
            proposal: &proposal,
            witnesses: &witnesses,
            keys: &alice,
            recipient: bob_address,
            anchors: &anchors,
        },
        BranchId::Nu6_3,
        anchors.height + 100,
        proving_key(),
        rng(),
    )
    .unwrap();

    // What scanning knows before enhancement runs: positions, and no memos.
    let (positions_before, memos_before): (i64, i64) = db
        .connection()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM cache.received_notes
                     WHERE commitment_tree_position IS NOT NULL),
                    (SELECT COUNT(*) FROM cache.received_notes WHERE memo IS NOT NULL)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(positions_before, 2, "scanning placed both notes in the tree");
    assert_eq!(memos_before, 0, "and could not recover either memo");

    let alice_keys = ScanKeys::from_accounts([(ALICE, alice.fvk.clone())]);
    let decrypted = decrypt_transaction(
        &test_params(),
        &alice_keys,
        &TransparentWatch::default(),
        built.txid(),
        anchors.height + 1,
        &raw(&built),
    )
    .unwrap();

    let outcome = db
        .put_enhanced_tx(&test_params(), &decrypted, TxMeta::default())
        .expect("the transaction stores");
    assert_matches::assert_matches!(outcome, PutOutcome::Stored { .. });

    // The change note now carries a memo, and the notes scanning placed have
    // not moved.
    let (positions_after, change_memo): (i64, i64) = db
        .connection()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM cache.received_notes
                     WHERE commitment_tree_position IS NOT NULL),
                    (SELECT COUNT(*) FROM cache.received_notes
                     WHERE memo IS NOT NULL AND is_change = 1)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        positions_after, positions_before,
        "enhancement must never write a commitment tree position, in either \
         direction: it has no idea where a note sits"
    );
    assert_eq!(change_memo, 1, "the change note's memo was grafted on");

    // And the payment out is recorded with its recipient.
    let (to, value): (String, i64) = db
        .connection()
        .query_row(
            "SELECT to_address, value FROM main.sent_outputs
             WHERE to_address IS NOT NULL AND to_account_id IS NULL",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("the outgoing payment was recorded");
    assert_eq!(value, 300_000);
    assert!(to.starts_with('u'), "recorded as a unified address, got {to}");

    // The raw bytes are kept, which is what makes a layout change a local
    // reindex rather than a chain rescan.
    let raw_rows: i64 = db
        .connection()
        .query_row("SELECT COUNT(*) FROM main.raw_transactions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(raw_rows, 1);
}

#[test]
fn a_transaction_that_touches_nothing_is_stored_nowhere() {
    // Enhancement reaches transactions the wallet may have no stake in. Storing
    // one would put a stranger's transaction in the durable database, which is
    // the one file the wallet never drops.
    use zakura_wallet_store::enhance::{PutOutcome, TxMeta};

    let alice = keys_from(1);
    let stranger = keys_from(99);

    // The stranger's own wallet, which is where their transaction comes from.
    let mut theirs = common::funded_wallet(PoolId::Ironwood, 2, 500_000, &stranger.fvk);
    let anchors = anchors(&mut theirs).expect("both trees have a shared anchor");
    let witnesses = spendable_notes(&mut theirs, ALICE, &stranger.fvk, &anchors, false).unwrap();
    let proposal = select(
        witnesses.iter().map(|(n, _)| n.clone()).collect(),
        PoolId::Ironwood,
        Zatoshis::const_from_u64(300_000),
    )
    .unwrap();
    let built = payment(
        &SpendRequest {
            proposal: &proposal,
            witnesses: &witnesses,
            keys: &stranger,
            recipient: keys_from(42).fvk.address_at(0u32, Scope::External),
            anchors: &anchors,
        },
        BranchId::Nu6_3,
        anchors.height + 100,
        proving_key(),
        rng(),
    )
    .unwrap();

    // Alice decrypts a transaction that is none of her business.
    let alice_keys = ScanKeys::from_accounts([(AccountId(7), alice.fvk.clone())]);
    let decrypted = decrypt_transaction(
        &test_params(),
        &alice_keys,
        &TransparentWatch::default(),
        built.txid(),
        anchors.height + 1,
        &raw(&built),
    )
    .unwrap();
    assert!(decrypted.outputs.is_empty(), "none of it decrypts for Alice");

    // Alice's wallet, which has never seen any of this.
    let mut db = common::funded_wallet(PoolId::Ironwood, 1, 100_000, &alice.fvk);
    let before: i64 = db
        .connection()
        .query_row("SELECT COUNT(*) FROM main.raw_transactions", [], |r| r.get(0))
        .unwrap();

    let outcome = db
        .put_enhanced_tx(&test_params(), &decrypted, TxMeta::default())
        .unwrap();

    assert_eq!(outcome, PutOutcome::Irrelevant);
    let (raw_rows, sent): (i64, i64) = db
        .connection()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM main.raw_transactions),
                    (SELECT COUNT(*) FROM main.sent_outputs)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(raw_rows, before, "nothing was written to the durable database");
    assert_eq!(sent, 0);
}

#[test]
fn a_send_is_recorded_before_it_is_broadcast() {
    // The ordering here is the point. A wallet that broadcasts first and
    // records afterwards has a window in which it has committed notes to a
    // transaction it does not know about — and the next payment it builds will
    // spend them again.
    use zakura_wallet_store::enhance::PutOutcome;

    let alice = keys_from(1);
    let bob_address = keys_from(42).fvk.address_at(0u32, Scope::External);

    let mut db = common::funded_wallet(PoolId::Ironwood, 2, 500_000, &alice.fvk);
    let anchors = anchors(&mut db).expect("both trees have a shared anchor");
    let witnesses = spendable_notes(&mut db, ALICE, &alice.fvk, &anchors, false).unwrap();
    let spendable_before = witnesses.len();
    assert_eq!(spendable_before, 2);

    let proposal = select(
        witnesses.iter().map(|(n, _)| n.clone()).collect(),
        PoolId::Ironwood,
        Zatoshis::const_from_u64(300_000),
    )
    .unwrap();
    let target = anchors.height + 1;
    let built = payment(
        &SpendRequest {
            proposal: &proposal,
            witnesses: &witnesses,
            keys: &alice,
            recipient: bob_address,
            anchors: &anchors,
        },
        BranchId::Nu6_3,
        anchors.height + 100,
        proving_key(),
        rng(),
    )
    .unwrap();

    let alice_keys = ScanKeys::from_accounts([(ALICE, alice.fvk.clone())]);
    let decrypted =
        decrypt_transaction(&test_params(), &alice_keys, &TransparentWatch::default(), built.txid(), target, &raw(&built))
            .unwrap();

    db.store_sent_transaction(
        &test_params(),
        &decrypted,
        Zatoshis::const_from_u64(15_000),
        target,
        1_700_000_000,
        Some("bob's address as typed"),
    )
    .expect("the send records");

    // The notes it spends are no longer offered. This is what stops the very
    // next payment double-spending them.
    let after = spendable_notes(&mut db, ALICE, &alice.fvk, &anchors, false).unwrap();
    assert!(
        after.len() < spendable_before,
        "the notes committed to a pending send must not still be spendable"
    );

    // And the wallet knows it is waiting on something, which is what makes a
    // cache rebuild refuse.
    assert!(db.has_outstanding_sent_transaction().unwrap());

    // The fee is exact, because the wallet chose it rather than inferring it,
    // and `target_height` marks the transaction as this installation's.
    let (fee, target_height, created): (i64, u32, u32) = db
        .connection()
        .query_row(
            "SELECT fee, target_height, created_time FROM cache.transactions
             WHERE target_height IS NOT NULL",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(fee, 15_000);
    assert_eq!(target_height, u32::from(target));
    assert_eq!(created, 1_700_000_000);

    // What the user typed is kept alongside what the protocol saw. They are not
    // the same string, and only one of them is worth showing back.
    let typed: Vec<u8> = db
        .connection()
        .query_row(
            "SELECT value FROM main.user_metadata WHERE key = 'recipient'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(typed, b"bob's address as typed");

    // Re-recording the same send is harmless, which matters because a retry
    // after a failed broadcast must not corrupt anything.
    let again = db
        .put_enhanced_tx(
            &test_params(),
            &decrypted,
            zakura_wallet_store::enhance::TxMeta::default(),
        )
        .unwrap();
    assert_matches::assert_matches!(again, PutOutcome::Stored { .. });
    let (fee_still, target_still): (i64, Option<u32>) = db
        .connection()
        .query_row(
            "SELECT fee, target_height FROM cache.transactions
             WHERE txid = :txid",
            rusqlite::named_params![":txid": built.txid().as_ref()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(fee_still, 15_000, "a later write must not blank the fee");
    assert_eq!(
        target_still,
        Some(u32::from(target)),
        "nor forget that this wallet built it"
    );
}

#[test]
fn enhancement_sees_the_transparent_side_of_a_transaction() {
    // Enhancement fetches whole transactions, and a whole transaction carries
    // its transparent bundle. Parsing only the two shielded bundles throws that
    // away, so a transaction reached only through enhancement — a shielding
    // built on another device, a payment to an address this wallet derived —
    // has its transparent outputs and its spends of the wallet's UTXOs silently
    // discarded, and they stay invisible until a restore sweep asks the server
    // about the wallet's addresses by name.
    use transparent::keys::{AccountPrivKey, NonHardenedChildIndex, TransparentKeyScope};

    let alice = keys_from(1);
    let recipient_key = AccountPrivKey::from_seed(
        &zcash_protocol::consensus::MAIN_NETWORK,
        &[7u8; 32],
        zip32::AccountId::try_from(0).unwrap(),
    )
    .expect("the seed derives a transparent account key");
    let recipient = transparent::address::TransparentAddress::from_pubkey(
        &recipient_key
            .to_account_pubkey()
            .derive_address_pubkey(
                TransparentKeyScope::EXTERNAL,
                NonHardenedChildIndex::from_index(9).unwrap(),
            )
            .unwrap(),
    );

    let mut db = common::funded_wallet(PoolId::Ironwood, 2, 500_000, &alice.fvk);
    let anchors = zakura_wallet_tx::anchors(&mut db).unwrap();
    let witnesses =
        zakura_wallet_tx::spendable_notes(&mut db, ALICE, &alice.fvk, &anchors, false).unwrap();

    let proposal = zakura_wallet_tx::plan_transparent_payment(
        witnesses.iter().map(|(n, _)| n.clone()).collect(),
        recipient,
        Zatoshis::const_from_u64(100_000),
    )
    .expect("the wallet's notes cover the payment");

    let built = payment(
        &SpendRequest {
            proposal: &proposal,
            witnesses: &witnesses,
            keys: &alice,
            // Unused: the payment leaves transparently. Only the change is
            // shielded, and that goes to the wallet's own internal address.
            recipient: alice.fvk.address_at(0u32, Scope::External),
            anchors: &anchors,
        },
        BranchId::Nu6_3,
        anchors.height + 100,
        proving_key(),
        rng(),
    )
    .expect("a transparent payment builds");

    let bytes = raw(&built);
    let keys = ScanKeys::from_accounts([(ALICE, alice.fvk.clone())]);

    // Watching the address that was paid: the receiving wallet's view.
    let script: transparent::address::Script = recipient.script().into();
    let watching = TransparentWatch::new([(script, ALICE, 1)], []);

    let seen = decrypt_transaction(
        &test_params(),
        &keys,
        &watching,
        built.txid(),
        anchors.height + 1,
        &bytes,
    )
    .expect("the transaction decrypts");

    assert_eq!(
        seen.transparent_received.len(),
        1,
        "the payment to a watched address must be found in the transparent bundle"
    );
    assert_eq!(
        seen.transparent_received[0].txout.value(),
        Zatoshis::const_from_u64(100_000)
    );
    assert!(!seen.is_coinbase, "an ordinary payment is not a coinbase");

    // Watching nothing: the same bytes must yield nothing transparent, so a
    // stranger's outputs are not accumulated.
    let blind = decrypt_transaction(
        &test_params(),
        &keys,
        &TransparentWatch::default(),
        built.txid(),
        anchors.height + 1,
        &bytes,
    )
    .expect("the transaction decrypts");
    assert!(blind.transparent_received.is_empty());
}
