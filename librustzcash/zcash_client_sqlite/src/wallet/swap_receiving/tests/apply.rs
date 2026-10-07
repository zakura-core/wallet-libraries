use super::*;
use std::collections::BTreeMap;
use zcash_primitives::transaction::TxId;

/// Pays receive key 8 at the tip before registering it, so scanning misses the note,
/// then watches the key from the next block and queues the payment. Also returns the
/// tip and the payment's path there.
pub(super) fn fixture() -> (State, RegisteredKey, PendingPayment, ChainPoint, MerklePath) {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let id = KeyId::new(Purpose::Receive, 8);
    let candidate = pay_candidate(&mut st, id);
    let through = tip(&st);
    assert!(unspent_keys(&st, through.height).is_empty());
    let db = st.wallet_mut().db_mut();
    let key = db
        .watch_swap_receive_key(account, 8, through.height + 1)
        .unwrap();
    db.queue_swap_payment(account, id, &candidate).unwrap();
    (st, key, candidate, through, first_leaf_path())
}

#[test]
fn swap_payment_applies_unscanned_key_note_atomically_and_reopens() {
    let (mut st, key, candidate, through, path) = fixture();
    let account = st.test_account().unwrap().id();
    let mut bad_path = path.auth_path();
    bad_path[0] = MerkleHashOrchard::empty_root(1.into());
    // A path that misses the wallet's root rejects the directory's answer: the queued
    // lookup is discarded so the next attempt asks again.
    assert_eq!(
        st.wallet_mut()
            .db_mut()
            .apply_pending_swap_payment(
                account,
                key.key_id(),
                &candidate,
                through,
                (through, &MerklePath::from_parts(0, bad_path))
            )
            .unwrap(),
        PaymentApplication::Rejected
    );
    assert!(
        st.wallet()
            .db()
            .get_unspent_ironwood_notes_at_historical_height(account, through.height)
            .unwrap()
            .is_empty()
    );
    assert!(
        st.wallet()
            .db()
            .pending_swap_payments(account, key.key_id())
            .unwrap()
            .is_empty()
    );
    st.wallet_mut()
        .db_mut()
        .transactionally(|db| db.queue_swap_payment(account, key.key_id(), &candidate))
        .unwrap();
    assert_eq!(
        st.wallet_mut()
            .db_mut()
            .apply_pending_swap_payment(
                account,
                key.key_id(),
                &candidate,
                through,
                (through, &path)
            )
            .unwrap(),
        PaymentApplication::Applied
    );
    let reopened = WalletDb::for_path(
        st.wallet().data_file_path(),
        *st.network(),
        test_clock(),
        test_rng(),
    )
    .unwrap();
    *st.wallet_mut().db_mut() = reopened;
    let notes = st
        .wallet()
        .db()
        .get_unspent_ironwood_notes_at_historical_height(account, through.height)
        .unwrap();
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].note().value().inner(), 100_000);
    assert_eq!(notes[0].swap_key_id(), Some(key.key_id()));
    assert!(
        st.wallet()
            .db()
            .pending_swap_payments(account, key.key_id())
            .unwrap()
            .is_empty()
    );
    assert!(crate::wallet::enhance_pir::is_protected(st.wallet().conn(), candidate.txid).unwrap());
    let stored_memo: Vec<u8> = st
        .wallet()
        .conn()
        .query_row("SELECT memo FROM ironwood_received_notes", [], |r| r.get(0))
        .unwrap();
    assert_eq!(stored_memo, vec![4; 512]);
    // A duplicate directory answer does not double credit the note.
    st.wallet_mut()
        .db_mut()
        .queue_swap_payment(account, key.key_id(), &candidate)
        .unwrap();
    assert_eq!(
        st.wallet_mut()
            .db_mut()
            .apply_pending_swap_payment(
                account,
                key.key_id(),
                &candidate,
                through,
                (through, &path)
            )
            .unwrap(),
        PaymentApplication::Applied
    );
    assert_eq!(
        st.wallet()
            .db()
            .get_unspent_ironwood_notes_at_historical_height(account, through.height)
            .unwrap()
            .len(),
        1
    );
    // Appending after importing a witness must preserve the evolving tree.
    let (later, _, _) = st.generate_next_block(
        &IronwoodFvk(key.full_viewing_key().clone()),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(40_000),
    );
    st.scan_cached_blocks(later, 1);
    let tx = st.wallet_mut().conn_mut().transaction().unwrap();
    assert!(
        crate::ironwood_tree(&tx)
            .unwrap()
            .witness_at_checkpoint_id(0u64.into(), &later)
            .unwrap()
            .is_some()
    );
}

#[test]
fn swap_payment_imports_an_already_spent_note_without_crediting_it() {
    use zcash_keys::address::{Address, UnifiedAddress};
    for pruned in [false, true] {
        let (mut st, key, candidate, _, _) = fixture();
        let account = st.test_account().unwrap().id();
        let recovered = candidate
            .encrypted_note
            .decrypt(
                &FullViewingKey::from(st.test_account().unwrap().usk().orchard()),
                key.key_id(),
            )
            .unwrap();
        let to = Address::Unified(
            UnifiedAddress::from_receivers(Some(key.receiver()), None, None).unwrap(),
        );
        let (height, _) = st.generate_next_block_spending(
            &IronwoodFvk(key.full_viewing_key().clone()),
            (*recovered.nullifier(), Zatoshis::const_from_u64(100_000)),
            to,
            Zatoshis::const_from_u64(20_000),
        );
        st.scan_cached_blocks(height, 1);
        let through = tip(&st);
        let mut tree =
            incrementalmerkletree::frontier::CommitmentTree::<MerkleHashOrchard, 32>::empty();
        let mut witness = None;
        let mut stmt = st
            .cache()
            .0
            .prepare("SELECT data FROM compactblocks ORDER BY height")
            .unwrap();
        for block in stmt.query_map([], |r| r.get::<_, Vec<u8>>(0)).unwrap() {
            let block = CompactBlock::decode(block.unwrap().as_slice()).unwrap();
            for tx in block.vtx {
                for action in tx.ironwood_actions {
                    let cmx = MerkleHashOrchard::from_cmx(&action.cmx().unwrap());
                    match &mut witness {
                        None => {
                            tree.append(cmx).unwrap();
                            witness = incrementalmerkletree::witness::IncrementalWitness::from_tree(
                                tree.clone(),
                            );
                        }
                        Some(witness) => witness.append(cmx).unwrap(),
                    }
                }
            }
        }
        drop(stmt);
        let proof: MerklePath = witness.unwrap().path().unwrap().into();
        if pruned {
            st.wallet_mut()
                .db_mut()
                .retain_swap_spend_history(account)
                .unwrap();
            st.wallet()
                .conn()
                .execute("DELETE FROM nullifier_map", [])
                .unwrap();
            st.wallet()
                .conn()
                .execute("DELETE FROM ironwood_nullifier_scan_blocks", [])
                .unwrap();
            assert_eq!(
                st.wallet_mut()
                    .db_mut()
                    .apply_pending_swap_payment(
                        account,
                        key.key_id(),
                        &candidate,
                        through,
                        (through, &proof)
                    )
                    .unwrap(),
                PaymentApplication::AwaitingSpendHistory
            );
            let reopened = WalletDb::for_path(
                st.wallet().data_file_path(),
                *st.network(),
                test_clock(),
                test_rng(),
            )
            .unwrap();
            *st.wallet_mut().db_mut() = reopened;
            st.scan_cached_blocks(candidate.height, 2);
        }

        assert_eq!(
            st.wallet_mut()
                .db_mut()
                .apply_pending_swap_payment(
                    account,
                    key.key_id(),
                    &candidate,
                    through,
                    (through, &proof)
                )
                .unwrap(),
            PaymentApplication::Applied
        );
        let spent: u64 = st
            .wallet()
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM ironwood_received_notes n
        JOIN ironwood_received_note_spends s ON s.ironwood_received_note_id=n.id WHERE n.nf=?1",
                [recovered.nullifier().to_bytes()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(spent, 1);
        assert!(
            st.wallet()
                .db()
                .get_unspent_ironwood_notes_at_historical_height(account, height)
                .unwrap()
                .iter()
                .all(|n| n.note().nullifier(key.full_viewing_key()) != *recovered.nullifier())
        );
    }
}

#[test]
fn privately_imported_note_spends_into_ordinary_internal_change() {
    use std::convert::Infallible;
    use zcash_client_backend::{
        data_api::wallet::{ConfirmationsPolicy, input_selection::GreedyInputSelector},
        fees::{DustOutputPolicy, StandardFeeRule, standard},
        wallet::OvkPolicy,
    };
    use zcash_keys::address::{Address, UnifiedAddress};
    use zcash_protocol::ShieldedPool;
    use zip321::{Payment, TransactionRequest};
    let (mut st, key, candidate, through, path) = fixture();
    let account = st.test_account().cloned().unwrap();
    st.wallet_mut()
        .db_mut()
        .apply_pending_swap_payment(
            account.id(),
            key.key_id(),
            &candidate,
            through,
            (through, &path),
        )
        .unwrap();
    for _ in 0..5 {
        let (h, _) = st.generate_empty_block();
        st.scan_cached_blocks(h, 1);
    }
    let recipient =
        FullViewingKey::from(&orchard::keys::SpendingKey::from_bytes([0xf5; 32]).unwrap())
            .address_at(0u32, Scope::External);
    let address =
        Address::Unified(UnifiedAddress::from_receivers(Some(recipient), None, None).unwrap());
    let request = TransactionRequest::new(vec![Payment::without_memo(
        address.to_zcash_address(st.network()),
        Zatoshis::const_from_u64(50_000),
    )])
    .unwrap();
    let strategy = standard::SingleOutputChangeStrategy::<TestDb>::new(
        StandardFeeRule::Zip317,
        None,
        ShieldedPool::Orchard,
        DustOutputPolicy::default(),
    );
    let proposal = st
        .propose_transfer(
            account.id(),
            &GreedyInputSelector::new(),
            &strategy,
            request,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();
    assert_eq!(
        proposal.input_count_in_pool(zcash_protocol::PoolType::IRONWOOD),
        1
    );
    let created = st
        .create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        )
        .unwrap();
    let (h, _) = st.generate_next_block_including(created[0]);
    st.scan_cached_blocks(h, 1);
    let notes = st
        .wallet()
        .db()
        .get_unspent_ironwood_notes_at_historical_height(account.id(), h)
        .unwrap();
    assert_eq!(notes.len(), 1);
    assert!(notes[0].swap_key_id().is_none());
    assert_eq!(
        notes[0].note().recipient(),
        FullViewingKey::from(account.usk().orchard()).address_at(0u32, Scope::Internal)
    );
}

#[test]
fn private_payment_uses_its_witness_anchor_and_survives_a_rewind() {
    let (mut st, key, candidate, proof_anchor, path) = fixture();
    let account = st.test_account().unwrap().id();
    let (height, _, _) = st.generate_next_block(
        &IronwoodFvk(key.full_viewing_key().clone()),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(10_000),
    );
    st.scan_cached_blocks(height, 1);
    let through = tip(&st);
    // The newer block changed the root. The supplied path belongs to the older accepted checkpoint.
    assert_eq!(
        st.wallet_mut()
            .db_mut()
            .apply_pending_swap_payment(
                account,
                key.key_id(),
                &candidate,
                through,
                (proof_anchor, &path)
            )
            .unwrap(),
        PaymentApplication::Applied
    );
    st.truncate_to_height_retaining_cache(proof_anchor.height);
    let notes = st
        .wallet()
        .db()
        .get_unspent_ironwood_notes_at_historical_height(account, proof_anchor.height)
        .unwrap();
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].note().value().inner(), 100_000);
}

#[test]
fn sweep_steps_queue_a_directory_lookup_and_apply_it_once() {
    let (mut st, key, candidate, through, path) = fixture();
    let account = st.test_account().unwrap().id();
    let key = key.key_id();
    // Start from the directory's report alone, not a queued candidate.
    st.wallet()
        .conn()
        .execute("DELETE FROM ironwood_swap_payment_recovery", [])
        .unwrap();
    let note = candidate.encrypted_note.to_bytes();
    let payment = DirectoryPayment {
        height: u32::from(candidate.height),
        block_hash: candidate.block_hash.0,
        txid: *candidate.txid.as_ref(),
        tx_index: candidate.tx_index.into(),
        action_index: candidate.action_index,
        position: candidate.position.into(),
        action_nullifier: note[..32].try_into().unwrap(),
        cmx: note[32..64].try_into().unwrap(),
        ephemeral_key: note[64..96].try_into().unwrap(),
        ciphertext_prefix: note[96..148].try_into().unwrap(),
    };
    let suffix: [u8; 528] = note[148..].try_into().unwrap();
    let db = st.wallet_mut().db_mut();

    let deferred = |result: Result<_, Error>| match result {
        Err(Error::SweepDeferred(reason)) => reason,
        other => panic!("expected a deferral, got {:?}", other.map(|_| ())),
    };
    assert_eq!(
        deferred(db.swap_publication_anchor(through.height + 1, through)),
        SweepDeferral::UnknownAnchor
    );
    let far = ChainPoint {
        height: through.height + MAX_PUBLICATION_LAG + 1,
        ..through
    };
    assert_eq!(
        deferred(db.swap_publication_anchor(through.height, far)),
        SweepDeferral::StalePublication
    );
    let anchor = db.swap_publication_anchor(through.height, through).unwrap();
    assert_eq!(anchor, through);

    assert_eq!(
        db.swap_note_data_needed(account, key, std::slice::from_ref(&payment))
            .unwrap(),
        [0]
    );
    let note_data = BTreeMap::from([(payment.position, suffix)]);
    db.begin_swap_discovery_attempt(account, key, 1_700_000_000)
        .unwrap();
    let backoff = |conn: &rusqlite::Connection| -> (u32, i64) {
        conn.query_row(
            "SELECT attempts, next_attempt_at FROM ironwood_swap_sweeps",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
    };
    assert_eq!(backoff(std::borrow::Borrow::borrow(&db.conn)).0, 1);
    // Without its note data the payment is not queued and the lookup is not done.
    assert!(
        !db.queue_swap_directory_lookup(
            account,
            key,
            anchor,
            std::slice::from_ref(&payment),
            &BTreeMap::new()
        )
        .unwrap()
    );
    assert_eq!(
        db.swap_note_data_needed(account, key, std::slice::from_ref(&payment))
            .unwrap(),
        [0]
    );
    assert!(
        db.queue_swap_directory_lookup(
            account,
            key,
            anchor,
            std::slice::from_ref(&payment),
            &note_data,
        )
        .unwrap()
    );
    // Queuing leaves the attempt's lease alone, so an answer that keeps being rejected
    // backs off like any other failure.
    assert_eq!(
        backoff(std::borrow::Borrow::borrow(&db.conn)),
        (1, 1_700_000_000 + 60)
    );
    // Queued now, so a repeated report needs no note data, and a corrected one needs it again.
    assert!(
        db.swap_note_data_needed(account, key, std::slice::from_ref(&payment))
            .unwrap()
            .is_empty()
    );
    let moved = DirectoryPayment {
        position: 1,
        ..payment.clone()
    };
    assert_eq!(
        db.swap_note_data_needed(account, key, &[moved]).unwrap(),
        [1]
    );

    assert_eq!(
        db.apply_swap_sweep(account, key, through, anchor, WATCHED, |_, _| None)
            .unwrap(),
        PaymentApplication::AwaitingWitness
    );
    let siblings = path.auth_path().map(|hash| hash.to_bytes());
    // A sibling that is not a field element gives no path.
    let mut invalid = siblings;
    invalid[3] = [0xff; 32];
    assert_eq!(
        db.apply_swap_sweep(account, key, through, anchor, WATCHED, |_, _| Some(invalid))
            .unwrap(),
        PaymentApplication::AwaitingWitness
    );
    assert_eq!(
        db.apply_swap_sweep(account, key, through, anchor, WATCHED, |position, cmx| {
            (position == candidate.position && cmx == candidate.encrypted_note.commitment())
                .then_some(siblings)
        })
        .unwrap(),
        PaymentApplication::Applied
    );
    assert!(
        st.wallet()
            .db()
            .get_unspent_ironwood_notes_at_historical_height(account, through.height)
            .unwrap()
            .iter()
            .any(|n| n.swap_key_id() == Some(key))
    );
    let db = st.wallet_mut().db_mut();
    assert!(
        !db.swap_history_pending(account, through.height + 1)
            .unwrap()
    );
    assert!(
        db.swap_note_data_needed(account, key, std::slice::from_ref(&payment))
            .unwrap()
            .is_empty()
    );
}

/// The transaction IDs of the wallet's Ironwood notes.
fn note_txids(st: &State) -> Vec<TxId> {
    let mut stmt = st
        .wallet()
        .conn()
        .prepare(
            "SELECT t.txid FROM ironwood_received_notes n
             JOIN transactions t ON t.id_tx = n.transaction_id ORDER BY n.id",
        )
        .unwrap();
    stmt.query_map([], |r| Ok(TxId::from_bytes(r.get(0)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// Whether the wallet stores a transaction with `txid`.
fn has_transaction(st: &State, txid: TxId) -> bool {
    st.wallet()
        .conn()
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM transactions WHERE txid = ?1)",
            [txid.as_ref()],
            |r| r.get(0),
        )
        .unwrap()
}

#[test]
fn scanning_moves_a_mislabeled_import_to_its_transaction() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let id = KeyId::new(Purpose::Refund, 0);
    let candidate = pay_candidate(&mut st, id);
    let through = tip(&st);
    let forged = PendingPayment {
        txid: TxId::from_bytes([7; 32]),
        ..candidate.clone()
    };
    let db = st.wallet_mut().db_mut();
    let key = db
        .reserve_swap_receiving_key_from(account, Purpose::Refund, through.height + 1)
        .unwrap();
    assert_eq!(key.key_id(), id);
    db.queue_swap_payment(account, id, &forged).unwrap();
    assert_eq!(
        db.apply_pending_swap_payment(account, id, &forged, through, (through, &first_leaf_path()))
            .unwrap(),
        PaymentApplication::Applied
    );
    assert_eq!(note_txids(&st), vec![forged.txid]);

    // Rescanning the payment's block with the key finds the same nullifier, which
    // previously failed the scan on the unique constraint.
    activate_key(&mut st, id, candidate.height);
    st.scan_cached_blocks(candidate.height, 1);
    assert_eq!(note_txids(&st), vec![candidate.txid]);
    assert!(!has_transaction(&st, forged.txid));
    assert_eq!(unspent_keys(&st, through.height), vec![Some(id)]);
}

#[test]
fn a_mislabeled_answer_for_a_scanned_note_is_dropped() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let from = st.wallet().chain_height().unwrap().unwrap() + 1;
    let key = st
        .wallet_mut()
        .db_mut()
        .reserve_swap_receiving_key_from(account, Purpose::Refund, from)
        .unwrap()
        .key_id();
    let candidate = pay_candidate(&mut st, key);
    assert_eq!(note_txids(&st), vec![candidate.txid]);
    let through = tip(&st);
    let forged = PendingPayment {
        txid: TxId::from_bytes([7; 32]),
        ..candidate
    };
    let db = st.wallet_mut().db_mut();
    db.queue_swap_payment(account, key, &forged).unwrap();
    assert_eq!(
        db.apply_pending_swap_payment(
            account,
            key,
            &forged,
            through,
            (through, &first_leaf_path())
        )
        .unwrap(),
        PaymentApplication::Applied
    );
    assert!(db.pending_swap_payments(account, key).unwrap().is_empty());
    assert_eq!(note_txids(&st), vec![candidate.txid]);
    assert!(!has_transaction(&st, forged.txid));
}

/// A corrected directory answer replaces a candidate that an unfinished lookup queued,
/// instead of conflicting with it on every attempt.
#[test]
fn a_corrected_answer_replaces_a_partially_queued_candidate() {
    let (mut st, key, candidate, through, _) = fixture();
    let account = st.test_account().unwrap().id();
    let key = key.key_id();
    st.wallet()
        .conn()
        .execute("DELETE FROM ironwood_swap_payment_recovery", [])
        .unwrap();
    let note = candidate.encrypted_note.to_bytes();
    let right = DirectoryPayment {
        height: u32::from(candidate.height),
        block_hash: candidate.block_hash.0,
        txid: *candidate.txid.as_ref(),
        tx_index: candidate.tx_index.into(),
        action_index: candidate.action_index,
        position: candidate.position.into(),
        action_nullifier: note[..32].try_into().unwrap(),
        cmx: note[32..64].try_into().unwrap(),
        ephemeral_key: note[64..96].try_into().unwrap(),
        ciphertext_prefix: note[96..148].try_into().unwrap(),
    };
    let data = BTreeMap::from([(right.position, note[148..].try_into().unwrap())]);
    // The first answer misstates the transaction index, and another payment whose note
    // data never arrived leaves the lookup unfinished.
    let wrong = DirectoryPayment {
        tx_index: right.tx_index + 1,
        ..right.clone()
    };
    let other = DirectoryPayment {
        txid: [7; 32],
        position: right.position + 1,
        ..right.clone()
    };
    let db = st.wallet_mut().db_mut();
    assert!(
        !db.queue_swap_directory_lookup(account, key, through, &[wrong, other], &data)
            .unwrap()
    );
    assert_eq!(db.pending_swap_payments(account, key).unwrap().len(), 1);
    assert_eq!(
        db.swap_note_data_needed(account, key, std::slice::from_ref(&right))
            .unwrap(),
        [right.position]
    );
    assert!(
        db.queue_swap_directory_lookup(account, key, through, std::slice::from_ref(&right), &data)
            .unwrap()
    );
    let queued = db.pending_swap_payments(account, key).unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].tx_index, candidate.tx_index);
}

/// A payment from before the account's birthday is not tracked, as no note before it
/// is, but its index is marked used and its sweep finishes, so a restore with a late
/// birthday does not hold up incoming issuance.
#[test]
fn a_payment_before_the_birthday_marks_its_index_used_and_finishes_the_sweep() {
    let (mut st, key, candidate, through, path) = fixture();
    let account = st.test_account().unwrap().id();
    let id = key.key_id();
    st.wallet()
        .conn()
        .execute(
            "UPDATE accounts SET birthday_height = ?1",
            [u32::from(candidate.height) + 1],
        )
        .unwrap();
    let siblings = path.auth_path().map(|hash| hash.to_bytes());
    let db = st.wallet_mut().db_mut();
    // Its inclusion is still checked: a path off the wallet's chain is rejected and
    // marks nothing.
    db.queue_swap_lookup(account, id, through, std::slice::from_ref(&candidate))
        .unwrap();
    let mut wrong = siblings;
    wrong[0] = MerkleHashOrchard::empty_root(1.into()).to_bytes();
    assert_eq!(
        db.apply_swap_sweep(account, id, through, through, WATCHED, |_, _| Some(wrong))
            .unwrap(),
        PaymentApplication::Rejected
    );
    db.queue_swap_lookup(account, id, through, std::slice::from_ref(&candidate))
        .unwrap();
    assert_eq!(
        db.apply_swap_sweep(account, id, through, through, WATCHED, |_, _| Some(
            siblings
        ))
        .unwrap(),
        PaymentApplication::Applied
    );
    assert!(!db.swap_history_pending(account, through.height).unwrap());
    assert!(db.pending_swap_payments(account, id).unwrap().is_empty());
    assert!(unspent_keys(&st, through.height).is_empty());
    let (used, advances, paid): (bool, bool, bool) = st
        .wallet()
        .conn()
        .query_row(
            "SELECT used, advances_allocation, paid_before_birthday FROM ironwood_receiving_keys
             WHERE purpose = 1 AND key_index = ?1",
            [id.index().to_be_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    // The verified payment also raises the recovery bound past its index.
    assert!(used && advances && paid);
}
