use super::*;
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::memo::MemoBytes;

use PaymentApplication::{Applied, AwaitingSpendHistory, AwaitingWitness, Rejected};

/// Retains spend history, pays receive key 8 at the tip before registering it, so
/// scanning misses the note, then watches the key from the next block and queues the
/// payment, the order of a restore: retain, scan, then register recovered keys. Also
/// returns the tip and the payment's path there.
pub(in crate::wallet::one_time_ivk) fn fixture()
-> (State, OneTimeKey, PendingPayment, ChainPoint, MerklePath) {
    fixture_in(ironwood_wallet())
}

/// [`fixture`] in `st`, an [`ironwood_wallet`] with no blocks.
pub(in crate::wallet::one_time_ivk) fn fixture_in(
    mut st: State,
) -> (State, OneTimeKey, PendingPayment, ChainPoint, MerklePath) {
    let account = st.test_account().unwrap().id();
    retain(st.wallet_mut().db_mut(), account);
    let candidate = pay_candidate(&mut st, key8());
    let through = tip(&st);
    assert!(unspent_keys(&st, through.height).is_empty());
    let db = st.wallet_mut().db_mut();
    let key = watch(db, account, 8, through.height + 1);
    queue_payment(db, account, key8(), &candidate).unwrap();
    (st, key, candidate, through, first_leaf_path())
}

/// Receive key 8, which the fixtures pay before registering it.
fn key8() -> KeyId {
    KeyId::new(Purpose::Receive, 8)
}

/// The path of the chain's Ironwood leaf at `position` at the cached tip.
fn witness_at(st: &State, position: u32) -> MerklePath {
    use incrementalmerkletree::{frontier::CommitmentTree, witness::IncrementalWitness};
    let mut tree = CommitmentTree::<MerkleHashOrchard, 32>::empty();
    let mut witness: Option<IncrementalWitness<_, 32>> = None;
    let blocks: Vec<Vec<u8>> = column(
        &st.cache().0,
        "SELECT data FROM compactblocks ORDER BY height",
        [],
    );
    let actions = blocks
        .iter()
        .flat_map(|data| CompactBlock::decode(data.as_slice()).unwrap().vtx)
        .flat_map(|tx| tx.ironwood_actions);
    for (leaf, action) in actions.enumerate() {
        let cmx = MerkleHashOrchard::from_cmx(&action.cmx().unwrap());
        match &mut witness {
            Some(witness) => witness.append(cmx).unwrap(),
            None => {
                tree.append(cmx).unwrap();
                if leaf == position as usize {
                    witness = IncrementalWitness::from_tree(tree.clone());
                }
            }
        }
    }
    witness.unwrap().path().unwrap().into()
}

/// Mines `paid`, which pays [`key8`], in a new [`ironwood_wallet`] retaining spend history,
/// before the key is registered. Returns the payment as a candidate, the tip and the
/// payment's path.
fn mine_unscanned(paid: &Transaction) -> (State, PendingPayment, ChainPoint, MerklePath) {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    retain(st.wallet_mut().db_mut(), account);
    let (height, _) = st.generate_next_block_from_tx(1, paid);
    st.scan_cached_blocks_with_one_time_ivks(height, 1);
    let candidate = candidate_at(&st, height, &derive(&st, key8()));
    let (through, path) = (tip(&st), witness_at(&st, candidate.position));
    (st, candidate, through, path)
}

/// Watches [`key8`] from after `candidate`'s block, then queues and applies `candidate`.
fn watch_and_apply(
    st: &mut State,
    candidate: &PendingPayment,
    through: ChainPoint,
    path: &MerklePath,
) -> PaymentApplication {
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    watch(db, account, 8, candidate.height + 1);
    queue_payment(db, account, key8(), candidate).unwrap();
    apply(db, account, key8(), candidate, through, path)
}

/// [`key8`]'s receiver, for payments built before the wallet that holds it.
fn key8_receiver() -> orchard::Address {
    derive(&ironwood_wallet(), key8()).address_at(0u32, Scope::External)
}

/// Stores `raw` as mined at `height`, index 1, as enhancement does.
fn store_mined(db: &mut Db, raw: &Transaction, height: BlockHeight) {
    let meta = zcash_client_backend::wallet::WalletTx::new(
        raw.txid(),
        1u16.into(),
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
    );
    tx(db, |c, _| {
        crate::wallet::put_tx_meta(c, &meta, height)?;
        crate::wallet::put_tx_data(c, raw, None, None, None, height)
    })
    .unwrap();
}

/// Mines and scans a spend of `key`'s 100,000-zatoshi note `candidate`, sending 20,000
/// to `to`. Returns the note's nullifier and the spend's height.
fn spend(
    st: &mut State,
    key: &OneTimeKey,
    candidate: &PendingPayment,
    to: orchard::Address,
) -> (orchard::note::Nullifier, BlockHeight) {
    let recovered = candidate.encrypted_note.decrypt(&parent(st), key.key_id());
    let nf = *recovered.unwrap().nullifier();
    let (height, _) = st.generate_next_block_spending(
        &IronwoodFvk(key.full_viewing_key().clone()),
        (nf, Zatoshis::const_from_u64(100_000)),
        unified(to),
        Zatoshis::const_from_u64(20_000),
    );
    st.scan_cached_blocks_with_one_time_ivks(height, 1);
    (nf, height)
}

/// Drops the queued candidates, so a test starts from the directory's report alone.
fn forget_queued(st: &State) {
    let sql = "DELETE FROM ironwood_one_time_payment_recovery";
    exec(st.wallet().conn(), sql, []);
}

/// The transaction IDs of the wallet's Ironwood notes.
fn note_txids(st: &State) -> Vec<TxId> {
    let sql = "SELECT t.txid FROM ironwood_received_notes n
               JOIN transactions t ON t.id_tx = n.transaction_id ORDER BY n.id";
    let txids = column(st.wallet().conn(), sql, []).into_iter();
    txids.map(TxId::from_bytes).collect()
}

/// Whether the wallet stores a transaction with `txid`.
fn has_transaction(st: &State, txid: TxId) -> bool {
    let sql = "SELECT EXISTS(SELECT 1 FROM transactions WHERE txid = ?1)";
    value(st.wallet().conn(), sql, [txid.as_ref()])
}

/// A path that misses the wallet's root rejects the directory's answer and discards the
/// queued lookup so the next attempt asks again. A valid path credits the unscanned key's
/// note atomically, durably and without the directory's memo; a duplicate answer does not
/// double credit it, and the tree keeps evolving after the imported witness.
#[test]
fn directory_payment_applies_unscanned_key_note_atomically_and_reopens() {
    let (mut st, key, candidate, through, path) = fixture();
    let account = st.test_account().unwrap().id();
    let id = key.key_id();
    let mut bad_path = path.auth_path();
    bad_path[0] = MerkleHashOrchard::empty_root(1.into());
    let bad_path = MerklePath::from_parts(0, bad_path);
    let db = st.wallet_mut().db_mut();
    assert_eq!(
        apply(db, account, id, &candidate, through, &bad_path),
        Rejected
    );
    assert!(pending(db, account, id).is_empty());
    assert!(notes(&st, through.height).is_empty());
    // The second answer is a duplicate.
    for _ in 0..2 {
        let db = st.wallet_mut().db_mut();
        queue_payment(db, account, id, &candidate).unwrap();
        assert_eq!(apply(db, account, id, &candidate, through, &path), Applied);
        reopen(&mut st);
        let found = notes(&st, through.height);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].note().value().inner(), 100_000);
        assert_eq!(found[0].one_time_key_id(), Some(id));
        assert!(pending(st.wallet().db(), account, id).is_empty());
    }
    // Nothing binds the directory's memo to the chain, so it is not stored.
    let sql = "SELECT memo FROM ironwood_received_notes";
    assert_eq!(value::<Option<Vec<u8>>>(st.wallet().conn(), sql, []), None);
    // Appending after importing a witness must preserve the evolving tree.
    let later = pay(&mut st, key.full_viewing_key(), 40_000);
    let tx = st.wallet_mut().conn_mut().transaction().unwrap();
    let tree = crate::ironwood_tree(&tx).unwrap();
    let witness = tree.witness_at_checkpoint_id(0u64.into(), &later).unwrap();
    assert!(witness.is_some());
}

/// A restore sweep credits a one-time-key note without a memo, and private memo retrieval
/// skips it (see `wallet::one_time_ivk`); only its full transaction stores one.
#[test]
fn a_restored_one_time_note_stores_no_memo() {
    use zcash_client_backend::data_api::wallet::decrypt_and_store_transaction_with_one_time_ivks;
    let memo = MemoBytes::from_bytes(b"the payment's memo").unwrap();
    let paid = external_payment(key8_receiver(), &memo);
    let (mut st, candidate, through, path) = mine_unscanned(&paid);
    let applied = watch_and_apply(&mut st, &candidate, through, &path);
    assert_eq!(applied, Applied);
    let sql = "SELECT n.memo, n.value, EXISTS(SELECT 1 FROM ironwood_memo_retrieval_queue)
               FROM ironwood_received_notes n";
    let stored = |st: &State| row::<(Option<Vec<u8>>, u64, bool)>(st.wallet().conn(), sql, []);
    assert_eq!(stored(&st), (None, 50_000, false));
    assert_eq!(unspent_keys(&st, through.height), vec![Some(key8())]);
    // Private memo retrieval skips the note even where it would recover other memos.
    let sql = "UPDATE ironwood_enhance_routing SET route = 2";
    exec(st.wallet().conn(), sql, []);
    crate::wallet::enhance_pir::queue_unsupported_memos(st.wallet().conn(), None).unwrap();
    assert_eq!(stored(&st), (None, 50_000, false));
    let network = *st.network();
    let height = Some(candidate.height);
    decrypt_and_store_transaction_with_one_time_ivks(&network, st.wallet_mut(), &paid, height)
        .unwrap();
    assert_eq!(stored(&st), (Some(memo.as_slice().to_vec()), 50_000, false));
}

/// The inclusion path does not authenticate a claimed transaction ID or action index, so
/// a stored raw transaction must hold the claimed action; a contradicted claim is rejected
/// and the stored transaction keeps its location. The path also does not show whether the
/// transaction has transparent parts, so a claim applied without the raw transaction
/// leaves it to enhancement, while one checked against it marks it privately complete.
#[test]
fn a_claim_is_checked_against_a_stored_raw_transaction() {
    use zcash_primitives::transaction::{Authorized, TransactionData};
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Raw {
        Absent,
        Matching,
        OtherAction,
        OutOfRange,
        NoIronwood,
    }
    // The payment also has a transparent output.
    let also = vec![payment(&p2pkh(7), 20_000, None)];
    let paid = external_payment_with(key8_receiver(), &MemoBytes::empty(), also);
    assert!(paid.transparent_bundle().is_some());
    let actions = paid.ironwood_bundle().unwrap().actions().len() as u32;
    let txid = paid.txid();
    let (branch, expiry) = (paid.consensus_branch_id(), paid.expiry_height());
    let empty =
        TransactionData::<Authorized>::from_parts_v6(branch, 0, expiry, None, None, None, None);
    let empty = empty.freeze().unwrap();
    for raw in [
        Raw::Absent,
        Raw::Matching,
        Raw::OtherAction,
        Raw::OutOfRange,
        Raw::NoIronwood,
    ] {
        let (mut st, genuine, through, path) = mine_unscanned(&paid);
        let account = st.test_account().unwrap().id();
        let mut candidate = genuine.clone();
        let stored = match raw {
            Raw::Absent => None,
            Raw::Matching => Some(&paid),
            Raw::OtherAction => {
                candidate.action_index = (genuine.action_index + 1) % actions;
                Some(&paid)
            }
            Raw::OutOfRange => {
                candidate.action_index = actions;
                Some(&paid)
            }
            Raw::NoIronwood => {
                candidate.txid = empty.txid();
                Some(&empty)
            }
        };
        if let Some(stored) = stored {
            store_mined(st.wallet_mut().db_mut(), stored, genuine.height);
        }
        let applied = watch_and_apply(&mut st, &candidate, through, &path);
        let conn = st.wallet().conn();
        if matches!(raw, Raw::Absent | Raw::Matching) {
            assert_eq!(applied, Applied, "{raw:?}");
            assert_eq!(note_txids(&st), [txid], "{raw:?}");
            let sql = "SELECT EXISTS(SELECT 1 FROM tx_retrieval_queue
                       WHERE txid = ?1 AND query_type = ?2)";
            let enhancement = crate::wallet::TxQueryType::Enhancement.code();
            let params = rusqlite::params![txid.as_ref(), enhancement];
            let requested: bool = value(conn, sql, params);
            let protected = crate::wallet::enhance_pir::is_protected(conn, txid).unwrap();
            let absent = raw == Raw::Absent;
            assert_eq!((requested, protected), (absent, !absent), "{raw:?}");
        } else {
            assert_eq!(applied, Rejected, "{raw:?}");
            assert!(note_txids(&st).is_empty(), "{raw:?}");
            let queued = pending(st.wallet().db(), account, key8());
            assert!(queued.is_empty(), "{raw:?}");
            let sql = "SELECT mined_height, tx_index FROM transactions WHERE txid = ?1";
            let location: (u32, u32) = row(conn, sql, [candidate.txid.as_ref()]);
            assert_eq!(location, (u32::from(genuine.height), 1), "{raw:?}");
        }
    }
}

/// A directory payment for an already spent note imports it as spent without crediting
/// it. With a gap in retained spend history it waits for that history, across a reopen,
/// instead of importing the note as unspent.
#[test]
fn directory_payment_imports_an_already_spent_note_without_crediting_it() {
    for pruned in [false, true] {
        let (mut st, key, candidate, _, _) = fixture();
        let account = st.test_account().unwrap().id();
        let id = key.key_id();
        let (nf, height) = spend(&mut st, &key, &candidate, key.receiver());
        let (through, proof) = (tip(&st), witness_at(&st, 0));
        if pruned {
            retain(st.wallet_mut().db_mut(), account);
            let sql = "DELETE FROM nullifier_map; DELETE FROM ironwood_nullifier_scan_blocks;";
            st.wallet().conn().execute_batch(sql).unwrap();
            let db = st.wallet_mut().db_mut();
            let applied = apply(db, account, id, &candidate, through, &proof);
            assert_eq!(applied, AwaitingSpendHistory);
            reopen(&mut st);
            st.scan_cached_blocks_with_one_time_ivks(candidate.height, 2);
        }
        let db = st.wallet_mut().db_mut();
        let applied = apply(db, account, id, &candidate, through, &proof);
        assert_eq!(applied, Applied, "pruned={pruned}");
        let sql = "SELECT COUNT(*) FROM ironwood_received_notes n
                   JOIN ironwood_received_note_spends s ON s.ironwood_received_note_id = n.id
                   WHERE n.nf = ?1";
        let spends: u64 = value(st.wallet().conn(), sql, [nf.to_bytes()]);
        assert_eq!(spends, 1, "pruned={pruned}");
        let (fvk, unspent) = (key.full_viewing_key(), notes(&st, height));
        assert!(unspent.iter().all(|n| n.note().nullifier(fvk) != nf));
    }
}

/// A spending transaction stored unmined, with no output compact scanning finds, gets
/// its canonical height and index from the nullifier map when the note is imported, so
/// the spend does not expire with the unmined row.
#[test]
fn directory_payment_reconciles_an_unmined_spending_transaction() {
    use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
    let (mut st, key, candidate, _, _) = fixture();
    let account = st.test_account().unwrap().id();
    let (_, height) = spend(&mut st, &key, &candidate, foreign_receiver());
    let (through, proof) = (tip(&st), witness_at(&st, 0));
    let sql = "SELECT data FROM compactblocks WHERE height = ?1";
    let data: Vec<u8> = value(&st.cache().0, sql, [u32::from(height)]);
    let spend = &CompactBlock::decode(data.as_slice()).unwrap().vtx[0];
    let spend_txid = spend.txid();
    assert!(!has_transaction(&st, spend_txid));
    // Observed unmined, expiring at the next block.
    let sql = "INSERT INTO transactions
                   (txid, min_observed_height, expiry_height, confirmed_unmined_at_height)
               VALUES (?1, ?2, ?3, ?2) RETURNING id_tx";
    let observed = (u32::from(candidate.height), u32::from(height + 1));
    let params = rusqlite::params![spend_txid.as_ref(), observed.0, observed.1];
    let id: i64 = value(st.wallet().conn(), sql, params);
    let db = st.wallet_mut().db_mut();
    let applied = apply(db, account, key.key_id(), &candidate, through, &proof);
    assert_eq!(applied, Applied);
    let sql = "SELECT id_tx, mined_height, tx_index, confirmed_unmined_at_height
               FROM transactions WHERE txid = ?1";
    let stored: (i64, Option<u32>, Option<u32>, Option<u32>) =
        row(st.wallet().conn(), sql, [spend_txid.as_ref()]);
    let index = u32::try_from(spend.index).unwrap();
    assert_eq!(stored, (id, Some(u32::from(height)), Some(index), None));
    st.generate_and_scan_empty_blocks_with_one_time_ivks(3);
    let summary = st.get_wallet_summary(ConfirmationsPolicy::MIN).unwrap();
    let balance = summary.account_balances().get(&account).unwrap();
    assert_eq!(balance.ironwood_balance().total(), Zatoshis::ZERO);
}

/// Scanning removes a known note's spend from the nullifier map (the scanner's real
/// split, not a hand-built fixture), so a scanned note's spentness and an answer for it
/// use the spend scanning linked. Deleting the account drops its nullifier coverage.
#[test]
fn directory_payment_keeps_a_scanned_spend_without_a_map_entry() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let birthday = st.sapling_activation_height();
    let key = reserve_key(st.wallet_mut().db_mut(), account, Purpose::Refund, birthday);
    let id = key.key_id();
    let candidate = pay_candidate(&mut st, id);
    let (nf, height) = spend(&mut st, &key, &candidate, foreign_receiver());
    let sql = "SELECT COUNT(*) FROM nullifier_map WHERE nf = ?1";
    assert_eq!(value::<u64>(st.wallet().conn(), sql, [nf.to_bytes()]), 0);
    let (through, proof) = (tip(&st), witness_at(&st, 0));
    let db = st.wallet_mut().db_mut();
    let status = spend_status(db, account, id, &candidate, through);
    assert!(matches!(status, Ok(SpendStatus::Spent(_))));
    queue_payment(db, account, id, &candidate).unwrap();
    assert_eq!(apply(db, account, id, &candidate, through, &proof), Applied);
    let sql = "SELECT t.mined_height FROM ironwood_received_note_spends s
               JOIN ironwood_received_notes n ON n.id = s.ironwood_received_note_id
               JOIN transactions t ON t.id_tx = s.transaction_id WHERE n.nf = ?1";
    let spent_at: Vec<u32> = column(st.wallet().conn(), sql, [nf.to_bytes()]);
    assert_eq!(spent_at, [u32::from(height)]);
    st.wallet_mut().delete_account(account).unwrap();
    let sql = "SELECT COUNT(*) FROM ironwood_nullifier_scan_blocks";
    assert_eq!(value::<u64>(st.wallet().conn(), sql, []), 0);
}

/// A privately imported note is spendable, and spending it makes ordinary internal
/// change rather than one-time-key change.
#[test]
fn privately_imported_note_spends_into_ordinary_internal_change() {
    let (mut st, key, candidate, through, path) = fixture();
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    let applied = apply(db, account, key.key_id(), &candidate, through, &path);
    assert_eq!(applied, Applied);
    st.generate_and_scan_empty_blocks_with_one_time_ivks(5);
    let (proposal, height) = spend_to_foreign(&mut st, 50_000);
    let ironwood = zcash_protocol::PoolType::IRONWOOD;
    assert_eq!(proposal.input_count_in_pool(ironwood), 1);
    let found = notes(&st, height);
    assert_eq!(found.len(), 1);
    assert!(found[0].one_time_key_id().is_none());
    let internal = parent(&st).address_at(0u32, Scope::Internal);
    assert_eq!(found[0].note().recipient(), internal);
}

/// A payment applies with a path at its older witness anchor after the tree has grown,
/// and the imported note survives a rewind to that anchor.
#[test]
fn private_payment_uses_its_witness_anchor_and_survives_a_rewind() {
    let (mut st, key, candidate, anchor, path) = fixture();
    let account = st.test_account().unwrap().id();
    pay(&mut st, key.full_viewing_key(), 10_000);
    let through = tip(&st);
    let db = st.wallet_mut().db_mut();
    let proof = (anchor, &path);
    let applied = apply_payment(db, account, key.key_id(), &candidate, through, proof);
    assert_eq!(applied.unwrap(), Applied);
    st.truncate_to_height_retaining_cache(anchor.height);
    let found = notes(&st, anchor.height);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].note().value().inner(), 100_000);
}

/// A sweep checks its publication anchor, queues the directory's lookup (leaving the
/// attempt's backoff lease alone, and skipping a repeat), waits for a valid witness and
/// applies the payment once, finishing the key's history. A repeated answer then skips
/// the imported payment, and one contradicting it is an error.
#[test]
fn sweep_steps_queue_a_directory_lookup_and_apply_it_once() {
    let (mut st, key, candidate, through, path) = fixture();
    let account = st.test_account().unwrap().id();
    let key = key.key_id();
    forget_queued(&st);
    let payment = directory_answer(&candidate);
    let one = std::slice::from_ref(&payment);
    let db = st.wallet_mut().db_mut();

    let deferred = |result: Result<_, SqliteClientError>| match result {
        Ok(Err(reason)) => reason,
        other => panic!("expected a deferral, got {:?}", other.map(|_| ())),
    };
    let anchor = db.directory_publication_anchor(through.height + 1, through);
    assert_eq!(deferred(anchor), SweepDeferral::UnknownAnchor);
    let far = ChainPoint {
        height: through.height + MAX_PUBLICATION_LAG + 1,
        ..through
    };
    let anchor = db.directory_publication_anchor(through.height, far);
    assert_eq!(deferred(anchor), SweepDeferral::StalePublication);
    let anchor = db.directory_publication_anchor(through.height, through);
    let anchor = anchor.unwrap().unwrap();
    assert_eq!(anchor, through);

    db.begin_one_time_sweep_attempt(account, key, 1_700_000_000, false)
        .unwrap();
    let sql = "SELECT attempts, next_attempt_at FROM ironwood_one_time_sweeps";
    assert_eq!(row::<(u32, i64)>(&db.conn, sql, []).0, 1);
    for _ in 0..2 {
        let queued = db.queue_directory_lookup(account, key, anchor, one);
        assert_eq!(queued.unwrap(), Ok(()));
        assert!(pending(db, account, key) == [candidate.clone()]);
    }
    // Queuing leaves the attempt's lease alone, so an answer that keeps being rejected
    // backs off like any other failure.
    let lease = row::<(u32, i64)>(&db.conn, sql, []);
    assert_eq!(lease, (1, 1_700_000_000 + 60));

    let applied = db.apply_one_time_sweep(account, key, through, anchor, WATCHED, |_, _| None);
    assert_eq!(applied.unwrap(), Ok(AwaitingWitness));
    let siblings = path.auth_path().map(|hash| hash.to_bytes());
    // A sibling that is not a field element gives no path.
    let mut invalid = siblings;
    invalid[3] = [0xff; 32];
    let witness = |_, _| Some(invalid);
    let applied = db.apply_one_time_sweep(account, key, through, anchor, WATCHED, witness);
    assert_eq!(applied.unwrap(), Ok(AwaitingWitness));
    let (position, cmx) = (candidate.position, candidate.encrypted_note.commitment());
    let witness = |at, at_cmx| (at == position && at_cmx == cmx).then_some(siblings);
    let applied = db.apply_one_time_sweep(account, key, through, anchor, WATCHED, witness);
    assert_eq!(applied.unwrap(), Ok(Applied));
    let found = notes(&st, through.height);
    assert!(found.iter().any(|n| n.one_time_key_id() == Some(key)));
    let db = st.wallet_mut().db_mut();
    let history_pending = db.one_time_history_pending(account, through.height + 1);
    assert!(!history_pending.unwrap());
    let queued = db.queue_directory_lookup(account, key, anchor, one);
    assert_eq!(queued.unwrap(), Ok(()));
    assert!(pending(db, account, key).is_empty());
    let moved = DirectoryPayment {
        position: 1,
        ..payment
    };
    assert!(
        db.queue_directory_lookup(account, key, anchor, &[moved])
            .is_err()
    );
}

/// An answer that mislabels a payment's transaction is applied as claimed while scanning
/// has not found the note, and rescanning with the key moves the note to its real
/// transaction (once failing on the nullifier's unique constraint). Once scanning has
/// found the note, the answer is dropped. Either way the forged transaction is not kept.
#[test]
fn a_mislabeled_answer_yields_to_the_scanned_transaction() {
    for scanned in [false, true] {
        let mut st = scanned_wallet();
        let account = st.test_account().unwrap().id();
        // A scanned note's answer is dropped before any spend history is needed.
        if !scanned {
            retain(st.wallet_mut().db_mut(), account);
        }
        let id = KeyId::new(Purpose::Refund, 0);
        let from = tip(&st).height + 1;
        if scanned {
            reserve_key(st.wallet_mut().db_mut(), account, Purpose::Refund, from);
        }
        let candidate = pay_candidate(&mut st, id);
        let found: Vec<_> = scanned.then_some(candidate.txid).into_iter().collect();
        assert_eq!(note_txids(&st), found, "scanned={scanned}");
        let through = tip(&st);
        let forged = PendingPayment {
            txid: TxId::from_bytes([7; 32]),
            ..candidate.clone()
        };
        let db = st.wallet_mut().db_mut();
        if !scanned {
            let key = reserve_key(db, account, Purpose::Refund, through.height + 1);
            assert_eq!(key.key_id(), id);
        }
        queue_payment(db, account, id, &forged).unwrap();
        let path = first_leaf_path();
        let applied = apply(db, account, id, &forged, through, &path);
        assert_eq!(applied, Applied, "scanned={scanned}");
        assert!(pending(db, account, id).is_empty(), "scanned={scanned}");
        if !scanned {
            assert_eq!(note_txids(&st), [forged.txid]);
            activate_key(st.wallet_mut().db_mut(), account, id, candidate.height);
            st.scan_cached_blocks_with_one_time_ivks(candidate.height, 1);
        }
        assert_eq!(note_txids(&st), [candidate.txid], "scanned={scanned}");
        assert!(!has_transaction(&st, forged.txid), "scanned={scanned}");
        let keys = unspent_keys(&st, through.height);
        assert_eq!(keys, [Some(id)], "scanned={scanned}");
    }
}

/// A seen hit is stored with the attempt that observed it, before any payment work, so
/// it survives that work deferring, a reopen, and a later publication's seen sets
/// missing the receiver while its corrected lookup drops the candidate.
#[test]
fn a_seen_hit_outlives_deferred_payment_work_and_a_corrected_lookup() {
    for deferral in [AwaitingWitness, AwaitingSpendHistory, Rejected] {
        let (mut st, key, _, through, path) = fixture();
        let account = st.test_account().unwrap().id();
        let key = key.key_id();
        let sql = "SELECT provider_seen, advances_allocation FROM ironwood_receiving_keys
                   WHERE purpose = 1 AND key_index = ?1";
        let seen = |st: &State| -> (bool, bool) {
            row(st.wallet().conn(), sql, [key.index().to_be_bytes()])
        };
        let mut siblings = path.auth_path().map(|hash| hash.to_bytes());
        match deferral {
            AwaitingSpendHistory => {
                retain(st.wallet_mut().db_mut(), account);
                let sql = "DELETE FROM nullifier_map; DELETE FROM ironwood_nullifier_scan_blocks;";
                st.wallet().conn().execute_batch(sql).unwrap();
            }
            Rejected => siblings[0] = MerkleHashOrchard::empty_root(1.into()).to_bytes(),
            _ => {}
        }
        // Publication A's seen set holds the receiver, and its payment work defers.
        let db = st.wallet_mut().db_mut();
        db.begin_one_time_sweep_attempt(account, key, 1_700_000_000, true)
            .unwrap();
        assert_eq!(seen(&st), (true, true));
        let witness = |_, _| (deferral != AwaitingWitness).then_some(siblings);
        let db = st.wallet_mut().db_mut();
        let applied = db.apply_one_time_sweep(account, key, through, through, WATCHED, witness);
        assert_eq!(applied.unwrap(), Ok(deferral));
        reopen(&mut st);
        // Publication B's sets miss the receiver and its lookup drops the candidate.
        let db = st.wallet_mut().db_mut();
        db.begin_one_time_sweep_attempt(account, key, 1_700_000_000, false)
            .unwrap();
        let queued = db.queue_directory_lookup(account, key, through, &[]);
        assert_eq!(queued.unwrap(), Ok(()));
        let applied = db.apply_one_time_sweep(account, key, through, through, WATCHED, |_, _| None);
        assert_eq!(applied.unwrap(), Ok(Applied));
        assert_eq!(seen(&st), (true, true));
        // Issuance skips it once every lower address was quoted too.
        let db = st.wallet_mut().db_mut();
        for index in 0..key.index() {
            let lower = watch(db, account, index, through.height + 1).key_id();
            db.begin_one_time_sweep_attempt(account, lower, 1_700_000_000, true)
                .unwrap();
            finish_sweep(db, account, lower, through);
        }
        let issued = prepare_from(db, account, 1_700_000_000, through.height + 1, None);
        assert_eq!(issued.unwrap().unwrap().key_id().index(), key.index() + 1);
    }
}

/// A corrected directory answer replaces a candidate an earlier lookup queued, instead
/// of conflicting with it on every attempt, and an answer at an anchor off the wallet's
/// chain defers without touching the queue.
#[test]
fn a_corrected_answer_replaces_a_queued_candidate() {
    let (mut st, key, candidate, through, _) = fixture();
    let account = st.test_account().unwrap().id();
    let key = key.key_id();
    forget_queued(&st);
    let right = directory_answer(&candidate);
    // The first answer misstates the transaction index.
    let wrong = DirectoryPayment {
        tx_index: right.tx_index + 1,
        ..right.clone()
    };
    let db = st.wallet_mut().db_mut();
    let queued = db.queue_directory_lookup(account, key, through, &[wrong]);
    assert_eq!(queued.unwrap(), Ok(()));
    let queued = pending(db, account, key);
    assert_eq!(queued.len(), 1);
    let sql = "SELECT lookup_height, lookup_hash, done_height FROM ironwood_one_time_sweeps
               WHERE receiving_key_id = ?1";
    let sweep = |db: &Db| -> (Option<u32>, Option<Vec<u8>>, Option<u32>) {
        row(&db.conn, sql, [key_ref(&db.conn, account, key).unwrap()])
    };
    let before = sweep(db);
    let right = std::slice::from_ref(&right);
    let reorged = ChainPoint {
        hash: BlockHash([99; 32]),
        ..through
    };
    let deferred = db.queue_directory_lookup(account, key, reorged, right);
    assert_eq!(deferred.unwrap(), Err(SweepDeferral::UnknownAnchor));
    assert!(pending(db, account, key) == queued);
    assert_eq!(sweep(db), before);
    let queued = db.queue_directory_lookup(account, key, through, right);
    assert_eq!(queued.unwrap(), Ok(()));
    let queued = pending(db, account, key);
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].tx_index, candidate.tx_index);
}

/// A payment from before the account's birthday is not tracked, as no note before it
/// is, but its index is marked used (raising the recovery bound) and its sweep finishes,
/// so a restore with a late birthday does not hold up incoming issuance. Its inclusion
/// is still checked, and a later payment claimed before the birthday is rejected, so a
/// directory cannot have a payment marked paid and dropped; a rejection marks nothing.
#[test]
fn a_payment_before_the_birthday_marks_its_index_used_and_finishes_the_sweep() {
    let (mut st, key, candidate, _, path) = fixture();
    let account = st.test_account().unwrap().id();
    let id = key.key_id();
    // The payment must precede the birthday block, which the wallet has scanned.
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    let through = tip(&st);
    let sql = "SELECT used, advances_allocation, paid_before_birthday
               FROM ironwood_receiving_keys WHERE purpose = 1 AND key_index = ?1";
    let flags = |st: &State| -> (bool, bool, bool) {
        row(st.wallet().conn(), sql, [id.index().to_be_bytes()])
    };
    let unmarked = flags(&st);
    assert!(!unmarked.2);
    let sweep = |st: &mut State, claim: &PendingPayment, siblings: [[u8; 32]; 32]| {
        let db = st.wallet_mut().db_mut();
        queue_lookup(db, account, id, through, std::slice::from_ref(claim)).unwrap();
        let witness = |_, _| Some(siblings);
        let applied = db.apply_one_time_sweep(account, id, through, through, WATCHED, witness);
        applied.unwrap().unwrap()
    };
    let siblings = path.auth_path().map(|hash| hash.to_bytes());
    let birthday = "UPDATE accounts SET birthday_height = ?1";

    // A payment at the birthday, claimed at the block before it.
    exec(st.wallet().conn(), birthday, [u32::from(candidate.height)]);
    forget_queued(&st);
    let height = candidate.height - 1;
    let block_hash = crate::wallet::get_block_hash(st.wallet().conn(), height).unwrap();
    let forged = PendingPayment {
        height,
        block_hash: block_hash.unwrap_or(candidate.block_hash),
        ..candidate.clone()
    };
    assert_eq!(sweep(&mut st, &forged, siblings), Rejected);
    assert_eq!(flags(&st), unmarked);

    // A payment before the birthday, with a path off the wallet's chain and then a valid one.
    let after = u32::from(candidate.height) + 1;
    exec(st.wallet().conn(), birthday, [after]);
    let mut wrong = siblings;
    wrong[0] = MerkleHashOrchard::empty_root(1.into()).to_bytes();
    assert_eq!(sweep(&mut st, &candidate, wrong), Rejected);
    assert_eq!(flags(&st), unmarked);
    assert_eq!(sweep(&mut st, &candidate, siblings), Applied);
    let db = st.wallet_mut().db_mut();
    let history_pending = db.one_time_history_pending(account, through.height);
    assert!(!history_pending.unwrap());
    assert!(pending(db, account, id).is_empty());
    assert!(unspent_keys(&st, through.height).is_empty());
    assert_eq!(flags(&st), (true, true, true));
}

/// A rewind that leaves a restored receipt short of the confirmations closing needs
/// reopens only a key that was scanning: one whose sweep closed it without scanning has
/// nothing to rescan, and reopening it would leave it open but never scanned.
#[test]
fn a_rewind_does_not_reopen_a_key_that_never_scanned() {
    let (mut st, key, candidate, through, path) = fixture();
    let account = st.test_account().unwrap().id();
    let key = key.key_id();
    let siblings = path.auth_path().map(|hash| hash.to_bytes());
    let db = st.wallet_mut().db_mut();
    queue_lookup(db, account, key, through, std::slice::from_ref(&candidate)).unwrap();
    let applied =
        db.apply_one_time_sweep(account, key, through, through, false, |_, _| Some(siblings));
    assert_eq!(applied.unwrap(), Ok(Applied));
    let sql = "SELECT active_from IS NULL, closed_at IS NOT NULL FROM ironwood_receiving_keys
               WHERE purpose = 1 AND key_index = ?1";
    let state =
        |st: &State| -> (bool, bool) { row(st.wallet().conn(), sql, [key.index().to_be_bytes()]) };
    assert_eq!(state(&st), (true, true));
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    st.truncate_to_height(through.height);
    assert_eq!(state(&st), (true, true));
}
