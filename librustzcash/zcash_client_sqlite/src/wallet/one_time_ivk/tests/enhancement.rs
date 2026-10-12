use super::*;
use zakura_one_time_ivk::swap::RefundMemo;
use zcash_client_backend::data_api::wallet::{
    decrypt_and_store_transaction, decrypt_and_store_transaction_with_one_time_ivks,
};
use zcash_protocol::{ShieldedPool, TxId, memo::MemoBytes};

/// Builds a wallet whose test account holds one confirmed 1,000,000 zatoshi
/// Ironwood note, returning the height of the block that paid it.
fn ironwood_funded_wallet() -> (State, BlockHeight) {
    let mut st = ironwood_wallet();
    let fvk = parent(&st);
    let first = pay(&mut st, &fvk, 1_000_000);
    st.generate_and_scan_empty_blocks_with_one_time_ivks(5);
    (st, first)
}

/// [`transfer`] from the test account, with Ironwood change carrying `memo`.
fn try_send(
    st: &mut State,
    payments: Vec<zip321::Payment>,
    memo: &MemoBytes,
) -> (Proposal, Result<TxId, SqliteClientError>) {
    let account = st.test_account().cloned().unwrap();
    let change = (Some(memo), ShieldedPool::Ironwood);
    transfer(st, (account.id(), account.usk()), payments, change)
}

/// [`try_send`], then mines and scans the transaction. Returns its proposal, txid and
/// height.
fn send(
    st: &mut State,
    payments: Vec<zip321::Payment>,
    memo: &MemoBytes,
) -> (Proposal, TxId, BlockHeight) {
    let (proposal, txid) = try_send(st, payments, memo);
    let txid = txid.unwrap();
    let (mined, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks_with_one_time_ivks(mined, 1);
    (proposal, txid, mined)
}

/// The encoded refund memo for key `index`.
fn refund_memo(index: u64) -> MemoBytes {
    MemoBytes::from_bytes(&RefundMemo::new(index).encode()).unwrap()
}

/// Runs refund memo recovery for `account` in its own transaction.
fn recover_memos(st: &mut State, account: AccountUuid) {
    tx(st.wallet_mut().db_mut(), |c, p| {
        store::restore::recovery::recover_refund_memos(c, p, account, clock_now())
    })
    .unwrap()
}

/// `(index, scan_from, queued for a sweep)` of each registered refund key.
fn refund_keys(st: &State) -> Vec<(u64, u32, bool)> {
    let keys: Vec<(Vec<u8>, u32, bool)> = rows(
        st.wallet().conn(),
        "SELECT k.key_index, k.scan_from,
            EXISTS(SELECT 1 FROM ironwood_one_time_sweeps s WHERE s.receiving_key_id = k.id)
         FROM ironwood_receiving_keys k WHERE k.purpose = 0 ORDER BY k.key_index",
        [],
    );
    let decode = |i: Vec<u8>| u64::from_be_bytes(i.try_into().unwrap());
    keys.into_iter()
        .map(|(i, from, swept)| (decode(i), from, swept))
        .collect()
}

/// Whether `txid` is stored with its raw data, and the memo of its Ironwood note.
fn stored_receipt(st: &State, txid: TxId) -> (bool, Option<Vec<u8>>) {
    let sql = "SELECT t.raw IS NOT NULL, rn.memo FROM ironwood_received_notes rn
               JOIN transactions t ON t.id_tx = rn.transaction_id WHERE t.txid = ?1";
    row(st.wallet().conn(), sql, [txid.as_ref()])
}

/// A scanned wallet holding a refund key that a transaction another wallet built pays
/// with memo `refund`, mined and scanned. Returns the key, transaction and its height.
fn externally_paid_refund_key(
    st: &mut State,
) -> (
    OneTimeKey,
    zcash_primitives::transaction::Transaction,
    BlockHeight,
) {
    let account = st.test_account().unwrap().id();
    let from = st.wallet().chain_height().unwrap().unwrap() + 1;
    let key = reserve_key(st.wallet_mut().db_mut(), account, Purpose::Refund, from);
    let tx = external_payment(key.receiver(), &MemoBytes::from_bytes(b"refund").unwrap());
    let (height, _) = st.generate_next_block_from_tx(1, &tx);
    st.scan_cached_blocks_with_one_time_ivks(height, 1);
    (key, tx, height)
}

/// Self-payments to both purposes, found as outgoing by ordinary OVK recovery, decrypt
/// with the one-time keys as one incoming record each, whether the full transaction is
/// stored before or after its compact block, and idempotently across a reopen.
#[test]
fn one_time_ivk_full_transaction_before_or_after_compact_scan() {
    for full_first in [false, true] {
        let (mut st, h) = ironwood_funded_wallet();
        let network = *st.network();
        let account = st.test_account().cloned().unwrap();
        let scan_from = st.wallet().chain_height().unwrap().unwrap() + 1;
        let keys: Vec<_> = [Purpose::Refund, Purpose::Receive]
            .into_iter()
            .map(|purpose| reserve_key(st.wallet_mut().db_mut(), account.id(), purpose, scan_from))
            .collect();
        let memo = MemoBytes::from_bytes(b"swap payment memo").unwrap();
        let payments = keys
            .iter()
            .map(|key| payment(&unified(key.receiver()), 50_000, Some(&memo)))
            .collect();
        let change = (None, ShieldedPool::Orchard);
        let (_, txid) = transfer(&mut st, (account.id(), account.usk()), payments, change);
        let txid = txid.unwrap();
        let tx = st.wallet().get_transaction(txid).unwrap().unwrap();

        let ufvks = st.wallet().get_unified_full_viewing_keys().unwrap();
        let decoded = zcash_client_backend::decrypt_transaction_with_one_time_ivks(
            &network,
            None,
            Some(h),
            &tx,
            &ufvks,
            st.wallet().get_one_time_scanning_keys().unwrap(),
        );
        for key in &keys {
            let outputs: Vec<_> = decoded
                .ironwood_outputs()
                .iter()
                .filter(|o| o.note().0.recipient() == key.receiver())
                .collect();
            assert_eq!(outputs.len(), 1);
            assert_eq!(outputs[0].one_time_key_id(), Some(key.key_id()));
            assert_eq!(
                outputs[0].transfer_type(),
                zcash_client_backend::TransferType::Incoming
            );
            assert_eq!(outputs[0].memo(), &memo);
        }
        // Without the one-time keys these payments would be stored as outgoing only.
        assert!(matches!(
            decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, None),
            Err(SqliteClientError::OneTimeIvksNotUsed)
        ));
        if full_first {
            decrypt_and_store_transaction_with_one_time_ivks(&network, st.wallet_mut(), &tx, None)
                .unwrap();
        }
        let (mined, _) = st.generate_next_block_including(txid);
        st.scan_cached_blocks_with_one_time_ivks(mined, 1);
        // Reopen before fetching the full transaction, as on a resumed sync.
        reopen(&mut st);
        for _ in 0..2 {
            decrypt_and_store_transaction_with_one_time_ivks(
                &network,
                st.wallet_mut(),
                &tx,
                Some(mined),
            )
            .unwrap();
        }
        st.scan_cached_blocks_with_one_time_ivks(mined, 1);
        let stored = notes(&st, mined);
        for key in keys {
            let note = stored
                .iter()
                .find(|n| n.one_time_key_id() == Some(key.key_id()));
            let note = note.unwrap();
            assert_eq!(note.note().recipient(), key.receiver());
            let memo_stored: Vec<u8> = value(
                st.wallet().conn(),
                "SELECT rn.memo FROM ironwood_received_notes rn
                 JOIN transactions t ON t.id_tx = rn.transaction_id
                 WHERE t.txid = ?1 AND rn.action_index = ?2",
                rusqlite::params![txid.as_ref(), note.output_index()],
            );
            assert_eq!(memo_stored, memo.as_slice());
        }
        assert_eq!(stored.len(), 3); // Both swap payments and ordinary internal change.
    }
}

/// A closed key still decrypts the transactions its stored notes came from, so fetching
/// an externally funded payment after closure stores it instead of discarding the
/// retrieval as irrelevant. This guards the store's `get_one_time_transaction_keys`.
#[test]
fn closed_key_decrypts_its_externally_funded_transaction_after_reopen() {
    use zakura_one_time_ivk::swap::COMPLETION_LIMIT_SECS;
    let mut st = scanned_wallet();
    let network = *st.network();
    let account = st.test_account().unwrap().id();
    let (key, tx, height) = externally_paid_refund_key(&mut st);
    st.generate_and_scan_empty_blocks_with_one_time_ivks(9);
    let sql = "SELECT COUNT(*) FROM tx_retrieval_queue WHERE txid = ?1";
    assert_eq!(
        value::<u64>(st.wallet().conn(), sql, [tx.txid().as_ref()]),
        1
    );
    let tip = st.wallet().chain_height().unwrap().unwrap();
    let now = clock_now() + COMPLETION_LIMIT_SECS;
    assert_eq!(close_at(st.wallet_mut().db_mut(), account, now, tip), 1);
    assert!(!scanning_keys(&st).contains(&key.key_id()));
    reopen(&mut st);
    decrypt_and_store_transaction_with_one_time_ivks(&network, st.wallet_mut(), &tx, Some(height))
        .unwrap();
    let memo = MemoBytes::from_bytes(b"refund")
        .unwrap()
        .as_slice()
        .to_vec();
    assert_eq!(stored_receipt(&st, tx.txid()), (true, Some(memo)));
    assert!(!scanning_keys(&st).contains(&key.key_id()));
}

/// A ZeWIF import into a wallet with an open one-time key decrypts with it, storing the
/// memo of a payment to that key rather than refusing the import.
#[cfg(feature = "zewif")]
#[test]
fn zewif_import_decrypts_with_open_one_time_keys() {
    let mut st = scanned_wallet();
    let (_, tx, height) = externally_paid_refund_key(&mut st);
    assert_eq!(stored_receipt(&st, tx.txid()), (false, None));

    let mut raw = vec![];
    tx.write(&mut raw).unwrap();
    let mut imported = ::zewif::Transaction::new(::zewif::TxId::from_bytes(*tx.txid().as_ref()));
    imported.set_tx_data(::zewif::TransactionData::Raw(::zewif::RawTxData::new(
        ::zewif::Data::from_bytes(&raw),
    )));
    imported.set_mined_height(::zewif::BlockHeight::from(u32::from(height)));
    let mut doc = ::zewif::Zewif::new(
        ::zewif::BlockHeight::from(u32::from(height)),
        ::zewif::BlockHash::from_bytes([0; 32]),
    );
    doc.add_transaction(imported.txid(), imported);
    let report = crate::zewif::import_wallet(
        st.wallet_mut().db_mut(),
        &doc,
        &mut crate::zewif::DiscardSecrets,
    )
    .unwrap();
    assert_eq!(report.transactions_stored, 1);
    let memo = MemoBytes::from_bytes(b"refund").unwrap();
    assert_eq!(
        stored_receipt(&st, tx.txid()),
        (true, Some(memo.as_slice().to_vec()))
    );
}

#[test]
fn refund_funding_memo_recovers_from_seed_with_zero_change() {
    let (mut st, first) = ironwood_funded_wallet();
    let network = *st.network();
    let account = st.test_account().cloned().unwrap();
    let memo = RefundMemo::new(7);
    let memo_bytes = refund_memo(7);
    let (proposal, txid, mined) = send(
        &mut st,
        vec![payment(&p2pkh(7), 985_000, None)],
        &memo_bytes,
    );
    let change = proposal.steps()[0].balance().proposed_change();
    assert_eq!(change.len(), 1);
    assert_eq!(change[0].value(), Zatoshis::ZERO);
    assert_eq!(change[0].memo(), Some(&memo_bytes));
    let tx = st.wallet().get_transaction(txid).unwrap().unwrap();

    // Replace the wallet with a seed restore. No reservations or sent-transaction
    // records survive, so recovery must authenticate chain inputs and the memo.
    let seed = SecretVec::new(st.test_seed().unwrap().expose_secret().clone());
    let _old_wallet = st.reset();
    let (restored, _) = st
        .wallet_mut()
        .create_account("restored", &seed, account.birthday(), None)
        .unwrap();
    st.wallet_mut().update_chain_tip(mined).unwrap();
    let blocks = u32::from(mined) - u32::from(first) + 1;
    st.scan_cached_blocks_with_one_time_ivks(first, blocks as usize);
    let pending = |st: &State| {
        store::restore::recovery::refund_memos_pending(st.wallet().conn(), restored).unwrap()
    };
    // Compact scanning stores the change without its memo.
    recover_memos(&mut st, restored);
    assert!(refund_keys(&st).is_empty());
    assert!(pending(&st));
    decrypt_and_store_transaction_with_one_time_ivks(&network, st.wallet_mut(), &tx, Some(mined))
        .unwrap();

    // Changing the authenticated scope, or losing own-send evidence, makes the memo
    // ineligible. A marker still waiting for its evidence holds back refund issuance.
    let set_scope = "UPDATE ironwood_received_notes SET recipient_key_scope = ?1 WHERE memo = ?2";
    exec(
        st.wallet().conn(),
        set_scope,
        rusqlite::params![0, memo_bytes.as_slice()],
    );
    recover_memos(&mut st, restored);
    assert!(refund_keys(&st).is_empty());
    exec(
        st.wallet().conn(),
        set_scope,
        rusqlite::params![1, memo_bytes.as_slice()],
    );
    let spends: Vec<(i64, i64)> = rows(
        st.wallet().conn(),
        "SELECT ironwood_received_note_id, transaction_id FROM ironwood_received_note_spends",
        [],
    );
    exec(
        st.wallet().conn(),
        "DELETE FROM ironwood_received_note_spends",
        [],
    );
    // Without own-send evidence, though scanning covers the funding block, the inputs
    // predate the birthday or the record is not this wallet's. It no longer holds back
    // issuance: its key is swept without advancing allocation, which skips its index.
    let replace_memo = |st: &State, from: &[u8], to: &[u8]| {
        let sql = "UPDATE ironwood_received_notes SET memo = ?2 WHERE memo = ?1";
        exec(st.wallet().conn(), sql, rusqlite::params![from, to]);
    };
    let unauthenticated = RefundMemo::new(0).encode();
    replace_memo(&st, memo_bytes.as_slice(), unauthenticated.as_slice());
    recover_memos(&mut st, restored);
    assert_eq!(refund_keys(&st), vec![(0, u32::from(mined), true)]);
    assert!(!pending(&st));
    let db = st.wallet_mut().db_mut();
    let next = db.reserve_refund_key(restored, mined).unwrap().unwrap();
    assert_eq!(next.key_id(), KeyId::new(Purpose::Refund, 1));
    replace_memo(&st, unauthenticated.as_slice(), memo_bytes.as_slice());
    exec(
        st.wallet().conn(),
        "DELETE FROM ironwood_receiving_keys",
        [],
    );
    for (note, transaction) in spends {
        let sql = "INSERT INTO ironwood_received_note_spends VALUES(?1,?2)";
        exec(
            st.wallet().conn(),
            sql,
            rusqlite::params![note, transaction],
        );
    }

    // A marked memo that does not decode is ignored.
    let mut invalid = memo.encode();
    invalid[5] = 0xff;
    replace_memo(&st, memo_bytes.as_slice(), invalid.as_slice());
    recover_memos(&mut st, restored);
    assert!(refund_keys(&st).is_empty());
    replace_memo(&st, invalid.as_slice(), memo_bytes.as_slice());

    // A failed enclosing transaction leaves the registration for a retry.
    let aborted: Result<(), SqliteClientError> = super::tx(st.wallet_mut().db_mut(), |c, p| {
        store::restore::recovery::recover_refund_memos(c, p, restored, clock_now())?;
        Err(corrupt("test rollback"))
    });
    assert!(aborted.is_err());
    assert!(refund_keys(&st).is_empty());

    // The wallet never scanned this key, so its history comes from a receiver-directory
    // sweep rather than trial decryption.
    recover_memos(&mut st, restored);
    let registered = vec![(7, u32::from(mined), true)];
    assert_eq!(refund_keys(&st), registered);
    assert!(!pending(&st));
    assert!(scanning_keys(&st).is_empty());
    let db = st.wallet().db();
    assert!(db.one_time_history_pending(restored, mined).unwrap());

    // A restored refund key makes no provider lookups. Like a restored incoming key, it
    // is watched for a day from its registration.
    let (registered_at, operations): (i64, i64) = row(
        st.wallet().conn(),
        "SELECT k.registered_at, (SELECT COUNT(*) FROM ironwood_one_time_operations o
            WHERE o.receiving_key_id = k.id)
         FROM ironwood_receiving_keys k WHERE k.purpose = 0",
        [],
    );
    assert_eq!((registered_at, operations), (clock_now(), 0));

    // Repeated recovery, including after identical re-enhancement, changes nothing,
    // and it widens a key that starts after its funding block.
    decrypt_and_store_transaction_with_one_time_ivks(&network, st.wallet_mut(), &tx, Some(mined))
        .unwrap();
    recover_memos(&mut st, restored);
    assert_eq!(refund_keys(&st), registered);
    let sql = "UPDATE ironwood_receiving_keys SET scan_from = scan_from + 1";
    exec(st.wallet().conn(), sql, []);
    recover_memos(&mut st, restored);
    assert_eq!(refund_keys(&st), registered);
}

/// A refund key's funding memo is issued only for the deposit its quote recorded, and a
/// transaction whose memo names another key than the deposit it pays fails to store,
/// starting no key and pairing nothing. Storing a matching funding transaction starts
/// its key above the scanned chain, and the funded quote then waits for the swap's
/// outcome; an unfunded quote never starts its key. Issuance recovers a funding memo
/// first, so it never reissues the funded index.
#[test]
fn a_refund_key_starts_scanning_when_its_matching_funding_transaction_is_stored() {
    use zakura_one_time_ivk::swap::{OperationStatus::Terminal, ReceiptExpectation};
    let (mut st, _) = ironwood_funded_wallet();
    let account = st.test_account().unwrap().id();
    let network = *st.network();
    let tip = st.wallet().chain_height().unwrap().unwrap();
    let now = clock_now();
    let [other, funded, stale] = [8, 7, 9].map(|byte| p2pkh(byte).encode(&network));
    let db = st.wallet_mut().db_mut();
    let [unfunded, key] = [0, 1].map(|_| {
        db.reserve_refund_key(account, tip)
            .unwrap()
            .unwrap()
            .key_id()
    });
    assert!(
        db.refund_funding_memo(account, key.index(), &funded)
            .is_err()
    );
    db.record_refund_operation(account, unfunded.index(), &other, now + 3_600, now)
        .unwrap();
    db.record_refund_operation(account, key.index(), &funded, now + 3_600, now)
        .unwrap();
    let rebound = db.record_refund_operation(account, key.index(), &stale, now + 3_600, now);
    assert!(rebound.is_err());
    let memos = [(unfunded, &other), (key, &funded)].map(|(key, deposit)| {
        db.refund_funding_memo(account, key.index(), deposit)
            .unwrap()
    });

    /// Refund keys' scan starts, `(key index, reference)` operations, and the stored
    /// transaction count.
    type Snapshot = (Vec<Option<u32>>, Vec<(Vec<u8>, String)>, i64);
    let state = |conn: &Connection| -> Snapshot {
        let active = column(
            conn,
            "SELECT active_from FROM ironwood_receiving_keys WHERE purpose = 0
             ORDER BY key_index",
            [],
        );
        let operations = rows(
            conn,
            "SELECT k.key_index, o.reference FROM ironwood_one_time_operations o
             JOIN ironwood_receiving_keys k ON k.id = o.receiving_key_id
             ORDER BY k.key_index, o.reference",
            [],
        );
        (
            active,
            operations,
            value(conn, "SELECT COUNT(*) FROM transactions", []),
        )
    };
    let before = state(st.wallet().conn());
    assert_eq!(before.0, [None, None]);
    let pay_funded = || vec![payment(&p2pkh(7), 100_000, None)];
    let (_, created) = try_send(&mut st, pay_funded(), &memos[0]);
    assert!(matches!(
        created,
        Err(SqliteClientError::InvalidOneTimeIvkInput(_))
    ));
    assert_eq!(state(st.wallet().conn()), before);

    let (proposal, txid) = try_send(&mut st, pay_funded(), &memos[1]);
    verify_refund_funding_proposal(&proposal, &memos[1], &funded).unwrap();
    assert!(verify_refund_funding_proposal(&proposal, &memos[1], &stale).is_err());
    assert!(verify_refund_funding_proposal(&proposal, &memos[0], &funded).is_err());
    // Storing the funding transaction starts its key above the scanned chain, so no
    // block is rescanned, and opens the funded quote until the provider reports.
    let (active, operations, _) = state(st.wallet().conn());
    assert_eq!(active, [None, Some(u32::from(tip) + 1)]);
    assert_eq!(operations, before.1);
    let sql = "SELECT observed_at, expectation FROM ironwood_one_time_operations
               WHERE reference = ?1";
    assert_eq!(row::<(i64, u8)>(st.wallet().conn(), sql, [&funded]), (0, 0));

    let (mined, _) = st.generate_next_block_including(txid.unwrap());
    st.scan_cached_blocks_with_one_time_ivks(mined, 1);
    // The key already scans from before its funding block, so recovery queues no sweep.
    recover_memos(&mut st, account);
    let db = st.wallet_mut().db_mut();
    assert!(!db.one_time_history_pending(account, mined).unwrap());
    assert_eq!(close_at(db, account, now, mined), 0);
    let finished = now + 7_200;
    let no_refund = Terminal(ReceiptExpectation::None);
    observe(db, account, key, &funded, no_refund, finished).unwrap();
    // The swap is over.
    assert_eq!(close_at(db, account, finished, mined), 1);
    assert_eq!(
        state(st.wallet().conn()).0,
        [None, Some(u32::from(tip) + 1)]
    );

    // A restored wallet's compact scan stores the change before enhancement
    // retrieves its memo, which holds back refund issuance until it arrives.
    let (note, stored): (i64, Vec<u8>) = row(
        st.wallet().conn(),
        "SELECT id, memo FROM ironwood_received_notes
         WHERE recipient_key_scope = 1 AND substr(memo, 1, 5) = X'FF5A535750'",
        [],
    );
    let set_memo = |st: &State, memo: Option<&[u8]>| {
        let sql = "UPDATE ironwood_received_notes SET memo = ?2 WHERE id = ?1";
        exec(st.wallet().conn(), sql, rusqlite::params![note, memo]);
    };
    set_memo(&st, None);
    assert!(matches!(
        st.wallet_mut().db_mut().reserve_refund_key(account, mined),
        Ok(Err(ReservationPolicy::Coverage))
    ));
    set_memo(&st, Some(&stored));
    let next = st.wallet_mut().db_mut().reserve_refund_key(account, mined);
    assert_eq!(next.unwrap().unwrap().key_id().index(), key.index() + 1);
}

#[test]
fn reissued_refund_key_sweeps_history_before_its_scan_start() {
    let (mut st, _) = ironwood_funded_wallet();
    let account = st.test_account().unwrap().id();
    let pays = vec![payment(&p2pkh(7), 100_000, None)];
    let (_, _, mined) = send(&mut st, pays, &refund_memo(0));
    // A restored wallet can issue the memo's index again before recovering the memo.
    let db = st.wallet_mut().db_mut();
    let key = reserve_key(db, account, Purpose::Refund, mined + 1);
    assert_eq!(key.key_id().index(), 0);
    recover_memos(&mut st, account);
    assert_eq!(refund_keys(&st), [(0, u32::from(mined), true)]);
    let db = st.wallet().db();
    assert!(db.one_time_history_pending(account, mined).unwrap());
}

#[test]
fn refund_memos_restore_keys_whatever_the_funding_outputs() {
    let shielded = unified(foreign_receiver());
    for recipients in [vec![shielded], vec![p2pkh(7), p2pkh(8)]] {
        let (mut st, _) = ironwood_funded_wallet();
        let account = st.test_account().unwrap().id();
        let pays = recipients
            .iter()
            .map(|a| payment(a, 100_000, None))
            .collect();
        let (_, _, mined) = send(&mut st, pays, &refund_memo(7));
        recover_memos(&mut st, account);
        assert_eq!(refund_keys(&st), [(7, u32::from(mined), true)]);
        let conn = st.wallet().conn();
        assert!(!store::restore::recovery::refund_memos_pending(conn, account).unwrap());
    }
}

/// A refund record retrieved over Enhance PIR restores its key from the memo alone.
/// A funding transaction flagged as having transparent outputs takes the public path
/// for its history first, as any such transaction does.
#[test]
fn refund_memo_over_pir_restores_its_key_without_the_raw_transaction() {
    use zcash_client_backend::data_api::enhance_pir::{
        EnhancePirRead, EnhancePirWork, EnhancePirWrite, EnhanceRecord, EnhanceRecordParts,
        EnhanceTransactionMetadata, EnhancementMode, TransactionEnhancementWork,
    };

    for flagged in [true, false] {
        let (mut st, first) = ironwood_funded_wallet();
        let network = *st.network();
        let account = st.test_account().cloned().unwrap();
        let pays = vec![payment(&p2pkh(7), 985_000, None)];
        let (_, txid, mined) = send(&mut st, pays, &refund_memo(7));
        let tx = st.wallet().get_transaction(txid).unwrap().unwrap();
        let sql = "SELECT fee FROM transactions WHERE txid=?1";
        let fee: u64 = value(st.wallet().conn(), sql, [txid.as_ref()]);

        // Restore privately. Compact blocks carry no transparent data.
        let seed = SecretVec::new(st.test_seed().unwrap().expose_secret().clone());
        let _old_wallet = st.reset();
        let (restored, _) = st
            .wallet_mut()
            .create_account("restored", &seed, account.birthday(), None)
            .unwrap();
        st.wallet_mut()
            .db_mut()
            .set_enhancement_mode(EnhancementMode::PrivateIronwood);
        st.wallet_mut().update_chain_tip(mined).unwrap();
        let blocks = u32::from(mined) - u32::from(first) + 1;
        st.scan_cached_blocks_with_one_time_ivks(first, blocks as usize);

        let work = st.wallet().db().transaction_enhancement_work().unwrap();
        let requests: Vec<_> = work
            .into_iter()
            .filter_map(|work| match work {
                TransactionEnhancementWork::Private(EnhancePirWork::Query(r))
                    if r.request_id().txid() == txid =>
                {
                    Some(r)
                }
                _ => None,
            })
            .collect();
        assert!(!requests.is_empty());

        // Genuine ciphertexts; only the server's transparent flag varies.
        let bundle = tx.ironwood_bundle().unwrap();
        let metadata =
            EnhanceTransactionMetadata::new(u32::from(tx.expiry_height()), Some(fee)).unwrap();
        let batch: Vec<_> = requests
            .iter()
            .map(|r| {
                let action = &bundle.actions()[r.request_id().output_index() as usize];
                let note = action.encrypted_note();
                let parts = EnhanceRecordParts {
                    enc_ciphertext_suffix: note.enc_ciphertext[52..].try_into().unwrap(),
                    cv_net: action.cv_net().to_bytes(),
                    out_ciphertext: note.out_ciphertext,
                    has_transparent_inputs: false,
                    has_transparent_outputs: flagged,
                    metadata,
                };
                (*r, EnhanceRecord::from_parts(parts))
            })
            .collect();
        let db = st.wallet_mut().db_mut();
        db.apply_ironwood_enhance_records(&batch).unwrap();

        let memo_stored: bool = value(
            st.wallet().conn(),
            "SELECT EXISTS(SELECT 1 FROM ironwood_received_notes n
             JOIN transactions t ON t.id_tx = n.transaction_id
             WHERE t.txid = ?1 AND n.memo IS NOT NULL)",
            [txid.as_ref()],
        );
        assert_eq!(memo_stored, !flagged, "flagged={flagged}");
        if flagged {
            let work = st.wallet().db().transaction_enhancement_work().unwrap();
            assert!(
                work.iter().any(
                    |w| matches!(w, TransactionEnhancementWork::Public(p) if p.txid() == txid)
                )
            );
            decrypt_and_store_transaction_with_one_time_ivks(
                &network,
                st.wallet_mut(),
                &tx,
                Some(mined),
            )
            .unwrap();
        }
        recover_memos(&mut st, restored);
        assert_eq!(refund_keys(&st), [(7, u32::from(mined), true)]);
    }
}

/// A quote binds to a refund key reserved here that is still open, and the key to that
/// quote's deposit alone; the key need not scan yet, since only its funding transaction
/// starts it.
#[test]
fn refund_quote_needs_an_open_reserved_refund_key_and_a_canonical_transparent_deposit() {
    let (mut st, _) = ironwood_funded_wallet();
    let account = st.test_account().unwrap().id();
    let network = *st.network();
    let tip = st.wallet().chain_height().unwrap().unwrap();
    let now = clock_now();
    let deposit = p2pkh(7).encode(&network);
    let own = unified(parent(&st).address_at(0u32, Scope::External)).encode(&network);
    let mainnet = p2pkh(7).encode(&zcash_protocol::consensus::MainNetwork);
    let tex = zcash_keys::address::Address::Tex([7; 20]).encode(&network);
    let padded = format!(" {deposit}");
    let db = st.wallet_mut().db_mut();
    let mut record = |index, deposit: &str, deadline| {
        db.record_refund_operation(account, index, deposit, deadline, now)
    };
    assert!(record(0, &deposit, now + 60).is_err());
    for _ in 0..2 {
        db.reserve_refund_key(account, tip).unwrap().unwrap();
    }
    let mut record = |index, deposit: &str, deadline| {
        db.record_refund_operation(account, index, deposit, deadline, now)
    };
    for bad in [&own, &tex, &mainnet, &padded] {
        assert!(record(0, bad, now + 60).is_err());
    }
    assert!(record(0, &deposit, now).is_err());
    for _ in 0..2 {
        record(0, &deposit, now + 60).unwrap();
    }
    assert!(record(1, &deposit, now + 60).is_err());
    // The key is bound to its deposit, so another swap cannot share its refunds.
    let other = p2pkh(8).encode(&network);
    assert!(matches!(
        record(0, &other, now + 60),
        Err(SqliteClientError::InvalidOneTimeIvkInput(_))
    ));
    assert!(db.refund_funding_memo(account, 0, &other).is_err());
    assert!(db.refund_funding_memo(account, 0, &deposit).is_ok());
    // A closed key would miss the refund.
    let sql = "UPDATE ironwood_receiving_keys SET closed_at = ?1 WHERE purpose = 0";
    exec(&db.conn, sql, [now]);
    assert!(db.refund_funding_memo(account, 0, &deposit).is_err());
}
