use super::*;
use zakura_one_time_ivk::swap::RefundMemo;
use zcash_client_backend::data_api::wallet::decrypt_and_store_transaction;
use zcash_protocol::{ShieldedPool, TxId, memo::MemoBytes};

/// Builds a wallet whose test account holds one confirmed 1,000,000 zatoshi
/// Ironwood note, returning the height of the block that paid it.
fn ironwood_funded_wallet() -> (State, BlockHeight) {
    let mut st = ironwood_wallet();
    let fvk = parent(&st);
    let first = pay(&mut st, &fvk, 1_000_000);
    st.generate_and_scan_empty_blocks(5);
    let account = st.test_account().unwrap().id();
    st.wallet_mut()
        .db_mut()
        .set_one_time_recovery_enabled(account, true)
        .unwrap();
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
    st.scan_cached_blocks(mined, 1);
    (proposal, txid, mined)
}

/// The encoded refund memo for key `index`.
fn refund_memo(index: u64) -> MemoBytes {
    MemoBytes::from_bytes(&RefundMemo::new(index).encode()).unwrap()
}

/// Queues every refund memo of `account` again, as tests that rewrite stored memos need,
/// and runs refund memo recovery in its own transaction.
fn recover_memos(st: &mut State, account: AccountUuid) {
    tx(st.wallet_mut().db_mut(), |c, p| {
        let owner = crate::wallet::get_account_ref(c, account)?;
        c.execute(
            "INSERT OR IGNORE INTO ironwood_one_time_pending_memos (note_id)
             SELECT id FROM ironwood_received_notes
             WHERE account_id = ?1 AND recipient_key_scope = 1 AND one_time_key_id IS NULL
               AND substr(memo, 1, 5) = X'FF5A535750'",
            [owner.0],
        )?;
        store::restore::recovery::recover_refund_memos(c, p, account)
    })
    .unwrap()
}

/// `(index, funding height, history due)` of each registered refund key: its history is
/// registered for a lookup, or its coverage is below its funding height for a filter re-check.
fn refund_keys(st: &State) -> Vec<(u64, u32, bool)> {
    let keys: Vec<(Vec<u8>, u32, bool)> = rows(
        st.wallet().conn(),
        "SELECT k.key_index, k.funding_height,
            EXISTS(SELECT 1 FROM ironwood_one_time_lookups l WHERE l.one_time_key_id = k.id)
            OR k.covered_height < k.funding_height
         FROM ironwood_one_time_keys k WHERE k.purpose = 0 ORDER BY k.key_index",
        [],
    );
    let decode = |i: Vec<u8>| u64::from_be_bytes(i.try_into().unwrap());
    keys.into_iter()
        .map(|(i, from, looked_up)| (decode(i), from, looked_up))
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
    scan_and_recover(st, height, 1);
    (key, tx, height)
}

/// Full transaction retrieval preserves a PIR-admitted note without broad key decryption.
#[test]
fn recovered_receipt_survives_full_transaction_retrieval() {
    let mut st = scanned_wallet();
    let network = *st.network();
    let (_, transaction, height) = externally_paid_refund_key(&mut st);
    reopen(&mut st);
    decrypt_and_store_transaction(&network, st.wallet_mut(), &transaction, Some(height)).unwrap();
    assert_eq!(stored_receipt(&st, transaction.txid()), (true, None));
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
    // records survive, so recovery must authenticate the memo from chain data.
    let seed = SecretVec::new(st.test_seed().unwrap().expose_secret().clone());
    let _old_wallet = st.reset();
    let (restored, _) = st
        .wallet_mut()
        .create_account("restored", &seed, account.birthday(), None)
        .unwrap();
    st.wallet_mut().update_chain_tip(mined).unwrap();
    let blocks = u32::from(mined) - u32::from(first) + 1;
    st.scan_cached_blocks(first, blocks as usize);
    st.wallet_mut()
        .db_mut()
        .set_one_time_recovery_enabled(restored, true)
        .unwrap();
    let pending = |st: &State| {
        store::restore::recovery::refund_memos_pending(st.wallet().conn(), restored).unwrap()
    };
    // Compact scanning stores the change without its memo.
    recover_memos(&mut st, restored);
    assert!(refund_keys(&st).is_empty());
    assert!(pending(&st));
    decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, Some(mined)).unwrap();
    // Storing the retrieved memo registers its key at once. Forget it to check the rules.
    assert_eq!(refund_keys(&st), [(7, u32::from(mined), true)]);
    exec(
        st.wallet().conn(),
        "DELETE FROM ironwood_one_time_keys WHERE purpose = 0",
        [],
    );

    // Changing the authenticated scope makes the memo ineligible.
    let set_scope = |st: &State, scope: u8| {
        let sql = "UPDATE ironwood_received_notes SET recipient_key_scope = ?1 WHERE memo = ?2";
        exec(
            st.wallet().conn(),
            sql,
            rusqlite::params![scope, memo_bytes.as_slice()],
        );
    };
    set_scope(&st, 0);
    recover_memos(&mut st, restored);
    assert!(refund_keys(&st).is_empty());
    set_scope(&st, 1);
    let replace_memo = |st: &State, from: &[u8], to: &[u8]| {
        exec(
            st.wallet().conn(),
            "UPDATE ironwood_received_notes SET memo = ?2 WHERE memo = ?1",
            rusqlite::params![from, to],
        );
    };

    // A marked memo that does not decode is ignored.
    let mut invalid = memo.encode();
    invalid[5] = 0xff;
    replace_memo(&st, memo_bytes.as_slice(), invalid.as_slice());
    recover_memos(&mut st, restored);
    assert!(refund_keys(&st).is_empty());
    replace_memo(&st, invalid.as_slice(), memo_bytes.as_slice());

    // A failed enclosing transaction leaves the registration for a retry.
    let aborted: Result<(), SqliteClientError> = super::tx(st.wallet_mut().db_mut(), |c, p| {
        store::restore::recovery::recover_refund_memos(c, p, restored)?;
        Err(corrupt("test rollback"))
    });
    assert!(aborted.is_err());
    assert!(refund_keys(&st).is_empty());

    // The wallet never scanned this key, so its history comes from a receiver-directory
    // lookup rather than trial decryption.
    recover_memos(&mut st, restored);
    let registered = vec![(7, u32::from(mined), true)];
    assert_eq!(refund_keys(&st), registered);
    assert!(!pending(&st));
    let db = st.wallet().db();
    assert!(lookup_pending(db, restored));

    // Recovery creates no synthetic provider operation.
    let operations: i64 = value(
        st.wallet().conn(),
        "SELECT COUNT(*) FROM ironwood_one_time_operations o
         JOIN ironwood_one_time_keys k ON k.id = o.one_time_key_id WHERE k.purpose = 0",
        [],
    );
    assert_eq!(operations, 0);

    // Repeated recovery, including after identical re-enhancement, changes nothing,
    // and it lowers a recorded funding height that is above the funding block.
    decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, Some(mined)).unwrap();
    recover_memos(&mut st, restored);
    assert_eq!(refund_keys(&st), registered);
    let sql = "UPDATE ironwood_one_time_keys SET funding_height = funding_height + 1";
    exec(st.wallet().conn(), sql, []);
    recover_memos(&mut st, restored);
    assert_eq!(refund_keys(&st), registered);
}

/// Funding verification refuses the recovery memo on change outside Ironwood, where
/// refund recovery never looks. Spending pre-Ironwood Orchard funds returns change to
/// Orchard, and a restored wallet would never find that refund key.
#[test]
fn refund_funding_refuses_its_memo_on_orchard_change() {
    use zcash_client_backend::{
        data_api::wallet::{ConfirmationsPolicy, input_selection::GreedyInputSelector},
        fees::{DustOutputPolicy, StandardFeeRule, standard::SingleOutputChangeStrategy},
    };
    use zcash_protocol::PoolType;
    let mut st = ironwood_wallet();
    let orchard = Zatoshis::const_from_u64(1_000_000);
    let (funded, _, _) =
        st.generate_next_block(&parent(&st), AddressType::DefaultExternal, orchard);
    st.scan_cached_blocks(funded, 1);
    st.generate_and_scan_empty_blocks(5);
    let account = st.test_account().unwrap().id();
    st.wallet_mut()
        .db_mut()
        .set_one_time_recovery_enabled(account, true)
        .unwrap();
    let tip = st.wallet().chain_height().unwrap().unwrap();
    let deposit = p2pkh(7).encode(st.network());
    let now = clock_now();
    let db = st.wallet_mut().db_mut();
    let key = reserve_refund(db, account, tip).unwrap().unwrap();
    let index = key.key_id().index();
    db.record_refund_operation(account, index, &deposit, now + 3_600, now)
        .unwrap();
    let memo = db.refund_funding_memo(account, index, &deposit).unwrap();
    let strategy = SingleOutputChangeStrategy::<TestDb>::new(
        StandardFeeRule::Zip317,
        Some(memo.clone()),
        ShieldedPool::Orchard,
        DustOutputPolicy::default(),
    );
    let request = zip321::TransactionRequest::new(vec![payment(&p2pkh(7), 100_000, None)]);
    let selector = GreedyInputSelector::new();
    let policy = ConfirmationsPolicy::MIN;
    let proposal = st
        .propose_transfer(account, &selector, &strategy, request.unwrap(), policy)
        .unwrap();
    let change = proposal.steps().first().balance().proposed_change();
    assert!(change.iter().all(|c| c.output_pool() == PoolType::ORCHARD));
    assert!(change.iter().any(|c| c.memo() == Some(&memo)));
    assert!(verify_refund_funding_proposal(&proposal, &memo, &deposit).is_err());
}

/// A refund key's funding memo is issued only for the deposit its quote recorded, and a
/// transaction whose memo names another key than the deposit it pays fails to store,
/// funding no key and pairing nothing. Storing a matching funding transaction records
/// the key's funding height and queues its history for PIR, and the funded quote then
/// waits for the swap's outcome. An unfunded quote never funds its key. Issuance
/// recovers a funding memo first, so it never reissues the funded index.
#[test]
fn a_refund_key_queues_history_when_its_matching_funding_transaction_is_stored() {
    use zakura_one_time_ivk::swap::{OperationStatus::Terminal, ReceiptExpectation};
    let (mut st, _) = ironwood_funded_wallet();
    let account = st.test_account().unwrap().id();
    let network = *st.network();
    let tip = st.wallet().chain_height().unwrap().unwrap();
    let now = clock_now();
    let [other, funded, stale] = [8, 7, 9].map(|byte| p2pkh(byte).encode(&network));
    let db = st.wallet_mut().db_mut();
    let [unfunded, key] =
        [0, 1].map(|_| reserve_refund(db, account, tip).unwrap().unwrap().key_id());
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

    /// Refund keys' funding heights, `(key index, reference)` operations, and the stored
    /// transaction count.
    type Snapshot = (Vec<Option<u32>>, Vec<(Vec<u8>, String)>, i64);
    let state = |conn: &Connection| -> Snapshot {
        let funding = column(
            conn,
            "SELECT funding_height FROM ironwood_one_time_keys WHERE purpose = 0
             ORDER BY key_index",
            [],
        );
        let operations = rows(
            conn,
            "SELECT k.key_index, o.reference FROM ironwood_one_time_operations o
             JOIN ironwood_one_time_keys k ON k.id = o.one_time_key_id
             ORDER BY k.key_index, o.reference",
            [],
        );
        (
            funding,
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
    // Storing the funding transaction records a funding height above the scanned chain,
    // so no block is rescanned, and keeps the funded quote open until the provider reports.
    let (funding, operations, _) = state(st.wallet().conn());
    assert_eq!(funding, [None, Some(u32::from(tip) + 1)]);
    assert_eq!(operations, before.1);
    let sql = "SELECT observed_at, expectation FROM ironwood_one_time_operations
               WHERE reference = ?1";
    assert_eq!(row::<(i64, u8)>(st.wallet().conn(), sql, [&funded]), (0, 0));

    let (mined, _) = st.generate_next_block_including(txid.unwrap());
    st.scan_cached_blocks(mined, 1);
    recover_memos(&mut st, account);
    let db = st.wallet_mut().db_mut();
    assert!(lookup_pending(db, account));
    observe(
        db,
        account,
        key,
        &funded,
        Terminal(ReceiptExpectation::None),
        now + 7_200,
    )
    .unwrap();
    assert!(lookup_pending(db, account));

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
        reserve_refund(st.wallet_mut().db_mut(), account, mined),
        Ok(Err(ReservationPolicy::FundingHistory))
    ));
    set_memo(&st, Some(&stored));
    let next = reserve_refund(st.wallet_mut().db_mut(), account, mined);
    assert_eq!(next.unwrap().unwrap().key_id().index(), key.index() + 1);
}

/// A restored account recovers a funding memo's refund key as soon as the scan stores the
/// funding transaction, so issuance never hands the memo's index out again, and the key's
/// history is due for a lookup.
#[test]
fn a_funding_memo_is_recovered_once_its_block_is_stored() {
    let (mut st, _) = ironwood_funded_wallet();
    let account = st.test_account().unwrap().id();
    let pays = vec![payment(&p2pkh(7), 100_000, None)];
    let (_, _, mined) = send(&mut st, pays, &refund_memo(0));
    assert_eq!(refund_keys(&st), [(0, u32::from(mined), true)]);
    let db = st.wallet_mut().db_mut();
    assert!(lookup_pending(db, account));
    let key = reserve_key(db, account, Purpose::Refund, mined + 1);
    assert_eq!(key.key_id().index(), 1);
}

/// Restores `st`'s seed into a fresh wallet born at `birthday`, scans from there through
/// `mined`, stores each of `txids`' full transactions for their memos, and enables one-time
/// recovery.
/// Returns the restored account. No PIR recovery runs, so the restore holds no one-time
/// note. Refund issuance waits while the memo is missing.
fn restore_through_funding(
    st: &mut State,
    birthday: &zcash_client_backend::data_api::AccountBirthday,
    txids: &[TxId],
    mined: BlockHeight,
) -> AccountUuid {
    let network = *st.network();
    let txs: Vec<_> = txids
        .iter()
        .map(|txid| st.wallet().get_transaction(*txid).unwrap().unwrap())
        .collect();
    let seed = SecretVec::new(st.test_seed().unwrap().expose_secret().clone());
    let _old_wallet = st.reset();
    let (restored, _) = st
        .wallet_mut()
        .create_account("restored", &seed, birthday, None)
        .unwrap();
    st.wallet_mut().update_chain_tip(mined).unwrap();
    let from = birthday.height();
    st.scan_cached_blocks(from, (u32::from(mined) - u32::from(from) + 1) as usize);
    let db = st.wallet_mut().db_mut();
    db.set_one_time_recovery_enabled(restored, true).unwrap();
    assert!(matches!(
        reserve_refund(db, restored, mined),
        Ok(Err(ReservationPolicy::FundingHistory))
    ));
    for tx in &txs {
        let height = st.wallet().get_tx_height(tx.txid()).unwrap();
        decrypt_and_store_transaction(&network, st.wallet_mut(), tx, height).unwrap();
    }
    restored
}

/// Whether `txid` spent a note this wallet holds, the evidence refund recovery no longer
/// requires.
fn spends_owned_note(st: &State, txid: TxId) -> bool {
    value(
        st.wallet().conn(),
        "SELECT EXISTS(SELECT 1 FROM v_received_output_spends s
         JOIN transactions t ON t.id_tx = s.transaction_id WHERE t.txid = ?1)",
        [txid.as_ref()],
    )
}

/// A second device on the same seed trusts the refund memo on its internal change although
/// the swap spent only a one-time note it has not recovered yet. It registers the funded
/// refund key and never issues that index for its own swap, which would link the two swaps.
#[test]
fn a_device_without_the_spent_one_time_notes_trusts_the_refund_memo() {
    let mut st = ironwood_wallet();
    let network = *st.network();
    let account = st.test_account().cloned().unwrap();
    // The first device's only funds are a payout to its first incoming one-time key.
    let db = st.wallet_mut().db_mut();
    let incoming = reserve_key(db, account.id(), Purpose::Receive, start());
    pay(&mut st, incoming.full_viewing_key(), 1_000_000);
    st.generate_and_scan_empty_blocks(5);

    let tip = st.wallet().chain_height().unwrap().unwrap();
    let deposit = p2pkh(7).encode(&network);
    let now = clock_now();
    let db = st.wallet_mut().db_mut();
    let key = reserve_refund(db, account.id(), tip).unwrap().unwrap();
    let index = key.key_id().index();
    db.record_refund_operation(account.id(), index, &deposit, now + 3_600, now)
        .unwrap();
    let memo = db
        .refund_funding_memo(account.id(), index, &deposit)
        .unwrap();
    let pays = vec![payment(&p2pkh(7), 500_000, None)];
    let (proposal, txid, mined) = send(&mut st, pays, &memo);
    verify_refund_funding_proposal(&proposal, &memo, &deposit).unwrap();
    let one_time_inputs: i64 = value(
        st.wallet().conn(),
        "SELECT COUNT(*) FROM ironwood_received_note_spends s
         JOIN ironwood_received_notes n ON n.id = s.ironwood_received_note_id
         JOIN transactions t ON t.id_tx = s.transaction_id
         WHERE t.txid = ?1 AND n.one_time_key_id IS NOT NULL",
        [txid.as_ref()],
    );
    assert_eq!(one_time_inputs, 1);

    // The second device scans the same chain from the same birthday, without PIR.
    let second = restore_through_funding(&mut st, account.birthday(), &[txid], mined);
    let one_time_notes: i64 = value(
        st.wallet().conn(),
        "SELECT COUNT(*) FROM ironwood_received_notes WHERE one_time_key_id IS NOT NULL",
        [],
    );
    assert_eq!(one_time_notes, 0);
    assert!(!spends_owned_note(&st, txid));

    recover_memos(&mut st, second);
    assert_eq!(refund_keys(&st), [(index, u32::from(mined), true)]);
    let db = st.wallet_mut().db_mut();
    let next = reserve_refund(db, second, mined).unwrap().unwrap();
    assert_eq!(next.key_id().index(), index + 1);
}

/// A restore born after the note a swap spent, and before its funding transaction, never
/// sees that spend. It still recovers the refund key from the memo on its internal change,
/// so it neither loses the refund nor issues the index again.
#[test]
fn a_restore_born_after_the_spent_note_recovers_the_refund_key() {
    let (mut st, _) = ironwood_funded_wallet();
    let born = st.latest_cached_block().unwrap().chain_state().clone();
    let birthday = zcash_client_backend::data_api::AccountBirthday::from_parts(born, None);
    st.generate_and_scan_empty_blocks(1);
    let pays = vec![payment(&p2pkh(7), 500_000, None)];
    let (_, txid, mined) = send(&mut st, pays, &refund_memo(3));
    assert!(spends_owned_note(&st, txid));
    assert!(birthday.height() < mined);

    let restored = restore_through_funding(&mut st, &birthday, &[txid], mined);
    assert!(!spends_owned_note(&st, txid));
    recover_memos(&mut st, restored);
    assert_eq!(refund_keys(&st), [(3, u32::from(mined), true)]);
    let db = st.wallet_mut().db_mut();
    assert!(lookup_pending(db, restored));
    let next = reserve_refund(db, restored, mined).unwrap().unwrap();
    assert_eq!(next.key_id().index(), 4);
}

/// Mines and scans `memo` on a payment from a wallet this seed does not hold to the test
/// account's internal address, as a viewing-key holder could send, and stores its full
/// transaction. Returns the height that mined it.
fn forge_internal_memo(st: &mut State, memo: &MemoBytes) -> BlockHeight {
    let network = *st.network();
    let internal = parent(st).address_at(0u32, Scope::Internal);
    let tx = external_payment(internal, memo);
    let (height, _) = st.generate_next_block_from_tx(1, &tx);
    st.scan_cached_blocks(height, 1);
    decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, Some(height)).unwrap();
    let stored: Vec<u8> = value(
        st.wallet().conn(),
        "SELECT n.memo FROM ironwood_received_notes n JOIN transactions t
         ON t.id_tx = n.transaction_id WHERE t.txid = ?1 AND n.recipient_key_scope = 1",
        [tx.txid().as_ref()],
    );
    assert_eq!(stored, memo.as_slice());
    height
}

/// A viewing-key holder can pay the wallet's internal address with a refund memo naming the
/// last index. Registering it would exhaust the refund index space, so a memo further than
/// the gap above the highest known refund index is ignored, and issuance continues.
#[test]
fn a_forged_refund_memo_far_above_known_indexes_is_ignored() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let height = forge_internal_memo(&mut st, &refund_memo(u64::MAX));
    recover_memos(&mut st, account);
    assert!(refund_keys(&st).is_empty());
    let next = reserve_refund(st.wallet_mut().db_mut(), account, height);
    assert_eq!(next.unwrap().unwrap().key_id().index(), 0);
}

/// A forged memo within the gap only marks its index used, and issuance continues above it.
#[test]
fn a_forged_refund_memo_within_the_gap_only_marks_its_index_used() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let height = forge_internal_memo(&mut st, &refund_memo(5));
    recover_memos(&mut st, account);
    assert_eq!(refund_keys(&st), [(5, u32::from(height), true)]);
    let next = reserve_refund(st.wallet_mut().db_mut(), account, height);
    assert_eq!(next.unwrap().unwrap().key_id().index(), 6);
}

/// A device reserves more refund keys than the gap without funding them, then funds the
/// next index from a note a restore also sees. That spend proves the memo is the wallet's
/// own, so the restore recovers the index although it is beyond the gap.
#[test]
fn an_own_spend_recovers_a_refund_memo_beyond_the_gap() {
    let (mut st, _) = ironwood_funded_wallet();
    let account = st.test_account().cloned().unwrap();
    let tip = st.wallet().chain_height().unwrap().unwrap();
    let deposit = p2pkh(7).encode(st.network());
    let now = clock_now();
    let db = st.wallet_mut().db_mut();
    let key = (0..=101)
        .map(|_| reserve_refund(db, account.id(), tip).unwrap().unwrap())
        .last()
        .unwrap();
    let index = key.key_id().index();
    assert_eq!(index, 101);
    db.record_refund_operation(account.id(), index, &deposit, now + 3_600, now)
        .unwrap();
    let memo = db
        .refund_funding_memo(account.id(), index, &deposit)
        .unwrap();
    let pays = vec![payment(&p2pkh(7), 100_000, None)];
    let (_, txid, mined) = send(&mut st, pays, &memo);

    let restored = restore_through_funding(&mut st, account.birthday(), &[txid], mined);
    assert!(spends_owned_note(&st, txid));
    recover_memos(&mut st, restored);
    assert_eq!(refund_keys(&st), [(101, u32::from(mined), true)]);
    let next = reserve_refund(st.wallet_mut().db_mut(), restored, mined);
    assert_eq!(next.unwrap().unwrap().key_id().index(), 102);
}

/// Another device funded refund indexes 0, 90 and 180, each within the gap of the one
/// before, but mined 180 first and 0 last. A restore recovers all three in one call, since
/// accepting 90 brings 180 within the gap, and likewise when 90 and 180 share a block.
#[test]
fn spaced_refund_memos_from_another_device_are_recovered_in_any_order() {
    let (mut st, _) = ironwood_funded_wallet();
    let account = st.test_account().cloned().unwrap();
    // One confirmed note for each funding transaction.
    let fvk = parent(&st);
    for _ in 0..2 {
        pay(&mut st, &fvk, 1_000_000);
    }
    st.generate_and_scan_empty_blocks(5);
    let funded: Vec<(TxId, BlockHeight)> = [180, 90, 0]
        .into_iter()
        .map(|index| {
            let pays = vec![payment(&p2pkh(7), 100_000, None)];
            let (_, txid, mined) = send(&mut st, pays, &refund_memo(index));
            (txid, mined)
        })
        .collect();
    let txids: Vec<TxId> = funded.iter().map(|(txid, _)| *txid).collect();
    let mined = funded.last().unwrap().1;
    let restored = restore_through_funding(&mut st, account.birthday(), &txids, mined);
    recover_memos(&mut st, restored);
    let at = |i: usize| u32::from(funded[i].1);
    let expected = vec![(0, at(2), true), (90, at(1), true), (180, at(0), true)];
    assert_eq!(refund_keys(&st), expected);

    // 90 and 180 mined together are taken in index order within the block.
    exec(st.wallet().conn(), "DELETE FROM ironwood_one_time_keys", []);
    exec(
        st.wallet().conn(),
        "UPDATE transactions SET mined_height = ?1, block = ?1,
             min_observed_height = MIN(min_observed_height, ?1) WHERE txid = ?2",
        rusqlite::params![at(0), txids[1].as_ref()],
    );
    recover_memos(&mut st, restored);
    let expected = vec![(0, at(2), true), (90, at(0), true), (180, at(0), true)];
    assert_eq!(refund_keys(&st), expected);
    let next = reserve_refund(st.wallet_mut().db_mut(), restored, mined);
    assert_eq!(next.unwrap().unwrap().key_id().index(), 181);
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
/// While public lookups are allowed, a funding transaction flagged as having transparent
/// outputs takes the public path for its history first, as any such transaction does.
/// Under `PrivateRequired`, which every real funding transaction meets because it pays
/// a transparent deposit, the record's memo is stored at once.
#[test]
fn refund_memo_over_pir_restores_its_key_without_the_raw_transaction() {
    use zcash_client_backend::data_api::{
        enhance_pir::{
            EnhancePirRead, EnhancePirWork, EnhancePirWrite, EnhanceRecord, EnhanceRecordParts,
            EnhanceTransactionMetadata, EnhancementMode, TransactionEnhancementWork,
        },
        transparent_ledger::{TransparentLedgerMode, TransparentLedgerWrite},
    };

    for (flagged, private) in [(true, false), (false, false), (true, true)] {
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
        let db = st.wallet_mut().db_mut();
        if private {
            db.set_transparent_ledger_mode(TransparentLedgerMode::PrivateRequired);
            db.apply_transparent_policy(TransparentLedgerMode::PrivateRequired)
                .unwrap();
        }
        db.set_enhancement_mode(EnhancementMode::PrivateIronwood);
        st.wallet_mut().update_chain_tip(mined).unwrap();
        let blocks = u32::from(mined) - u32::from(first) + 1;
        st.scan_cached_blocks(first, blocks as usize);
        st.wallet_mut()
            .db_mut()
            .set_one_time_recovery_enabled(restored, true)
            .unwrap();

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
        let public = flagged && !private;
        assert_eq!(memo_stored, !public, "flagged={flagged} private={private}");
        let work = st.wallet().db().transaction_enhancement_work().unwrap();
        assert_eq!(
            work.iter()
                .any(|w| matches!(w, TransactionEnhancementWork::Public(p) if p.txid() == txid)),
            public,
            "flagged={flagged} private={private}"
        );
        if public {
            decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, Some(mined)).unwrap();
        }
        // Storing the memo registers its key, by private enhancement or full retrieval.
        assert_eq!(refund_keys(&st), [(7, u32::from(mined), true)]);
    }
}

/// A quote binds only to a refund key reserved in this account, and the key to that
/// quote's deposit alone. Funding, not the quote, later queues the key's history for PIR.
#[test]
fn refund_quote_needs_a_reserved_refund_key_and_a_canonical_transparent_deposit() {
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
        reserve_refund(db, account, tip).unwrap().unwrap();
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
}

/// Whether one of `account`'s keys is registered for a lookup not done yet, or a refund key
/// waits for a filter re-check from its funding height.
fn lookup_pending(db: &Db, account: AccountUuid) -> bool {
    value(
        &db.conn,
        "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_lookups l
             JOIN ironwood_one_time_keys k ON k.id = l.one_time_key_id
             JOIN accounts a ON a.id = k.account_id
             WHERE a.uuid = ?1 AND l.target_height IS NOT NULL)
         OR EXISTS(SELECT 1 FROM ironwood_one_time_keys k JOIN accounts a ON a.id = k.account_id
             WHERE a.uuid = ?1 AND k.covered_height < k.funding_height)",
        [account.0],
    )
}

/// Disabling receiver discovery does not discard independently authenticated outgoing details.
#[test]
fn outgoing_one_time_payment_details_survive_disabled_discovery() {
    for enabled in [false, true] {
        let mut desktop = scanned_wallet();
        let account = desktop.test_account().unwrap().id();
        let start = desktop.sapling_activation_height();
        let key = reserve(
            desktop.wallet_mut().db_mut(),
            account,
            Purpose::Receive,
            start,
        )
        .unwrap();
        let (mut phone, _) = ironwood_funded_wallet();
        assert_eq!(parent(&phone), parent(&desktop));
        let sender = phone.test_account().cloned().unwrap();
        let memo = MemoBytes::from_bytes(b"self payment").unwrap();
        let to = payment(&unified(key.receiver()), 50_000, Some(&memo));
        let (_, txid) = transfer(
            &mut phone,
            (sender.id(), sender.usk()),
            vec![to],
            (None, ShieldedPool::Orchard),
        );
        let transaction = phone
            .wallet()
            .get_transaction(txid.unwrap())
            .unwrap()
            .unwrap();
        desktop
            .wallet_mut()
            .db_mut()
            .set_one_time_recovery_enabled(account, enabled)
            .unwrap();
        let network = *desktop.network();
        decrypt_and_store_transaction(&network, desktop.wallet_mut(), &transaction, None).unwrap();
        let sent: (u64, Vec<u8>, String) = desktop.wallet().conn().query_row(
            "SELECT n.value,n.memo,n.to_address FROM sent_notes n JOIN transactions t ON t.id_tx=n.transaction_id
             WHERE t.txid=?1 AND n.output_pool=4 AND n.value=50000",
            [transaction.txid().as_ref()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
        assert_eq!(sent.0, 50_000);
        assert_eq!(sent.1, memo.as_slice());
        assert!(!sent.2.is_empty());
        let received: u64 = value(
            desktop.wallet().conn(),
            "SELECT COUNT(*) FROM ironwood_received_notes WHERE one_time_key_id IS NOT NULL",
            [],
        );
        assert_eq!(received, 0);
    }
}

/// Refund memos naming 150 and then 100, funded after a restore's birthday: 150 spends a
/// note from before the birthday, so the restore cannot prove it funded it, while 100
/// spends notes received after the birthday, which it owns. Returns the wallet restored with only 150's
/// transaction stored and scanned through its block, the restored account, and 100's
/// transaction and block.
fn memo_150_then_100() -> (
    State,
    AccountUuid,
    zcash_primitives::transaction::Transaction,
    BlockHeight,
) {
    let (mut st, _) = ironwood_funded_wallet();
    let born = st.latest_cached_block().unwrap().chain_state().clone();
    let birthday = zcash_client_backend::data_api::AccountBirthday::from_parts(born, None);
    st.generate_and_scan_empty_blocks(1);
    let pays = || vec![payment(&p2pkh(7), 100_000, None)];
    let (_, first, first_mined) = send(&mut st, pays(), &refund_memo(150));
    let fvk = parent(&st);
    pay(&mut st, &fvk, 1_000_000);
    st.generate_and_scan_empty_blocks(5);
    let (_, second, second_mined) = send(&mut st, pays(), &refund_memo(100));
    let later = st.wallet().get_transaction(second).unwrap().unwrap();
    let restored = restore_through_funding(&mut st, &birthday, &[first], first_mined);
    (st, restored, later, second_mined)
}

/// The rows waiting in the pending memo queue.
fn pending_memos(st: &State) -> u32 {
    value(
        st.wallet().conn(),
        "SELECT COUNT(*) FROM ironwood_one_time_pending_memos",
        [],
    )
}

/// R150 is far past every known refund index and unproven, so it waits in the queue, and
/// processing that unchanged queue again adds no work. Learning R100 brings R150 within
/// the gap, so both are accepted and the queue empties.
#[test]
fn a_memo_past_the_gap_waits_until_a_lower_index_is_learned() {
    let (mut st, restored, later, mined) = memo_150_then_100();
    assert!(refund_keys(&st).is_empty());
    assert_eq!(pending_memos(&st), 1);
    let work = st.wallet().db().one_time_new_work().unwrap();
    tx(st.wallet_mut().db_mut(), |c, p| {
        store::restore::recovery::recover_refund_memos(c, p, restored)
    })
    .unwrap();
    st.scan_cached_blocks(mined, 1);
    assert_eq!(st.wallet().db().one_time_new_work().unwrap(), work);
    assert_eq!(pending_memos(&st), 1);
    let network = *st.network();
    decrypt_and_store_transaction(&network, st.wallet_mut(), &later, Some(mined)).unwrap();
    let indexes: Vec<u64> = refund_keys(&st).iter().map(|(i, _, _)| *i).collect();
    assert_eq!(indexes, [100, 150]);
    assert_eq!(pending_memos(&st), 0);
}

/// A funding memo enhancement stores after the last block batch registers its refund key
/// at once, and the new-work counter goes up in the same transaction.
#[test]
fn a_memo_stored_after_the_last_batch_bumps_the_new_work_counter() {
    let (mut st, _, later, mined) = memo_150_then_100();
    st.scan_cached_blocks(mined, 1);
    let work = st.wallet().db().one_time_new_work().unwrap();
    let network = *st.network();
    decrypt_and_store_transaction(&network, st.wallet_mut(), &later, Some(mined)).unwrap();
    assert!(refund_keys(&st).iter().any(|(index, _, _)| *index == 100));
    assert!(st.wallet().db().one_time_new_work().unwrap() > work);
}

/// A memo queued while its transaction was unmined is retried as soon as storing the
/// transaction again records its block, without waiting for a block batch.
#[test]
fn storing_a_queued_memos_transaction_again_retries_it() {
    let (mut st, first) = ironwood_funded_wallet();
    let account = st.test_account().cloned().unwrap();
    let network = *st.network();
    let pays = vec![payment(&p2pkh(7), 100_000, None)];
    let (_, txid, mined) = send(&mut st, pays, &refund_memo(7));
    let tx = st.wallet().get_transaction(txid).unwrap().unwrap();
    let seed = SecretVec::new(st.test_seed().unwrap().expose_secret().clone());
    let _old_wallet = st.reset();
    let (restored, _) = st
        .wallet_mut()
        .create_account("restored", &seed, account.birthday(), None)
        .unwrap();
    st.wallet_mut().update_chain_tip(mined).unwrap();
    let blocks = u32::from(mined) - u32::from(first);
    st.scan_cached_blocks(first, blocks as usize);
    st.wallet_mut()
        .db_mut()
        .set_one_time_recovery_enabled(restored, true)
        .unwrap();
    decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, None).unwrap();
    assert!(refund_keys(&st).is_empty(), "an unmined memo waits");
    decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, Some(mined)).unwrap();
    assert_eq!(refund_keys(&st), [(7, u32::from(mined), true)]);
}

/// The pending memo query starts from the queue, not from the account's note history.
#[test]
fn the_pending_memo_query_is_driven_by_the_queue() {
    let (st, _) = ironwood_funded_wallet();
    let plan: Vec<(i64, i64, i64, String)> = rows(
        st.wallet().conn(),
        &format!(
            "EXPLAIN QUERY PLAN {}",
            store::restore::recovery::PENDING_MEMOS
        ),
        [1],
    );
    assert_eq!(plan[0].3, "SCAN q", "{plan:?}");
}

/// Whether `account` has one-time recovery enabled.
fn enabled(st: &State, account: AccountUuid) -> bool {
    let db = st.wallet().db();
    db.one_time_recovery(account, 0, None).unwrap().enabled
}

/// Whether `account`'s use marker is set.
fn used(st: &State, account: AccountUuid) -> bool {
    let db = st.wallet().db();
    db.one_time_recovery(account, 0, None).unwrap().used
}

/// A restored wallet that never enabled recovery, holding `memo` on an unmined payment to
/// its internal address, stored. Returns the transaction.
fn unmined_internal_memo(
    memo: &MemoBytes,
) -> (
    State,
    AccountUuid,
    zcash_primitives::transaction::Transaction,
) {
    let mut st = restored_wallet();
    let account = st.test_account().unwrap().id();
    let network = *st.network();
    let tx = external_payment(parent(&st).address_at(0u32, Scope::Internal), memo);
    decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, None).unwrap();
    (st, account, tx)
}

/// A refund memo that a block batch mines on a never-enabled account is evidence of a swap.
/// The batch's transaction sets the use marker, enables recovery, registers the refund key
/// and queues its bootstrap lookup from the funding height, and a rolled back transaction
/// leaves none of it.
#[test]
fn a_mined_refund_memo_enables_a_never_enabled_account_in_one_transaction() {
    let (mut st, account, tx) = unmined_internal_memo(&refund_memo(0));
    assert_eq!(pending_memos(&st), 1);
    let (mined, _) = st.generate_next_block_from_tx(1, &tx);
    let aborted: Result<(), SqliteClientError> = super::tx(st.wallet_mut().db_mut(), |c, p| {
        c.execute(
            "UPDATE transactions SET mined_height = ?1 WHERE txid = ?2",
            rusqlite::params![u32::from(mined), tx.txid().as_ref()],
        )?;
        store::restore::recovery::recover_memo_accounts(c, p, None)?;
        Err(corrupt("test rollback"))
    });
    assert!(aborted.is_err());
    assert!(!enabled(&st, account) && !used(&st, account) && refund_keys(&st).is_empty());
    assert_eq!(pending_memos(&st), 1);
    let work = st.wallet().db().one_time_new_work().unwrap();
    st.scan_cached_blocks(mined, 1);
    assert!(enabled(&st, account) && used(&st, account));
    assert_eq!(refund_keys(&st), [(0, u32::from(mined), true)]);
    let bootstrap = store::restore::tests::discovery::work_of(&st, KeyId::new(Purpose::Refund, 0));
    assert_eq!(bootstrap.from, mined);
    assert!(st.wallet().db().one_time_new_work().unwrap() > work);
    assert_eq!(pending_memos(&st), 0);
}

/// A refund memo whose transaction is unmined enables nothing and stays queued through
/// block batches that don't mine it, until the batch that mines it enables the account.
#[test]
fn an_unmined_refund_memo_waits_for_the_batch_that_mines_it() {
    let (mut st, account, tx) = unmined_internal_memo(&refund_memo(0));
    st.generate_and_scan_empty_blocks(1);
    assert!(!enabled(&st, account) && !used(&st, account) && refund_keys(&st).is_empty());
    assert_eq!(pending_memos(&st), 1);
    let (mined, _) = st.generate_next_block_from_tx(1, &tx);
    st.scan_cached_blocks(mined, 1);
    assert!(enabled(&st, account));
    assert_eq!(refund_keys(&st), [(0, u32::from(mined), true)]);
}

/// A memo with the refund prefix that doesn't decode enables nothing, mined or not, and
/// storing it already removes it from the queue.
#[test]
fn a_malformed_refund_memo_enables_nothing_and_leaves_the_queue() {
    let mut invalid = RefundMemo::new(0).encode();
    invalid[5] = 0xff;
    let (mut st, account, tx) = unmined_internal_memo(&MemoBytes::from_bytes(&invalid).unwrap());
    assert_eq!(pending_memos(&st), 0);
    let (mined, _) = st.generate_next_block_from_tx(1, &tx);
    st.scan_cached_blocks(mined, 1);
    assert!(!enabled(&st, account) && !used(&st, account) && refund_keys(&st).is_empty());
    assert_eq!(pending_memos(&st), 0);
}

/// A mined memo the 100-index gap rule defers registers no key, but it is still evidence of
/// a swap: it enables the account and sets the marker, and stays queued.
#[test]
fn a_gap_deferred_memo_enables_the_account_and_sets_the_marker() {
    let (mut st, account, tx) = unmined_internal_memo(&refund_memo(150));
    let (mined, _) = st.generate_next_block_from_tx(1, &tx);
    st.scan_cached_blocks(mined, 1);
    assert!(enabled(&st, account) && used(&st, account));
    assert!(refund_keys(&st).is_empty());
    assert_eq!(pending_memos(&st), 1);
}

/// Recording the wallet's own funding of a refund key sets the use marker, before the
/// funding transaction is mined.
#[test]
fn own_refund_funding_sets_the_marker() {
    let (mut st, _) = ironwood_funded_wallet();
    let account = st.test_account().unwrap().id();
    let tip = st.wallet().chain_height().unwrap().unwrap();
    let deposit = p2pkh(7).encode(st.network());
    let now = clock_now();
    let db = st.wallet_mut().db_mut();
    let index = reserve_refund(db, account, tip)
        .unwrap()
        .unwrap()
        .key_id()
        .index();
    db.record_refund_operation(account, index, &deposit, now + 3_600, now)
        .unwrap();
    let memo = db.refund_funding_memo(account, index, &deposit).unwrap();
    exec(
        st.wallet().conn(),
        "UPDATE ironwood_one_time_recovery SET used = 0",
        [],
    );
    let (_, txid) = try_send(&mut st, vec![payment(&p2pkh(7), 100_000, None)], &memo);
    txid.unwrap();
    assert!(used(&st, account));
}
