//! Full transactions obey discovery fences without losing known receipts.
use super::*;
use zcash_client_backend::{
    data_api::{
        DecryptedTransaction,
        one_time_ivk::recovery::{
            OneTimeRecoveryRead, OneTimeRecoveryWrite, OneTimeTransactionScan,
        },
        wallet::decrypt_and_store_transaction_with_one_time_ivks,
    },
    decrypt_transaction_with_one_time_ivks,
};
use zcash_primitives::transaction::Transaction as ZcashTransaction;
use zcash_protocol::memo::MemoBytes;

/// Creates a local live refund operation and an externally funded real payment.
fn fixture() -> (State, OneTimeKey, ZcashTransaction) {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let from = st.wallet().chain_height().unwrap().unwrap() + 1;
    let key = reserve_refund(st.wallet_mut().db_mut(), account, from)
        .unwrap()
        .unwrap();
    let now = clock_now();
    st.wallet_mut()
        .db_mut()
        .begin_refund_operation(
            account,
            key.key_id().index(),
            now + 60,
            now,
            Some(&empty_seen(now)),
        )
        .unwrap()
        .unwrap();
    let tx = external_payment(key.receiver(), &MemoBytes::from_bytes(b"refund").unwrap());
    (st, key, tx)
}

/// Captures and decrypts without committing, allowing settings to change during the operation.
fn decrypt<'a>(
    st: &mut State,
    tx: &'a ZcashTransaction,
) -> DecryptedTransaction<'a, ZcashTransaction, AccountUuid> {
    let scan = st
        .wallet_mut()
        .prepare_one_time_transaction_scan(tx.txid(), None)
        .unwrap();
    let ufvks = st.wallet().get_unified_full_viewing_keys().unwrap();
    decrypt_transaction_with_one_time_ivks(
        st.network(),
        None,
        st.wallet().chain_height().unwrap(),
        tx,
        &ufvks,
        scan.keys,
    )
    .with_one_time_permits(scan.permits)
}

/// Counts authenticated one-time notes independently of mined status or witnesses.
fn receipts(st: &State) -> u64 {
    value(
        st.wallet().conn(),
        "SELECT COUNT(*) FROM ironwood_received_notes WHERE one_time_key_id IS NOT NULL",
        [],
    )
}

/// A live local swap can learn its full receipt without filters, but cannot claim whole-block evidence.
#[test]
fn live_full_receipt_does_not_settle_a_whole_block() {
    let (mut st, _, payment) = fixture();
    let decoded = decrypt(&mut st, &payment);
    assert_eq!(decoded.ironwood_outputs().len(), 1);
    st.wallet_mut().store_decrypted_tx(decoded).unwrap();
    assert_eq!(receipts(&st), 1);
    assert_eq!(
        value::<u64>(
            st.wallet().conn(),
            "SELECT COUNT(*) FROM ironwood_key_scans",
            []
        ),
        0
    );
    assert_eq!(
        value::<u64>(
            st.wallet().conn(),
            "SELECT COUNT(*) FROM ironwood_one_time_keys WHERE watch_closed_height IS NOT NULL",
            []
        ),
        0
    );
}

/// Both pause and pause/resume revoke full receipts already decrypted by an earlier generation.
#[test]
fn full_receipt_commit_rechecks_toggle_generation() {
    for resume in [false, true] {
        let (mut st, _, payment) = fixture();
        let account = st.test_account().unwrap().id();
        let decoded = decrypt(&mut st, &payment);
        st.wallet_mut()
            .set_one_time_recovery_enabled(account, false)
            .unwrap();
        if resume {
            st.wallet_mut()
                .set_one_time_recovery_enabled(account, true)
                .unwrap();
        }
        st.wallet_mut().store_decrypted_tx(decoded).unwrap();
        assert_eq!(receipts(&st), 0);
        st.wallet_mut()
            .set_one_time_recovery_enabled(account, true)
            .unwrap();
        let network = *st.network();
        decrypt_and_store_transaction_with_one_time_ivks(&network, st.wallet_mut(), &payment, None)
            .unwrap();
        assert_eq!(receipts(&st), 1);
    }
}

/// Known-note enhancement remains available while off, without allowing a later payment to its key.
#[test]
fn disabled_full_transaction_repairs_only_known_nullifiers() {
    let (mut st, key, payment) = fixture();
    let account = st.test_account().unwrap().id();
    let decoded = decrypt(&mut st, &payment);
    st.wallet_mut().store_decrypted_tx(decoded).unwrap();
    assert_eq!(
        value::<u64>(
            st.wallet().conn(),
            "SELECT COUNT(*) FROM ironwood_received_notes WHERE one_time_key_id IS NOT NULL AND nf IS NULL",
            []
        ),
        1
    );
    exec(
        st.wallet().conn(),
        "UPDATE ironwood_received_notes SET memo=NULL WHERE one_time_key_id IS NOT NULL",
        [],
    );
    st.wallet_mut()
        .set_one_time_recovery_enabled(account, false)
        .unwrap();
    reopen(&mut st);
    let decoded = decrypt(&mut st, &payment);
    assert_eq!(decoded.ironwood_outputs().len(), 1);
    st.wallet_mut().store_decrypted_tx(decoded).unwrap();
    assert_eq!(receipts(&st), 1);
    let restored: Vec<u8> = value(
        st.wallet().conn(),
        "SELECT memo FROM ironwood_received_notes WHERE one_time_key_id IS NOT NULL",
        [],
    );
    assert_eq!(
        restored,
        MemoBytes::from_bytes(b"refund").unwrap().as_slice()
    );
    let (height, _) = st.generate_next_block_from_tx(1, &payment);
    st.scan_cached_blocks_with_recovery(height, 1, &[]);
    assert_eq!(unspent_keys(&st, height), vec![Some(key.key_id())]);
    assert_eq!(
        value::<u64>(
            st.wallet().conn(),
            "SELECT COUNT(*) FROM ironwood_received_notes WHERE nf IS NOT NULL AND commitment_tree_position IS NOT NULL",
            []
        ),
        1
    );
    let later = external_payment(key.receiver(), &MemoBytes::from_bytes(b"second").unwrap());
    // Even a caller supplying a raw old key cannot bypass the durable admission fence.
    let ufvks = st.wallet().get_unified_full_viewing_keys().unwrap();
    let decoded = decrypt_transaction_with_one_time_ivks(
        st.network(),
        None,
        st.wallet().chain_height().unwrap(),
        &later,
        &ufvks,
        [key.scanning_key],
    );
    assert_eq!(decoded.ironwood_outputs().len(), 1);
    st.wallet_mut().store_decrypted_tx(decoded).unwrap();
    assert_eq!(receipts(&st), 1);
}

/// Registration alone and expiry never authorize transaction-wide trial decryption.
#[test]
fn full_transaction_selection_requires_live_local_provenance() {
    let (mut st, key, payment) = fixture();
    let account = st.test_account().unwrap().id();
    let other = reserve_key(st.wallet_mut().db_mut(), account, Purpose::Receive, start());
    let scan = st
        .wallet_mut()
        .prepare_one_time_transaction_scan(payment.txid(), None)
        .unwrap();
    assert_eq!(scan.keys.len(), 1);
    assert_eq!(scan.keys[0].key_id(), key.key_id());
    assert_ne!(scan.keys[0].key_id(), other.key_id());
    let network = *st.network();
    let path = st.wallet().data_file_path();
    let late_clock = FixedClock::new(
        std::time::UNIX_EPOCH + std::time::Duration::from_secs((clock_now() + 86461) as u64),
    );
    *st.wallet_mut().db_mut() = WalletDb::for_path(path, network, late_clock, test_rng()).unwrap();
    let scan = st
        .wallet_mut()
        .prepare_one_time_transaction_scan(payment.txid(), None)
        .unwrap();
    assert!(scan.keys.is_empty());
}

/// A pending canonical filter match selects only its own mined block, and enhancement leaves it pending.
#[test]
fn full_transaction_filter_hint_is_exact_and_not_completion() {
    use zcash_client_backend::data_api::one_time_ivk::recovery::{FilterJudgment, History};
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    check_seen(st.wallet_mut().db_mut(), account);
    st.wallet_mut()
        .accept_one_time_history(
            account,
            History {
                genesis: [1; 32],
                archive: [2; 32],
                epoch: 0,
            },
        )
        .unwrap();
    let key = KeyId::new(Purpose::Receive, 0);
    let fvk = derive(&st, key);
    let payment = external_payment(fvk.address_at(0u32, Scope::External), &MemoBytes::empty());
    let (height, _) = st.generate_next_block_from_tx(1, &payment);
    let point = ChainPoint {
        height,
        hash: st.latest_cached_block().unwrap().chain_state().block_hash(),
    };
    st.scan_cached_blocks_with_recovery(height, 1, &[]);
    let work = st
        .wallet()
        .one_time_filter_work(account, 1024)
        .unwrap()
        .unwrap();
    st.wallet_mut()
        .record_one_time_filters(
            account,
            &work,
            &[FilterJudgment {
                block: point,
                hits: vec![key],
            }],
        )
        .unwrap();
    let wrong = st
        .wallet_mut()
        .prepare_one_time_transaction_scan(payment.txid(), Some(height + 1))
        .unwrap();
    assert!(wrong.keys.is_empty());
    let network = *st.network();
    decrypt_and_store_transaction_with_one_time_ivks(
        &network,
        st.wallet_mut(),
        &payment,
        Some(height),
    )
    .unwrap();
    assert_eq!(receipts(&st), 1);
    assert_eq!(
        st.wallet()
            .one_time_recovery_state(account)
            .unwrap()
            .unwrap()
            .pending_matches,
        1
    );
    assert_eq!(
        value::<u64>(
            st.wallet().conn(),
            "SELECT COUNT(*) FROM ironwood_key_scans",
            []
        ),
        0
    );
}
