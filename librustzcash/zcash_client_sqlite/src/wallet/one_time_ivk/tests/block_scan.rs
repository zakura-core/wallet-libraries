//! Real compact-note scanning through exact-block discovery permissions.
use super::*;
use std::cell::Cell;
use zcash_client_backend::data_api::{
    chain::{ChainState, scan_cached_blocks_with_recovery},
    one_time_ivk::recovery::{BlockHints, OneTimeRecoveryWrite},
};

/// Mines a real compact note and returns the exact block hint for its receiver.
fn payment_hint(st: &mut State, key: KeyId) -> BlockHints<AccountUuid> {
    let recipient = IronwoodFvk(derive(st, key));
    let (height, _, _) = st.generate_next_block(
        &recipient,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(50_000),
    );
    BlockHints {
        block: ChainPoint {
            height,
            hash: st.latest_cached_block().unwrap().chain_state().block_hash(),
        },
        keys: vec![(st.test_account().unwrap().id(), key)],
    }
}

/// Counts persisted exact-key whole-block scan evidence.
fn evidence(st: &State) -> u32 {
    value(
        st.wallet().conn(),
        "SELECT COUNT(*) FROM ironwood_key_scans",
        [],
    )
}

/// A ready receive hint scans only its exact block, including when a later block pays the same key.
#[test]
fn block_hint_does_not_create_a_forward_watch() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    check_seen(st.wallet_mut().db_mut(), account);
    let key = KeyId::new(Purpose::Receive, 0);
    let first = payment_hint(&mut st, key);
    let second = payment_hint(&mut st, key);
    st.scan_cached_blocks_with_recovery(first.block.height, 2, std::slice::from_ref(&first));
    assert_eq!(unspent_keys(&st, second.block.height), vec![Some(key)]);
    assert_eq!(evidence(&st), 1);
    // A delayed filter can replay its own block without widening scanning to any other block.
    st.scan_cached_blocks_with_recovery(second.block.height, 1, std::slice::from_ref(&second));
    assert_eq!(
        unspent_keys(&st, second.block.height),
        vec![Some(key), Some(key)]
    );
    assert_eq!(evidence(&st), 2);
}

/// Disabling between key capture and note commit fences discovery while ordinary receipts commit.
#[test]
fn disabled_during_scan_preserves_ordinary_progress() {
    for resume in [false, true] {
        let mut st = ironwood_wallet();
        let account = st.test_account().unwrap().id();
        check_seen(st.wallet_mut().db_mut(), account);
        let key = KeyId::new(Purpose::Receive, 0);
        let hint = payment_hint(&mut st, key);
        let ordinary = IronwoodFvk(parent(&st));
        let (last, _, _) = st.generate_next_block(
            &ordinary,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(70_000),
        );
        let network = *st.network();
        let path = st.wallet().data_file_path();
        let mut scanning = WalletDb::for_path(path, network, test_clock(), test_rng()).unwrap();
        let source = super::scanning::DuringScan {
            inner: st.cache(),
            at: 2,
            reads: Cell::new(0),
            run: || {
                let mut db = WalletDb::for_path(path, network, test_clock(), test_rng()).unwrap();
                db.set_one_time_recovery_enabled(account, false).unwrap();
                if resume {
                    db.set_one_time_recovery_enabled(account, true).unwrap();
                }
            },
        };
        scan_cached_blocks_with_recovery(
            &network,
            &source,
            &mut scanning,
            hint.block.height,
            &ChainState::empty(hint.block.height - 1, BlockHash([0; 32])),
            2,
            std::slice::from_ref(&hint),
        )
        .unwrap();
        assert_eq!(unspent_keys(&st, last), vec![None]);
        assert_eq!(
            st.wallet()
                .block_fully_scanned()
                .unwrap()
                .unwrap()
                .block_height(),
            last
        );
        assert_eq!(evidence(&st), 0);
        st.wallet_mut()
            .set_one_time_recovery_enabled(account, true)
            .unwrap();
        st.scan_cached_blocks_with_recovery(hint.block.height, 1, &[hint]);
        assert_eq!(unspent_keys(&st, last).len(), 2);
        assert_eq!(evidence(&st), 1);
    }
}

/// A locally submitted operation watches without a filter, and the original deadline stops it.
#[test]
fn local_watch_scans_without_network_and_expires() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key = reserve_refund(st.wallet_mut().db_mut(), account, start())
        .unwrap()
        .unwrap()
        .key_id();
    let now = clock_now();
    let seen = empty_seen(now);
    st.wallet_mut()
        .db_mut()
        .begin_refund_operation(account, key.index(), now + 60, now, Some(&seen))
        .unwrap()
        .unwrap();
    let hint = payment_hint(&mut st, key);
    st.scan_cached_blocks_with_recovery(hint.block.height, 1, &[]);
    assert_eq!(unspent_keys(&st, hint.block.height), vec![Some(key)]);
    assert_eq!(evidence(&st), 1);
    // Advance the injected wallet clock past the immutable hard limit.
    let network = *st.network();
    let path = st.wallet().data_file_path();
    let late_clock = FixedClock::new(
        std::time::UNIX_EPOCH + std::time::Duration::from_secs((now + 86461) as u64),
    );
    *st.wallet_mut().db_mut() = WalletDb::for_path(path, network, late_clock, test_rng()).unwrap();
    let late = payment_hint(&mut st, key);
    st.scan_cached_blocks_with_recovery(late.block.height, 1, &[]);
    assert_eq!(unspent_keys(&st, late.block.height), vec![Some(key)]);
    assert_eq!(evidence(&st), 1);
    st.scan_cached_blocks_with_recovery(late.block.height, 1, std::slice::from_ref(&late));
    assert_eq!(unspent_keys(&st, late.block.height).len(), 2);
}

/// Even a supplied positive hint cannot discover a note while the account is disabled.
#[test]
fn disabled_before_scan_does_not_discover() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    check_seen(st.wallet_mut().db_mut(), account);
    st.wallet_mut()
        .set_one_time_recovery_enabled(account, false)
        .unwrap();
    let hint = payment_hint(&mut st, KeyId::new(Purpose::Receive, 0));
    st.scan_cached_blocks_with_recovery(hint.block.height, 1, std::slice::from_ref(&hint));
    assert!(unspent_keys(&st, hint.block.height).is_empty());
    assert_eq!(evidence(&st), 0);
    assert_eq!(
        st.wallet()
            .block_fully_scanned()
            .unwrap()
            .unwrap()
            .block_height(),
        hint.block.height
    );
}

/// Repair while disabled can re-mine a known receipt but cannot admit another payment to its key.
#[test]
fn disabled_reorg_repair_keeps_only_known_receipts() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key = KeyId::new(Purpose::Receive, 0);
    let known = payment_hint(&mut st, key);
    st.scan_cached_blocks_with_recovery(known.block.height, 1, std::slice::from_ref(&known));
    let later = payment_hint(&mut st, key);
    st.truncate_to_height_retaining_cache(known.block.height - 1);
    st.wallet_mut()
        .set_one_time_recovery_enabled(account, false)
        .unwrap();
    st.scan_cached_blocks_with_recovery(known.block.height, 2, &[]);
    assert_eq!(unspent_keys(&st, later.block.height), vec![Some(key)]);
    assert_eq!(evidence(&st), 0);
    let mined: u32 = value(
        st.wallet().conn(),
        "SELECT mined_height FROM transactions WHERE id_tx=(SELECT transaction_id FROM ironwood_received_notes LIMIT 1)",
        [],
    );
    assert_eq!(mined, u32::from(known.block.height));
}

/// Whole-block evidence covers both notes and settles a delayed filter after a database restart.
#[test]
fn complete_scan_settles_delayed_match_after_restart() {
    use zcash_client_backend::data_api::{
        one_time_ivk::recovery::{FilterJudgment, History, OneTimeRecoveryRead},
        testing::FakeCompactOutput,
    };
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
    let recipient = IronwoodFvk(derive(&st, key));
    let (height, _, _) = st.generate_next_block_multi(&[
        FakeCompactOutput::new(
            &recipient,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(40_000),
        ),
        FakeCompactOutput::new(
            &recipient,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(50_000),
        ),
    ]);
    let block = ChainPoint {
        height,
        hash: st.latest_cached_block().unwrap().chain_state().block_hash(),
    };
    st.scan_cached_blocks_with_recovery(
        height,
        1,
        &[BlockHints {
            block,
            keys: vec![(account, key)],
        }],
    );
    assert_eq!(unspent_keys(&st, height), vec![Some(key), Some(key)]);
    assert_eq!(evidence(&st), 1);
    reopen(&mut st);
    st.wallet_mut()
        .prepare_one_time_recovery(account, 1024, clock_now())
        .unwrap();
    let work = st
        .wallet()
        .one_time_filter_work(account, 1024)
        .unwrap()
        .unwrap();
    assert!(
        st.wallet_mut()
            .record_one_time_filters(
                account,
                &work,
                &[FilterJudgment {
                    block,
                    hits: vec![key]
                }]
            )
            .unwrap()
    );
    assert!(
        st.wallet()
            .one_time_pending_matches(account, 1024)
            .unwrap()
            .is_empty()
    );
}

/// Pausing one account during a shared block scan leaves another account's discovery authorized.
#[test]
fn account_toggle_does_not_cancel_other_accounts() {
    use zcash_client_backend::data_api::testing::FakeCompactOutput;
    let mut st = ironwood_wallet();
    let first = st.test_account().unwrap().id();
    let (second, usk) = st.create_account_from_test_seed("second");
    for account in [first, second] {
        check_seen(st.wallet_mut().db_mut(), account);
    }
    let key = KeyId::new(Purpose::Receive, 0);
    let one = IronwoodFvk(derive(&st, key));
    let two = IronwoodFvk(key.derive(&FullViewingKey::from(usk.orchard())).unwrap());
    let (height, _, _) = st.generate_next_block_multi(&[
        FakeCompactOutput::new(
            &one,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(40_000),
        ),
        FakeCompactOutput::new(
            &two,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(50_000),
        ),
    ]);
    let block = ChainPoint {
        height,
        hash: st.latest_cached_block().unwrap().chain_state().block_hash(),
    };
    let network = *st.network();
    let path = st.wallet().data_file_path();
    let mut scanning = WalletDb::for_path(path, network, test_clock(), test_rng()).unwrap();
    let source = super::scanning::DuringScan {
        inner: st.cache(),
        at: 2,
        reads: Cell::new(0),
        run: || {
            WalletDb::for_path(path, network, test_clock(), test_rng())
                .unwrap()
                .set_one_time_recovery_enabled(first, false)
                .unwrap();
        },
    };
    scan_cached_blocks_with_recovery(
        &network,
        &source,
        &mut scanning,
        height,
        &ChainState::empty(height - 1, BlockHash([0; 32])),
        1,
        &[BlockHints {
            block,
            keys: vec![(first, key), (second, key)],
        }],
    )
    .unwrap();
    let owners: Vec<AccountUuid> = st
        .wallet()
        .conn()
        .prepare(
            "SELECT a.uuid FROM ironwood_received_notes n JOIN accounts a ON a.id=n.account_id",
        )
        .unwrap()
        .query_map([], |r| r.get::<_, uuid::Uuid>(0).map(AccountUuid))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(owners, vec![second]);
    assert_eq!(evidence(&st), 1);
}

/// A refused receipt must not leave a later in-batch spend visible as a wallet transaction.
#[test]
fn stale_receipt_does_not_leave_a_phantom_spend() {
    for ordinary_change in [false, true] {
        let mut st = ironwood_wallet();
        let account = st.test_account().unwrap().id();
        check_seen(st.wallet_mut().db_mut(), account);
        let key = KeyId::new(Purpose::Receive, 0);
        let recipient = IronwoodFvk(derive(&st, key));
        let amount = Zatoshis::const_from_u64(50_000);
        let (height, _, nf) =
            st.generate_next_block(&recipient, AddressType::DefaultExternal, amount);
        let block = ChainPoint {
            height,
            hash: st.latest_cached_block().unwrap().chain_state().block_hash(),
        };
        let ordinary = IronwoodFvk(parent(&st));
        st.generate_next_block_spending(
            if ordinary_change {
                &ordinary
            } else {
                &recipient
            },
            (nf, amount),
            unified(foreign_receiver()),
            Zatoshis::const_from_u64(if ordinary_change { 40_000 } else { 50_000 }),
        );
        let network = *st.network();
        let path = st.wallet().data_file_path();
        let mut scanning = WalletDb::for_path(path, network, test_clock(), test_rng()).unwrap();
        let source = super::scanning::DuringScan {
            inner: st.cache(),
            at: 2,
            reads: Cell::new(0),
            run: || {
                WalletDb::for_path(path, network, test_clock(), test_rng())
                    .unwrap()
                    .set_one_time_recovery_enabled(account, false)
                    .unwrap();
            },
        };
        scan_cached_blocks_with_recovery(
            &network,
            &source,
            &mut scanning,
            height,
            &ChainState::empty(height - 1, BlockHash([0; 32])),
            2,
            &[BlockHints {
                block,
                keys: vec![(account, key)],
            }],
        )
        .unwrap();
        assert_eq!(
            value::<u32>(st.wallet().conn(), "SELECT COUNT(*) FROM transactions", []),
            u32::from(ordinary_change)
        );
        assert_eq!(evidence(&st), 0);
        assert_eq!(
            st.wallet()
                .block_fully_scanned()
                .unwrap()
                .unwrap()
                .block_height(),
            height + 1
        );
        st.wallet_mut()
            .set_one_time_recovery_enabled(account, true)
            .unwrap();
        st.scan_cached_blocks_with_recovery(
            height,
            1,
            &[BlockHints {
                block,
                keys: vec![(account, key)],
            }],
        );
        assert_eq!(
            value::<u32>(
                st.wallet().conn(),
                "SELECT COUNT(*) FROM ironwood_received_notes WHERE one_time_key_id IS NOT NULL",
                []
            ),
            1
        );
        assert_eq!(
            unspent_keys(&st, height + 1),
            if ordinary_change { vec![None] } else { vec![] }
        );
    }
}
