use std::{cell::Cell, ops::Range};

use zakura_dynamic_ivk::lifecycle::{OperationStatus, ReceiptExpectation};
use zcash_client_backend::data_api::chain::{
    BlockSource, ChainState, error, scan_cached_blocks_with_dynamic_ivks,
};

use super::*;

/// Block ranges the wallet still has to scan.
fn queued(st: &State) -> Vec<Range<BlockHeight>> {
    st.wallet()
        .suggest_scan_ranges()
        .unwrap()
        .iter()
        .map(|r| r.block_range().clone())
        .collect()
}

/// A test-block recipient for `key`, derived without registering it.
fn recipient(st: &State, key: KeyId) -> IronwoodFvk {
    let parent = FullViewingKey::from(st.test_account().unwrap().usk().orchard());
    IronwoodFvk(key.derive(&parent).unwrap())
}

/// Reports a finished swap on each of `keys`, which closes them.
fn close(st: &mut State, keys: &[KeyId]) {
    let account = st.test_account().unwrap().id();
    let tip = crate::wallet::chain_tip_height(st.wallet().conn())
        .unwrap()
        .unwrap();
    let db = st.wallet_mut().db_mut();
    for key in keys {
        let finished = OperationStatus::Terminal(ReceiptExpectation::None);
        observe(db, account, *key, "swap", finished, 0).unwrap();
    }
    assert_eq!(close_at(db, account, 0, tip), keys.len());
}

#[test]
fn dynamic_ivk_scan_reopen_and_spend_into_ordinary_change() {
    scan_reopen_and_spend(false);
}

#[test]
fn closed_dynamic_keys_still_spend_into_ordinary_change() {
    scan_reopen_and_spend(true);
}

/// Scans payments to both purposes beside an ordinary note, optionally closes the
/// dynamic keys, then spends all three notes into ordinary change.
fn scan_reopen_and_spend(close_keys: bool) {
    use std::convert::Infallible;
    use zcash_client_backend::{
        data_api::wallet::{ConfirmationsPolicy, input_selection::GreedyInputSelector},
        fees::{DustOutputPolicy, StandardFeeRule, standard},
        wallet::OvkPolicy,
    };
    use zcash_keys::address::{Address, UnifiedAddress};
    use zcash_protocol::ShieldedPool;
    use zip321::{Payment, TransactionRequest};

    let mut st = ironwood_wallet();
    let network = *st.network();
    let account = st.test_account().cloned().unwrap();
    let ordinary = FullViewingKey::from(account.usk().orchard());
    let start = st.sapling_activation_height();
    let refund = reserve_key(
        st.wallet_mut().db_mut(),
        account.id(),
        Purpose::Refund,
        start,
    );
    let incoming = reserve_key(
        st.wallet_mut().db_mut(),
        account.id(),
        Purpose::Receive,
        start,
    );

    // Both purposes and the ordinary key coexist in one account's batch runner.
    let (first, _, refund_nf) = st.generate_next_block(
        &IronwoodFvk(refund.full_viewing_key().clone()),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(2_000_000),
    );
    let (_, _, incoming_nf) = st.generate_next_block(
        &IronwoodFvk(incoming.full_viewing_key().clone()),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(3_000_000),
    );
    st.generate_next_block(
        &IronwoodFvk(ordinary.clone()),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(4_000_000),
    );
    st.scan_cached_blocks_with_dynamic_ivks(first, 3);
    for _ in 0..5 {
        let (h, _) = st.generate_empty_block();
        st.scan_cached_blocks_with_dynamic_ivks(h, 1);
    }

    // Replay the same canonical outputs. The note key reference must be idempotent.
    st.scan_cached_blocks_with_dynamic_ivks(first, 8);
    let path = st.wallet().data_file_path().to_owned();
    // Reopen before reconstruction and spending. No derived FVK is persisted in the DB.
    let reopened = WalletDb::for_path(path, network, test_clock(), test_rng()).unwrap();
    *st.wallet_mut().db_mut() = reopened;
    let height = st.wallet().chain_height().unwrap().unwrap();
    let notes = st
        .wallet()
        .db()
        .get_unspent_ironwood_notes_at_historical_height(account.id(), height)
        .unwrap();
    assert_eq!(notes.len(), 3);
    let refund_note = notes
        .iter()
        .find(|n| n.dynamic_key_id() == Some(refund.key_id()))
        .unwrap();
    assert_eq!(refund_note.note().recipient(), refund.receiver());
    assert_eq!(
        refund_note.note().nullifier(refund.full_viewing_key()),
        refund_nf
    );
    let incoming_note = notes
        .iter()
        .find(|n| n.dynamic_key_id() == Some(incoming.key_id()))
        .unwrap();
    assert_eq!(incoming_note.note().recipient(), incoming.receiver());
    assert_eq!(
        incoming_note.note().nullifier(incoming.full_viewing_key()),
        incoming_nf
    );
    assert!(notes.iter().any(|n| n.dynamic_key_id().is_none()));

    if close_keys {
        // A key closes once its receipts have ten confirmations.
        st.generate_and_scan_empty_blocks_with_dynamic_ivks(3);
        close(&mut st, &[refund.key_id(), incoming.key_id()]);
        assert!(st.wallet().get_dynamic_scanning_keys().unwrap().is_empty());
    }

    let receiver =
        FullViewingKey::from(&orchard::keys::SpendingKey::from_bytes([0xf5; 32]).unwrap())
            .address_at(0u32, Scope::External);
    let address =
        Address::Unified(UnifiedAddress::from_receivers(Some(receiver), None, None).unwrap());
    let request = TransactionRequest::new(vec![Payment::without_memo(
        address.to_zcash_address(&network),
        Zatoshis::const_from_u64(6_000_000),
    )])
    .unwrap();
    let change_strategy = standard::SingleOutputChangeStrategy::<TestDb>::new(
        StandardFeeRule::Zip317,
        None,
        ShieldedPool::Orchard,
        DustOutputPolicy::default(),
    );
    let proposal = st
        .propose_transfer(
            account.id(),
            &GreedyInputSelector::new(),
            &change_strategy,
            request,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();
    assert_eq!(
        proposal.input_count_in_pool(zcash_protocol::PoolType::IRONWOOD),
        3
    );
    let created = st
        .create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        )
        .unwrap();
    let (h, _) = st.generate_next_block_including(created[0]);
    st.scan_cached_blocks_with_dynamic_ivks(h, 1);
    let notes = st
        .wallet()
        .db()
        .get_unspent_ironwood_notes_at_historical_height(account.id(), h)
        .unwrap();
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].dynamic_key_id(), None);
    assert_eq!(notes[0].spending_key_scope(), Scope::Internal);
    assert_eq!(
        notes[0].note().recipient(),
        ordinary.address_at(0u32, Scope::Internal)
    );

    // Only a key that is still open trial-decrypts a late payment.
    let (late_height, _, _) = st.generate_next_block(
        &IronwoodFvk(refund.full_viewing_key().clone()),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(70_000),
    );
    st.scan_cached_blocks_with_dynamic_ivks(late_height, 1);
    let late = unspent_keys(&st, late_height);
    assert_eq!(late.len(), if close_keys { 1 } else { 2 });
    assert_eq!(
        late.iter().filter(|k| **k == Some(refund.key_id())).count(),
        usize::from(!close_keys)
    );
    // Spending and closing keep both registrations.
    assert_eq!(all_keys(st.wallet().db(), account.id()).unwrap().len(), 2);
}

#[test]
fn dynamic_ivk_rejects_mismatched_note_metadata() {
    use incrementalmerkletree::Position;
    use orchard::note::{Note, NoteVersion, RandomSeed, Rho};
    use zcash_client_backend::wallet::WalletOutput;
    use zcash_note_encryption::EphemeralKeyBytes;
    use zcash_protocol::ShieldedPool;

    let mut st = wallet(false);
    let account = st.test_account().unwrap().id();
    let key = watch(st.wallet_mut().db_mut(), account, 4, start());
    let rho = Rho::from_bytes(&[1; 32]).unwrap();
    let note = Note::from_parts(
        key.receiver(),
        orchard::value::NoteValue::from_raw(50_000),
        rho,
        RandomSeed::from_bytes([2; 32], &rho).unwrap(),
        NoteVersion::V3,
    )
    .unwrap();
    let output = |key_id, scope, nf| {
        WalletOutput::from_parts(
            0,
            EphemeralKeyBytes([0; 32]),
            (note, orchard::ValuePool::Ironwood),
            false,
            Position::from(0),
            nf,
            account,
            Some(scope),
        )
        .with_dynamic_key_id(key_id)
    };
    let nf = note.nullifier(key.full_viewing_key());
    let conn = st.wallet().conn();
    let valid = output(Some(key.key_id()), Scope::External, Some(nf));
    assert!(
        validate_received_key(conn, st.network(), ShieldedPool::Ironwood, &valid)
            .unwrap()
            .is_some()
    );
    assert!(validate_received_key(conn, st.network(), ShieldedPool::Orchard, &valid).is_err());
    assert!(
        validate_received_key(
            conn,
            st.network(),
            ShieldedPool::Ironwood,
            &output(Some(key.key_id()), Scope::Internal, Some(nf))
        )
        .is_err()
    );
    let wrong_nf = orchard::note::Nullifier::from_bytes(&[1; 32]).unwrap();
    assert!(
        validate_received_key(
            conn,
            st.network(),
            ShieldedPool::Ironwood,
            &output(Some(key.key_id()), Scope::External, Some(wrong_nf))
        )
        .is_err()
    );
    assert!(
        validate_received_key(
            conn,
            st.network(),
            ShieldedPool::Ironwood,
            &output(
                Some(KeyId::new(Purpose::Receive, 5)),
                Scope::External,
                Some(nf)
            )
        )
        .is_err()
    );
    // Validation alone is not evidence committed to the wallet.
    let db = st.wallet().db();
    let key = all_keys(db, account).unwrap()[0].key_id();
    assert!(!key_state(db, key).1);
}

#[test]
fn dynamic_ivk_reconstructs_only_with_the_registered_account() {
    let mut st = wallet(false);
    let account = st.test_account().unwrap().id();
    let key = reserve_key(st.wallet_mut().db_mut(), account, Purpose::Refund, start());
    let id: i64 = st
        .wallet()
        .conn()
        .query_row("SELECT id FROM ironwood_receiving_keys", [], |r| r.get(0))
        .unwrap();
    let parent = orchard::keys::FullViewingKey::from(st.test_account().unwrap().usk().orchard());
    assert_eq!(
        note_key(st.wallet().conn(), id, &parent).unwrap().0,
        key.key_id()
    );
    let other = orchard::keys::FullViewingKey::from(
        &orchard::keys::SpendingKey::from_bytes([9; 32]).unwrap(),
    );
    assert!(note_key(st.wallet().conn(), id, &other).is_err());
    st.wallet()
        .conn()
        .execute(
            "UPDATE ironwood_receiving_keys SET receiver = zeroblob(43)",
            [],
        )
        .unwrap();
    assert!(note_key(st.wallet().conn(), id, &parent).is_err());
}

#[test]
fn lookahead_keys_are_swept_instead_of_scanned() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let key = KeyId::new(Purpose::Receive, 1);
    let (first, _, _) = st.generate_next_block(
        &recipient(&st, key),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(50_000),
    );
    st.scan_cached_blocks_with_dynamic_ivks(first, 1);
    lookahead(st.wallet_mut().db_mut(), account, 2, first);
    // Unlike activation, registering for a sweep replays no scanned history.
    assert!(queued(&st).is_empty());
    assert!(st.wallet().get_dynamic_scanning_keys().unwrap().is_empty());
    assert!(
        st.wallet()
            .db()
            .dynamic_history_pending(account, first)
            .unwrap()
    );
    let (later, _, _) = st.generate_next_block(
        &recipient(&st, key),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(60_000),
    );
    st.scan_cached_blocks_with_dynamic_ivks(later, 1);
    assert!(unspent_keys(&st, later).is_empty());
}

#[test]
fn active_keys_scan_whole_batches_across_their_start() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let (first, _) = st.generate_empty_block();
    st.scan_cached_blocks_with_dynamic_ivks(first, 1);
    let key = reserve_key(
        st.wallet_mut().db_mut(),
        account,
        Purpose::Receive,
        first + 2,
    );
    st.generate_empty_block();
    let (paid, _, _) = st.generate_next_block(
        &IronwoodFvk(key.full_viewing_key().clone()),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(50_000),
    );
    st.generate_empty_block();
    assert_eq!(
        st.scan_cached_blocks_with_dynamic_ivks(first + 1, 3)
            .scanned_range(),
        first + 1..first + 4
    );
    assert_eq!(unspent_keys(&st, paid + 1), vec![Some(key.key_id())]);
    // The key was in the batch's snapshot, so nothing is requeued.
    assert!(queued(&st).is_empty());
}

#[test]
fn activation_rescans_scanned_blocks_from_its_start_and_survives_reopen() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let key = KeyId::new(Purpose::Refund, 0);
    let (first, _) = st.generate_empty_block();
    let (paid, _, _) = st.generate_next_block(
        &recipient(&st, key),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(70_000),
    );
    st.generate_empty_block();
    st.scan_cached_blocks_with_dynamic_ivks(first, 3);
    assert!(unspent_keys(&st, paid + 1).is_empty());
    assert!(queued(&st).is_empty());

    reserve_key(st.wallet_mut().db_mut(), account, Purpose::Refund, paid);
    assert_eq!(queued(&st), vec![paid..paid + 2]);
    assert_eq!(
        st.wallet()
            .block_fully_scanned()
            .unwrap()
            .map(|b| b.block_height()),
        Some(first)
    );

    let reopened = WalletDb::for_path(
        st.wallet().data_file_path(),
        *st.network(),
        test_clock(),
        test_rng(),
    )
    .unwrap();
    *st.wallet_mut().db_mut() = reopened;
    st.scan_cached_blocks_with_dynamic_ivks(paid, 2);
    assert!(queued(&st).is_empty());
    assert_eq!(unspent_keys(&st, paid + 1), vec![Some(key)]);
}

#[test]
fn reopening_a_closed_key_rescans_blocks_scanned_without_it() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let (first, _) = st.generate_empty_block();
    let key = reserve_key(st.wallet_mut().db_mut(), account, Purpose::Refund, first);
    st.scan_cached_blocks_with_dynamic_ivks(first, 1);
    close(&mut st, &[key.key_id()]);
    let (paid, _, _) = st.generate_next_block(
        &IronwoodFvk(key.full_viewing_key().clone()),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(70_000),
    );
    st.generate_empty_block();
    st.scan_cached_blocks_with_dynamic_ivks(paid, 2);
    assert!(unspent_keys(&st, paid + 1).is_empty());

    activate_key(st.wallet_mut().db_mut(), account, key.key_id(), paid);
    assert_eq!(queued(&st), vec![paid..paid + 2]);
    st.scan_cached_blocks_with_dynamic_ivks(paid, 2);
    assert_eq!(unspent_keys(&st, paid + 1), vec![Some(key.key_id())]);
}

#[test]
fn reactivating_an_open_key_rescans_only_blocks_below_its_start() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let (first, _) = st.generate_empty_block();
    for _ in 0..3 {
        st.generate_empty_block();
    }
    st.scan_cached_blocks_with_dynamic_ivks(first, 4);
    let key = reserve_key(
        st.wallet_mut().db_mut(),
        account,
        Purpose::Receive,
        first + 2,
    )
    .key_id();
    assert_eq!(queued(&st), vec![first + 2..first + 4]);
    st.scan_cached_blocks_with_dynamic_ivks(first + 2, 2);

    // A later start never narrows the active range.
    activate_key(st.wallet_mut().db_mut(), account, key, first + 3);
    assert!(queued(&st).is_empty());
    activate_key(st.wallet_mut().db_mut(), account, key, first);
    assert_eq!(queued(&st), vec![first..first + 2]);
}

/// Registers a key after the scanner captures its keys, before its first cache read.
struct RegisterDuringScan<'a, B, F> {
    inner: &'a B,
    register: F,
    ran: Cell<bool>,
}

impl<B: BlockSource, F: Fn()> BlockSource for RegisterDuringScan<'_, B, F> {
    type Error = B::Error;

    fn with_blocks<C, E>(
        &self,
        from: Option<BlockHeight>,
        limit: Option<usize>,
        callback: C,
    ) -> Result<(), error::Error<E, Self::Error>>
    where
        C: FnMut(CompactBlock) -> Result<(), error::Error<E, Self::Error>>,
    {
        if !self.ran.replace(true) {
            (self.register)();
        }
        self.inner.with_blocks(from, limit, callback)
    }
}

#[test]
fn key_activated_mid_batch_is_requeued_for_the_blocks_it_missed() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let key = KeyId::new(Purpose::Receive, 0);
    let (first, _) = st.generate_empty_block();
    let (paid, _, _) = st.generate_next_block(
        &recipient(&st, key),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(50_000),
    );
    st.generate_empty_block();
    let network = *st.network();
    let path = st.wallet().data_file_path();
    let mut scanning_db = WalletDb::for_path(path, network, test_clock(), test_rng()).unwrap();
    let source = RegisterDuringScan {
        inner: st.cache(),
        ran: Cell::new(false),
        register: || {
            let mut db = WalletDb::for_path(path, network, test_clock(), test_rng()).unwrap();
            reserve_key(&mut db, account, Purpose::Receive, paid);
        },
    };
    scan_cached_blocks_with_dynamic_ivks(
        &network,
        &source,
        &mut scanning_db,
        first,
        &ChainState::empty(first - 1, BlockHash([0; 32])),
        3,
    )
    .unwrap();
    assert!(unspent_keys(&st, paid + 1).is_empty());
    assert_eq!(queued(&st), vec![paid..paid + 2]);

    st.scan_cached_blocks_with_dynamic_ivks(paid, 2);
    assert_eq!(unspent_keys(&st, paid + 1), vec![Some(key)]);
    assert!(queued(&st).is_empty());
}
