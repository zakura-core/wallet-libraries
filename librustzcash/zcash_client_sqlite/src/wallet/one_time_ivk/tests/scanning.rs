use std::{cell::Cell, ops::Range};

use zakura_one_time_ivk::swap::{OperationStatus, ReceiptExpectation};
use zcash_client_backend::data_api::chain::{
    BlockSource, ChainState, error, scan_cached_blocks_with_one_time_ivks,
};

use super::*;

/// Block ranges the wallet still has to scan.
fn queued(st: &State) -> Vec<Range<BlockHeight>> {
    let ranges = st.wallet().suggest_scan_ranges().unwrap();
    ranges.iter().map(|r| r.block_range().clone()).collect()
}

/// Mines, without scanning, a block paying `value` to `key`, which need not be
/// registered, and returns its height.
fn mine_payment(st: &mut State, key: KeyId, value: u64) -> BlockHeight {
    let recipient = IronwoodFvk(derive(st, key));
    let value = Zatoshis::const_from_u64(value);
    st.generate_next_block(&recipient, AddressType::DefaultExternal, value)
        .0
}

/// Reports a finished swap on each of `keys`, which closes them.
fn close(st: &mut State, keys: &[KeyId]) {
    let account = st.test_account().unwrap().id();
    let tip = st.wallet().chain_height().unwrap().unwrap();
    let db = st.wallet_mut().db_mut();
    for key in keys {
        let finished = OperationStatus::Terminal(ReceiptExpectation::None);
        observe(db, account, *key, "swap", finished, 0).unwrap();
    }
    assert_eq!(close_at(db, account, 0, tip), keys.len());
}

/// Scans payments to both purposes beside an ordinary note, optionally closes the
/// one-time keys, then spends all three notes into ordinary change. Only a key still
/// open trial-decrypts a later payment, and neither spending nor closing forgets a key.
#[test]
fn scanned_one_time_notes_reopen_and_spend_into_ordinary_change() {
    for close_keys in [false, true] {
        let mut st = ironwood_wallet();
        let account = st.test_account().unwrap().id();
        let ordinary = parent(&st);
        let start = st.sapling_activation_height();
        let db = st.wallet_mut().db_mut();
        let refund = reserve_key(db, account, Purpose::Refund, start);
        let incoming = reserve_key(db, account, Purpose::Receive, start);

        // Both purposes and the ordinary key coexist in one account's batch runner.
        let mut nfs = vec![];
        for (fvk, value) in [
            (refund.full_viewing_key(), 2_000_000),
            (incoming.full_viewing_key(), 3_000_000),
            (&ordinary, 4_000_000),
        ] {
            let recipient = IronwoodFvk(fvk.clone());
            let value = Zatoshis::const_from_u64(value);
            nfs.push(
                st.generate_next_block(&recipient, AddressType::DefaultExternal, value)
                    .2,
            );
        }
        st.scan_cached_blocks_with_one_time_ivks(start, 3);
        st.generate_and_scan_empty_blocks_with_one_time_ivks(5);
        // Replay the same canonical outputs. The note key reference must be idempotent.
        st.scan_cached_blocks_with_one_time_ivks(start, 8);
        // Reopen before reconstruction and spending. No derived FVK is persisted in the DB.
        reopen(&mut st);
        let stored = notes(&st, st.wallet().chain_height().unwrap().unwrap());
        assert_eq!(stored.len(), 3);
        for (key, nf) in [(&refund, nfs[0]), (&incoming, nfs[1])] {
            let note = stored
                .iter()
                .find(|n| n.one_time_key_id() == Some(key.key_id()));
            let note = note.unwrap().note();
            assert_eq!(note.recipient(), key.receiver());
            assert_eq!(note.nullifier(key.full_viewing_key()), nf);
        }
        assert!(stored.iter().any(|n| n.one_time_key_id().is_none()));

        if close_keys {
            // A key closes once its receipts have ten confirmations.
            st.generate_and_scan_empty_blocks_with_one_time_ivks(3);
            close(&mut st, &[refund.key_id(), incoming.key_id()]);
            assert!(scanning_keys(&st).is_empty());
        }

        let (proposal, h) = spend_to_foreign(&mut st, 6_000_000);
        assert_eq!(
            proposal.input_count_in_pool(zcash_protocol::PoolType::IRONWOOD),
            3
        );
        let change = notes(&st, h);
        assert_eq!(change.len(), 1);
        assert_eq!(change[0].one_time_key_id(), None);
        assert_eq!(change[0].spending_key_scope(), Scope::Internal);
        assert_eq!(
            change[0].note().recipient(),
            ordinary.address_at(0u32, Scope::Internal)
        );

        let late_height = pay(&mut st, refund.full_viewing_key(), 70_000);
        let late = unspent_keys(&st, late_height);
        assert_eq!(late.len(), if close_keys { 1 } else { 2 });
        assert_eq!(
            late.iter().filter(|k| **k == Some(refund.key_id())).count(),
            usize::from(!close_keys)
        );
        assert_eq!(all_keys(st.wallet().db(), account).unwrap().len(), 2);
    }
}

#[test]
fn spare_input_slots_spend_one_time_key_notes_first() {
    use std::convert::Infallible;
    use zcash_client_backend::{
        data_api::wallet::{
            ConfirmationsPolicy,
            input_selection::{GreedyInputSelector, NoteSelection, SpendPolicy},
        },
        fees::{DustOutputPolicy, StandardFeeRule, standard},
        wallet::OvkPolicy,
    };
    use zcash_keys::address::{Address, UnifiedAddress};
    use zcash_protocol::ShieldedPool;
    use zip321::{Payment, TransactionRequest};

    let mut st = ironwood_wallet();
    let network = *st.network();
    let account = st.test_account().cloned().unwrap();
    let ordinary = IronwoodFvk(FullViewingKey::from(account.usk().orchard()));
    let start = st.sapling_activation_height();
    let refund = reserve_key(
        st.wallet_mut().db_mut(),
        account.id(),
        Purpose::Refund,
        start,
    );
    let (first, _, _) = st.generate_next_block(
        &ordinary,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(1_000_000),
    );
    st.generate_next_block(
        &IronwoodFvk(refund.full_viewing_key().clone()),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(200_000),
    );
    st.generate_next_block(
        &ordinary,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(100_000),
    );
    st.scan_cached_blocks_with_one_time_ivks(first, 3);
    st.generate_and_scan_empty_blocks_with_one_time_ivks(5);

    // The largest note funds the payment alone. Its payment and change outputs leave one
    // spare spend slot, which the swap note takes instead of the smaller ordinary note.
    let receiver =
        FullViewingKey::from(&orchard::keys::SpendingKey::from_bytes([0xf5; 32]).unwrap())
            .address_at(0u32, Scope::External);
    let address =
        Address::Unified(UnifiedAddress::from_receivers(Some(receiver), None, None).unwrap());
    let request = TransactionRequest::new(vec![Payment::without_memo(
        address.to_zcash_address(&network),
        Zatoshis::const_from_u64(300_000),
    )])
    .unwrap();
    let change_strategy = standard::SingleOutputChangeStrategy::<TestDb>::new(
        StandardFeeRule::Zip317,
        None,
        ShieldedPool::Orchard,
        DustOutputPolicy::default(),
    );
    let policy = SpendPolicy::shielded_pools([ShieldedPool::Ironwood])
        .with_note_selection(NoteSelection::PreferConsolidation);
    let proposal = st
        .propose_transfer_with_policy(
            account.id(),
            &GreedyInputSelector::new(),
            &change_strategy,
            request,
            ConfirmationsPolicy::MIN,
            &policy,
        )
        .unwrap();
    let mut inputs: Vec<_> = proposal
        .steps()
        .first()
        .shielded_inputs()
        .unwrap()
        .notes()
        .iter()
        .map(|note| u64::from(note.note().value()))
        .collect();
    inputs.sort_unstable();
    assert_eq!(inputs, [200_000, 1_000_000]);

    let created = st
        .create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        )
        .unwrap();
    let (height, _) = st.generate_next_block_including(created[0]);
    st.scan_cached_blocks_with_one_time_ivks(height, 1);
    // The one-time-key note's value now sits in ordinary internal change.
    assert_eq!(unspent_keys(&st, height), [None, None]);
}

/// Pays the test account's ordinary Ironwood address `ordinary` and a fresh refund key `one_time`
/// (zatoshis), scans them, then proposes, mines and scans an Ironwood payment of `value` with
/// `NoteSelection::PreferConsolidation` and change split by `split`. Returns the sorted input values
/// and the one-time key of each unspent note afterwards.
fn spend_with_one_time_note(
    ordinary: &[u64],
    one_time: u64,
    value: u64,
    split: zcash_client_backend::fees::SplitPolicy,
) -> (Vec<u64>, Vec<Option<KeyId>>) {
    use std::convert::Infallible;
    use zcash_client_backend::{
        data_api::wallet::{
            ConfirmationsPolicy,
            input_selection::{GreedyInputSelector, NoteSelection, SpendPolicy},
        },
        fees::{DustOutputPolicy, zip317::MultiOutputChangeStrategy},
        wallet::OvkPolicy,
    };
    use zcash_keys::address::{Address, UnifiedAddress};
    use zcash_primitives::transaction::fees::zip317;
    use zcash_protocol::ShieldedPool;
    use zip321::{Payment, TransactionRequest};

    let mut st = ironwood_wallet();
    let network = *st.network();
    let account = st.test_account().cloned().unwrap();
    let start = st.sapling_activation_height();
    let refund = reserve_key(
        st.wallet_mut().db_mut(),
        account.id(),
        Purpose::Refund,
        start,
    );
    let (first, _, _) = st.generate_next_block(
        &IronwoodFvk(refund.full_viewing_key().clone()),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(one_time),
    );
    let ordinary_fvk = IronwoodFvk(FullViewingKey::from(account.usk().orchard()));
    for value in ordinary {
        st.generate_next_block(
            &ordinary_fvk,
            AddressType::DefaultExternal,
            Zatoshis::from_u64(*value).unwrap(),
        );
    }
    st.scan_cached_blocks_with_one_time_ivks(first, ordinary.len() + 1);
    st.generate_and_scan_empty_blocks_with_one_time_ivks(5);

    let receiver =
        FullViewingKey::from(&orchard::keys::SpendingKey::from_bytes([0xf5; 32]).unwrap())
            .address_at(0u32, Scope::External);
    let address =
        Address::Unified(UnifiedAddress::from_receivers(Some(receiver), None, None).unwrap());
    let request = TransactionRequest::new(vec![Payment::without_memo(
        address.to_zcash_address(&network),
        Zatoshis::from_u64(value).unwrap(),
    )])
    .unwrap();
    let change_strategy = MultiOutputChangeStrategy::<_, TestDb>::new(
        zip317::FeeRule::standard(),
        None,
        ShieldedPool::Ironwood,
        DustOutputPolicy::default(),
        split,
    );
    let policy = SpendPolicy::shielded_pools([ShieldedPool::Ironwood])
        .with_note_selection(NoteSelection::PreferConsolidation);
    let proposal = st
        .propose_transfer_with_policy(
            account.id(),
            &GreedyInputSelector::new(),
            &change_strategy,
            request,
            ConfirmationsPolicy::MIN,
            &policy,
        )
        .unwrap();
    let mut inputs: Vec<_> = proposal
        .steps()
        .first()
        .shielded_inputs()
        .unwrap()
        .notes()
        .iter()
        .map(|note| u64::from(note.note().value()))
        .collect();
    inputs.sort_unstable();

    let created = st
        .create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        )
        .unwrap();
    let (height, _) = st.generate_next_block_including(created[0]);
    st.scan_cached_blocks_with_one_time_ivks(height, 1);
    (inputs, unspent_keys(&st, height))
}

#[test]
fn funding_prefers_one_time_key_notes_without_adding_inputs() {
    use zcash_client_backend::fees::SplitPolicy;

    // Largest-first funding is the two ordinary notes, and its two inputs fill both actions, so no
    // slot is spare. The one-time-key note still replaces the smaller ordinary note.
    let (inputs, unspent) = spend_with_one_time_note(
        &[2_000_000, 1_200_000],
        1_000_000,
        2_500_000,
        SplitPolicy::single_output(),
    );
    assert_eq!(inputs, [1_000_000, 2_000_000]);
    assert_eq!(unspent, [None, None]);
}

#[test]
fn split_change_does_not_block_one_time_key_consolidation() {
    use std::num::NonZeroUsize;
    use zcash_client_backend::fees::SplitPolicy;

    // The ordinary note funds the payment alone. Were the one-time-key note counted as a note the
    // wallet keeps, spending it would add a change output, and every spare-slot prefix (each
    // starting with it) would change the shape, so even the small notes would stay unspent.
    let (inputs, unspent) = spend_with_one_time_note(
        &[2_000_000, 20_000, 20_000],
        1_000_000,
        1_500_000,
        SplitPolicy::with_min_output_value(
            NonZeroUsize::new(4).unwrap(),
            Zatoshis::const_from_u64(100_000),
        ),
    );
    assert_eq!(inputs, [20_000, 20_000, 1_000_000, 2_000_000]);
    assert_eq!(unspent, [None; 4]);
}

#[test]
fn one_time_ivk_rejects_mismatched_note_metadata() {
    use incrementalmerkletree::Position;
    use orchard::note::{NoteVersion, RandomSeed, Rho};
    use zcash_client_backend::wallet::WalletOutput;
    use zcash_note_encryption::EphemeralKeyBytes;
    use zcash_protocol::ShieldedPool;

    let mut st = wallet(false);
    let account = st.test_account().unwrap().id();
    let key = watch(st.wallet_mut().db_mut(), account, 4, start());
    let rho = Rho::from_bytes(&[1; 32]).unwrap();
    let seed = RandomSeed::from_bytes([2; 32], &rho).unwrap();
    let value = orchard::value::NoteValue::from_raw(50_000);
    let note = Note::from_parts(key.receiver(), value, rho, seed, NoteVersion::V3).unwrap();
    let nf = note.nullifier(key.full_viewing_key());
    let validate = |pool, key_id, scope, nf| {
        let (ephemeral, position) = (EphemeralKeyBytes([0; 32]), Position::from(0));
        let note = (note, orchard::ValuePool::Ironwood);
        let output = WalletOutput::from_parts(
            0,
            ephemeral,
            note,
            false,
            position,
            Some(nf),
            account,
            Some(scope),
        )
        .with_one_time_key_id(Some(key_id));
        validate_received_key(st.wallet().conn(), st.network(), pool, &output)
    };
    let (ironwood, external) = (ShieldedPool::Ironwood, Scope::External);
    let valid = validate(ironwood, key.key_id(), external, nf);
    assert!(valid.unwrap().is_some());
    let wrong_nf = orchard::note::Nullifier::from_bytes(&[1; 32]).unwrap();
    let unregistered = KeyId::new(Purpose::Receive, 5);
    for (pool, key_id, scope, nf) in [
        (ShieldedPool::Orchard, key.key_id(), external, nf),
        (ironwood, key.key_id(), Scope::Internal, nf),
        (ironwood, key.key_id(), external, wrong_nf),
        (ironwood, unregistered, external, nf),
    ] {
        assert!(validate(pool, key_id, scope, nf).is_err());
    }
    // Validation alone is not evidence committed to the wallet.
    assert!(!key_state(st.wallet().db(), key.key_id()).1);
}

/// Lookahead keys wait for a sweep: unlike activation, registering them replays no
/// scanned history, and scanning never trial-decrypts with them.
#[test]
fn lookahead_keys_are_swept_instead_of_scanned() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let key = KeyId::new(Purpose::Receive, 1);
    let first = mine_payment(&mut st, key, 50_000);
    st.scan_cached_blocks_with_one_time_ivks(first, 1);
    lookahead(st.wallet_mut().db_mut(), account, 2, first);
    assert!(queued(&st).is_empty());
    assert!(scanning_keys(&st).is_empty());
    assert!(
        st.wallet()
            .one_time_history_pending(account, first)
            .unwrap()
    );
    let later = mine_payment(&mut st, key, 60_000);
    st.scan_cached_blocks_with_one_time_ivks(later, 1);
    assert!(unspent_keys(&st, later).is_empty());
}

#[test]
fn active_keys_scan_whole_batches_across_their_start() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let (first, _) = st.generate_empty_block();
    st.scan_cached_blocks_with_one_time_ivks(first, 1);
    let key = reserve_key(
        st.wallet_mut().db_mut(),
        account,
        Purpose::Receive,
        first + 2,
    )
    .key_id();
    st.generate_empty_block();
    let paid = mine_payment(&mut st, key, 50_000);
    st.generate_empty_block();
    let scanned = st.scan_cached_blocks_with_one_time_ivks(first + 1, 3);
    assert_eq!(scanned.scanned_range(), first + 1..first + 4);
    assert_eq!(unspent_keys(&st, paid + 1), vec![Some(key)]);
    // The key was in the batch's snapshot, so nothing is requeued.
    assert!(queued(&st).is_empty());
}

/// Activating a new key, or reopening a closed one, rescans blocks scanned without it
/// from its start, and the queued rescan survives a reopen.
#[test]
fn activation_rescans_scanned_blocks_from_its_start_and_survives_reopen() {
    for closed in [false, true] {
        let mut st = ironwood_wallet();
        let account = st.test_account().unwrap().id();
        let key = KeyId::new(Purpose::Refund, 0);
        let (first, _) = st.generate_empty_block();
        if closed {
            reserve_key(st.wallet_mut().db_mut(), account, Purpose::Refund, first);
        }
        st.scan_cached_blocks_with_one_time_ivks(first, 1);
        if closed {
            close(&mut st, &[key]);
        }
        let paid = mine_payment(&mut st, key, 70_000);
        st.generate_empty_block();
        st.scan_cached_blocks_with_one_time_ivks(paid, 2);
        assert!(unspent_keys(&st, paid + 1).is_empty());
        assert!(queued(&st).is_empty());

        let db = st.wallet_mut().db_mut();
        if closed {
            activate_key(db, account, key, paid);
        } else {
            reserve_key(db, account, Purpose::Refund, paid);
        }
        assert_eq!(queued(&st), vec![paid..paid + 2], "{closed}");
        let scanned = st.wallet().block_fully_scanned().unwrap();
        assert_eq!(scanned.map(|b| b.block_height()), Some(first));
        reopen(&mut st);
        st.scan_cached_blocks_with_one_time_ivks(paid, 2);
        assert!(queued(&st).is_empty());
        assert_eq!(unspent_keys(&st, paid + 1), vec![Some(key)], "{closed}");
    }
}

#[test]
fn reactivating_an_open_key_rescans_only_blocks_below_its_start() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let first = st.generate_and_scan_empty_blocks_with_one_time_ivks(4) - 3;
    let db = st.wallet_mut().db_mut();
    let key = reserve_key(db, account, Purpose::Receive, first + 2).key_id();
    assert_eq!(queued(&st), vec![first + 2..first + 4]);
    st.scan_cached_blocks_with_one_time_ivks(first + 2, 2);

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
    let paid = mine_payment(&mut st, key, 50_000);
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
    let chain = ChainState::empty(first - 1, BlockHash([0; 32]));
    scan_cached_blocks_with_one_time_ivks(&network, &source, &mut scanning_db, first, &chain, 3)
        .unwrap();
    assert!(unspent_keys(&st, paid + 1).is_empty());
    assert_eq!(queued(&st), vec![paid..paid + 2]);

    st.scan_cached_blocks_with_one_time_ivks(paid, 2);
    assert_eq!(unspent_keys(&st, paid + 1), vec![Some(key)]);
    assert!(queued(&st).is_empty());
}

/// Ordinary scanning keeps no Ironwood spend evidence for restore sweeps until the wallet
/// holds one-time IVK state, a registered key or a spend retention row, and keeps it for
/// every block scanned from then on.
#[test]
fn spend_evidence_is_kept_only_with_one_time_ivk_state() {
    for registered_key in [true, false] {
        let mut st = ironwood_wallet();
        let account = st.test_account().unwrap().id();
        let covered = |st: &State| -> Vec<u32> {
            let sql = "SELECT height FROM ironwood_nullifier_scan_blocks ORDER BY height";
            column(st.wallet().conn(), sql, [])
        };
        let scan_empty_block = |st: &mut State| {
            let (height, _) = st.generate_empty_block();
            st.scan_cached_blocks(height, 1);
            u32::from(height)
        };
        scan_empty_block(&mut st);
        scan_empty_block(&mut st);
        assert!(covered(&st).is_empty(), "{registered_key}");
        assert_eq!(retention_height(&st), None);

        let db = st.wallet_mut().db_mut();
        if registered_key {
            // A sweep-only key is not trial-decrypted, so ordinary scanning continues.
            let from = db.chain_height().unwrap().unwrap() + 1;
            watch(db, account, 0, from);
        } else {
            retain(db, account);
        }
        let scanned = [scan_empty_block(&mut st), scan_empty_block(&mut st)];
        assert_eq!(covered(&st), scanned, "{registered_key}");
    }
}
