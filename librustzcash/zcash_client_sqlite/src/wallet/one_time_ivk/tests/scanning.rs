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

/// Software PCZT signing spends a one-time note: the PCZT carries the one-time FVK, and
/// the account's spend authorizing key signs it.
#[cfg(feature = "pczt-tests")]
#[test]
fn pczt_signs_and_proves_a_one_time_spend() {
    use std::convert::Infallible;
    use zcash_client_backend::{
        data_api::wallet::{ConfirmationsPolicy, input_selection::GreedyInputSelector},
        fees::{DustOutputPolicy, StandardFeeRule, standard::SingleOutputChangeStrategy},
        wallet::OvkPolicy,
    };
    use zcash_primitives::transaction::{
        builder::cached_orchard_proving_key, components::orchard::bundle_version_for_branch,
    };

    let mut st = ironwood_wallet();
    let account = st.test_account().cloned().unwrap();
    let start = st.sapling_activation_height();
    let refund = reserve_key(
        st.wallet_mut().db_mut(),
        account.id(),
        Purpose::Refund,
        start,
    );
    let recipient = IronwoodFvk(refund.full_viewing_key().clone());
    let value = Zatoshis::const_from_u64(2_000_000);
    st.generate_next_block(&recipient, AddressType::DefaultExternal, value);
    st.scan_cached_blocks_with_one_time_ivks(start, 1);
    st.generate_and_scan_empty_blocks_with_one_time_ivks(2);

    let strategy = SingleOutputChangeStrategy::<TestDb>::new(
        StandardFeeRule::Zip317,
        None,
        zcash_protocol::ShieldedPool::Orchard,
        DustOutputPolicy::default(),
    );
    let to = payment(&unified(foreign_receiver()), 1_000_000, None);
    let request = zip321::TransactionRequest::new(vec![to]).unwrap();
    let proposal = st
        .propose_transfer(
            account.id(),
            &GreedyInputSelector::new(),
            &strategy,
            request,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();
    let pczt = st
        .create_pczt_from_proposal::<Infallible, _, Infallible>(
            account.id(),
            OvkPolicy::Sender,
            &proposal,
            None,
        )
        .unwrap();
    let one_time_fvk = refund.full_viewing_key().to_bytes();
    let mut spends_with_key = 0;
    pczt::roles::verifier::Verifier::new(pczt.clone())
        .with_ironwood::<Infallible, _>(|bundle| {
            spends_with_key = bundle
                .actions()
                .iter()
                .filter(|a| a.spend().fvk().as_ref().map(|f| f.to_bytes()) == Some(one_time_fvk))
                .count();
            Ok(())
        })
        .unwrap();
    assert_eq!(spends_with_key, 1);

    let ask = orchard::keys::SpendAuthorizingKey::from(account.usk().orchard());
    let mut signer = pczt::roles::signer::Signer::new(pczt).unwrap();
    let mut signed = 0;
    for index in 0.. {
        match signer.sign_ironwood(index, &ask) {
            Ok(()) => signed += 1,
            Err(pczt::roles::signer::Error::InvalidIndex) => break,
            Err(pczt::roles::signer::Error::IronwoodSign(
                orchard::pczt::SignerError::WrongSpendAuthorizingKey,
            )) => {}
            Err(e) => panic!("{e:?}"),
        }
    }
    assert_eq!(signed, 1);
    let signed = signer.finish();
    let branch =
        zcash_protocol::consensus::BranchId::try_from(*signed.global().consensus_branch_id())
            .unwrap();
    let pk = cached_orchard_proving_key(
        bundle_version_for_branch(branch, orchard::ValuePool::Ironwood)
            .unwrap()
            .circuit_version(),
    )
    .expect("the current Ironwood circuit supports proving");
    let proven = pczt::roles::prover::Prover::new(signed)
        .create_ironwood_proof(pk)
        .unwrap()
        .finish();
    assert!(proven.ironwood().zkproof().is_some());
    st.extract_and_store_transaction_from_pczt(proven).unwrap();
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
    let validate = |note: Note, pool, key_id, scope, nf| {
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
    let valid = validate(note, ironwood, key.key_id(), external, nf);
    assert!(valid.unwrap().is_some());
    let wrong_nf = orchard::note::Nullifier::from_bytes(&[1; 32]).unwrap();
    let unregistered = KeyId::new(Purpose::Receive, 5);
    // Another of the key's diversified addresses is not its registered receiver.
    let other = key.full_viewing_key().address_at(1u32, external);
    let other = Note::from_parts(other, value, rho, seed, NoteVersion::V3).unwrap();
    let other_nf = other.nullifier(key.full_viewing_key());
    for (note, pool, key_id, scope, nf) in [
        (note, ShieldedPool::Orchard, key.key_id(), external, nf),
        (note, ironwood, key.key_id(), Scope::Internal, nf),
        (note, ironwood, key.key_id(), external, wrong_nf),
        (note, ironwood, unregistered, external, nf),
        (other, ironwood, key.key_id(), external, other_nf),
    ] {
        assert!(validate(note, pool, key_id, scope, nf).is_err());
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
    lookahead(st.wallet_mut().db_mut(), account);
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

/// A rewind starts open keys at the first rescanned block, so a payment the replacement
/// chain mines below a key's old start is still found.
#[test]
fn a_rewind_scans_open_keys_from_the_rewind() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let first = st.generate_and_scan_empty_blocks_with_one_time_ivks(3) - 2;
    let db = st.wallet_mut().db_mut();
    let key = reserve_key(db, account, Purpose::Receive, first + 3).key_id();
    st.truncate_to_height(first);
    let paid = mine_payment(&mut st, key, 50_000);
    st.generate_empty_block();
    st.scan_cached_blocks_with_one_time_ivks(paid, 2);
    assert_eq!(unspent_keys(&st, paid + 1), vec![Some(key)]);
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

/// A rewind below the pruning window truncates at the window's floor but rescans every
/// block above its target, so one-time state above the target goes too.
#[test]
fn rewind_below_the_pruning_window_repairs_one_time_state_from_its_target() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    retain(st.wallet_mut().db_mut(), account);
    let target = st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    st.generate_and_scan_empty_blocks_with_one_time_ivks(crate::PRUNING_DEPTH as usize + 10);
    let covered_above = |st: &State| -> u32 {
        let sql = "SELECT COUNT(*) FROM ironwood_nullifier_scan_blocks WHERE height > ?1";
        value(st.wallet().conn(), sql, [u32::from(target)])
    };
    assert!(covered_above(&st) > crate::PRUNING_DEPTH);

    let chain_state = ChainState::empty(target, BlockHash([0; 32]));
    st.wallet_mut()
        .rewind_to_chain_state(chain_state, std::collections::HashSet::new())
        .unwrap();
    assert_eq!(covered_above(&st), 0);
}

/// Ordinary scanning keeps no Ironwood spend evidence for restore sweeps until the wallet
/// holds one-time IVK state, a registered key or a spend retention row, and keeps it for
/// every block scanned from then on.
#[test]
fn spend_evidence_is_kept_only_with_one_time_state() {
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
