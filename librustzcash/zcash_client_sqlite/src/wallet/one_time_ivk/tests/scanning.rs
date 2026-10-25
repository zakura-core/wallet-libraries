use super::*;
use std::cell::Cell;
use zcash_client_backend::data_api::chain::{BlockSource, ChainState, error};

/// PIR-admitted notes survive reopening and spend into ordinary change.
#[test]
fn recovered_notes_reopen_and_spend_into_ordinary_change() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let start = st.sapling_activation_height();
    let ordinary = parent(&st);
    let refund = reserve_key(st.wallet_mut().db_mut(), account, Purpose::Refund, start);
    let receive = reserve_key(st.wallet_mut().db_mut(), account, Purpose::Receive, start);
    for (fvk, amount) in [
        (refund.full_viewing_key(), 2_000_000),
        (receive.full_viewing_key(), 3_000_000),
        (&ordinary, 4_000_000),
    ] {
        st.generate_next_block(
            &IronwoodFvk(fvk.clone()),
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(amount),
        );
    }
    scan_and_recover(&mut st, start, 3);
    st.generate_and_scan_empty_blocks(10);
    reopen(&mut st);
    assert_eq!(notes(&st, tip(&st).height).len(), 3);
    let (proposal, height) = spend_to_foreign(&mut st, 6_000_000);
    assert_eq!(
        proposal.input_count_in_pool(zcash_protocol::PoolType::IRONWOOD),
        3
    );
    let change = notes(&st, height);
    assert_eq!(change.len(), 1);
    assert_eq!(change[0].one_time_key_id(), None);
    assert_eq!(change[0].spending_key_scope(), Scope::Internal);
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
    scan_and_recover(&mut st, start, 1);
    st.generate_and_scan_empty_blocks(2);

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
    // Extraction requires the marker output because of this flag.
    let flag = "zcash_client_backend:spends_one_time";
    assert!(pczt.global().proprietary().contains_key(flag));
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

    // A batch Signer can check the one-time note's address only against its own FVK,
    // so the batch view keeps that FVK and no other. Without the one-time flag it keeps
    // none, and the Signer rejects the spend.
    let batch_fvks = |pczt: &pczt::Pczt| {
        let batch_view = zcash_client_backend::data_api::wallet::redact_pczt_for_batch_signer(
            pczt,
            &parent(&st),
        );
        let mut fvks = vec![];
        pczt::roles::verifier::Verifier::new(batch_view)
            .with_ironwood::<Infallible, _>(|bundle| {
                fvks = bundle
                    .actions()
                    .iter()
                    .filter_map(|a| a.spend().fvk().as_ref().map(|f| f.to_bytes()))
                    .collect();
                Ok(())
            })
            .unwrap();
        fvks
    };
    assert_eq!(batch_fvks(&pczt), vec![one_time_fvk]);
    let unflagged = pczt::roles::redactor::Redactor::new(pczt.clone())
        .redact_global_with(|mut global| global.redact_proprietary(flag))
        .finish();
    assert!(batch_fvks(&unflagged).is_empty());

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
    let key = KeyId::new(Purpose::Receive, 4);
    let key = tx(st.wallet_mut().db_mut(), |c, p| {
        register(c, p, account, key)
    })
    .unwrap()
    .1;
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
    assert!(!super::value::<bool>(
        st.wallet().conn(),
        "SELECT used FROM ironwood_one_time_keys WHERE purpose = 1",
        []
    ));
}

/// Runs `run` once, before cache read `at` of a scan. The scanner captures its keys before
/// read 0, its trial decryption, and the wallet's nullifiers before read 1.
pub(super) struct DuringScan<'a, B, F> {
    pub(super) inner: &'a B,
    pub(super) at: usize,
    pub(super) run: F,
    pub(super) reads: Cell<usize>,
}

impl<B: BlockSource, F: Fn()> BlockSource for DuringScan<'_, B, F> {
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
        if self.reads.replace(self.reads.get() + 1) == self.at {
            (self.run)();
        }
        self.inner.with_blocks(from, limit, callback)
    }
}

/// A rewind below the pruning window truncates at the window's floor but rescans every
/// block above its target, so the journal's coverage above the target goes too.
#[test]
fn rewind_below_the_pruning_window_repairs_one_time_state_from_its_target() {
    let mut st = ironwood_wallet();
    let target = st.generate_and_scan_empty_blocks(1);
    st.generate_and_scan_empty_blocks(crate::PRUNING_DEPTH as usize + 10);
    let covered_end = |st: &State| -> u32 {
        let sql = "SELECT MAX(end_height) FROM ironwood_journal_coverage";
        value(st.wallet().conn(), sql, [])
    };
    assert!(covered_end(&st) > u32::from(target) + crate::PRUNING_DEPTH);

    let chain_state = ChainState::empty(target, BlockHash([0; 32]));
    st.wallet_mut()
        .rewind_to_chain_state(chain_state, std::collections::HashSet::new())
        .unwrap();
    assert_eq!(covered_end(&st), u32::from(target) + 1);
}
