use super::*;
use crate::testing::{
    BlockCache,
    db::{TestDb, TestDbFactory},
};
use zcash_client_backend::data_api::enhance_pir::{
    IronwoodEnhanceRecord as EnhanceRecord, apply_ironwood_enhance_record as apply_record,
};
use zcash_client_backend::data_api::{
    TransactionDataRequest, WalletRead, WalletWrite,
    enhance_pir::{
        EnhancePirRead, EnhancePirWrite, EnhancementMode, apply_ironwood_enhance_record,
    },
    testing::{
        AddressType, IronwoodFvk, TestBuilder, TestState, orchard::OrchardPoolTester,
        pool::ShieldedPoolTester,
    },
};
use zcash_primitives::block::BlockHash;
use zcash_protocol::{
    consensus::BlockHeight, local_consensus::LocalNetwork, memo::MemoBytes, value::Zatoshis,
};

type State = TestState<BlockCache, TestDb, LocalNetwork>;

fn fixture() -> (State, crate::TxRef, EnhancePirRequest) {
    fixture_with_factory(TestDbFactory::default())
}

fn fixture_with_factory(factory: TestDbFactory) -> (State, crate::TxRef, EnhancePirRequest) {
    let mut st = state_with_factory(factory);
    let fvk = IronwoodFvk(OrchardPoolTester::test_account_fvk(&st));
    let (height, _, _) = st.generate_next_block(
        &fvk,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(10_000),
    );
    st.scan_cached_blocks(height, 1);
    let tx_ref = st
        .wallet()
        .conn()
        .query_row(
            "SELECT id_tx FROM transactions WHERE mined_height = ?1",
            [u32::from(height)],
            |row| row.get(0).map(crate::TxRef),
        )
        .unwrap();
    let requests = st.wallet().db().enhance_pir_requests().unwrap();
    assert_eq!(
        requests.len(),
        1,
        "scanning queues work after storing the note"
    );
    let request = requests[0];
    assert!(
        st.wallet()
            .db()
            .pending_ironwood_memo(request.position())
            .unwrap()
            .is_some()
    );
    (st, tx_ref, request)
}

fn state_with_factory(factory: TestDbFactory) -> State {
    let activation = BlockHeight::from_u32(100_000);
    let network = LocalNetwork {
        nu6: Some(activation),
        nu6_1: Some(activation),
        nu6_2: Some(activation),
        nu6_3: Some(activation),
        ..TestBuilder::<(), ()>::DEFAULT_NETWORK
    };
    let mut st = TestBuilder::new()
        .with_network(network)
        .with_data_store_factory(factory)
        .with_block_cache(BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();
    // Establish a real retained checkpoint before the block the reorg test removes.
    let (empty_height, _) = st.generate_empty_block();
    st.scan_cached_blocks(empty_height, 1);
    st
}

mod discovery;
mod recovery;

fn outgoing(st: &State, tx_ref: crate::TxRef, position: u64, index: usize) -> EnhancePirRequest {
    queue_transaction(
        st.wallet().conn(),
        tx_ref,
        &[IronwoodEnhanceCandidate::from_parts(
            position.into(),
            index,
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 52],
            vec![st.test_account().unwrap().id()],
        )],
        true,
    )
    .unwrap();
    requests(st.wallet().conn())
        .unwrap()
        .into_iter()
        .find(|r| u64::from(r.position()) == position)
        .unwrap()
}

fn wire_record(inputs: bool, outputs: bool) -> EnhanceRecord {
    let mut ciphertext = [0; 580];
    ciphertext[..52].copy_from_slice(&[4; 52]);
    EnhanceRecord::from_parts([3; 32], ciphertext, [5; 32], [6; 80], inputs, outputs)
}

fn visible(st: &State, request: EnhancePirRequest) -> bool {
    st.wallet()
        .db()
        .transaction_data_requests()
        .unwrap()
        .contains(&TransactionDataRequest::Enhancement(
            request.request_id().txid(),
        ))
}

fn validated(
    request: EnhancePirRequest,
    transparent: bool,
    incoming: bool,
    outgoing: IronwoodOutgoingResult<AccountUuid>,
) -> ValidatedIronwoodEnhancement<AccountUuid> {
    ValidatedIronwoodEnhancement::for_testing(
        request,
        transparent,
        incoming.then(MemoBytes::empty),
        outgoing,
    )
}

fn finish_incoming(st: &mut State, request: EnhancePirRequest) {
    assert_eq!(
        st.wallet_mut()
            .db_mut()
            .apply_ironwood_enhancement(validated(
                request,
                false,
                true,
                IronwoodOutgoingResult::NotRequested
            ))
            .unwrap(),
        EnhancePirStoreResult::Stored
    );
}

#[test]
fn either_transparent_flag_routes_the_entire_transaction_and_is_sticky() {
    for (inputs, outputs) in [(true, false), (false, true), (true, true)] {
        let (mut st, tx_ref, incoming) = fixture();
        let outgoing = outgoing(&st, tx_ref, 99, 4);
        st.wallet_mut()
            .db_mut()
            .set_enhancement_mode(EnhancementMode::PrivateIronwood);
        assert!(!visible(&st, incoming));
        assert_eq!(
            apply_record(
                st.wallet_mut().db_mut(),
                outgoing,
                &wire_record(inputs, outputs)
            )
            .unwrap(),
            EnhancePirStoreResult::LwdRequired
        );
        assert!(visible(&st, incoming));
        assert!(requests(st.wallet().conn()).unwrap().is_empty());
        assert!(!is_protected(st.wallet().conn(), incoming.request_id().txid()).unwrap());

        // Late false flags and repeated compact scans cannot undo fallback.
        assert_eq!(
            apply_record(
                st.wallet_mut().db_mut(),
                outgoing,
                &wire_record(false, false)
            )
            .unwrap(),
            EnhancePirStoreResult::AlreadyResolved
        );
        queue_transaction(st.wallet().conn(), tx_ref, &[], true).unwrap();
        assert!(requests(st.wallet().conn()).unwrap().is_empty());
        assert!(visible(&st, incoming));
    }
}

#[test]
fn incoming_authentication_precedes_shape_and_flags_are_not_authenticated() {
    use orchard::note_encryption::{IronwoodDomain, IronwoodNoteEncryption};
    use zcash_client_backend::data_api::enhance_pir::IronwoodEnhanceRecord;
    use zcash_note_encryption::Domain;

    let (mut st, _, request) = fixture();
    let pending = st
        .wallet()
        .db()
        .pending_ironwood_memo(request.position())
        .unwrap()
        .unwrap();
    let encryptor = IronwoodNoteEncryption::new(None, pending.note, [7; 512]);
    let ciphertext = encryptor.encrypt_note_plaintext();
    let record = |bytes| {
        IronwoodEnhanceRecord::from_parts(
            IronwoodDomain::epk_bytes(encryptor.epk()).0,
            bytes,
            [0; 32],
            [0; 80],
            true,
            false,
        )
    };
    let mut corrupt = ciphertext;
    corrupt[579] ^= 1;
    assert_eq!(
        apply_ironwood_enhance_record(st.wallet_mut().db_mut(), request, &record(corrupt)).unwrap(),
        EnhancePirStoreResult::Rejected
    );
    assert!(is_protected(st.wallet().conn(), request.request_id().txid()).unwrap());
    assert_eq!(
        apply_ironwood_enhance_record(st.wallet_mut().db_mut(), request, &record(ciphertext))
            .unwrap(),
        EnhancePirStoreResult::LwdRequired
    );
}

#[test]
fn stale_identity_cannot_change_memos_or_routing() {
    let (mut st, _, request) = fixture();
    for stale in [
        EnhancePirRequest::new(
            request.position(),
            IronwoodEnhanceRequestId::new(TxId::from_bytes([9; 32]), 0),
        ),
        EnhancePirRequest::new(
            request.position(),
            IronwoodEnhanceRequestId::new(request.request_id().txid(), 999),
        ),
        EnhancePirRequest::new(Position::from(999), request.request_id()),
    ] {
        assert_eq!(
            st.wallet_mut()
                .db_mut()
                .apply_ironwood_enhancement(validated(
                    stale,
                    true,
                    true,
                    IronwoodOutgoingResult::NotRequested
                ))
                .unwrap(),
            EnhancePirStoreResult::AlreadyResolved
        );
    }
    assert_eq!(requests(st.wallet().conn()).unwrap(), vec![request]);
    assert!(is_protected(st.wallet().conn(), request.request_id().txid()).unwrap());
}

#[test]
fn non_recovery_discards_candidate_and_retires_only_completed_transactions() {
    for incoming_first in [false, true] {
        let (mut st, tx_ref, incoming) = fixture_with_factory(TestDbFactory::file_backed());
        let outgoing = outgoing(&st, tx_ref, 99, 4);
        st.wallet()
            .conn()
            .execute(
                "INSERT INTO tx_retrieval_queue (txid, query_type) VALUES (?1, 0)",
                [incoming.request_id().txid().as_ref()],
            )
            .unwrap();
        st.wallet_mut()
            .db_mut()
            .set_enhancement_mode(EnhancementMode::PrivateIronwood);

        let mut parts = [0; 580];
        parts[..52].copy_from_slice(&[8; 52]);
        let wrong = EnhanceRecord::from_parts([3; 32], parts, [5; 32], [6; 80], true, false);
        assert_eq!(
            apply_record(st.wallet_mut().db_mut(), outgoing, &wrong).unwrap(),
            EnhancePirStoreResult::Rejected
        );
        assert_eq!(requests(st.wallet().conn()).unwrap().len(), 2);
        if incoming_first {
            finish_incoming(&mut st, incoming);
        }
        assert_eq!(
            apply_record(
                st.wallet_mut().db_mut(),
                outgoing,
                &wire_record(false, false)
            )
            .unwrap(),
            EnhancePirStoreResult::NotRecoverable
        );
        for table in [
            "ironwood_enhance_outgoing_queue",
            "ironwood_enhance_outgoing_accounts",
            "sent_notes",
        ] {
            assert_eq!(
                st.wallet()
                    .conn()
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r
                        .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
        assert_eq!(
            apply_record(
                st.wallet_mut().db_mut(),
                outgoing,
                &wire_record(true, false)
            )
            .unwrap(),
            EnhancePirStoreResult::AlreadyResolved
        );
        assert!(is_protected(st.wallet().conn(), incoming.request_id().txid()).unwrap());
        st.wallet_mut()
            .db_mut()
            .set_enhancement_mode(EnhancementMode::Standard);
        assert_eq!(visible(&st, incoming), !incoming_first);
        if !incoming_first {
            finish_incoming(&mut st, incoming);
        }
        assert!(requests(st.wallet().conn()).unwrap().is_empty());
        assert!(!visible(&st, incoming));
        let statuses: i64 = st
            .wallet()
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM tx_retrieval_queue WHERE query_type = 0",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(statuses, 1);
        let reopened = crate::WalletDb::for_path(
            st.wallet().data_file_path(),
            *st.network(),
            crate::testing::db::test_clock(),
            crate::testing::db::test_rng(),
        )
        .unwrap();
        assert!(reopened.enhance_pir_requests().unwrap().is_empty());
        assert!(!reopened.transaction_data_requests().unwrap().contains(
            &TransactionDataRequest::Enhancement(incoming.request_id().txid())
        ));
        // No tombstone prevents an explicit reconstruction from trying again.
        let requeued = outgoing_requeued(&st, tx_ref);
        assert!(requests(st.wallet().conn()).unwrap().contains(&requeued));
    }
}

fn outgoing_requeued(st: &State, tx_ref: crate::TxRef) -> EnhancePirRequest {
    outgoing(st, tx_ref, 99, 4)
}

#[test]
fn non_recovery_preserves_other_outgoing_and_discovery_work() {
    for discovery_pending in [false, true] {
        let (mut st, tx_ref, incoming) = fixture();
        let account = st.test_account().unwrap().id();
        let candidates = [99u64, 100].map(|position| {
            IronwoodEnhanceCandidate::from_parts(
                position.into(),
                position as usize,
                [1; 32],
                [2; 32],
                [3; 32],
                [4; 52],
                vec![account],
            )
        });
        queue_transaction(st.wallet().conn(), tx_ref, &candidates, true).unwrap();
        if discovery_pending {
            st.wallet().conn().execute("INSERT INTO ironwood_enhance_discovery_queue (transaction_id, suspended) VALUES (?1, 1)", [tx_ref.0]).unwrap();
        }
        finish_incoming(&mut st, incoming);
        let outgoing = requests(st.wallet().conn()).unwrap();
        for (index, request) in outgoing.iter().enumerate() {
            assert_eq!(
                apply_record(
                    st.wallet_mut().db_mut(),
                    *request,
                    &wire_record(false, false)
                )
                .unwrap(),
                EnhancePirStoreResult::NotRecoverable
            );
            assert_eq!(visible(&st, incoming), discovery_pending || index == 0);
        }
    }
}

#[test]
fn completion_retires_only_enhancement_and_survives_replay() {
    let (mut st, tx_ref, incoming) = fixture();
    let outgoing = outgoing(&st, tx_ref, 99, 4);
    st.wallet()
        .conn()
        .execute(
            "INSERT INTO tx_retrieval_queue (txid, query_type) VALUES (:txid, 0)",
            named_params![":txid": incoming.request_id().txid().as_ref()],
        )
        .unwrap();
    finish_incoming(&mut st, incoming);
    assert!(
        visible(&st, incoming),
        "partial completion retains fallback"
    );
    let fvk = OrchardPoolTester::test_account_fvk(&st);
    let from_account = st.test_account().unwrap().id();
    let complete = || {
        validated(
            outgoing,
            false,
            false,
            IronwoodOutgoingResult::Recovered {
                from_account,
                recipient: fvk.address_at(3u32, Scope::External),
                value: Zatoshis::const_from_u64(123),
                memo: MemoBytes::empty(),
            },
        )
    };
    assert_eq!(
        st.wallet_mut()
            .db_mut()
            .apply_ironwood_enhancement(complete())
            .unwrap(),
        EnhancePirStoreResult::Stored
    );
    assert_eq!(
        st.wallet_mut()
            .db_mut()
            .apply_ironwood_enhancement(complete())
            .unwrap(),
        EnhancePirStoreResult::AlreadyResolved
    );
    for mode in [EnhancementMode::Standard, EnhancementMode::PrivateIronwood] {
        st.wallet_mut().db_mut().set_enhancement_mode(mode);
        assert!(!visible(&st, incoming));
    }
    let (value, memo): (u64, Vec<u8>) = st
        .wallet()
        .conn()
        .query_row(
            "SELECT value, memo FROM sent_notes WHERE transaction_id = :tx AND output_index = 4",
            named_params![":tx": tx_ref.0],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((value, memo), (123, vec![0xf6]));
    let statuses: i64 = st
        .wallet()
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM tx_retrieval_queue WHERE query_type = 0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(statuses, 1);
    queue_transaction(
        st.wallet().conn(),
        tx_ref,
        &[IronwoodEnhanceCandidate::from_parts(
            99.into(),
            4,
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 52],
            vec![from_account],
        )],
        true,
    )
    .unwrap();
    assert!(requests(st.wallet().conn()).unwrap().is_empty());
    assert!(!visible(&st, incoming));
}

#[test]
fn atomic_write_rolls_back_memo_and_routing_on_queue_failure() {
    for transparent in [false, true] {
        let (mut st, tx_ref, incoming) = fixture();
        let _outgoing = outgoing(
            &st,
            tx_ref,
            u64::from(incoming.position()),
            incoming.request_id().output_index() as usize,
        );
        // The same action has incoming and outgoing work. Fail after its first
        // mutation: neither a stored memo nor a routing change may survive.
        st.wallet().conn().execute_batch(
            "CREATE TRIGGER fail_outgoing_delete BEFORE DELETE ON ironwood_enhance_outgoing_queue
             BEGIN SELECT RAISE(ABORT, 'injected failure'); END;"
        ).unwrap();
        assert!(
            st.wallet_mut()
                .db_mut()
                .apply_ironwood_enhancement(validated(
                    incoming,
                    transparent,
                    true,
                    IronwoodOutgoingResult::NotRecoverable
                ))
                .is_err()
        );
        assert!(
            st.wallet()
                .db()
                .pending_ironwood_memo(incoming.position())
                .unwrap()
                .is_some()
        );
        assert!(
            st.wallet()
                .db()
                .pending_ironwood_outgoing(incoming.position())
                .unwrap()
                .is_some()
        );
        assert!(is_protected(st.wallet().conn(), incoming.request_id().txid()).unwrap());
    }
}

#[test]
fn full_data_supersedes_inflight_work() {
    let (mut st, tx_ref, request) = fixture();
    st.wallet()
        .conn()
        .execute(
            "UPDATE transactions SET raw = X'00' WHERE id_tx = :tx",
            named_params![":tx": tx_ref.0],
        )
        .unwrap();
    assert_eq!(
        st.wallet_mut()
            .db_mut()
            .apply_ironwood_enhancement(validated(
                request,
                true,
                true,
                IronwoodOutgoingResult::NotRequested
            ))
            .unwrap(),
        EnhancePirStoreResult::AlreadyResolved
    );
    assert!(requests(st.wallet().conn()).unwrap().is_empty());
    clear_work(st.wallet().conn(), tx_ref).unwrap();
    assert!(
        pending(
            st.wallet().conn(),
            &TestBuilder::<(), ()>::DEFAULT_NETWORK,
            request.position()
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn explicit_mixed_scan_discards_all_work_but_keeps_recovered_data() {
    let (mut st, tx_ref, request) = fixture();
    let _outgoing = outgoing(&st, tx_ref, 99, 4);
    finish_incoming(&mut st, request);
    queue_transaction(st.wallet().conn(), tx_ref, &[], false).unwrap();
    assert!(visible(&st, request));
    assert!(requests(st.wallet().conn()).unwrap().is_empty());
    let memo: Vec<u8> = st
        .wallet()
        .conn()
        .query_row(
            "SELECT memo FROM ironwood_received_notes WHERE transaction_id = :tx",
            named_params![":tx": tx_ref.0],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(memo, vec![0xf6]);
    queue_transaction(st.wallet().conn(), tx_ref, &[], true).unwrap();
    assert!(!is_protected(st.wallet().conn(), request.request_id().txid()).unwrap());
}

#[test]
fn reorg_prunes_private_work_but_retains_lwd_decisions() {
    for mixed in [false, true] {
        let (mut st, tx_ref, request) = fixture();
        if mixed {
            require_lwd(st.wallet().conn(), tx_ref).unwrap();
        }
        let height: u32 = st
            .wallet()
            .conn()
            .query_row(
                "SELECT mined_height FROM transactions WHERE id_tx = :tx",
                named_params![":tx": tx_ref.0],
                |row| row.get(0),
            )
            .unwrap();
        st.wallet_mut()
            .db_mut()
            .truncate_to_height(BlockHeight::from_u32(height - 1))
            .unwrap();
        assert!(requests(st.wallet().conn()).unwrap().is_empty());
        let route: Option<i64> = st
            .wallet()
            .conn()
            .query_row(
                "SELECT route FROM ironwood_enhance_routing WHERE transaction_id = :tx",
                named_params![":tx": tx_ref.0],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        assert_eq!(route, mixed.then_some(LWD_REQUIRED));
        assert_eq!(
            st.wallet_mut()
                .db_mut()
                .apply_ironwood_enhancement(validated(
                    request,
                    true,
                    true,
                    IronwoodOutgoingResult::NotRequested
                ))
                .unwrap(),
            EnhancePirStoreResult::AlreadyResolved
        );
    }
}

#[test]
fn reopening_restores_routes_but_requires_reapplying_the_runtime_setting() {
    use crate::testing::db::{test_clock, test_rng};
    let (mut st, tx_ref, request) = fixture_with_factory(TestDbFactory::file_backed());
    st.wallet_mut()
        .db_mut()
        .set_enhancement_mode(EnhancementMode::PrivateIronwood);
    let mut reopened = crate::WalletDb::for_path(
        st.wallet().data_file_path(),
        *st.network(),
        test_clock(),
        test_rng(),
    )
    .unwrap();
    assert_eq!(reopened.enhance_pir_requests().unwrap(), vec![request]);
    assert!(reopened.transaction_data_requests().unwrap().contains(
        &TransactionDataRequest::Enhancement(request.request_id().txid())
    ));
    reopened.set_enhancement_mode(EnhancementMode::PrivateIronwood);
    assert!(!reopened.transaction_data_requests().unwrap().contains(
        &TransactionDataRequest::Enhancement(request.request_id().txid())
    ));
    require_lwd(st.wallet().conn(), tx_ref).unwrap();
    assert!(reopened.enhance_pir_requests().unwrap().is_empty());
    assert!(reopened.transaction_data_requests().unwrap().contains(
        &TransactionDataRequest::Enhancement(request.request_id().txid())
    ));
}

#[test]
fn losing_a_funding_account_cannot_erase_incomplete_outgoing_work() {
    let (mut st, tx_ref, incoming) = fixture();
    let outgoing = outgoing(&st, tx_ref, 99, 4);
    let response = validated(
        outgoing,
        false,
        false,
        IronwoodOutgoingResult::NotRecoverable,
    );
    let tx = st.wallet_mut().conn_mut().transaction().unwrap();
    tx.execute("DELETE FROM ironwood_enhance_outgoing_accounts", [])
        .unwrap();
    remove_orphaned_outgoing(&tx).unwrap();
    tx.commit().unwrap();
    assert_eq!(
        st.wallet_mut()
            .db_mut()
            .apply_ironwood_enhancement(response)
            .unwrap(),
        EnhancePirStoreResult::AlreadyResolved
    );
    assert!(
        pending_outgoing(st.wallet().conn(), outgoing.position())
            .unwrap()
            .is_none()
    );
    finish_incoming(&mut st, incoming);
    assert!(requests(st.wallet().conn()).unwrap().is_empty());
    assert!(visible(&st, incoming));
}

#[test]
fn a_response_validated_before_position_reassignment_is_still_rejected() {
    let (mut st, _, request) = fixture();
    let response = validated(request, true, true, IronwoodOutgoingResult::NotRequested);
    st.wallet()
        .conn()
        .execute(
            "UPDATE transactions SET txid = :replacement WHERE txid = :old",
            named_params![":replacement": &[8u8; 32], ":old": request.request_id().txid().as_ref()],
        )
        .unwrap();
    assert_eq!(
        st.wallet_mut()
            .db_mut()
            .apply_ironwood_enhancement(response)
            .unwrap(),
        EnhancePirStoreResult::AlreadyResolved
    );
    let replacement = requests(st.wallet().conn()).unwrap()[0];
    assert_eq!(replacement.position(), request.position());
    assert_ne!(replacement.request_id(), request.request_id());
    assert!(is_protected(st.wallet().conn(), replacement.request_id().txid()).unwrap());
}

#[test]
fn rescanning_removes_outgoing_jobs_now_covered_by_incoming_decryption() {
    let (st, tx_ref, request) = fixture();
    outgoing(
        &st,
        tx_ref,
        u64::from(request.position()),
        request.request_id().output_index() as usize,
    );
    assert!(
        pending_outgoing(st.wallet().conn(), request.position())
            .unwrap()
            .is_some()
    );
    queue_transaction(st.wallet().conn(), tx_ref, &[], true).unwrap();
    assert!(
        pending_outgoing(st.wallet().conn(), request.position())
            .unwrap()
            .is_none()
    );
    assert_eq!(requests(st.wallet().conn()).unwrap(), vec![request]);
}

#[test]
fn a_mixed_spend_without_received_ironwood_notes_is_sticky() {
    use zcash_client_backend::wallet::WalletSpend;
    use zcash_protocol::consensus::TxIndex;
    let (st, _, original) = fixture();
    let txid = TxId::from_bytes([7; 32]);
    let tx_ref = st
        .wallet()
        .conn()
        .query_row(
            "INSERT INTO transactions (txid, mined_height, min_observed_height)
         VALUES (:txid, 100001, 100001) RETURNING id_tx",
            named_params![":txid": txid.as_ref()],
            |row| row.get(0).map(crate::TxRef),
        )
        .unwrap();
    let pending = st
        .wallet()
        .db()
        .pending_ironwood_memo(original.position())
        .unwrap()
        .unwrap();
    let nf = orchard::note::Nullifier::from_bytes(&pending.note.rho().to_bytes()).unwrap();
    let scanned = WalletTx::new(
        txid,
        TxIndex::from(0u16),
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![WalletSpend::from_parts(
            0,
            nf,
            st.test_account().unwrap().id(),
        )],
        vec![],
    )
    .with_ironwood_enhance_candidates(vec![], false);
    queue_scanned(st.wallet().conn(), tx_ref, &scanned).unwrap();
    let provisional = scanned.with_ironwood_enhance_candidates(vec![], true);
    queue_scanned(st.wallet().conn(), tx_ref, &provisional).unwrap();
    let route: i64 = st
        .wallet()
        .conn()
        .query_row(
            "SELECT route FROM ironwood_enhance_routing WHERE transaction_id = :tx",
            named_params![":tx": tx_ref.0],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(route, LWD_REQUIRED);
}

#[test]
fn retirement_failure_rolls_back_candidate_discard() {
    let (mut st, tx_ref, incoming) = fixture();
    let outgoing = outgoing(&st, tx_ref, 99, 4);
    finish_incoming(&mut st, incoming);
    st.wallet()
        .conn()
        .execute_batch(
            "CREATE TRIGGER fail_retirement BEFORE DELETE ON tx_retrieval_queue
         BEGIN SELECT RAISE(ABORT, 'injected retirement failure'); END;",
        )
        .unwrap();
    assert!(
        apply_record(
            st.wallet_mut().db_mut(),
            outgoing,
            &wire_record(false, false)
        )
        .is_err()
    );
    assert_eq!(requests(st.wallet().conn()).unwrap(), vec![outgoing]);
    assert!(visible(&st, incoming));
    assert_eq!(
        st.wallet()
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM ironwood_enhance_outgoing_accounts",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
}
