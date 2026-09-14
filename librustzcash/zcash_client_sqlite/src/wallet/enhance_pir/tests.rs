use super::*;
use crate::testing::{
    BlockCache,
    db::{TestDb, TestDbFactory},
};
use zcash_client_backend::data_api::enhance_pir::EnhanceRecord;
use zcash_client_backend::data_api::enhance_pir::EnhanceRecordParts;
use zcash_client_backend::data_api::{
    TransactionDataRequest, WalletRead, WalletWrite,
    enhance_pir::{EnhancePirRead, EnhancePirWrite, EnhancementMode},
    testing::{
        AddressType, IronwoodFvk, TestBuilder, TestState, orchard::OrchardPoolTester,
        pool::ShieldedPoolTester,
    },
};
use zcash_client_backend::wallet::IronwoodEnhanceCandidate;
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
    let requests = st.wallet().db().query_requests().unwrap();
    assert_eq!(
        requests.len(),
        1,
        "scanning queues work after storing the note"
    );
    let request = requests[0];
    assert!(
        st.wallet()
            .db()
            .pending_memo(request.position())
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

fn outgoing(st: &State, tx_ref: crate::TxRef, position: u64, index: usize) -> EnhancePirRequest {
    queue_transaction(
        st.wallet().conn(),
        tx_ref,
        &IronwoodEnhancementPlan::Eligible {
            outgoing: vec![IronwoodEnhanceCandidate::from_parts(
                position.into(),
                index,
                [1; 32],
                [2; 32],
                [3; 32],
                [4; 52],
                vec![st.test_account().unwrap().id()],
            )],
        },
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
    EnhanceRecord::from_parts(EnhanceRecordParts {
        ephemeral_key: [3; 32],
        enc_ciphertext: ciphertext,
        cv_net: [5; 32],
        out_ciphertext: [6; 80],
        has_transparent_inputs: inputs,
        has_transparent_outputs: outputs,
    })
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
            .apply_validated(validated(
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
        queue_transaction(
            st.wallet().conn(),
            tx_ref,
            &IronwoodEnhancementPlan::Eligible { outgoing: vec![] },
        )
        .unwrap();
        assert!(requests(st.wallet().conn()).unwrap().is_empty());
        assert!(visible(&st, incoming));
    }
}

#[test]
fn incoming_authentication_precedes_shape_and_flags_are_not_authenticated() {
    use orchard::note_encryption::{IronwoodDomain, IronwoodNoteEncryption};
    use zcash_client_backend::data_api::enhance_pir::EnhanceRecord;
    use zcash_note_encryption::Domain;

    let (mut st, _, request) = fixture();
    let pending = st
        .wallet()
        .db()
        .pending_memo(request.position())
        .unwrap()
        .unwrap();
    let encryptor = IronwoodNoteEncryption::new(None, pending.note, [7; 512]);
    let ciphertext = encryptor.encrypt_note_plaintext();
    let record = |bytes| {
        EnhanceRecord::from_parts(EnhanceRecordParts {
            ephemeral_key: IronwoodDomain::epk_bytes(encryptor.epk()).0,
            enc_ciphertext: bytes,
            cv_net: [0; 32],
            out_ciphertext: [0; 80],
            has_transparent_inputs: true,
            has_transparent_outputs: false,
        })
    };
    let mut corrupt = ciphertext;
    corrupt[579] ^= 1;
    assert_eq!(
        apply_record(st.wallet_mut().db_mut(), request, &record(corrupt)).unwrap(),
        EnhancePirStoreResult::Rejected
    );
    assert!(is_protected(st.wallet().conn(), request.request_id().txid()).unwrap());
    assert_eq!(
        apply_record(st.wallet_mut().db_mut(), request, &record(ciphertext)).unwrap(),
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
                .apply_validated(validated(
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
fn non_recovery_suspends_work_without_completion_or_public_fallback() {
    let (mut st, tx_ref, incoming) = fixture();
    let outgoing = outgoing(&st, tx_ref, 99, 4);
    st.wallet_mut()
        .db_mut()
        .set_enhancement_mode(EnhancementMode::PrivateIronwood);

    let mut wrong = wire_record(true, false);
    // A mismatched compact prefix must not apply even a positive flag.
    let mut parts = [0; 580];
    parts[..52].copy_from_slice(&[8; 52]);
    wrong = EnhanceRecord::from_parts(EnhanceRecordParts {
        ephemeral_key: *wrong.ephemeral_key(),
        enc_ciphertext: parts,
        cv_net: [5; 32],
        out_ciphertext: [6; 80],
        has_transparent_inputs: true,
        has_transparent_outputs: false,
    });
    assert_eq!(
        apply_record(st.wallet_mut().db_mut(), outgoing, &wrong).unwrap(),
        EnhancePirStoreResult::Rejected
    );
    assert_eq!(requests(st.wallet().conn()).unwrap().len(), 2);

    assert_eq!(
        apply_record(
            st.wallet_mut().db_mut(),
            outgoing,
            &wire_record(false, false)
        )
        .unwrap(),
        EnhancePirStoreResult::NotRecoverable
    );
    finish_incoming(&mut st, incoming);
    assert!(requests(st.wallet().conn()).unwrap().is_empty());
    assert!(!visible(&st, incoming));
    st.wallet_mut()
        .db_mut()
        .set_enhancement_mode(EnhancementMode::Standard);
    assert!(
        visible(&st, incoming),
        "non-recovery is not proven dummy/completion"
    );
    outgoing_requeued(&st, tx_ref);
}

fn outgoing_requeued(st: &State, tx_ref: crate::TxRef) {
    let request = outgoing(st, tx_ref, 99, 4);
    assert!(requests(st.wallet().conn()).unwrap().contains(&request));
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
            .apply_validated(complete())
            .unwrap(),
        EnhancePirStoreResult::Stored
    );
    assert_eq!(
        st.wallet_mut()
            .db_mut()
            .apply_validated(complete())
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
        &IronwoodEnhancementPlan::Eligible {
            outgoing: vec![IronwoodEnhanceCandidate::from_parts(
                99.into(),
                4,
                [1; 32],
                [2; 32],
                [3; 32],
                [4; 52],
                vec![from_account],
            )],
        },
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
            "CREATE TRIGGER fail_outgoing_update BEFORE UPDATE ON ironwood_enhance_outgoing_queue
             BEGIN SELECT RAISE(ABORT, 'injected failure'); END;
             CREATE TRIGGER fail_outgoing_delete BEFORE DELETE ON ironwood_enhance_outgoing_queue
             BEGIN SELECT RAISE(ABORT, 'injected failure'); END;"
        ).unwrap();
        assert!(
            st.wallet_mut()
                .db_mut()
                .apply_validated(validated(
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
                .pending_memo(incoming.position())
                .unwrap()
                .is_some()
        );
        assert!(
            st.wallet()
                .db()
                .pending_outgoing(incoming.position())
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
            .apply_validated(validated(
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
    queue_transaction(
        st.wallet().conn(),
        tx_ref,
        &IronwoodEnhancementPlan::Ineligible,
    )
    .unwrap();
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
    queue_transaction(
        st.wallet().conn(),
        tx_ref,
        &IronwoodEnhancementPlan::Eligible { outgoing: vec![] },
    )
    .unwrap();
    assert!(!is_protected(st.wallet().conn(), request.request_id().txid()).unwrap());
}

#[test]
fn reorg_prunes_positions_but_retains_protection_and_lwd_decisions() {
    use crate::testing::db::{test_clock, test_rng};
    for mixed in [false, true] {
        let (mut st, tx_ref, request) = fixture_with_factory(TestDbFactory::file_backed());
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
        assert_eq!(
            route,
            Some(if mixed {
                LWD_REQUIRED
            } else {
                PRIVATE_PROTECTED
            })
        );
        for mode in [EnhancementMode::PrivateIronwood, EnhancementMode::Standard] {
            st.wallet_mut().db_mut().set_enhancement_mode(mode);
            let expected = mixed || mode == EnhancementMode::Standard;
            assert_eq!(visible(&st, request), expected);
            st.wallet_mut()
                .db_mut()
                .transactionally(|db| {
                    assert_eq!(
                        db.transaction_data_requests()?.contains(
                            &TransactionDataRequest::Enhancement(request.request_id().txid())
                        ),
                        expected
                    );
                    Ok::<_, SqliteClientError>(())
                })
                .unwrap();
            let reopened = crate::WalletDb::for_path(
                st.wallet().data_file_path(),
                *st.network(),
                test_clock(),
                test_rng(),
            )
            .unwrap()
            .with_enhancement_mode(mode);
            assert_eq!(
                reopened.transaction_data_requests().unwrap().contains(
                    &TransactionDataRequest::Enhancement(request.request_id().txid())
                ),
                expected
            );
        }
        assert_eq!(
            st.wallet_mut()
                .db_mut()
                .apply_validated(validated(
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
fn reopening_uses_explicit_mode_and_preserves_routes() {
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
    .unwrap()
    .with_enhancement_mode(zcash_client_backend::data_api::enhance_pir::EnhancementMode::Standard);
    assert_eq!(reopened.query_requests().unwrap(), vec![request]);
    assert!(reopened.transaction_data_requests().unwrap().contains(
        &TransactionDataRequest::Enhancement(request.request_id().txid())
    ));
    reopened.set_enhancement_mode(EnhancementMode::PrivateIronwood);
    assert!(!reopened.transaction_data_requests().unwrap().contains(
        &TransactionDataRequest::Enhancement(request.request_id().txid())
    ));
    require_lwd(st.wallet().conn(), tx_ref).unwrap();
    assert!(reopened.query_requests().unwrap().is_empty());
    assert!(reopened.transaction_data_requests().unwrap().contains(
        &TransactionDataRequest::Enhancement(request.request_id().txid())
    ));
}

#[test]
fn losing_a_funding_account_cannot_erase_incomplete_outgoing_work() {
    let (mut st, tx_ref, incoming) = fixture();
    let _outgoing = outgoing(&st, tx_ref, 99, 4);
    let tx = st.wallet_mut().conn_mut().transaction().unwrap();
    tx.execute("DELETE FROM ironwood_enhance_outgoing_accounts", [])
        .unwrap();
    crate::wallet::suspend_orphaned_ironwood_enhancement(&tx).unwrap();
    tx.commit().unwrap();
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
        st.wallet_mut().db_mut().apply_validated(response).unwrap(),
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
    queue_transaction(
        st.wallet().conn(),
        tx_ref,
        &IronwoodEnhancementPlan::Eligible { outgoing: vec![] },
    )
    .unwrap();
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
        .pending_memo(original.position())
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
    .with_ironwood_enhancement_plan(IronwoodEnhancementPlan::Ineligible);
    queue_scanned(st.wallet().conn(), tx_ref, &scanned).unwrap();
    let provisional = scanned
        .with_ironwood_enhancement_plan(IronwoodEnhancementPlan::Eligible { outgoing: vec![] });
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

// Test projections keep individual queue assertions readable while exercising the single
// application read API. These helpers are not part of the production wallet interface.
fn requests(conn: &Connection) -> Result<Vec<EnhancePirRequest>, SqliteClientError> {
    Ok(work(conn)?
        .into_iter()
        .filter_map(|work| match work {
            EnhancePirWork::Query(request) => Some(request),
            _ => None,
        })
        .collect())
}

fn apply_record<Db: EnhancePirWrite>(
    db: &mut Db,
    request: EnhancePirRequest,
    record: &EnhanceRecord,
) -> Result<EnhancePirStoreResult, Db::Error> {
    db.apply_ironwood_enhance_record(request, record)
}

impl<C: std::borrow::Borrow<Connection>, P: Parameters, CL, R> crate::WalletDb<C, P, CL, R> {
    fn query_requests(&self) -> Result<Vec<EnhancePirRequest>, SqliteClientError> {
        Ok(self
            .enhance_pir_work()?
            .into_iter()
            .filter_map(|work| match work {
                EnhancePirWork::Query(request) => Some(request),
                _ => None,
            })
            .collect())
    }
    fn discovery_requests(
        &self,
    ) -> Result<Vec<IronwoodEnhanceDiscoveryRequest>, SqliteClientError> {
        Ok(self
            .enhance_pir_work()?
            .into_iter()
            .filter_map(|work| match work {
                EnhancePirWork::Rediscover(request) => Some(request),
                _ => None,
            })
            .collect())
    }
    fn discovery_suspensions(
        &self,
    ) -> Result<Vec<IronwoodEnhanceDiscoveryFailure>, SqliteClientError> {
        Ok(self
            .enhance_pir_work()?
            .into_iter()
            .filter_map(|work| match work {
                EnhancePirWork::Suspended(EnhancePirSuspension::Discovery(failure)) => {
                    Some(failure)
                }
                _ => None,
            })
            .collect())
    }
    fn pending_memo(
        &self,
        position: Position,
    ) -> Result<Option<PendingIronwoodMemo<AccountUuid>>, SqliteClientError> {
        pending(self.conn.borrow(), &self.params, position)
    }
    fn pending_outgoing(
        &self,
        position: Position,
    ) -> Result<Option<PendingIronwoodOutgoing<AccountUuid>>, SqliteClientError> {
        pending_outgoing(self.conn.borrow(), position)
    }
}

impl<C: std::borrow::BorrowMut<Connection>, P: Parameters, CL: crate::util::Clock, R: rand::Rng>
    crate::WalletDb<C, P, CL, R>
{
    fn apply_validated(
        &mut self,
        enhancement: ValidatedIronwoodEnhancement<AccountUuid>,
    ) -> Result<EnhancePirStoreResult, SqliteClientError> {
        self.transactionally(|wdb| apply(wdb.conn.0, wdb.params, enhancement))
    }
}

#[test]
fn unified_work_preserves_both_suspension_kinds_across_reopen() {
    use crate::testing::db::{test_clock, test_rng};

    let (mut st, tx_ref, incoming) = fixture_with_factory(TestDbFactory::file_backed());
    let outgoing = outgoing(&st, tx_ref, 99, 4);
    assert_eq!(
        st.wallet_mut()
            .db_mut()
            .apply_ironwood_enhance_record(outgoing, &wire_record(false, false))
            .unwrap(),
        EnhancePirStoreResult::NotRecoverable,
    );
    // This incoming-only fixture has no durable spending associations.
    super::discovery::queue(st.wallet().conn(), tx_ref).unwrap();
    let suspended = vec![
        EnhancePirWork::Suspended(EnhancePirSuspension::Discovery(
            IronwoodEnhanceDiscoveryFailure {
                txid: incoming.request_id().txid(),
                reason: IronwoodEnhanceDiscoveryFailureReason::NoFundingAccounts,
            },
        )),
        EnhancePirWork::Suspended(EnhancePirSuspension::OutgoingNotRecoverable(outgoing)),
    ];
    let expected = std::iter::once(EnhancePirWork::Query(incoming))
        .chain(suspended.iter().copied())
        .collect::<Vec<_>>();
    assert_eq!(st.wallet().db().enhance_pir_work().unwrap(), expected);
    finish_incoming(&mut st, incoming);

    for mode in [EnhancementMode::PrivateIronwood, EnhancementMode::Standard] {
        let mut reopened = crate::WalletDb::for_path(
            st.wallet().data_file_path(),
            *st.network(),
            test_clock(),
            test_rng(),
        )
        .unwrap()
        .with_enhancement_mode(mode);
        assert_eq!(reopened.enhance_pir_work().unwrap(), suspended);
        let exposes =
            |db: &crate::WalletDb<_, _, _, _>| {
                db.transaction_data_requests().unwrap().contains(
                    &TransactionDataRequest::Enhancement(incoming.request_id().txid()),
                )
            };
        assert_eq!(exposes(&reopened), mode == EnhancementMode::Standard);
        let inherited =
            reopened
                .transactionally(|db| -> Result<_, SqliteClientError> {
                    Ok(db.transaction_data_requests()?.contains(
                        &TransactionDataRequest::Enhancement(incoming.request_id().txid()),
                    ))
                })
                .unwrap();
        assert_eq!(inherited, mode == EnhancementMode::Standard);
    }
}

#[test]
fn request_enumeration_requires_mode_even_without_a_chain_tip() {
    use crate::testing::db::{test_clock, test_rng};
    let file = tempfile::NamedTempFile::new().unwrap();
    for mut db in [
        crate::WalletDb::from_connection(
            rusqlite::Connection::open_in_memory().unwrap(),
            TestBuilder::<(), ()>::DEFAULT_NETWORK,
            test_clock(),
            test_rng(),
        ),
        crate::WalletDb::for_path(
            file.path(),
            TestBuilder::<(), ()>::DEFAULT_NETWORK,
            test_clock(),
            test_rng(),
        )
        .unwrap(),
    ] {
        crate::wallet::init::WalletMigrator::new()
            .init_or_migrate(&mut db)
            .unwrap();
        assert!(matches!(
            db.transaction_data_requests(),
            Err(SqliteClientError::EnhancementModeNotConfigured)
        ));
        assert!(matches!(
            db.enhance_pir_work(),
            Err(SqliteClientError::EnhancementModeNotConfigured)
        ));
        db.transactionally(|tx| {
            assert!(matches!(
                tx.transaction_data_requests(),
                Err(SqliteClientError::EnhancementModeNotConfigured)
            ));
            assert!(matches!(
                tx.enhance_pir_work(),
                Err(SqliteClientError::EnhancementModeNotConfigured)
            ));
            Ok::<_, SqliteClientError>(())
        })
        .unwrap();
        for mode in [EnhancementMode::Standard, EnhancementMode::PrivateIronwood] {
            db.set_enhancement_mode(mode);
            assert!(db.transaction_data_requests().unwrap().is_empty());
            assert!(db.enhance_pir_work().unwrap().is_empty());
            db.transactionally(|tx| {
                assert_eq!(tx.enhancement_mode, Some(mode));
                assert!(tx.transaction_data_requests()?.is_empty());
                assert!(tx.enhance_pir_work()?.is_empty());
                Ok::<_, SqliteClientError>(())
            })
            .unwrap();
        }
    }
}

#[test]
fn reopening_requires_mode_before_enumerating_persisted_work() {
    use crate::testing::db::{test_clock, test_rng};
    let (st, _, _) = fixture_with_factory(TestDbFactory::file_backed());
    let expected = st.wallet().db().enhance_pir_work().unwrap();
    assert!(!expected.is_empty());
    let db = crate::WalletDb::for_path(
        st.wallet().data_file_path(),
        *st.network(),
        test_clock(),
        test_rng(),
    )
    .unwrap();
    assert!(matches!(
        db.transaction_data_requests(),
        Err(SqliteClientError::EnhancementModeNotConfigured)
    ));
    assert!(matches!(
        db.enhance_pir_work(),
        Err(SqliteClientError::EnhancementModeNotConfigured)
    ));
    let db = db.with_enhancement_mode(EnhancementMode::PrivateIronwood);
    assert_eq!(db.enhance_pir_work().unwrap(), expected);
    assert!(db.transaction_data_requests().unwrap().is_empty());
}
