use super::*;
use group::{Group, GroupEncoding};
use orchard::{
    keys::{FullViewingKey, OutgoingViewingKey},
    note::{ExtractedNoteCommitment, NoteVersion},
    note_encryption::{IronwoodDomain, IronwoodNoteEncryption},
    value::ValueCommitment,
};
use pasta_curves::pallas;
use prost::Message;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use zcash_client_backend::{
    data_api::{
        chain::BlockSource,
        enhance_pir::{
            IronwoodEnhanceDiscoveryFailure, IronwoodEnhanceDiscoveryFailureReason::*,
            IronwoodEnhanceDiscoveryRequest, IronwoodEnhanceDiscoveryResult::*,
        },
    },
    proto::compact_formats::{CompactBlock, CompactOrchardAction, CompactTx},
};
use zcash_note_encryption::Domain;

/// A real V3 encrypted action and its matching PIR record, including authentic OVK ciphertext.
fn encrypted_action(
    nf: [u8; 32],
    recipient: orchard::Address,
    ovk: OutgoingViewingKey,
    value: u64,
) -> (CompactOrchardAction, EnhanceRecord) {
    let rho = Rho::from_bytes(&nf).unwrap();
    let rseed = RandomSeed::from_bytes([7; 32], &rho).unwrap();
    let note = Note::from_parts(
        recipient,
        NoteValue::from_raw(value),
        rho,
        rseed,
        NoteVersion::V3,
    )
    .unwrap();
    let encryptor = IronwoodNoteEncryption::new(Some(ovk), note, [4; 512]);
    let cmx = ExtractedNoteCommitment::from(note.commitment());
    let cv = ValueCommitment::from_bytes(&pallas::Point::generator().to_bytes()).unwrap();
    let mut rng = ChaCha20Rng::from_seed([7; 32]);
    let record = EnhanceRecord::from_parts(
        IronwoodDomain::epk_bytes(encryptor.epk()).0,
        encryptor.encrypt_note_plaintext(),
        cv.to_bytes(),
        encryptor.encrypt_outgoing_plaintext(&cv, &cmx, &mut rng),
        false,
        false,
    );
    (
        CompactOrchardAction {
            nullifier: nf.to_vec(),
            cmx: cmx.to_bytes().to_vec(),
            ephemeral_key: record.ephemeral_key().to_vec(),
            ciphertext: record.ciphertext()[..52].to_vec(),
        },
        record,
    )
}

fn cached(st: &State, height: BlockHeight) -> CompactBlock {
    let mut result = None;
    st.cache()
        .with_blocks::<_, SqliteClientError>(Some(height), Some(1), |block| {
            result = Some(block);
            Ok(())
        })
        .unwrap();
    result.unwrap()
}

struct Send {
    st: State,
    funding_height: BlockHeight,
    second_funding: Option<(BlockHeight, AccountUuid)>,
    block: CompactBlock,
    record: EnhanceRecord,
    recipient: orchard::Address,
}

impl Send {
    fn new(change: bool) -> Self {
        Self::with_second_funder(change, false)
    }

    fn with_second_funder(change: bool, second_funder: bool) -> Self {
        let mut st = state_with_factory(TestDbFactory::file_backed());
        st.wallet_mut()
            .db_mut()
            .set_enhancement_mode(EnhancementMode::PrivateIronwood);
        let fvk = IronwoodFvk(OrchardPoolTester::test_account_fvk(&st));
        let second = second_funder.then(|| {
            let (account, usk) = st.create_account_from_test_seed("second funder");
            (
                account,
                IronwoodFvk(usk.to_unified_full_viewing_key().orchard().unwrap().clone()),
            )
        });
        let (funding_height, _, nf) = st.generate_next_block(
            &fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(50_000),
        );
        let second_funding = second.as_ref().map(|(account, key)| {
            let (height, _, nf) = st.generate_next_block(
                key,
                AddressType::DefaultExternal,
                Zatoshis::const_from_u64(10_000),
            );
            (height, *account, nf)
        });
        let (height, _) = st.generate_empty_block();
        let mut block = cached(&st, height);
        let other_fvk: FullViewingKey =
            OrchardPoolTester::sk_to_fvk(&OrchardPoolTester::sk(&[0xf5; 32]));
        let recipient = other_fvk.address_at(0u32, Scope::External);
        let mut actions = vec![];
        if change {
            actions.push(
                encrypted_action(
                    nf.to_bytes(),
                    fvk.0.address_at(0u32, Scope::Internal),
                    fvk.0.to_ovk(Scope::Internal),
                    30_000,
                )
                .0,
            );
        }
        let (action, record) = encrypted_action(
            second_funding
                .map(|(_, _, nf)| nf.to_bytes())
                .unwrap_or_else(|| if change { [9; 32] } else { nf.to_bytes() }),
            recipient,
            second
                .as_ref()
                .map_or(&fvk, |(_, key)| key)
                .0
                .to_ovk(Scope::External),
            if second_funder {
                30_000
            } else if change {
                20_000
            } else {
                50_000
            },
        );
        actions.push(action);
        block
            .chain_metadata
            .as_mut()
            .unwrap()
            .ironwood_commitment_tree_size += actions.len() as u32;
        block.vtx = vec![CompactTx {
            txid: vec![42; 32],
            index: 1,
            ironwood_actions: actions,
            ..Default::default()
        }];
        // Only this final block is replaced; its predecessor's cached ChainState is unchanged.
        st.cache()
            .0
            .execute(
                "UPDATE compactblocks SET data = ?1 WHERE height = ?2",
                rusqlite::params![block.encode_to_vec(), u32::from(height)],
            )
            .unwrap();
        Self {
            st,
            funding_height,
            second_funding: second_funding.map(|(height, account, _)| (height, account)),
            block,
            record,
            recipient,
        }
    }

    fn tx_ref(&self) -> crate::TxRef {
        self.st
            .wallet()
            .conn()
            .query_row(
                "SELECT id_tx FROM transactions WHERE txid = ?1",
                [&self.block.vtx[0].txid],
                |row| row.get(0).map(crate::TxRef),
            )
            .unwrap()
    }

    fn queued(&self) -> bool {
        self.st.wallet().conn().query_row("SELECT EXISTS(SELECT 1 FROM tx_retrieval_queue WHERE txid = ?1 AND query_type = ?2)",
            rusqlite::params![&self.block.vtx[0].txid, TxQueryType::Enhancement.code()], |row| row.get(0)).unwrap()
    }

    fn requests(&self) -> Vec<EnhancePirRequest> {
        self.st
            .wallet()
            .db()
            .enhance_pir_requests()
            .unwrap()
            .into_iter()
            .filter(|r| r.request_id().txid().as_ref().as_slice() == self.block.vtx[0].txid)
            .collect()
    }

    fn scan_send(&mut self) {
        self.st.scan_cached_blocks(self.block.height(), 1);
    }
    fn scan_funding(&mut self) {
        self.st.scan_cached_blocks(self.funding_height, 1);
    }

    fn discovery(&self) -> IronwoodEnhanceDiscoveryRequest {
        let jobs = self
            .st
            .wallet()
            .db()
            .ironwood_enhance_discovery_requests()
            .unwrap();
        assert_eq!(jobs.len(), 1);
        jobs[0]
    }

    fn rebuild(&mut self) {
        let request = self.discovery();
        assert_eq!(
            self.st
                .wallet_mut()
                .db_mut()
                .rebuild_ironwood_enhancement(request, &self.block)
                .unwrap(),
            Rebuilt(1)
        );
        assert!(
            self.st
                .wallet()
                .db()
                .ironwood_enhance_discovery_requests()
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn later_funding_account_reopens_discarded_ovk_recovery() {
    let mut send = Send::with_second_funder(true, true);
    send.scan_funding();
    send.scan_send();
    let outgoing = send
        .requests()
        .into_iter()
        .find(|r| r.request_id().output_index() == 1)
        .unwrap();
    assert_eq!(
        apply_record(send.st.wallet_mut().db_mut(), outgoing, &send.record).unwrap(),
        EnhancePirStoreResult::NotRecoverable
    );
    assert!(
        send.st
            .wallet()
            .db()
            .ironwood_enhance_discovery_requests()
            .unwrap()
            .is_empty()
    );
    assert!(
        send.st
            .wallet()
            .db()
            .pending_ironwood_outgoing(outgoing.position())
            .unwrap()
            .is_none()
    );
    // Finish change too: discovering the second funder must reopen a transaction
    // whose earlier non-recovery already retired its enhancement intent.
    for incoming in send.requests() {
        finish_incoming(&mut send.st, incoming);
    }
    send.st
        .wallet_mut()
        .db_mut()
        .set_enhancement_mode(EnhancementMode::Standard);
    assert!(!visible(&send.st, outgoing));
    send.st
        .wallet_mut()
        .db_mut()
        .set_enhancement_mode(EnhancementMode::PrivateIronwood);
    let (height, account) = send.second_funding.unwrap();
    send.st.scan_cached_blocks(height, 1);
    send.rebuild();
    let pending = send
        .st
        .wallet()
        .db()
        .pending_ironwood_outgoing(outgoing.position())
        .unwrap()
        .unwrap();
    assert_eq!(pending.account_ids.len(), 2);
    assert!(pending.account_ids.contains(&account));
    assert_eq!(
        apply_record(send.st.wallet_mut().db_mut(), outgoing, &send.record).unwrap(),
        EnhancePirStoreResult::Stored
    );
    let from_account: AccountUuid = send
        .st
        .wallet()
        .conn()
        .query_row(
            "SELECT a.uuid FROM sent_notes sn JOIN accounts a ON a.id = sn.from_account_id
         WHERE sn.transaction_id = ?1 AND sn.output_index = 1",
            [send.tx_ref().0],
            |row| row.get(0).map(AccountUuid),
        )
        .unwrap();
    assert_eq!(from_account, account);
}

/// Two discovery jobs at one height: A pays B, and B pays an external recipient.
/// Deleting A retains the first transaction for B, but removes its only funding key.
fn shared_and_independent_jobs() -> Send {
    let mut send = Send::with_second_funder(true, true);
    let (_, account_b) = send.second_funding.unwrap();
    let account = send
        .st
        .wallet()
        .db()
        .get_account(account_b)
        .unwrap()
        .unwrap();
    let key_b = account.ufvk().unwrap().orchard().unwrap();
    let key_a = OrchardPoolTester::test_account_fvk(&send.st);
    let actions = &send.block.vtx[0].ironwood_actions;
    let shared = encrypted_action(
        actions[0].nf().unwrap().to_bytes(),
        key_b.address_at(0u32, Scope::External),
        key_a.to_ovk(Scope::External),
        50_000,
    )
    .0;
    let (independent, record) = encrypted_action(
        actions[1].nf().unwrap().to_bytes(),
        send.recipient,
        key_b.to_ovk(Scope::External),
        10_000,
    );
    send.block.vtx[0].ironwood_actions = vec![shared];
    send.block.vtx.push(CompactTx {
        txid: vec![43; 32],
        index: 2,
        ironwood_actions: vec![independent],
        ..Default::default()
    });
    send.record = record;
    send.st
        .cache()
        .0
        .execute(
            "UPDATE compactblocks SET data = ?1 WHERE height = ?2",
            rusqlite::params![send.block.encode_to_vec(), u32::from(send.block.height())],
        )
        .unwrap();
    send.scan_send();
    send.scan_funding();
    send.st
        .scan_cached_blocks(send.second_funding.unwrap().0, 1);
    send
}

#[test]
fn deleting_a_funder_does_not_block_another_transaction_in_the_block() {
    let mut send = shared_and_independent_jobs();
    let account_a = send.st.test_account().unwrap().id();
    let request = send.discovery();
    send.st
        .wallet_mut()
        .db_mut()
        .delete_account(account_a)
        .unwrap();
    assert!(
        send.queued(),
        "shared transaction and its enhancement intent survive"
    );
    let suspended = vec![IronwoodEnhanceDiscoveryFailure {
        txid: send.block.vtx[0].txid(),
        reason: NoFundingAccounts,
    }];
    assert_eq!(
        send.st
            .wallet()
            .db()
            .suspended_ironwood_enhance_discoveries()
            .unwrap(),
        suspended
    );
    let incoming = send.requests()[0];
    finish_incoming(&mut send.st, incoming);
    assert!(
        send.queued(),
        "memo completion must not retire a suspended discovery job"
    );
    assert!(
        !visible(&send.st, incoming),
        "deleting keys is not permission to use LWD"
    );
    assert_eq!(
        send.st
            .wallet_mut()
            .db_mut()
            .rebuild_ironwood_enhancement(request, &send.block)
            .unwrap(),
        Rebuilt(1)
    );
    let outgoing = send
        .st
        .wallet()
        .db()
        .enhance_pir_requests()
        .unwrap()
        .into_iter()
        .find(|r| r.request_id().txid() == send.block.vtx[1].txid())
        .unwrap();
    assert_eq!(
        apply_record(send.st.wallet_mut().db_mut(), outgoing, &send.record).unwrap(),
        EnhancePirStoreResult::Stored
    );
    assert!(
        send.st
            .wallet()
            .db()
            .ironwood_enhance_discovery_requests()
            .unwrap()
            .is_empty(),
        "a suspended-only block is not downloaded again"
    );
    assert_eq!(
        send.st
            .wallet_mut()
            .db_mut()
            .rebuild_ironwood_enhancement(request, &send.block)
            .unwrap(),
        AlreadyResolved
    );
    use crate::testing::db::{test_clock, test_rng};
    let mut reopened = crate::WalletDb::for_path(
        send.st.wallet().data_file_path(),
        *send.st.network(),
        test_clock(),
        test_rng(),
    )
    .unwrap();
    assert_eq!(
        reopened.suspended_ironwood_enhance_discoveries().unwrap(),
        suspended
    );
    assert!(reopened.transaction_data_requests().unwrap().contains(
        &TransactionDataRequest::Enhancement(incoming.request_id().txid())
    ));
    reopened.set_enhancement_mode(EnhancementMode::PrivateIronwood);
    assert!(!reopened.transaction_data_requests().unwrap().contains(
        &TransactionDataRequest::Enhancement(incoming.request_id().txid())
    ));
}

#[test]
fn transaction_local_failure_does_not_block_a_valid_sibling() {
    for missing in [false, true] {
        let mut send = shared_and_independent_jobs();
        let request = send.discovery();
        let mut bad = send.block.clone();
        let reason = if missing {
            bad.vtx[0].txid = vec![99; 32];
            TransactionMissing
        } else {
            bad.vtx[0].ironwood_actions[0].ephemeral_key.clear();
            ContextMismatch
        };
        let unresolved = vec![IronwoodEnhanceDiscoveryFailure {
            txid: send.block.vtx[0].txid(),
            reason,
        }];
        assert_eq!(
            send.st
                .wallet_mut()
                .db_mut()
                .rebuild_ironwood_enhancement(request, &bad)
                .unwrap(),
            Incomplete {
                rebuilt: 1,
                unresolved: unresolved.clone()
            }
        );
        assert!(send.queued());
        assert_eq!(
            send.discovery(),
            request,
            "failed job is retryable, not deleted"
        );
        let healthy = send
            .st
            .wallet()
            .db()
            .enhance_pir_requests()
            .unwrap()
            .into_iter()
            .find(|r| r.request_id().txid() == send.block.vtx[1].txid())
            .unwrap();
        assert!(!visible(&send.st, healthy));
        assert_eq!(
            apply_record(send.st.wallet_mut().db_mut(), healthy, &send.record).unwrap(),
            EnhancePirStoreResult::Stored
        );
        assert_eq!(
            send.st
                .wallet_mut()
                .db_mut()
                .rebuild_ironwood_enhancement(request, &bad)
                .unwrap(),
            Incomplete {
                rebuilt: 0,
                unresolved
            }
        );
        assert_eq!(
            send.st
                .wallet_mut()
                .db_mut()
                .rebuild_ironwood_enhancement(request, &send.block)
                .unwrap(),
            Rebuilt(1)
        );
    }
}

#[test]
fn an_active_orphan_is_suspended_without_blocking_a_valid_sibling() {
    let mut send = shared_and_independent_jobs();
    let account_a = send.st.test_account().unwrap().id();
    let request = send.discovery();
    send.st
        .wallet_mut()
        .db_mut()
        .delete_account(account_a)
        .unwrap();
    // Simulate a job whose deletion cleanup was missed by an older implementation.
    send.st
        .wallet()
        .conn()
        .execute(
            "UPDATE ironwood_enhance_discovery_queue SET suspended = 0",
            [],
        )
        .unwrap();
    let unresolved = vec![IronwoodEnhanceDiscoveryFailure {
        txid: send.block.vtx[0].txid(),
        reason: NoFundingAccounts,
    }];
    assert_eq!(
        send.st
            .wallet_mut()
            .db_mut()
            .rebuild_ironwood_enhancement(request, &send.block)
            .unwrap(),
        Incomplete {
            rebuilt: 1,
            unresolved: unresolved.clone()
        }
    );
    assert_eq!(
        send.st
            .wallet()
            .db()
            .suspended_ironwood_enhance_discoveries()
            .unwrap(),
        unresolved
    );
    assert!(
        send.st
            .wallet()
            .db()
            .ironwood_enhance_discovery_requests()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_sql_error_rolls_back_sibling_progress_and_defensive_suspension() {
    for orphaned in [false, true] {
        let mut send = shared_and_independent_jobs();
        let request = send.discovery();
        if orphaned {
            let account_a = send.st.test_account().unwrap().id();
            send.st
                .wallet_mut()
                .db_mut()
                .delete_account(account_a)
                .unwrap();
            send.st
                .wallet()
                .conn()
                .execute(
                    "UPDATE ironwood_enhance_discovery_queue SET suspended = 0",
                    [],
                )
                .unwrap();
        }
        let before = send.st.wallet().db().enhance_pir_requests().unwrap();
        // The second job fails after the first job has been rebuilt or suspended.
        send.st.wallet().conn().execute_batch(
            "CREATE TRIGGER fail_second_discovery BEFORE DELETE ON ironwood_enhance_discovery_queue
             WHEN (SELECT tx_index FROM transactions WHERE id_tx = OLD.transaction_id) = 2
             BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        ).unwrap();
        assert!(
            send.st
                .wallet_mut()
                .db_mut()
                .rebuild_ironwood_enhancement(request, &send.block)
                .is_err()
        );
        assert_eq!(
            send.st.wallet().db().enhance_pir_requests().unwrap(),
            before
        );
        assert!(
            send.st
                .wallet()
                .db()
                .suspended_ironwood_enhance_discoveries()
                .unwrap()
                .is_empty()
        );
        let jobs: i64 = send
            .st
            .wallet()
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM ironwood_enhance_discovery_queue WHERE suspended = 0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(jobs, 2);
        assert!(send.queued());
        send.st
            .wallet()
            .conn()
            .execute_batch("DROP TRIGGER fail_second_discovery")
            .unwrap();
        assert_eq!(
            send.st
                .wallet_mut()
                .db_mut()
                .rebuild_ironwood_enhancement(request, &send.block)
                .unwrap(),
            if orphaned {
                Incomplete {
                    rebuilt: 1,
                    unresolved: vec![IronwoodEnhanceDiscoveryFailure {
                        txid: send.block.vtx[0].txid(),
                        reason: NoFundingAccounts,
                    }],
                }
            } else {
                Rebuilt(2)
            }
        );
    }
}

#[test]
fn invalid_block_geometry_or_ordering_rejects_all_jobs_without_mutation() {
    let mut send = shared_and_independent_jobs();
    let request = send.discovery();
    let before = send.st.wallet().db().enhance_pir_requests().unwrap();
    for kind in 0..4 {
        let mut bad = send.block.clone();
        match kind {
            0 => {
                bad.chain_metadata
                    .as_mut()
                    .unwrap()
                    .ironwood_commitment_tree_size += 1
            }
            1 => bad.vtx.reverse(),
            2 => bad.vtx[1].txid = bad.vtx[0].txid.clone(),
            _ => bad.vtx.pop().map(|_| ()).unwrap(),
        }
        assert_eq!(
            send.st
                .wallet_mut()
                .db_mut()
                .rebuild_ironwood_enhancement(request, &bad)
                .unwrap(),
            Rejected
        );
        assert_eq!(
            send.st.wallet().db().enhance_pir_requests().unwrap(),
            before
        );
        let jobs: i64 = send
            .st
            .wallet()
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM ironwood_enhance_discovery_queue",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(jobs, 2);
    }
}

#[test]
fn reconstruction_requires_the_preceding_tree_size() {
    let mut send = Send::new(false);
    send.scan_send();
    send.scan_funding();
    let request = send.discovery();
    let prior_height = u32::from(request.height) - 1;
    let prior_size = send
        .st
        .wallet()
        .conn()
        .query_row(
            "SELECT ironwood_commitment_tree_size FROM blocks WHERE height = ?1",
            [prior_height],
            |row| row.get::<_, u32>(0),
        )
        .unwrap();
    send.st
        .wallet()
        .conn()
        .execute(
            "UPDATE blocks SET ironwood_commitment_tree_size = NULL WHERE height = ?1",
            [prior_height],
        )
        .unwrap();

    assert_eq!(
        send.st
            .wallet_mut()
            .db_mut()
            .rebuild_ironwood_enhancement(request, &send.block)
            .unwrap(),
        Rejected
    );
    assert!(
        send.st
            .wallet()
            .db()
            .ironwood_enhance_discovery_requests()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        send.st
            .wallet()
            .db()
            .suspended_ironwood_enhance_discoveries()
            .unwrap(),
        vec![IronwoodEnhanceDiscoveryFailure {
            txid: send.block.vtx[0].txid(),
            reason: AnchorUnavailable,
        }]
    );
    assert!(send.requests().is_empty());
    assert!(send.queued());
    send.st
        .wallet()
        .conn()
        .execute(
            "UPDATE blocks SET ironwood_commitment_tree_size = ?1 WHERE height = ?2",
            rusqlite::params![prior_size, prior_height],
        )
        .unwrap();
    assert_eq!(send.discovery(), request);
    assert!(
        send.st
            .wallet()
            .db()
            .suspended_ironwood_enhance_discoveries()
            .unwrap()
            .is_empty()
    );
    send.rebuild();
}

#[test]
fn discovery_waits_for_the_spending_blocks_tree_size() {
    let mut send = Send::new(false);
    send.scan_send();
    send.scan_funding();
    let request = send.discovery();
    send.st
        .wallet()
        .conn()
        .execute(
            "UPDATE blocks SET ironwood_commitment_tree_size = NULL WHERE height = ?1",
            [u32::from(request.height)],
        )
        .unwrap();

    assert!(
        send.st
            .wallet()
            .db()
            .ironwood_enhance_discovery_requests()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        send.st
            .wallet()
            .db()
            .suspended_ironwood_enhance_discoveries()
            .unwrap(),
        vec![IronwoodEnhanceDiscoveryFailure {
            txid: send.block.vtx[0].txid(),
            reason: AnchorUnavailable,
        }]
    );
    assert!(send.queued());
}

#[test]
fn reconstruction_cannot_take_an_outgoing_position_from_another_transaction() {
    let mut send = shared_and_independent_jobs();
    let request = send.discovery();
    let end = send
        .block
        .chain_metadata
        .as_ref()
        .unwrap()
        .ironwood_commitment_tree_size;
    let position = end - 1;
    let owner = send
        .st
        .wallet()
        .conn()
        .query_row(
            "SELECT id_tx FROM transactions WHERE txid = ?1",
            [&send.block.vtx[0].txid],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    send.st
        .wallet()
        .conn()
        .execute(
            "INSERT INTO ironwood_enhance_outgoing_queue (
             commitment_tree_position, transaction_id, output_index, nullifier, cmx,
             ephemeral_key, compact_ciphertext
         ) VALUES (?1, ?2, 9, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                position, owner, [91u8; 32], [92u8; 32], [93u8; 32], [94u8; 52]
            ],
        )
        .unwrap();
    let before = send.st.wallet().db().enhance_pir_requests().unwrap();

    assert_eq!(
        send.st
            .wallet_mut()
            .db_mut()
            .rebuild_ironwood_enhancement(request, &send.block)
            .unwrap(),
        Rejected
    );
    let claimant = send
        .st
        .wallet()
        .conn()
        .query_row(
            "SELECT id_tx FROM transactions WHERE txid = ?1",
            [&send.block.vtx[1].txid],
            |row| row.get::<_, i64>(0).map(crate::TxRef),
        )
        .unwrap();
    assert!(
        queue_transaction(
            send.st.wallet().conn(),
            claimant,
            &[IronwoodEnhanceCandidate::from_parts(
                u64::from(position).into(),
                0,
                [81; 32],
                [82; 32],
                [83; 32],
                [84; 52],
                vec![],
            )],
            true,
        )
        .is_err(),
        "the queue itself must also refuse cross-transaction replacement"
    );
    let retained_owner = send
        .st
        .wallet()
        .conn()
        .query_row(
            "SELECT transaction_id FROM ironwood_enhance_outgoing_queue
         WHERE commitment_tree_position = ?1",
            [position],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    assert_eq!(retained_owner, owner);
    assert_eq!(
        send.st.wallet().db().enhance_pir_requests().unwrap(),
        before
    );
    assert_eq!(send.discovery(), request);
    assert!(send.queued());
}

#[test]
fn deleting_one_of_multiple_funders_keeps_discovery_active() {
    let mut send = Send::with_second_funder(true, true);
    send.scan_send();
    send.scan_funding();
    let (height, account_b) = send.second_funding.unwrap();
    send.st.scan_cached_blocks(height, 1);
    let account_a = send.st.test_account().unwrap().id();
    send.st
        .wallet_mut()
        .db_mut()
        .delete_account(account_a)
        .unwrap();
    assert!(
        send.st
            .wallet()
            .db()
            .suspended_ironwood_enhance_discoveries()
            .unwrap()
            .is_empty()
    );
    send.rebuild();
    for request in send.requests() {
        let pending = send
            .st
            .wallet()
            .db()
            .pending_ironwood_outgoing(request.position())
            .unwrap()
            .unwrap();
        assert_eq!(pending.account_ids, vec![account_b]);
    }
}

#[test]
fn deleting_an_exclusively_owned_transaction_cascades_its_discovery_job() {
    let mut send = Send::new(false);
    send.scan_send();
    send.scan_funding();
    send.discovery();
    let account = send.st.test_account().unwrap().id();
    send.st
        .wallet_mut()
        .db_mut()
        .delete_account(account)
        .unwrap();
    assert!(
        send.st
            .wallet()
            .db()
            .ironwood_enhance_discovery_requests()
            .unwrap()
            .is_empty()
    );
    assert!(
        send.st
            .wallet()
            .db()
            .suspended_ironwood_enhance_discoveries()
            .unwrap()
            .is_empty()
    );
    let jobs: i64 = send
        .st
        .wallet()
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM ironwood_enhance_discovery_queue",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(jobs, 0);
}

#[test]
fn linking_another_funder_reactivates_the_existing_suspended_job() {
    let mut send = Send::with_second_funder(true, true);
    let (height, account_b) = send.second_funding.unwrap();
    let account = send
        .st
        .wallet()
        .db()
        .get_account(account_b)
        .unwrap()
        .unwrap();
    let key_b = account.ufvk().unwrap().orchard().unwrap();
    let key_a = OrchardPoolTester::test_account_fvk(&send.st);
    // B receives one output, retaining this transaction when A is deleted, but B's
    // funding note is not scanned until after the discovery job has been suspended.
    send.block.vtx[0].ironwood_actions[0] = encrypted_action(
        send.block.vtx[0].ironwood_actions[0]
            .nf()
            .unwrap()
            .to_bytes(),
        key_b.address_at(0u32, Scope::External),
        key_a.to_ovk(Scope::External),
        30_000,
    )
    .0;
    send.st
        .cache()
        .0
        .execute(
            "UPDATE compactblocks SET data = ?1 WHERE height = ?2",
            rusqlite::params![send.block.encode_to_vec(), u32::from(send.block.height())],
        )
        .unwrap();
    send.scan_send();
    send.scan_funding();
    let tx_ref = send.tx_ref();
    let account_a = send.st.test_account().unwrap().id();
    send.st
        .wallet_mut()
        .db_mut()
        .delete_account(account_a)
        .unwrap();
    assert_eq!(
        send.st
            .wallet()
            .db()
            .suspended_ironwood_enhance_discoveries()
            .unwrap(),
        vec![IronwoodEnhanceDiscoveryFailure {
            txid: send.block.vtx[0].txid(),
            reason: NoFundingAccounts,
        }]
    );
    assert!(
        send.st
            .wallet()
            .db()
            .ironwood_enhance_discovery_requests()
            .unwrap()
            .is_empty()
    );

    send.st.scan_cached_blocks(height, 1);
    assert_eq!(send.tx_ref(), tx_ref);
    assert!(
        send.st
            .wallet()
            .db()
            .suspended_ironwood_enhance_discoveries()
            .unwrap()
            .is_empty()
    );
    send.rebuild();
    let outgoing = send
        .requests()
        .into_iter()
        .find(|r| r.request_id().output_index() == 1)
        .unwrap();
    let pending = send
        .st
        .wallet()
        .db()
        .pending_ironwood_outgoing(outgoing.position())
        .unwrap()
        .unwrap();
    assert_eq!(pending.account_ids, vec![account_b]);
    assert_eq!(
        apply_record(send.st.wallet_mut().db_mut(), outgoing, &send.record).unwrap(),
        EnhancePirStoreResult::Stored
    );
}

#[test]
fn restoring_a_funding_key_and_rescanning_reactivates_suspended_discovery() {
    use zcash_client_backend::data_api::AccountPurpose;
    for funding_b_first in [false, true] {
        let mut send = shared_and_independent_jobs();
        let account_a = send.st.test_account().unwrap().id();
        let key = send
            .st
            .wallet()
            .db()
            .get_account(account_a)
            .unwrap()
            .unwrap()
            .ufvk()
            .unwrap()
            .clone();
        let birthday = send.st.test_account().unwrap().birthday().clone();
        send.st
            .wallet_mut()
            .db_mut()
            .delete_account(account_a)
            .unwrap();
        assert_eq!(
            send.st
                .wallet()
                .db()
                .suspended_ironwood_enhance_discoveries()
                .unwrap()
                .len(),
            1
        );
        send.st
            .wallet_mut()
            .db_mut()
            .import_account_ufvk(
                "restored A",
                &key,
                &birthday,
                AccountPurpose::Spending { derivation: None },
                None,
            )
            .unwrap();
        // Import rewinds and clears routing, but B's spend link survives. Exercise both
        // direct scan-time recovery and rediscovery of this retained link, alongside A's
        // newly restored funding note. A's funding always arrives after the send block.
        if funding_b_first {
            send.st
                .scan_cached_blocks(send.second_funding.unwrap().0, 1);
        }
        send.scan_send();
        send.scan_funding();
        if !funding_b_first {
            send.st
                .scan_cached_blocks(send.second_funding.unwrap().0, 1);
        }
        assert!(
            send.st
                .wallet()
                .db()
                .suspended_ironwood_enhance_discoveries()
                .unwrap()
                .is_empty()
        );
        let request = send.discovery();
        let txid: [u8; 32] = send
            .st
            .wallet()
            .conn()
            .query_row(
                "SELECT t.txid FROM ironwood_enhance_discovery_queue q
         JOIN transactions t ON t.id_tx = q.transaction_id WHERE t.txid = ?1",
                [&send.block.vtx[0].txid],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(txid.as_slice(), send.block.vtx[0].txid);
        assert_eq!(
            send.st
                .wallet_mut()
                .db_mut()
                .rebuild_ironwood_enhancement(request, &send.block)
                .unwrap(),
            Rebuilt(if funding_b_first { 1 } else { 2 })
        );
        assert!(
            send.st
                .wallet()
                .db()
                .ironwood_enhance_discovery_requests()
                .unwrap()
                .is_empty()
        );
        let outgoing = send
            .st
            .wallet()
            .db()
            .enhance_pir_requests()
            .unwrap()
            .into_iter()
            .find(|r| r.request_id().txid() == send.block.vtx[1].txid())
            .unwrap();
        assert_eq!(
            apply_record(send.st.wallet_mut().db_mut(), outgoing, &send.record).unwrap(),
            EnhancePirStoreResult::Stored
        );
    }
}

#[test]
fn suspension_failure_rolls_back_account_deletion() {
    let mut send = shared_and_independent_jobs();
    let account_a = send.st.test_account().unwrap().id();
    send.st.wallet().conn().execute_batch("CREATE TRIGGER fail_suspend BEFORE UPDATE OF suspended ON ironwood_enhance_discovery_queue
        BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
    assert!(
        send.st
            .wallet_mut()
            .db_mut()
            .delete_account(account_a)
            .is_err()
    );
    assert!(
        send.st
            .wallet()
            .db()
            .get_account(account_a)
            .unwrap()
            .is_some()
    );
    assert_eq!(
        super::super::discovery::funding(send.st.wallet().conn(), send.tx_ref())
            .unwrap()
            .len(),
        1
    );
    assert!(
        send.st
            .wallet()
            .db()
            .suspended_ironwood_enhance_discoveries()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn retro_link_and_discovery_enqueue_roll_back_together() {
    let mut send = Send::new(true);
    send.scan_send();
    let change = send.requests()[0];
    finish_incoming(&mut send.st, change);
    send.st
        .wallet()
        .conn()
        .execute_batch(
            "CREATE TRIGGER fail_discovery_insert BEFORE INSERT ON ironwood_enhance_discovery_queue
        BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        )
        .unwrap();
    assert!(
        send.st
            .try_scan_cached_blocks(send.funding_height, 1)
            .is_err()
    );
    assert!(!send.queued());
    let links: i64 = send
        .st
        .wallet()
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM ironwood_received_note_spends WHERE transaction_id = ?1",
            [send.tx_ref().0],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(links, 0);
    send.st
        .wallet()
        .conn()
        .execute_batch("DROP TRIGGER fail_discovery_insert")
        .unwrap();
    send.scan_funding();
    send.rebuild();
}

#[test]
fn mixed_compact_shape_discovered_without_change_uses_lwd() {
    use zcash_client_backend::proto::compact_formats::{CompactSaplingSpend, CompactTxIn, TxOut};
    for pool in 0..4 {
        let mut send = Send::new(false);
        let tx = &mut send.block.vtx[0];
        match pool {
            0 => tx.vin.push(CompactTxIn {
                prevout_txid: vec![8; 32],
                prevout_index: 0,
            }),
            1 => tx.vout.push(TxOut::default()),
            2 => tx.spends.push(CompactSaplingSpend { nf: vec![8; 32] }),
            _ => {
                tx.actions.push(tx.ironwood_actions[0].clone());
                send.block
                    .chain_metadata
                    .as_mut()
                    .unwrap()
                    .orchard_commitment_tree_size += 1;
            }
        }
        send.st
            .cache()
            .0
            .execute(
                "UPDATE compactblocks SET data = ?1 WHERE height = ?2",
                rusqlite::params![send.block.encode_to_vec(), u32::from(send.block.height())],
            )
            .unwrap();
        send.scan_send();
        send.scan_funding();
        send.rebuild();
        let request = EnhancePirRequest::new(
            1.into(),
            IronwoodEnhanceRequestId::new(send.block.vtx[0].txid(), 0),
        );
        assert!(visible(&send.st, request));
        assert!(send.requests().is_empty());
        assert!(!is_protected(send.st.wallet().conn(), request.request_id().txid()).unwrap());
    }
}

#[test]
fn retro_link_reopens_retired_enhancement_and_recovers_recipient_privately() {
    for memo_first in [true, false] {
        let mut send = Send::new(true);
        send.scan_send();
        let change = send.requests()[0];
        assert_eq!(send.requests().len(), 1);
        if memo_first {
            finish_incoming(&mut send.st, change);
            assert!(
                !send.queued(),
                "reproduce retirement before the spend is linkable"
            );
        }
        send.scan_funding();
        send.discovery();
        assert!(
            send.queued(),
            "retro-link must restore already-retired intent"
        );
        assert!(!visible(&send.st, change));
        if !memo_first {
            finish_incoming(&mut send.st, change);
        }
        assert!(
            send.queued(),
            "discovery blocks retirement even with no PIR requests"
        );
        assert!(send.requests().is_empty());

        // Mode changes and process restarts must not lose the obligation.
        use crate::testing::db::{test_clock, test_rng};
        let mut reopened = crate::WalletDb::for_path(
            send.st.wallet().data_file_path(),
            *send.st.network(),
            test_clock(),
            test_rng(),
        )
        .unwrap();
        assert_eq!(
            reopened.ironwood_enhance_discovery_requests().unwrap(),
            vec![send.discovery()]
        );
        assert!(reopened.transaction_data_requests().unwrap().contains(
            &TransactionDataRequest::Enhancement(change.request_id().txid())
        ));
        reopened.set_enhancement_mode(EnhancementMode::PrivateIronwood);
        assert!(!reopened.transaction_data_requests().unwrap().contains(
            &TransactionDataRequest::Enhancement(change.request_id().txid())
        ));

        send.rebuild();
        let outgoing = send.requests()[0];
        assert_eq!(outgoing.request_id().output_index(), 1);
        assert_eq!(u64::from(outgoing.position()), 2);
        let account = send.st.test_account().unwrap().id();
        assert_eq!(
            send.st
                .wallet()
                .db()
                .pending_ironwood_outgoing(outgoing.position())
                .unwrap()
                .unwrap()
                .account_ids,
            vec![account]
        );
        assert_eq!(
            apply_record(send.st.wallet_mut().db_mut(), outgoing, &send.record).unwrap(),
            EnhancePirStoreResult::Stored
        );
        assert!(!send.queued());
        assert!(send.requests().is_empty());
        let value: u64 = send
            .st
            .wallet()
            .conn()
            .query_row(
                "SELECT value FROM sent_notes WHERE transaction_id = ?1 AND output_index = 1",
                [send.tx_ref().0],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(value, 20_000);
        let stored_address: String = send
            .st
            .wallet()
            .conn()
            .query_row(
                "SELECT to_address FROM sent_notes WHERE transaction_id = ?1 AND output_index = 1",
                [send.tx_ref().0],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            stored_address,
            Receiver::Orchard(send.recipient)
                .to_zcash_address(send.st.network().network_type())
                .to_string()
        );
        assert!(is_protected(send.st.wallet().conn(), change.request_id().txid()).unwrap());
        // A replay with the now-spent nullifier omitted must reopen discovery, not lose data.
        send.scan_send();
        send.rebuild();
        assert!(!send.queued());
    }
}

#[test]
fn retro_link_discovers_a_send_without_any_received_output() {
    let mut send = Send::new(false);
    send.scan_send();
    assert!(send.requests().is_empty());
    send.scan_funding();
    assert!(send.queued());
    send.rebuild();
    assert_eq!(send.requests().len(), 1);
    let outgoing = send.requests()[0];
    assert!(!visible(&send.st, outgoing));
    assert_eq!(
        apply_record(send.st.wallet_mut().db_mut(), outgoing, &send.record).unwrap(),
        EnhancePirStoreResult::Stored
    );
    assert!(!send.queued());
}

#[test]
fn funding_first_stays_private_without_discovery_and_repeated_funding_scan_is_inert() {
    let mut send = Send::new(true);
    send.scan_funding();
    send.scan_send();
    assert_eq!(send.requests().len(), 2);
    assert!(
        send.st
            .wallet()
            .db()
            .ironwood_enhance_discovery_requests()
            .unwrap()
            .is_empty()
    );
    send.scan_funding();
    assert!(
        send.st
            .wallet()
            .db()
            .ironwood_enhance_discovery_requests()
            .unwrap()
            .is_empty()
    );
    for request in send.requests() {
        assert!(!visible(&send.st, request));
    }
}

#[test]
fn malformed_or_stale_discovery_never_falls_back_or_clears_work() {
    let mut send = Send::new(true);
    send.scan_send();
    send.scan_funding();
    let request = send.discovery();
    for kind in 0..9 {
        let mut bad = send.block.clone();
        match kind {
            0 => bad.hash = vec![8; 32],
            1 => bad.height = u64::MAX,
            2 => bad.chain_metadata = None,
            3 => bad.vtx.clear(),
            4 => bad.vtx[0].ironwood_actions[1].ephemeral_key.clear(),
            5 => bad.vtx[0].index += 1,
            6 => bad.vtx[0].txid = vec![8; 32],
            7 => bad.vtx[0].ironwood_actions[0].nullifier = vec![8; 32],
            _ => bad.vtx[0].ironwood_actions.pop().map(|_| ()).unwrap(),
        }
        assert_eq!(
            send.st
                .wallet_mut()
                .db_mut()
                .rebuild_ironwood_enhancement(request, &bad)
                .unwrap(),
            match kind {
                4 | 5 | 7 => Incomplete {
                    rebuilt: 0,
                    unresolved: vec![IronwoodEnhanceDiscoveryFailure {
                        txid: send.block.vtx[0].txid(),
                        reason: ContextMismatch,
                    }]
                },
                6 => Incomplete {
                    rebuilt: 0,
                    unresolved: vec![IronwoodEnhanceDiscoveryFailure {
                        txid: send.block.vtx[0].txid(),
                        reason: TransactionMissing,
                    }]
                },
                _ => Rejected,
            },
            "case {kind}"
        );
        assert_eq!(send.discovery(), request);
        assert!(send.queued());
    }
    let stale = IronwoodEnhanceDiscoveryRequest {
        block_hash: BlockHash([8; 32]),
        ..request
    };
    assert_eq!(
        send.st
            .wallet_mut()
            .db_mut()
            .rebuild_ironwood_enhancement(stale, &send.block)
            .unwrap(),
        AlreadyResolved
    );
    send.rebuild();
    assert_eq!(
        send.st
            .wallet_mut()
            .db_mut()
            .rebuild_ironwood_enhancement(request, &send.block)
            .unwrap(),
        AlreadyResolved
    );
}

#[test]
fn discovery_commit_is_atomic_and_mixed_routing_is_sticky() {
    let mut send = Send::new(true);
    send.scan_send();
    send.scan_funding();
    let request = send.discovery();
    send.st
        .wallet()
        .conn()
        .execute_batch(
            "CREATE TRIGGER fail_discovery_delete BEFORE DELETE ON ironwood_enhance_discovery_queue
        BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        )
        .unwrap();
    assert!(
        send.st
            .wallet_mut()
            .db_mut()
            .rebuild_ironwood_enhancement(request, &send.block)
            .is_err()
    );
    assert_eq!(
        send.requests().len(),
        1,
        "outgoing insert rolls back with job deletion"
    );
    assert_eq!(send.discovery(), request);
    send.st
        .wallet()
        .conn()
        .execute_batch("DROP TRIGGER fail_discovery_delete")
        .unwrap();
    send.rebuild();
    let outgoing = send
        .requests()
        .into_iter()
        .find(|r| r.request_id().output_index() == 1)
        .unwrap();
    let mixed = EnhanceRecord::from_parts(
        *send.record.ephemeral_key(),
        *send.record.ciphertext(),
        *send.record.cv_net(),
        *send.record.out_ciphertext(),
        true,
        false,
    );
    assert_eq!(
        apply_record(send.st.wallet_mut().db_mut(), outgoing, &mixed).unwrap(),
        EnhancePirStoreResult::LwdRequired
    );
    send.scan_funding();
    send.scan_send();
    assert!(
        send.st
            .wallet()
            .db()
            .ironwood_enhance_discovery_requests()
            .unwrap()
            .is_empty()
    );
    assert!(visible(&send.st, outgoing));
    assert_eq!(
        send.st
            .wallet_mut()
            .db_mut()
            .rebuild_ironwood_enhancement(request, &send.block)
            .unwrap(),
        AlreadyResolved
    );
}

#[test]
fn rewind_and_full_data_clear_discovery() {
    for full_data in [false, true] {
        let mut send = Send::new(true);
        send.scan_send();
        send.scan_funding();
        let request = send.discovery();
        if full_data {
            send.st
                .wallet()
                .conn()
                .execute(
                    "UPDATE transactions SET raw = X'00' WHERE id_tx = ?1",
                    [send.tx_ref().0],
                )
                .unwrap();
            clear_work(send.st.wallet().conn(), send.tx_ref()).unwrap();
            super::super::discovery::queue(send.st.wallet().conn(), send.tx_ref()).unwrap();
        } else {
            send.st
                .wallet_mut()
                .db_mut()
                .truncate_to_height(send.funding_height)
                .unwrap();
        }
        assert!(
            send.st
                .wallet()
                .db()
                .ironwood_enhance_discovery_requests()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            send.st
                .wallet_mut()
                .db_mut()
                .rebuild_ironwood_enhancement(request, &send.block)
                .unwrap(),
            AlreadyResolved
        );
    }
}

#[test]
fn unbound_ciphertext_tampering_discards_but_compact_mismatch_does_not() {
    for tamper_note_tail in [false, true] {
        let mut send = Send::new(false);
        send.scan_funding();
        send.scan_send();
        let request = send.requests()[0];
        let record = &send.record;
        let mut epk = *record.ephemeral_key();
        epk[0] ^= 1;
        let wrong = EnhanceRecord::from_parts(
            epk,
            *record.ciphertext(),
            *record.cv_net(),
            *record.out_ciphertext(),
            false,
            false,
        );
        assert_eq!(
            apply_record(send.st.wallet_mut().db_mut(), request, &wrong).unwrap(),
            EnhancePirStoreResult::Rejected
        );
        assert_eq!(send.requests(), vec![request]);
        let mut ciphertext = *record.ciphertext();
        let mut outgoing = *record.out_ciphertext();
        if tamper_note_tail {
            ciphertext[579] ^= 1;
        } else {
            outgoing[0] ^= 1;
        }
        let corrupt = EnhanceRecord::from_parts(
            *record.ephemeral_key(),
            ciphertext,
            *record.cv_net(),
            outgoing,
            false,
            false,
        );
        assert_eq!(
            apply_record(send.st.wallet_mut().db_mut(), request, &corrupt).unwrap(),
            EnhancePirStoreResult::NotRecoverable
        );
        assert!(send.requests().is_empty());
        assert_eq!(
            send.st
                .wallet()
                .conn()
                .query_row("SELECT COUNT(*) FROM sent_notes", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        send.st
            .wallet_mut()
            .db_mut()
            .set_enhancement_mode(EnhancementMode::Standard);
        assert!(!visible(&send.st, request));
    }
}
