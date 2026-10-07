use super::*;

mod activity_outgoing;

/// Isolate memo identity from accounting and effects. The integration tests below use the
/// migrated wallet schema and the private enhancement writer instead.
fn memo_fixture() -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE v_received_outputs (
            account_id INTEGER, transaction_id INTEGER, pool INTEGER,
            output_index INTEGER, memo BLOB);
         CREATE TABLE sent_notes (
            from_account_id INTEGER, transaction_id INTEGER, output_pool INTEGER,
            output_index INTEGER, memo BLOB);
         INSERT INTO sent_notes VALUES (1, 2, 4, 3, NULL);",
    )
    .unwrap();
    conn
}

#[test]
fn recovered_memo_requires_the_same_account_transaction_pool_and_index() {
    for received_identity in [(9, 2, 4, 3), (1, 9, 4, 3), (1, 2, 3, 3), (1, 2, 4, 9)] {
        let conn = memo_fixture();
        conn.execute(
            "INSERT INTO v_received_outputs VALUES (?1, ?2, ?3, ?4, X'F6')",
            rusqlite::params![
                received_identity.0,
                received_identity.1,
                received_identity.2,
                received_identity.3
            ],
        )
        .unwrap();
        assert!(
            has_unretrieved_memo(&conn, 1, 2).unwrap(),
            "{received_identity:?}"
        );
    }
}

#[test]
fn matching_recovered_memos_work_in_every_shielded_pool_but_do_not_hide_other_missing_memos() {
    for pool in [2, 3, 4] {
        let conn = memo_fixture();
        conn.execute("UPDATE sent_notes SET output_pool = ?", [pool])
            .unwrap();
        conn.execute(
            "INSERT INTO v_received_outputs VALUES (1, 2, ?1, 3, X'F6')",
            [pool],
        )
        .unwrap();
        assert!(!has_unretrieved_memo(&conn, 1, 2).unwrap());
        conn.execute(
            "INSERT INTO v_received_outputs VALUES (1, 2, ?1, 4, NULL)",
            [pool],
        )
        .unwrap();
        assert!(has_unretrieved_memo(&conn, 1, 2).unwrap());
    }
}

#[cfg(feature = "orchard")]
mod ironwood {
    use super::*;
    use crate::testing::{
        BlockCache,
        db::{TestDb, TestDbFactory},
    };
    use zcash_client_backend::data_api::{
        Account as _,
        enhance_pir::{
            EnhancePirRead, EnhancePirStoreResult, EnhancePirWork, EnhancePirWrite, EnhanceRecord,
            EnhanceRecordParts, EnhanceTransactionMetadata, EnhancementMode,
            TransactionEnhancementWork,
        },
        testing::{
            AddressType, IronwoodFvk, TestBuilder, TestState, orchard::OrchardPoolTester,
            pool::ShieldedPoolTester,
        },
        transparent_ledger::TransparentLedgerRead,
    };
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::{local_consensus::LocalNetwork, memo::MemoBytes};

    type State = TestState<BlockCache, TestDb, LocalNetwork>;

    struct Fixture {
        st: State,
        account: AccountUuid,
        txid: TxId,
        tx: i64,
    }

    impl Fixture {
        fn new(owned_value: u64) -> Self {
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
                .with_data_store_factory(TestDbFactory::default())
                .with_block_cache(BlockCache::new())
                .with_account_from_sapling_activation(BlockHash([0; 32]))
                .build();
            st.wallet_mut()
                .db_mut()
                .set_enhancement_mode(EnhancementMode::PrivateIronwood);
            let account = st.test_account().unwrap().id();
            let fvk = IronwoodFvk(OrchardPoolTester::test_account_fvk(&st));
            let (height, _, _) = st.generate_next_block(
                &fvk,
                AddressType::DefaultExternal,
                Zatoshis::const_from_u64(30_000),
            );
            st.scan_cached_blocks(height, 1);
            let funding_note: i64 = st
                .wallet()
                .conn()
                .query_row("SELECT id FROM ironwood_received_notes", [], |r| r.get(0))
                .unwrap();
            let (height, _, _) = st.generate_next_block(
                &fvk,
                AddressType::DefaultExternal,
                Zatoshis::from_u64(owned_value).unwrap(),
            );
            st.scan_cached_blocks(height, 1);
            let (tx, txid): (i64, [u8; 32]) = st
                .wallet()
                .conn()
                .query_row(
                    "SELECT id_tx, txid FROM transactions WHERE mined_height = ?",
                    [u32::from(height)],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            let conn = st.wallet().conn();
            // Synthetic financial evidence: 30,000 spent = owned receipt + external payment
            // + 5,000 fee. Compact scanning supplies real note identities and settled effects.
            conn.execute(
                "INSERT INTO ironwood_received_note_spends VALUES (?1, ?2)",
                [funding_note, tx],
            )
            .unwrap();
            conn.execute("UPDATE transactions SET fee = 5000 WHERE id_tx = ?", [tx])
                .unwrap();
            conn.execute(
                "INSERT INTO sent_notes (transaction_id, output_pool, output_index,
                    from_account_id, to_account_id, value, memo)
                 SELECT transaction_id, 4, action_index, account_id, account_id, value, NULL
                 FROM ironwood_received_notes WHERE transaction_id = ?",
                [tx],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO sent_notes (transaction_id, output_pool, output_index,
                    from_account_id, to_address, value, memo)
                 SELECT transaction_id, 4, action_index + 1, account_id, 'synthetic external', ?2, X'F6'
                 FROM ironwood_received_notes WHERE transaction_id = ?1",
                rusqlite::params![tx, 25_000 - owned_value]).unwrap();
            Self {
                st,
                account,
                txid: TxId::from_bytes(txid),
                tx,
            }
        }

        fn history(&self) -> TransactionHistoryDetails {
            let mut entries = self
                .st
                .wallet()
                .db()
                .transaction_history_details(self.account, &[self.txid])
                .unwrap();
            assert_eq!(entries.len(), 1);
            entries.remove(0)
        }

        fn recover(&mut self, memo: MemoBytes) {
            let request = self
                .st
                .wallet()
                .db()
                .transaction_enhancement_work()
                .unwrap()
                .into_iter()
                .find_map(|work| match work {
                    TransactionEnhancementWork::Private(EnhancePirWork::Query(request))
                        if request.request_id().txid() == self.txid =>
                    {
                        Some(request)
                    }
                    _ => None,
                })
                .unwrap();
            let pending = crate::wallet::enhance_pir::pending(
                self.st.wallet().conn(),
                self.st.network(),
                request.position(),
            )
            .unwrap()
            .unwrap();
            let encryptor = orchard::note_encryption::IronwoodNoteEncryption::new(
                None,
                pending.note,
                *memo.as_array(),
            );
            let ciphertext = encryptor.encrypt_note_plaintext();
            let record = EnhanceRecord::from_parts(EnhanceRecordParts {
                enc_ciphertext_suffix: ciphertext[52..].try_into().unwrap(),
                cv_net: [0; 32],
                out_ciphertext: [0; 80],
                has_transparent_inputs: false,
                has_transparent_outputs: false,
                metadata: EnhanceTransactionMetadata::new(0, Some(5000)).unwrap(),
            });
            assert_eq!(
                self.st
                    .wallet_mut()
                    .db_mut()
                    .apply_ironwood_enhance_record(request, &record)
                    .unwrap(),
                EnhancePirStoreResult::Stored
            );
            let (received_known, sent_unknown): (bool, bool) = self
                .st
                .wallet()
                .conn()
                .query_row(
                    "SELECT r.memo IS NOT NULL, s.memo IS NULL FROM ironwood_received_notes r
                 JOIN sent_notes s ON s.transaction_id = r.transaction_id
                    AND s.output_pool = 4 AND s.output_index = r.action_index
                 WHERE r.transaction_id = ?",
                    [self.tx],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!((received_known, sent_unknown), (true, true));
            assert!(
                crate::wallet::enhance_pir::pending(
                    self.st.wallet().conn(),
                    self.st.network(),
                    request.position()
                )
                .unwrap()
                .is_none()
            );
            assert_eq!(
                self.st
                    .wallet()
                    .conn()
                    .query_row(
                        "SELECT route FROM ironwood_enhance_routing WHERE transaction_id = ?",
                        [self.tx],
                        |r| r.get::<_, i64>(0)
                    )
                    .unwrap(),
                0
            );
        }
    }

    #[test]
    fn private_incoming_recovery_completes_owned_sent_memos() {
        for value in [0, 10_000] {
            for memo in [
                MemoBytes::empty(),
                MemoBytes::from_bytes(b"private memo").unwrap(),
            ] {
                let mut fixture = Fixture::new(value);
                let before = fixture.history();
                assert!(before.effects.iter().all(|e| e.completeness.is_settled()));
                assert_eq!(before.account_movement.spent, 30_000);
                assert_eq!(before.payment_details, DetailCompleteness::Incomplete);
                fixture.recover(memo);
                let after = fixture.history();
                assert_eq!(after.payment_details, DetailCompleteness::Complete);
                assert_eq!(after.classification, HistoryClassification::Reconstructed);
                assert_eq!(after.fee, FeeState::Known(Zatoshis::const_from_u64(5000)));
            }
        }
    }

    #[test]
    fn recovered_owned_memo_does_not_complete_a_missing_external_memo() {
        let mut fixture = Fixture::new(10_000);
        fixture.recover(MemoBytes::empty());
        assert_eq!(
            fixture.history().payment_details,
            DetailCompleteness::Complete
        );
        fixture.st.wallet().conn().execute(
            "UPDATE sent_notes SET memo = NULL WHERE transaction_id = ? AND to_address IS NOT NULL",
            [fixture.tx]).unwrap();
        assert_eq!(
            fixture.history().payment_details,
            DetailCompleteness::Incomplete
        );
    }

    #[test]
    fn recovered_owned_memo_does_not_hide_another_missing_received_memo() {
        let mut fixture = Fixture::new(10_000);
        fixture.recover(MemoBytes::empty());
        assert_eq!(
            fixture.history().payment_details,
            DetailCompleteness::Complete
        );
        // A separate zero-value receipt changes no financial accounting, but still needs a memo.
        fixture
            .st
            .wallet()
            .conn()
            .execute(
                "INSERT INTO ironwood_received_notes (transaction_id, action_index, account_id,
                diversifier, value, rho, rseed, is_change, memo, note_version)
             SELECT transaction_id, action_index + 2, account_id, diversifier, 0, rho, rseed,
                is_change, NULL, note_version
             FROM ironwood_received_notes WHERE transaction_id = ?",
                [fixture.tx],
            )
            .unwrap();
        let history = fixture.history();
        assert!(history.effects.iter().all(|e| e.completeness.is_settled()));
        assert_eq!(history.payment_details, DetailCompleteness::Incomplete);
    }

    #[test]
    fn recovered_owned_memo_does_not_complete_unbalanced_accounting_or_unsettled_effects() {
        let mut fixture = Fixture::new(10_000);
        fixture.recover(MemoBytes::empty());
        assert_eq!(
            fixture.history().payment_details,
            DetailCompleteness::Complete
        );
        fixture
            .st
            .wallet()
            .conn()
            .execute(
                "UPDATE transactions SET fee = 5001 WHERE id_tx = ?",
                [fixture.tx],
            )
            .unwrap();
        assert_eq!(
            fixture.history().payment_details,
            DetailCompleteness::Incomplete
        );
        fixture
            .st
            .wallet()
            .conn()
            .execute(
                "UPDATE transactions SET fee = NULL WHERE id_tx = ?",
                [fixture.tx],
            )
            .unwrap();
        assert_eq!(
            fixture.history().payment_details,
            DetailCompleteness::Incomplete
        );
        fixture
            .st
            .wallet()
            .conn()
            .execute(
                "UPDATE transactions SET fee = 5000, mined_height = NULL WHERE id_tx = ?",
                [fixture.tx],
            )
            .unwrap();
        let history = fixture.history();
        assert!(history.effects.iter().any(|e| !e.completeness.is_settled()));
        assert_eq!(history.payment_details, DetailCompleteness::Incomplete);
    }
}
