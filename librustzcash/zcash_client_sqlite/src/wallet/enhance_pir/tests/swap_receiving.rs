use super::*;

#[cfg(feature = "experimental-swap-receiving")]
#[test]
fn swap_receiving_pir_authenticates_memos_after_reopen() {
    use super::discovery::{cached, encrypted_action};
    use crate::{
        WalletDb,
        testing::db::{test_clock, test_rng},
        wallet::swap_receiving::Purpose,
    };
    use orchard::keys::OutgoingViewingKey;
    use prost::Message;
    use zcash_client_backend::proto::compact_formats::CompactTx;

    for purpose in [Purpose::Refund, Purpose::Receive] {
        let mut st = state_with_factory(TestDbFactory::file_backed());
        let account = st.test_account().unwrap().id();
        let key = st
            .wallet_mut()
            .db_mut()
            .reserve_swap_receiving_key(account, purpose, BlockHeight::from_u32(100_000))
            .unwrap();
        st.wallet_mut()
            .db_mut()
            .set_enhancement_mode(EnhancementMode::PrivateIronwood);
        let (height, _) = st.generate_empty_block();
        let mut block = cached(&st, height);
        let (action, record) = encrypted_action(
            [9; 32],
            key.receiver(),
            OutgoingViewingKey::from([0; 32]),
            30_000,
        );
        block
            .chain_metadata
            .as_mut()
            .unwrap()
            .ironwood_commitment_tree_size += 1;
        block.vtx = vec![CompactTx {
            index: 1,
            txid: vec![8; 32],
            ironwood_actions: vec![action],
            ..Default::default()
        }];
        st.cache()
            .0
            .execute(
                "UPDATE compactblocks SET data = ?1 WHERE height = ?2",
                rusqlite::params![block.encode_to_vec(), u32::from(height)],
            )
            .unwrap();
        st.scan_cached_blocks(height, 1);
        let mut reopened = WalletDb::for_path(
            st.wallet().data_file_path(),
            *st.network(),
            test_clock(),
            test_rng(),
        )
        .unwrap();
        reopened.set_enhancement_mode(EnhancementMode::PrivateIronwood);
        *st.wallet_mut().db_mut() = reopened;
        let requests = st.wallet().db().query_requests().unwrap();
        assert_eq!(requests.len(), 1);
        let request = requests[0];
        let pending = st
            .wallet()
            .db()
            .pending_memo(request.position())
            .unwrap()
            .unwrap();
        assert_eq!(pending.note.recipient(), key.receiver());
        assert!(pending.receiving_ivk.is_some());

        let mut suffix = *record.enc_ciphertext_suffix();
        suffix[527] ^= 1;
        let corrupt = EnhanceRecord::from_parts(EnhanceRecordParts {
            enc_ciphertext_suffix: suffix,
            cv_net: *record.cv_net(),
            out_ciphertext: *record.out_ciphertext(),
            has_transparent_inputs: false,
            has_transparent_outputs: false,
            metadata: record.metadata(),
        });
        assert_eq!(
            apply_record(st.wallet_mut().db_mut(), request, &corrupt).unwrap(),
            EnhancePirStoreResult::Rejected
        );
        assert_eq!(st.wallet().db().query_requests().unwrap(), requests);
        // A corrupt registration is an error, not fallback to the ordinary IVK.
        st.wallet()
            .conn()
            .execute(
                "UPDATE ironwood_receiving_keys SET receiver = zeroblob(43)",
                [],
            )
            .unwrap();
        assert!(apply_record(st.wallet_mut().db_mut(), request, &record).is_err());
        st.wallet()
            .conn()
            .execute(
                "UPDATE ironwood_receiving_keys SET receiver = ?1",
                [key.receiver().to_raw_address_bytes()],
            )
            .unwrap();
        assert_eq!(
            apply_record(st.wallet_mut().db_mut(), request, &record).unwrap(),
            EnhancePirStoreResult::Stored
        );
        assert!(st.wallet().db().query_requests().unwrap().is_empty());
        let (memo, key_ref): (Vec<u8>, Option<i64>) = st
            .wallet()
            .conn()
            .query_row(
                "SELECT memo, receiving_key_id FROM ironwood_received_notes",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(memo, [4; 512]);
        assert!(key_ref.is_some());
        assert!(!visible(&st, request));
        assert!(
            st.wallet()
                .get_transaction(request.request_id().txid())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            apply_record(st.wallet_mut().db_mut(), request, &record).unwrap(),
            EnhancePirStoreResult::AlreadyResolved
        );
    }
}

#[cfg(not(feature = "experimental-swap-receiving"))]
#[test]
fn swap_receiving_pir_without_feature_preserves_pending_work() {
    let (mut st, _, request) = fixture();
    st.wallet().conn().execute_batch(
        "INSERT INTO ironwood_receiving_keys
         (id, account_id, purpose, derivation_version, key_index, receiver, scan_from, advances_allocation)
         SELECT 1, account_id, 0, 1, zeroblob(8), zeroblob(43), 0, 1 FROM ironwood_received_notes LIMIT 1;
         UPDATE ironwood_received_notes SET receiving_key_id = 1;"
    ).unwrap();
    assert!(matches!(
        st.wallet().db().pending_memo(request.position()),
        Err(SqliteClientError::SwapReceivingNotEnabled)
    ));
    assert!(matches!(
        apply_record(
            st.wallet_mut().db_mut(),
            request,
            &wire_record(false, false)
        ),
        Err(SqliteClientError::SwapReceivingNotEnabled)
    ));
    assert_eq!(st.wallet().db().query_requests().unwrap(), vec![request]);
}
