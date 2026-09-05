use super::*;
use secrecy::{ExposeSecret, SecretVec};
use std::{collections::HashMap, convert::Infallible};
use zcash_client_backend::{
    TransferType, data_api::wallet::ConfirmationsPolicy, decrypt_transaction,
    fees::StandardFeeRule, wallet::OvkPolicy,
};
use zcash_keys::address::{Address, UnifiedAddress};

/// Build with the default bundle policy, then restore from compact blocks so no
/// locally created sent notes or full transaction can bypass private recovery.
#[test]
fn default_padding_and_ovk_discard_complete_like_regular_enhancement() {
    for discard in [false, true] {
        let mut st = state_with_factory(TestDbFactory::default());
        let account = st.test_account().unwrap().clone();
        let seed = SecretVec::new(st.test_seed().unwrap().expose_secret().clone());
        let fvk = IronwoodFvk(OrchardPoolTester::test_account_fvk(&st));
        let (funding_height, _, _) = st.generate_next_block(
            &fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(20_000),
        );
        for _ in 0..2 {
            st.generate_next_block(
                &fvk,
                AddressType::DefaultExternal,
                Zatoshis::const_from_u64(20_000),
            );
        }
        st.scan_cached_blocks(funding_height, 3);
        st.generate_and_scan_empty_blocks(5);
        let recipient = OrchardPoolTester::sk_to_fvk(&OrchardPoolTester::sk(&[0xf5; 32]))
            .address_at(0u32, Scope::External);
        let address =
            Address::Unified(UnifiedAddress::from_receivers(Some(recipient), None, None).unwrap());
        // Three real spends force three actions. A single payment and the
        // wallet's zero-valued change leave one builder-generated padding output.
        let proposal = st
            .propose_standard_transfer::<Infallible>(
                account.id(),
                StandardFeeRule::Zip317,
                ConfirmationsPolicy::MIN,
                &address,
                Zatoshis::const_from_u64(45_000),
                Some(MemoBytes::empty()),
                None,
                ShieldedPool::Ironwood,
            )
            .unwrap();
        let txid = st
            .create_proposed_transactions::<Infallible, _, Infallible, _>(
                account.usk(),
                if discard {
                    OvkPolicy::Discard
                } else {
                    OvkPolicy::Sender
                },
                &proposal,
            )
            .unwrap()[0];
        let transaction = st.wallet().get_transaction(txid).unwrap().unwrap();
        let bundle = transaction.ironwood_bundle().unwrap();
        assert_eq!(
            bundle.actions().len(),
            3,
            "default bundle pads outputs to match three spends"
        );
        let (send_height, _) = st.generate_next_block_from_tx(1, &transaction);

        st.reset();
        let (account_id, usk) = st
            .wallet_mut()
            .create_account("restored", &seed, account.birthday(), None)
            .unwrap();
        st.wallet_mut()
            .db_mut()
            .set_enhancement_mode(EnhancementMode::PrivateIronwood);
        let start = funding_height - 1;
        st.scan_cached_blocks(
            start,
            usize::try_from(u32::from(send_height) - u32::from(start) + 1).unwrap(),
        );
        let requests: Vec<_> = st
            .wallet()
            .db()
            .enhance_pir_requests()
            .unwrap()
            .into_iter()
            .filter(|r| r.request_id().txid() == txid)
            .collect();
        assert_eq!(
            requests.len(),
            3,
            "compact scanning queues payment, padding, and incoming change"
        );
        assert_eq!(
            requests
                .iter()
                .filter(|r| st
                    .wallet()
                    .db()
                    .pending_ironwood_outgoing(r.position())
                    .unwrap()
                    .is_some())
                .count(),
            2,
            "payment and padding are outgoing candidates"
        );

        let ufvks = HashMap::from([(account_id, usk.to_unified_full_viewing_key())]);
        let regular = decrypt_transaction(
            st.network(),
            Some(send_height),
            Some(send_height),
            &transaction,
            &ufvks,
        );
        let expected: Vec<_> = regular
            .ironwood_outputs()
            .iter()
            .filter(|output| output.transfer_type() == TransferType::Outgoing)
            .collect();
        assert_eq!(expected.len(), usize::from(!discard));
        let mut discarded = 0;
        for request in &requests {
            let action = &bundle.actions()[request.request_id().output_index() as usize];
            let encrypted = action.encrypted_note();
            let record = EnhanceRecord::from_parts(
                encrypted.epk_bytes,
                encrypted.enc_ciphertext,
                action.cv_net().to_bytes(),
                encrypted.out_ciphertext,
                false,
                false,
            );
            let result = apply_record(st.wallet_mut().db_mut(), *request, &record).unwrap();
            if result == EnhancePirStoreResult::NotRecoverable {
                discarded += 1;
            } else {
                assert_eq!(result, EnhancePirStoreResult::Stored);
            }
        }
        assert_eq!(discarded, if discard { 2 } else { 1 });
        let tx_ref: i64 = st
            .wallet()
            .conn()
            .query_row(
                "SELECT id_tx FROM transactions WHERE txid = ?1",
                [txid.as_ref()],
                |r| r.get(0),
            )
            .unwrap();
        // Scanning already records the account-internal change as a sent note.
        // Compare the total recovered set as well as the external output details,
        // so filtering change cannot hide a spurious sent entry for padding.
        assert_eq!(
            st.wallet()
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM sent_notes WHERE transaction_id = ?1",
                    [tx_ref],
                    |r| r.get::<_, usize>(0)
                )
                .unwrap(),
            regular.ironwood_outputs().len()
        );
        let mut stmt = st.wallet().conn().prepare("SELECT output_index, to_address, value, memo FROM sent_notes WHERE transaction_id = ?1 AND to_account_id IS NULL ORDER BY output_index").unwrap();
        let actual: Vec<(usize, String, u64, Vec<u8>)> = stmt
            .query_map([tx_ref], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(actual.len(), expected.len());
        for (actual, expected) in actual.iter().zip(expected) {
            assert_eq!(actual.0, expected.index());
            assert_eq!(
                actual.1,
                Receiver::Orchard(recipient)
                    .to_zcash_address(st.network().network_type())
                    .to_string()
            );
            assert_eq!(actual.2, expected.note().0.value().inner());
            assert_eq!(actual.3, memo_repr(Some(expected.memo())).unwrap());
        }
        assert_eq!(st.wallet().conn().query_row("SELECT COUNT(*) FROM ironwood_enhance_outgoing_queue WHERE transaction_id = ?1", [tx_ref], |r| r.get::<_, i64>(0)).unwrap(), 0);
        assert!(
            !st.wallet()
                .db()
                .enhance_pir_requests()
                .unwrap()
                .iter()
                .any(|r| r.request_id().txid() == txid)
        );
        drop(stmt);
        st.wallet_mut()
            .db_mut()
            .set_enhancement_mode(EnhancementMode::Standard);
        assert!(
            !st.wallet()
                .transaction_data_requests()
                .unwrap()
                .contains(&TransactionDataRequest::Enhancement(txid))
        );
    }
}
