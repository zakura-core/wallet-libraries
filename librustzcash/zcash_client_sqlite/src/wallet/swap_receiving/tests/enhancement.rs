use super::*;
use std::convert::Infallible;
use zcash_client_backend::{
    data_api::{
        WalletRead,
        testing::{AddressType, IronwoodFvk},
        wallet::{
            ConfirmationsPolicy, decrypt_and_store_transaction,
            input_selection::GreedyInputSelector,
        },
    },
    fees::{DustOutputPolicy, StandardFeeRule, standard},
    wallet::OvkPolicy,
};
use zcash_keys::address::{Address, UnifiedAddress};
use zcash_protocol::{ShieldedPool, memo::MemoBytes, value::Zatoshis};
use zip321::{Payment, TransactionRequest};

fn full_transaction_roundtrip(full_first: bool) {
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
        .with_data_store_factory(TestDbFactory::file_backed())
        .with_block_cache(crate::testing::BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();
    let account = st.test_account().cloned().unwrap();
    let parent = orchard::keys::FullViewingKey::from(account.usk().orchard());
    let (h, _, _) = st.generate_next_block(
        &IronwoodFvk(parent),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(1_000_000),
    );
    st.scan_cached_blocks(h, 1);
    for _ in 0..5 {
        let (h, _) = st.generate_empty_block();
        st.scan_cached_blocks(h, 1);
    }

    let scan_from = st.wallet().chain_height().unwrap().unwrap() + 1;
    let keys: Vec<_> = [Purpose::Refund, Purpose::Receive]
        .into_iter()
        .map(|purpose| {
            st.wallet_mut()
                .db_mut()
                .reserve_swap_receiving_key(account.id(), purpose, scan_from)
                .unwrap()
        })
        .collect();
    let memo = MemoBytes::from_bytes(b"swap payment memo").unwrap();
    let payments = keys
        .iter()
        .map(|key| {
            let address = Address::Unified(
                UnifiedAddress::from_receivers(Some(key.receiver()), None, None).unwrap(),
            );
            Payment::new(
                address.to_zcash_address(&network),
                Some(Zatoshis::const_from_u64(50_000)),
                Some(memo.clone()),
                None,
                None,
                vec![],
            )
            .unwrap()
        })
        .collect();
    let strategy = standard::SingleOutputChangeStrategy::<TestDb>::new(
        StandardFeeRule::Zip317,
        None,
        ShieldedPool::Orchard,
        DustOutputPolicy::default(),
    );
    let proposal = st
        .propose_transfer(
            account.id(),
            &GreedyInputSelector::new(),
            &strategy,
            TransactionRequest::new(payments).unwrap(),
            ConfirmationsPolicy::MIN,
        )
        .unwrap();
    let created = st
        .create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        )
        .unwrap();
    let tx = st.wallet().get_transaction(created[0]).unwrap().unwrap();

    // Ordinary OVK recovery finds these self-payments as outgoing. Swap decryption
    // must replace those records with incoming records, not duplicate them.
    let ufvks = st.wallet().get_unified_full_viewing_keys().unwrap();
    let decoded = zcash_client_backend::decrypt_transaction(&network, None, Some(h), &tx, &ufvks)
        .with_swap_receiving_keys(st.wallet().get_swap_scanning_keys().unwrap());
    for key in &keys {
        let outputs: Vec<_> = decoded
            .ironwood_outputs()
            .iter()
            .filter(|o| o.note().0.recipient() == key.receiver())
            .collect();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].swap_key_id(), Some(key.key_id()));
        assert_eq!(
            outputs[0].transfer_type(),
            zcash_client_backend::TransferType::Incoming
        );
        assert_eq!(outputs[0].memo(), &memo);
    }
    if full_first {
        decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, None).unwrap();
    }
    let (mined, _) = st.generate_next_block_including(created[0]);
    st.scan_cached_blocks(mined, 1);
    // Close/reopen before fetching the full transaction, as on a resumed sync.
    let reopened = WalletDb::for_path(
        st.wallet().data_file_path(),
        network,
        test_clock(),
        test_rng(),
    )
    .unwrap();
    *st.wallet_mut().db_mut() = reopened;
    for _ in 0..2 {
        decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, Some(mined)).unwrap();
    }
    st.scan_cached_blocks(mined, 1);
    let notes = st
        .wallet()
        .db()
        .get_unspent_ironwood_notes_at_historical_height(account.id(), mined)
        .unwrap();
    for key in keys {
        let note = notes
            .iter()
            .find(|n| n.swap_key_id() == Some(key.key_id()))
            .unwrap();
        assert_eq!(note.note().recipient(), key.receiver());
        let stored: Vec<u8> = st.wallet().conn().query_row(
            "SELECT rn.memo FROM ironwood_received_notes rn JOIN transactions t ON t.id_tx = rn.transaction_id
             WHERE t.txid = ?1 AND rn.action_index = ?2",
            rusqlite::params![tx.txid().as_ref(), note.output_index()], |r| r.get(0)).unwrap();
        assert_eq!(stored, memo.as_slice());
    }
    assert_eq!(notes.len(), 3); // Both swap payments and ordinary internal change.
}

#[test]
fn swap_receiving_full_transaction_after_compact_scan() {
    full_transaction_roundtrip(false);
}

#[test]
fn swap_receiving_full_transaction_before_compact_scan() {
    full_transaction_roundtrip(true);
}
