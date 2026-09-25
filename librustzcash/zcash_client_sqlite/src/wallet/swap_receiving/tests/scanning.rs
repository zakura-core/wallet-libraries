use super::*;

#[test]
fn swap_receiving_scan_reopen_and_spend_into_ordinary_change() {
    use std::convert::Infallible;
    use zcash_client_backend::{
        data_api::{
            WalletRead,
            testing::{AddressType, IronwoodFvk},
            wallet::{ConfirmationsPolicy, input_selection::GreedyInputSelector},
        },
        fees::{DustOutputPolicy, StandardFeeRule, standard},
        wallet::OvkPolicy,
    };
    use zcash_keys::address::{Address, UnifiedAddress};
    use zcash_protocol::{ShieldedPool, value::Zatoshis};
    use zip321::{Payment, TransactionRequest};

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
    let ordinary = orchard::keys::FullViewingKey::from(account.usk().orchard());
    let refund = st
        .wallet_mut()
        .db_mut()
        .reserve_swap_receiving_key(account.id(), Purpose::Refund, activation)
        .unwrap();
    let incoming = st
        .wallet_mut()
        .db_mut()
        .watch_swap_receive_key(account.id(), 9, activation)
        .unwrap();

    // Both purposes and the ordinary key coexist in one account's batch runner.
    let (first, _, refund_nf) = st.generate_next_block(
        &IronwoodFvk(refund.full_viewing_key().clone()),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(2_000_000),
    );
    let (_, _, incoming_nf) = st.generate_next_block(
        &IronwoodFvk(incoming.full_viewing_key().clone()),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(3_000_000),
    );
    st.generate_next_block(
        &IronwoodFvk(ordinary.clone()),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(4_000_000),
    );
    st.scan_cached_blocks(first, 3);
    for _ in 0..5 {
        let (h, _) = st.generate_empty_block();
        st.scan_cached_blocks(h, 1);
    }

    // Replay the same canonical outputs. The note key reference must be idempotent.
    st.scan_cached_blocks(first, 8);
    let path = st.wallet().data_file_path().to_owned();
    // Reopen before reconstruction and spending. No derived FVK is persisted in the DB.
    let reopened = WalletDb::for_path(path, network, test_clock(), test_rng()).unwrap();
    *st.wallet_mut().db_mut() = reopened;
    let height = st.wallet().chain_height().unwrap().unwrap();
    let notes = st
        .wallet()
        .db()
        .get_unspent_ironwood_notes_at_historical_height(account.id(), height)
        .unwrap();
    assert_eq!(notes.len(), 3);
    let refund_note = notes
        .iter()
        .find(|n| n.swap_key_id() == Some(refund.key_id()))
        .unwrap();
    assert_eq!(refund_note.note().recipient(), refund.receiver());
    assert_eq!(
        refund_note.note().nullifier(refund.full_viewing_key()),
        refund_nf
    );
    let incoming_note = notes
        .iter()
        .find(|n| n.swap_key_id() == Some(incoming.key_id()))
        .unwrap();
    assert_eq!(incoming_note.note().recipient(), incoming.receiver());
    assert_eq!(
        incoming_note.note().nullifier(incoming.full_viewing_key()),
        incoming_nf
    );
    assert!(notes.iter().any(|n| n.swap_key_id().is_none()));
    assert_eq!(
        st.wallet_mut()
            .db_mut()
            .reserve_swap_receiving_key(account.id(), Purpose::Receive, height + 1)
            .unwrap()
            .key_id()
            .index(),
        10
    );

    let receiver = orchard::keys::FullViewingKey::from(
        &orchard::keys::SpendingKey::from_bytes([0xf5; 32]).unwrap(),
    )
    .address_at(0u32, Scope::External);
    let address =
        Address::Unified(UnifiedAddress::from_receivers(Some(receiver), None, None).unwrap());
    let request = TransactionRequest::new(vec![Payment::without_memo(
        address.to_zcash_address(&network),
        Zatoshis::const_from_u64(6_000_000),
    )])
    .unwrap();
    let change_strategy = standard::SingleOutputChangeStrategy::<TestDb>::new(
        StandardFeeRule::Zip317,
        None,
        ShieldedPool::Orchard,
        DustOutputPolicy::default(),
    );
    let proposal = st
        .propose_transfer(
            account.id(),
            &GreedyInputSelector::new(),
            &change_strategy,
            request,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();
    assert_eq!(
        proposal.input_count_in_pool(zcash_protocol::PoolType::IRONWOOD),
        3
    );
    let created = st
        .create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        )
        .unwrap();
    let (h, _) = st.generate_next_block_including(created[0]);
    st.scan_cached_blocks(h, 1);
    let notes = st
        .wallet()
        .db()
        .get_unspent_ironwood_notes_at_historical_height(account.id(), h)
        .unwrap();
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].swap_key_id(), None);
    assert_eq!(notes[0].spending_key_scope(), Scope::Internal);
    assert_eq!(
        notes[0].note().recipient(),
        ordinary.address_at(0u32, Scope::Internal)
    );
    let (late_height, _, _) = st.generate_next_block(
        &IronwoodFvk(refund.full_viewing_key().clone()),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(70_000),
    );
    st.scan_cached_blocks(late_height, 1);
    let notes = st
        .wallet()
        .db()
        .get_unspent_ironwood_notes_at_historical_height(account.id(), late_height)
        .unwrap();
    assert_eq!(notes.len(), 2);
    assert_eq!(
        notes
            .iter()
            .filter(|n| n.swap_key_id() == Some(refund.key_id()))
            .count(),
        1
    );
    // Spending does not retire a receiver or forget the next allocation.
    assert_eq!(
        st.wallet()
            .db()
            .get_swap_receiving_keys(account.id())
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn swap_receiving_rejects_mismatched_note_metadata() {
    use incrementalmerkletree::Position;
    use orchard::note::{Note, NoteVersion, RandomSeed, Rho};
    use zcash_client_backend::wallet::WalletOutput;
    use zcash_note_encryption::EphemeralKeyBytes;
    use zcash_protocol::ShieldedPool;

    let mut st = wallet(false);
    let account = st.test_account().unwrap().id();
    let key = st
        .wallet_mut()
        .db_mut()
        .watch_swap_receive_key(account, 4, start())
        .unwrap();
    let rho = Rho::from_bytes(&[1; 32]).unwrap();
    let note = Note::from_parts(
        key.receiver(),
        orchard::value::NoteValue::from_raw(50_000),
        rho,
        RandomSeed::from_bytes([2; 32], &rho).unwrap(),
        NoteVersion::V3,
    )
    .unwrap();
    let output = |key_id, scope, nf| {
        WalletOutput::from_parts(
            0,
            EphemeralKeyBytes([0; 32]),
            (note, orchard::ValuePool::Ironwood),
            false,
            Position::from(0),
            nf,
            account,
            Some(scope),
        )
        .with_swap_key_id(key_id)
    };
    let nf = note.nullifier(key.full_viewing_key());
    let conn = st.wallet().conn();
    let valid = output(Some(key.key_id()), Scope::External, Some(nf));
    assert!(
        validate_received_key(conn, st.network(), ShieldedPool::Ironwood, &valid)
            .unwrap()
            .is_some()
    );
    assert!(validate_received_key(conn, st.network(), ShieldedPool::Orchard, &valid).is_err());
    assert!(
        validate_received_key(
            conn,
            st.network(),
            ShieldedPool::Ironwood,
            &output(Some(key.key_id()), Scope::Internal, Some(nf))
        )
        .is_err()
    );
    let wrong_nf = orchard::note::Nullifier::from_bytes(&[1; 32]).unwrap();
    assert!(
        validate_received_key(
            conn,
            st.network(),
            ShieldedPool::Ironwood,
            &output(Some(key.key_id()), Scope::External, Some(wrong_nf))
        )
        .is_err()
    );
    assert!(
        validate_received_key(
            conn,
            st.network(),
            ShieldedPool::Ironwood,
            &output(
                Some(KeyId::new(Purpose::Receive, 5)),
                Scope::External,
                Some(nf)
            )
        )
        .is_err()
    );
    // Validation alone is not evidence committed to the wallet.
    assert!(!st.wallet().db().get_swap_receiving_keys(account).unwrap()[0].advances_allocation());
}

#[test]
fn swap_receiving_reconstructs_only_with_the_registered_account() {
    let mut st = wallet(false);
    let account = st.test_account().unwrap().id();
    let key = st
        .wallet_mut()
        .db_mut()
        .reserve_swap_receiving_key(account, Purpose::Refund, start())
        .unwrap();
    let id: i64 = st
        .wallet()
        .conn()
        .query_row("SELECT id FROM ironwood_receiving_keys", [], |r| r.get(0))
        .unwrap();
    let parent = orchard::keys::FullViewingKey::from(st.test_account().unwrap().usk().orchard());
    assert_eq!(
        note_key(st.wallet().conn(), st.network(), id, &parent)
            .unwrap()
            .0,
        key.key_id()
    );
    let other = orchard::keys::FullViewingKey::from(
        &orchard::keys::SpendingKey::from_bytes([9; 32]).unwrap(),
    );
    assert!(note_key(st.wallet().conn(), st.network(), id, &other).is_err());
    st.wallet()
        .conn()
        .execute(
            "UPDATE ironwood_receiving_keys SET receiver = zeroblob(43)",
            [],
        )
        .unwrap();
    assert!(note_key(st.wallet().conn(), st.network(), id, &parent).is_err());
}
