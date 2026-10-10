use super::*;
use orchard::{
    note::{NoteVersion, RandomSeed, Rho},
    value::NoteValue,
};
use zcash_primitives::transaction::TxId;

fn state() -> State {
    TestBuilder::new()
        .with_data_store_factory(TestDbFactory::file_backed())
        .with_block_cache(crate::testing::BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build()
}
fn encrypted(key: &DynamicKey) -> EncryptedNote {
    let rho = Rho::from_bytes(&[9; 32]).unwrap();
    let note = Note::from_parts(
        key.receiver(),
        NoteValue::from_raw(30_000),
        rho,
        RandomSeed::from_bytes([7; 32], &rho).unwrap(),
        NoteVersion::V3,
    )
    .unwrap();
    encrypt_note(note)
}

#[test]
fn directory_payment_queue_authenticates_retries_and_survives_reopen_without_credit() {
    let mut st = state();
    let account = st.test_account().unwrap().id();
    let key = watch(st.wallet_mut().db_mut(), account, 0, start());
    let (height, _) = st.generate_empty_block();
    st.scan_cached_blocks_with_dynamic_ivks(height, 1);
    // An authentic ciphertext alone is not evidence that its note is on chain.
    let candidate = PendingPayment {
        txid: TxId::from_bytes([8; 32]),
        action_index: 0,
        height,
        block_hash: st.wallet().get_block_hash(height).unwrap().unwrap(),
        tx_index: 1,
        position: 0,
        encrypted_note: encrypted(&key),
    };
    let mut bad = candidate.clone();
    let mut bytes = *bad.encrypted_note.to_bytes();
    bytes[675] ^= 1;
    bad.encrypted_note = EncryptedNote::from_bytes(bytes);
    assert!(queue_payment(st.wallet_mut().db_mut(), account, key.key_id(), &bad).is_err());
    assert!(pending(st.wallet().db(), account, key.key_id()).is_empty());
    queue_payment(st.wallet_mut().db_mut(), account, key.key_id(), &candidate).unwrap();
    queue_payment(st.wallet_mut().db_mut(), account, key.key_id(), &candidate).unwrap();
    let mut conflict = candidate.clone();
    conflict.position = 1;
    assert!(queue_payment(st.wallet_mut().db_mut(), account, key.key_id(), &conflict).is_err());
    let mut wrong_block = candidate.clone();
    wrong_block.block_hash = BlockHash([99; 32]);
    assert!(
        queue_payment(
            st.wallet_mut().db_mut(),
            account,
            key.key_id(),
            &wrong_block
        )
        .is_err()
    );
    let reopening = WalletDb::for_path(
        st.wallet().data_file_path(),
        *st.network(),
        test_clock(),
        test_rng(),
    )
    .unwrap();
    let jobs = pending(&reopening, account, key.key_id());
    assert_eq!(jobs.len(), 1);
    assert!(jobs[0] == candidate);
    assert!(!key_state(&reopening, key.key_id()).1);
    let credited: u64 = st
        .wallet()
        .conn()
        .query_row("SELECT COUNT(*) FROM ironwood_received_notes", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(credited, 0);
    let rollback: Result<(), SqliteClientError> = st
        .wallet_mut()
        .db_mut()
        .transactionally_with_extension(|db, _| {
            let mut second = candidate.clone();
            second.txid = TxId::from_bytes([10; 32]);
            store::payments::queue_payment(db.conn.0, db.params, account, key.key_id(), &second)?;
            Err(corrupt("rollback fixture"))
        });
    assert!(rollback.is_err());
    assert_eq!(pending(st.wallet().db(), account, key.key_id()).len(), 1);
    let (orphan_height, _) = st.generate_empty_block();
    st.scan_cached_blocks_with_dynamic_ivks(orphan_height, 1);
    let mut orphan = candidate.clone();
    orphan.txid = TxId::from_bytes([12; 32]);
    orphan.height = orphan_height;
    orphan.block_hash = st.wallet().get_block_hash(orphan_height).unwrap().unwrap();
    queue_payment(st.wallet_mut().db_mut(), account, key.key_id(), &orphan).unwrap();
    st.truncate_to_height_retaining_cache(height);
    let retained = pending(st.wallet().db(), account, key.key_id());
    assert_eq!(retained.len(), 1);
    assert!(retained[0] == candidate);
    assert_eq!(all_keys(st.wallet().db(), account).unwrap().len(), 1);
}

#[test]
fn directory_payment_absence_requires_retained_contiguous_nullifiers() {
    use zcash_client_backend::data_api::ll::LowLevelWalletWrite;
    use zcash_protocol::ShieldedPool;
    let mut st = state();
    let account = st.test_account().unwrap().id();
    let key = reserve_key(st.wallet_mut().db_mut(), account, Purpose::Refund, start());
    let (first, _) = st.generate_empty_block();
    let (last, _) = st.generate_empty_block();
    st.scan_cached_blocks_with_dynamic_ivks(first, 2);
    let candidate = PendingPayment {
        txid: TxId::from_bytes([8; 32]),
        action_index: 0,
        height: first,
        block_hash: st.wallet().get_block_hash(first).unwrap().unwrap(),
        tx_index: 1,
        position: 0,
        encrypted_note: encrypted(&key),
    };
    let through = tip(&st);
    assert_eq!(
        spend_status(
            st.wallet_mut().db_mut(),
            account,
            key.key_id(),
            &candidate,
            through
        ),
        Ok(SpendStatus::Unspent)
    );
    st.wallet_mut()
        .db_mut()
        .transactionally_with_extension(|db, _| {
            LowLevelWalletWrite::prune_tracked_nullifiers(db, 0)
        })
        .unwrap();
    assert_eq!(
        spend_status(
            st.wallet_mut().db_mut(),
            account,
            key.key_id(),
            &candidate,
            through
        ),
        Ok(SpendStatus::Unknown)
    );
    let nf = candidate
        .encrypted_note
        .decrypt(
            &FullViewingKey::from(st.test_account().unwrap().usk().orchard()),
            key.key_id(),
        )
        .unwrap()
        .nullifier()
        .to_bytes();
    let spend_txid = TxId::from_bytes([11; 32]);
    let tx = st.wallet_mut().conn_mut().transaction().unwrap();
    crate::wallet::insert_nullifier_map(
        &tx,
        last,
        ShieldedPool::Ironwood,
        &[(1u16.into(), spend_txid, vec![nf])],
    )
    .unwrap();
    tx.commit().unwrap();
    assert_eq!(
        spend_status(
            st.wallet_mut().db_mut(),
            account,
            key.key_id(),
            &candidate,
            through
        ),
        Ok(SpendStatus::Spent(spend_txid))
    );
    let mut wrong = through;
    wrong.hash.0[0] ^= 1;
    assert!(
        spend_status(
            st.wallet_mut().db_mut(),
            account,
            key.key_id(),
            &candidate,
            wrong
        ) == Err(SweepDeferral::UnknownAnchor)
    );
    st.truncate_to_height_retaining_cache(first);
    assert_eq!(
        spend_status(
            st.wallet_mut().db_mut(),
            account,
            key.key_id(),
            &candidate,
            through
        ),
        Ok(SpendStatus::Unknown)
    );
    let rows: u64 = st
        .wallet()
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM ironwood_nullifier_scan_blocks WHERE height > ?1",
            [u32::from(first)],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(rows, 0);
    // Keep the import boundary explicit: spentness alone has not inserted a wallet note.
    assert_eq!(
        st.wallet()
            .conn()
            .query_row("SELECT COUNT(*) FROM ironwood_received_notes", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn directory_payment_spentness_includes_spends_already_linked_by_scanning() {
    use zcash_keys::address::{Address, UnifiedAddress};
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let birthday = st.sapling_activation_height();
    let key = reserve_key(st.wallet_mut().db_mut(), account, Purpose::Refund, birthday);
    let fvk = IronwoodFvk(key.full_viewing_key().clone());
    let (height, _, nf) = st.generate_next_block(
        &fvk,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(100_000),
    );
    st.scan_cached_blocks_with_dynamic_ivks(height, 1);
    let notes = st
        .wallet()
        .db()
        .get_unspent_ironwood_notes_at_historical_height(account, height)
        .unwrap();
    let candidate = PendingPayment {
        txid: TxId::from_bytes([8; 32]),
        action_index: 0,
        height,
        block_hash: st.wallet().get_block_hash(height).unwrap().unwrap(),
        tx_index: 1,
        position: 0,
        encrypted_note: encrypt_note(*notes[0].note()),
    };
    let to =
        Address::Unified(UnifiedAddress::from_receivers(Some(key.receiver()), None, None).unwrap());
    let (spent_height, _) = st.generate_next_block_spending(
        &fvk,
        (nf, Zatoshis::const_from_u64(100_000)),
        to,
        Zatoshis::const_from_u64(20_000),
    );
    st.scan_cached_blocks_with_dynamic_ivks(spent_height, 1);
    // This is the scanner's real split, not a hand-built nullifier-map fixture.
    let unlinked: u64 = st
        .wallet()
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM nullifier_map WHERE nf=?1",
            [nf.to_bytes()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(unlinked, 0);
    let through = tip(&st);
    let status = spend_status(
        st.wallet_mut().db_mut(),
        account,
        key.key_id(),
        &candidate,
        through,
    );
    assert!(matches!(status, Ok(SpendStatus::Spent(_))));
    st.wallet_mut().delete_account(account).unwrap();
    let coverage: u64 = st
        .wallet()
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM ironwood_nullifier_scan_blocks",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(coverage, 0);
}
