//! Local reconfirmation for transactions compact scanning cannot rediscover, with durable
//! status fallback when the accepted block changes or original evidence is missing.

use zcash_client_backend::data_api::TransactionStatus;
use zcash_primitives::transaction::Transaction;

use super::public_fixtures::{
    EXTERNAL, expiring_transaction, external_of, funding, outpoint, public_wallet, store,
    transaction,
};
use super::*;

fn tip(st: &State) -> BlockHeight {
    st.wallet().chain_height().unwrap().unwrap()
}

fn status_work(st: &State) -> Vec<TxId> {
    use zcash_client_backend::data_api::status::TransactionStatusRead as _;
    st.wallet()
        .db()
        .transaction_status_work()
        .unwrap()
        .into_iter()
        .map(|work| work.txid())
        .collect()
}

fn mined_height(st: &State, tx: &Transaction) -> Option<u32> {
    conn(st)
        .query_row(
            "SELECT mined_height FROM transactions WHERE txid = ?1",
            [tx.txid().as_ref()],
            |row| row.get(0),
        )
        .unwrap()
}

#[test]
fn importing_an_account_restores_unobservable_transactions_from_the_same_block() {
    use zcash_client_backend::data_api::status::TransactionStatusMode;
    for mode in [
        TransactionStatusMode::Public,
        TransactionStatusMode::Private,
    ] {
        let (mut st, accounts) = public_wallet(0);
        st.wallet_mut().db_mut().set_status_mode(mode);
        let parent = funding(0xe0, external_of(&st, accounts[0]), 1_000_000);
        let send = transaction(vec![outpoint(&parent, 0)], vec![(EXTERNAL, 990_000)]);
        store(&mut st, &parent);
        store(&mut st, &send);
        let mined = tip(&st);
        import_account(&mut st, 9);
        assert_eq!(mined_height(&st, &send), None);
        assert!(status_work(&st).is_empty());
        // Explicit queries remain available; waiting is an automatic scheduling decision only.
        use zcash_client_backend::data_api::status::TransactionStatusRead;
        assert_eq!(
            st.wallet()
                .db()
                .transaction_status_work_for(send.txid())
                .unwrap()
                .txid(),
            send.txid()
        );
        let birthday = st.test_account().unwrap().birthday().height();
        st.scan_cached_blocks(birthday, usize::try_from(mined - birthday).unwrap());
        assert_eq!(mined_height(&st, &send), None); // prior heights cannot authorize inclusion
        assert!(status_work(&st).is_empty());
        st.scan_cached_blocks(mined, 1);
        assert_eq!(mined_height(&st, &parent), Some(u32::from(mined)));
        assert_eq!(mined_height(&st, &send), Some(u32::from(mined)));
        assert!(status_work(&st).is_empty());
        assert_eq!(
            conn(&st)
                .query_row("SELECT COUNT(*) FROM tx_reconfirmation_receipts", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        // Inclusion restoration does not invent a current unspentness observation.
        assert!(conn(&st).query_row("SELECT max_observed_unspent_height IS NULL FROM transparent_received_outputs LIMIT 1", [], |r|r.get::<_,bool>(0)).unwrap());
    }
}

#[test]
fn local_reconfirmation_succeeds_past_expiry_without_a_status_observation() {
    use zcash_client_backend::data_api::status::TransactionStatusMode;
    let (mut st, accounts) = public_wallet(0);
    st.wallet_mut()
        .db_mut()
        .set_status_mode(TransactionStatusMode::Private);
    let parent = funding(0xe2, external_of(&st, accounts[0]), 1_000_000);
    store(&mut st, &parent);
    let mined = tip(&st);
    let send = expiring_transaction(
        vec![outpoint(&parent, 0)],
        vec![(EXTERNAL, 990_000)],
        mined + 3,
    );
    store(&mut st, &send);
    import_account(&mut st, 9);
    let birthday = st.test_account().unwrap().birthday().height();
    st.scan_cached_blocks(birthday, usize::try_from((mined - birthday) + 1).unwrap());
    scan_new_blocks(&mut st, 110);
    assert_eq!(mined_height(&st, &send), Some(u32::from(mined)));
    assert!(status_work(&st).is_empty());
    // Repeated same-chain rewinds reuse newly captured evidence, still without network work.
    st.wallet_mut().truncate_to_height(mined - 1).unwrap();
    assert_eq!(mined_height(&st, &send), None);
    assert!(status_work(&st).is_empty());
    st.scan_cached_blocks(mined, 111);
    assert_eq!(mined_height(&st, &send), Some(u32::from(mined)));
    assert!(status_work(&st).is_empty());
}

#[test]
fn replaced_block_needs_status_and_cannot_restore_the_old_confirmation() {
    use zcash_client_backend::data_api::status::{
        TransactionStatusMode, TransactionStatusRead, TransactionStatusWork,
    };
    let (mut st, accounts) = public_wallet(0);
    st.wallet_mut()
        .db_mut()
        .set_status_mode(TransactionStatusMode::Public);
    let parent = funding(0xe3, external_of(&st, accounts[0]), 1_000_000);
    store(&mut st, &parent);
    let mined = tip(&st);
    let old_hash = st.wallet().get_block_hash(mined).unwrap().unwrap();
    st.truncate_to_height(mined - 1); // discard the old cached block and create a replacement
    assert!(status_work(&st).is_empty());
    set_policy(&mut st, PrivateRequired);
    scan_new_blocks(&mut st, 1);
    assert_ne!(
        st.wallet().get_block_hash(mined).unwrap().unwrap(),
        old_hash
    );
    assert_eq!(mined_height(&st, &parent), None);
    let work = st.wallet().db().transaction_status_work().unwrap();
    assert!(
        matches!(work.as_slice(),[TransactionStatusWork::Private(r)] if r.txid()==parent.txid() && r.earliest_possible_inclusion().is_none())
    );
    st.wallet_mut()
        .set_transaction_status(parent.txid(), TransactionStatus::Mined(mined))
        .unwrap();
    assert_eq!(mined_height(&st, &parent), Some(u32::from(mined)));
    assert!(status_work(&st).is_empty());
}

#[test]
fn rejected_scan_batch_does_not_reconfirm_or_consume_receipts() {
    use zcash_client_backend::data_api::status::TransactionStatusMode;
    let (mut st, accounts) = public_wallet(0);
    st.wallet_mut()
        .db_mut()
        .set_status_mode(TransactionStatusMode::Public);
    let parent = funding(0xe4, external_of(&st, accounts[0]), 1_000_000);
    store(&mut st, &parent);
    let mined = tip(&st);
    st.wallet_mut().truncate_to_height(mined - 1).unwrap();
    // The old hash is present in cache, but an invalid scan origin must fail before reconciliation.
    let invalid_origin = zcash_client_backend::data_api::chain::ChainState::empty(
        mined - 1,
        zcash_primitives::block::BlockHash([42; 32]),
    );
    assert!(
        st.try_scan_cached_blocks_with_state(mined, &invalid_origin, 1)
            .is_err()
    );
    assert_eq!(mined_height(&st, &parent), None);
    conn(&st).execute_batch("CREATE TRIGGER reject_reconfirmation BEFORE DELETE ON tx_reconfirmation_receipts BEGIN SELECT RAISE(ABORT, 'reject reconciliation'); END").unwrap();
    assert!(st.try_scan_cached_blocks(mined, 1).is_err());
    assert_eq!(mined_height(&st, &parent), None);
    assert_eq!(
        conn(&st)
            .query_row("SELECT COUNT(*) FROM tx_reconfirmation_receipts", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert!(status_work(&st).is_empty());
    conn(&st)
        .execute_batch("DROP TRIGGER reject_reconfirmation")
        .unwrap();
    st.scan_cached_blocks(mined, 1);
    assert_eq!(mined_height(&st, &parent), Some(u32::from(mined)));
}

#[test]
fn out_of_order_reconfirmation_batches_restore_only_their_own_heights() {
    use zcash_client_backend::data_api::status::TransactionStatusMode;
    let (mut st, accounts) = public_wallet(0);
    st.wallet_mut()
        .db_mut()
        .set_status_mode(TransactionStatusMode::Private);
    let parent = funding(0xe5, external_of(&st, accounts[0]), 1_000_000);
    store(&mut st, &parent);
    let mined = tip(&st);
    scan_new_blocks(&mut st, 2);
    st.wallet_mut().truncate_to_height(mined - 1).unwrap();
    // An accepted later range, including its high frontier, cannot settle an earlier receipt.
    st.scan_cached_blocks(mined + 1, 2);
    assert_eq!(mined_height(&st, &parent), None);
    assert!(status_work(&st).is_empty());
    st.scan_cached_blocks(mined, 1);
    assert_eq!(mined_height(&st, &parent), Some(u32::from(mined)));
    assert!(status_work(&st).is_empty());
}

#[test]
fn mined_payload_supersedes_reconfirmation_before_old_block_rescan() {
    use zcash_client_backend::data_api::{
        status::TransactionStatusMode, wallet::decrypt_and_store_transaction,
    };
    let (mut st, accounts) = public_wallet(0);
    st.wallet_mut()
        .db_mut()
        .set_status_mode(TransactionStatusMode::Private);
    let parent = funding(0xe6, external_of(&st, accounts[0]), 1_000_000);
    store(&mut st, &parent);
    let old_height = tip(&st);
    scan_new_blocks(&mut st, 1);
    st.wallet_mut().truncate_to_height(old_height - 1).unwrap();
    let network = *st.network();
    // Actual payload ingestion establishes a newer mined observation and completes enhancement.
    decrypt_and_store_transaction(&network, st.wallet_mut(), &parent, Some(old_height + 1))
        .unwrap();
    assert_eq!(
        conn(&st)
            .query_row("SELECT COUNT(*) FROM tx_reconfirmation_receipts", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    st.scan_cached_blocks(old_height, 2);
    assert_eq!(mined_height(&st, &parent), Some(u32::from(old_height + 1)));
    assert!(status_work(&st).is_empty());
}

#[test]
fn deleting_account_cascades_reconfirmation_evidence_and_obligations() {
    use zcash_client_backend::data_api::status::TransactionStatusMode;
    let (mut st, accounts) = public_wallet(0);
    st.wallet_mut()
        .db_mut()
        .set_status_mode(TransactionStatusMode::Private);
    let parent = funding(0xe7, external_of(&st, accounts[0]), 1_000_000);
    store(&mut st, &parent);
    let mined = tip(&st);
    st.wallet_mut().truncate_to_height(mined - 1).unwrap();
    assert_eq!(
        conn(&st)
            .query_row("SELECT COUNT(*) FROM tx_reconfirmation_receipts", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    st.wallet_mut().delete_account(accounts[0]).unwrap();
    assert_eq!(
        conn(&st)
            .query_row("SELECT COUNT(*) FROM tx_reconfirmation_receipts", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert!(
        !conn(&st)
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM transactions WHERE txid=?1)",
                [parent.txid().as_ref()],
                |r| r.get::<_, bool>(0)
            )
            .unwrap()
    );
    assert!(status_work(&st).is_empty());
}

#[test]
fn mixed_transaction_reconfirmation_ignores_shielded_bundles_owned_by_another_wallet() {
    use zcash_client_backend::data_api::status::TransactionStatusMode;
    let (mut st, accounts) = public_wallet(0);
    st.wallet_mut()
        .db_mut()
        .set_status_mode(TransactionStatusMode::Private);
    let to = external_of(&st, accounts[0]);
    let mut sender = TestBuilder::new()
        .with_data_store_factory(TestDbFactory::file_backed())
        .with_block_cache(BlockCache::new())
        .with_account_from_sapling_activation(zcash_primitives::block::BlockHash([0; 32]))
        .set_account_index(zip32::AccountId::try_from(1).unwrap())
        .build();
    let (txid, _) = pay_from_sapling(&mut sender, to, 50_000);
    let payment = sender.wallet().get_transaction(txid).unwrap().unwrap();
    assert!(payment.sapling_bundle().is_some());
    assert!(payment.transparent_bundle().is_some());
    store(&mut st, &payment);
    let mined = tip(&st);
    for pool in ["sapling", "orchard", "ironwood"] {
        for suffix in ["received_notes", "received_note_spends"] {
            assert_eq!(conn(&st).query_row(&format!("SELECT COUNT(*) FROM {pool}_{suffix} n JOIN transactions t ON t.id_tx=n.transaction_id WHERE t.txid=?1"), [txid.as_ref()], |r|r.get::<_,i64>(0)).unwrap(), 0);
        }
    }
    st.wallet_mut().truncate_to_height(mined - 1).unwrap();
    assert_eq!(
        conn(&st)
            .query_row("SELECT COUNT(*) FROM tx_reconfirmation_receipts", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert!(status_work(&st).is_empty());
    st.scan_cached_blocks(mined, 1);
    assert_eq!(mined_height(&st, &payment), Some(u32::from(mined)));
    for table in [
        "tpir_coverage",
        "tpir_qualified_revisions",
        "tpir_active_accounts",
    ] {
        assert_eq!(
            conn(&st)
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    assert!(status_work(&st).is_empty());
}
