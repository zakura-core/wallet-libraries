use super::*;
use std::convert::Infallible;
use transparent::address::TransparentAddress;
use zcash_client_backend::{
    data_api::wallet::{
        ConfirmationsPolicy, decrypt_and_store_transaction, input_selection::GreedyInputSelector,
    },
    fees::{DustOutputPolicy, StandardFeeRule, standard},
    wallet::OvkPolicy,
};
use zcash_keys::address::{Address, UnifiedAddress};
use zcash_protocol::{ShieldedPool, TxId, memo::MemoBytes};
use zip321::{Payment, TransactionRequest};

fn full_transaction_roundtrip(full_first: bool) {
    let (mut st, h) = ironwood_funded_wallet();
    let network = *st.network();
    let account = st.test_account().cloned().unwrap();

    let scan_from = st.wallet().chain_height().unwrap().unwrap() + 1;
    let keys: Vec<_> = [Purpose::Refund, Purpose::Receive]
        .into_iter()
        .map(|purpose| {
            st.wallet_mut()
                .db_mut()
                .reserve_swap_receiving_key_from(account.id(), purpose, scan_from)
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

/// Builds a wallet whose test account holds one confirmed 1,000,000 zatoshi
/// Ironwood note, returning the height of the block that paid it.
fn ironwood_funded_wallet() -> (State, BlockHeight) {
    let mut st = ironwood_wallet();
    let account = st.test_account().cloned().unwrap();
    let parent = orchard::keys::FullViewingKey::from(account.usk().orchard());
    let (first, _, _) = st.generate_next_block(
        &IronwoodFvk(parent),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(1_000_000),
    );
    st.scan_cached_blocks(first, 1);
    for _ in 0..5 {
        let (h, _) = st.generate_empty_block();
        st.scan_cached_blocks(h, 1);
    }
    (st, first)
}

/// Creates and stores, without mining, a transaction paying `payments` from the test
/// account with `memo` on Ironwood change. Returns its proposal and txid.
fn create_with_change_memo(
    st: &mut State,
    payments: Vec<Payment>,
    memo: &MemoBytes,
) -> (
    zcash_client_backend::proposal::Proposal<StandardFeeRule, crate::ReceivedNoteId>,
    TxId,
) {
    let account = st.test_account().cloned().unwrap();
    let strategy = standard::SingleOutputChangeStrategy::<TestDb>::new(
        StandardFeeRule::Zip317,
        Some(memo.clone()),
        ShieldedPool::Ironwood,
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
    (proposal, created[0])
}

/// [`create_with_change_memo`], then mines and scans the transaction. Returns its
/// proposal, txid and height.
fn send_with_change_memo(
    st: &mut State,
    payments: Vec<Payment>,
    memo: &MemoBytes,
) -> (
    zcash_client_backend::proposal::Proposal<StandardFeeRule, crate::ReceivedNoteId>,
    TxId,
    BlockHeight,
) {
    let (proposal, txid) = create_with_change_memo(st, payments, memo);
    let (mined, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks(mined, 1);
    (proposal, txid, mined)
}

/// Runs refund memo recovery for `account` in its own transaction, returning the
/// number of unreadable funding records.
fn recover_memos(st: &mut State, account: AccountUuid) -> usize {
    st.wallet_mut()
        .db_mut()
        .transactionally(|db| db.recover_refund_memos(account))
        .unwrap()
}

/// `(index, scan_from, queued for a sweep)` of each registered refund key.
fn refund_keys(st: &State) -> Vec<(u64, u32, bool)> {
    st.wallet()
        .conn()
        .prepare(
            "SELECT k.key_index, k.scan_from,
                EXISTS(SELECT 1 FROM ironwood_swap_sweeps s WHERE s.receiving_key_id = k.id)
             FROM ironwood_receiving_keys k WHERE k.purpose = 0 ORDER BY k.key_index",
        )
        .unwrap()
        .query_map([], |r| {
            let index: Vec<u8> = r.get(0)?;
            Ok((
                u64::from_be_bytes(index.try_into().unwrap()),
                r.get(1)?,
                r.get(2)?,
            ))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn refund_funding_memo_recovers_from_seed_with_zero_change() {
    use zakura_swap_receiving::RefundMemo;
    let (mut st, first) = ironwood_funded_wallet();
    let network = *st.network();
    let account = st.test_account().cloned().unwrap();
    let deposit =
        Address::Transparent(TransparentAddress::PublicKeyHash([7; 20])).to_zcash_address(&network);
    let memo = RefundMemo::new(7);
    let memo_bytes = MemoBytes::from_bytes(&memo.encode()).unwrap();
    let (proposal, txid, mined) = send_with_change_memo(
        &mut st,
        vec![Payment::without_memo(
            deposit.clone(),
            Zatoshis::const_from_u64(985_000),
        )],
        &memo_bytes,
    );
    let change = proposal.steps()[0].balance().proposed_change();
    assert_eq!(change.len(), 1);
    assert_eq!(change[0].value(), Zatoshis::ZERO);
    assert_eq!(change[0].memo(), Some(&memo_bytes));
    let tx = st.wallet().get_transaction(txid).unwrap().unwrap();

    // Replace the wallet with a seed restore. No reservations or sent-transaction
    // records survive, so recovery must authenticate chain inputs and the memo.
    let seed = SecretVec::new(st.test_seed().unwrap().expose_secret().clone());
    let _old_wallet = st.reset();
    let (restored, _) = st
        .wallet_mut()
        .create_account("restored", &seed, account.birthday(), None)
        .unwrap();
    st.wallet_mut().update_chain_tip(mined).unwrap();
    st.scan_cached_blocks(first, (u32::from(mined) - u32::from(first) + 1) as usize);
    let pending = |st: &State| {
        st.wallet()
            .db()
            .swap_refund_memos_pending(restored)
            .unwrap()
    };
    // Compact scanning stores the change without its memo.
    assert_eq!(recover_memos(&mut st, restored), 0);
    assert!(refund_keys(&st).is_empty());
    assert!(pending(&st));
    decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, Some(mined)).unwrap();

    // Changing the authenticated scope, or losing own-send evidence, makes the memo
    // ineligible. A marker still waiting for its evidence holds back refund issuance.
    let set_scope = |st: &State, scope: u8| {
        st.wallet()
            .conn()
            .execute(
                "UPDATE ironwood_received_notes SET recipient_key_scope = ?1 WHERE memo = ?2",
                rusqlite::params![scope, memo_bytes.as_slice()],
            )
            .unwrap();
    };
    set_scope(&st, 0);
    assert_eq!(recover_memos(&mut st, restored), 0);
    assert!(refund_keys(&st).is_empty());
    set_scope(&st, 1);
    let spends: Vec<(i64, i64)> = st
        .wallet()
        .conn()
        .prepare(
            "SELECT ironwood_received_note_id,transaction_id FROM ironwood_received_note_spends",
        )
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    st.wallet()
        .conn()
        .execute("DELETE FROM ironwood_received_note_spends", [])
        .unwrap();
    // Without own-send evidence, though scanning covers the funding block, the inputs
    // predate the birthday or the record is not this wallet's. It no longer holds back
    // issuance: its key is swept without advancing allocation, which skips its index.
    let swap_memo = |st: &State, from: &[u8], to: &[u8]| {
        st.wallet()
            .conn()
            .execute(
                "UPDATE ironwood_received_notes SET memo = ?2 WHERE memo = ?1",
                rusqlite::params![from, to],
            )
            .unwrap();
    };
    let unauthenticated = RefundMemo::new(0).encode();
    swap_memo(&st, memo_bytes.as_slice(), unauthenticated.as_slice());
    assert_eq!(recover_memos(&mut st, restored), 0);
    assert_eq!(refund_keys(&st), vec![(0, u32::from(mined), true)]);
    assert!(!pending(&st));
    let next = st
        .wallet_mut()
        .db_mut()
        .reserve_swap_refund_key(restored, mined)
        .unwrap()
        .key_id();
    assert_eq!(next, KeyId::new(Purpose::Refund, 1));
    swap_memo(&st, unauthenticated.as_slice(), memo_bytes.as_slice());
    st.wallet()
        .conn()
        .execute("DELETE FROM ironwood_receiving_keys", [])
        .unwrap();
    for (note, transaction) in spends {
        st.wallet()
            .conn()
            .execute(
                "INSERT INTO ironwood_received_note_spends VALUES(?1,?2)",
                rusqlite::params![note, transaction],
            )
            .unwrap();
    }

    // Unsupported data is counted without failing recovery.
    let mut invalid = memo.encode();
    invalid[5] = 0xff;
    let replace_memo = |st: &State, from: &[u8], to: &[u8]| {
        st.wallet()
            .conn()
            .execute(
                "UPDATE ironwood_received_notes SET memo = ?2 WHERE memo = ?1",
                rusqlite::params![from, to],
            )
            .unwrap();
    };
    replace_memo(&st, memo_bytes.as_slice(), invalid.as_slice());
    assert_eq!(recover_memos(&mut st, restored), 1);
    assert!(refund_keys(&st).is_empty());
    replace_memo(&st, invalid.as_slice(), memo_bytes.as_slice());

    // A failed enclosing transaction leaves the registration for a retry.
    let aborted: Result<(), Error> = st.wallet_mut().db_mut().transactionally(|db| {
        db.recover_refund_memos(restored)?;
        Err(corrupt("test rollback"))
    });
    assert!(aborted.is_err());
    assert!(refund_keys(&st).is_empty());

    // The wallet never scanned this key, so its history comes from a receiver-directory
    // sweep rather than trial decryption.
    assert_eq!(recover_memos(&mut st, restored), 0);
    let registered = vec![(7, u32::from(mined), true)];
    assert_eq!(refund_keys(&st), registered);
    assert!(!pending(&st));
    assert!(
        st.wallet()
            .db()
            .get_swap_scanning_keys()
            .unwrap()
            .is_empty()
    );
    assert!(
        st.wallet()
            .db()
            .swap_history_pending(restored, mined)
            .unwrap()
    );

    // A restored refund key makes no provider lookups. Like a restored incoming key, it
    // is watched for a day from its registration.
    let (registered_at, operations): (i64, i64) = st
        .wallet()
        .conn()
        .query_row(
            "SELECT k.registered_at, (SELECT COUNT(*) FROM ironwood_swap_operations o
                WHERE o.receiving_key_id = k.id)
             FROM ironwood_receiving_keys k WHERE k.purpose = 0",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((registered_at, operations), (unix_now(&test_clock()), 0));

    // Repeated recovery, including after identical re-enhancement, changes nothing,
    // and it widens a key that starts after its funding block.
    decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, Some(mined)).unwrap();
    assert_eq!(recover_memos(&mut st, restored), 0);
    assert_eq!(refund_keys(&st), registered);
    st.wallet()
        .conn()
        .execute(
            "UPDATE ironwood_receiving_keys SET scan_from = scan_from + 1",
            [],
        )
        .unwrap();
    assert_eq!(recover_memos(&mut st, restored), 0);
    assert_eq!(refund_keys(&st), registered);
}

/// A refund key starts scanning when its funding transaction is stored, above the
/// scanned chain, and the funded quote then waits for the swap's outcome. An unfunded
/// quote never starts its key or holds a started one open.
#[test]
fn a_refund_key_starts_scanning_when_its_funding_transaction_is_stored() {
    use zakura_swap_receiving::{
        RefundMemo,
        lifecycle::{OperationStatus::Terminal, ReceiptExpectation},
    };
    let (mut st, _) = ironwood_funded_wallet();
    let account = st.test_account().unwrap().id();
    let network = *st.network();
    let tip = st.wallet().chain_height().unwrap().unwrap();
    let now = unix_now(&test_clock());
    let transparent = |byte| Address::Transparent(TransparentAddress::PublicKeyHash([byte; 20]));
    let deposit = transparent(7);
    let funded = deposit.encode(&network);
    let stale = transparent(8).encode(&network);
    let never = transparent(9).encode(&network);
    let active_from = |conn: &Connection, key: KeyId| -> Option<u32> {
        conn.query_row(
            "SELECT active_from FROM ironwood_receiving_keys
             WHERE purpose = 0 AND key_index = ?1",
            [key.index().to_be_bytes()],
            |r| r.get(0),
        )
        .unwrap()
    };
    let db = st.wallet_mut().db_mut();
    let unfunded = db.reserve_swap_refund_key(account, tip).unwrap().key_id();
    let key = db.reserve_swap_refund_key(account, tip).unwrap().key_id();
    db.record_swap_refund_quote(account, unfunded.index(), &never, now + 3_600, now)
        .unwrap();
    assert!(db.swap_funding_memo(account, key.index(), &funded).is_err());
    for deposit in [&stale, &funded] {
        db.record_swap_refund_quote(account, key.index(), deposit, now + 3_600, now)
            .unwrap();
    }
    assert_eq!(active_from(&db.conn, unfunded), None);
    assert_eq!(active_from(&db.conn, key), None);
    let memo = db.swap_funding_memo(account, key.index(), &funded).unwrap();
    let (proposal, txid) = create_with_change_memo(
        &mut st,
        vec![Payment::without_memo(
            deposit.to_zcash_address(&network),
            Zatoshis::const_from_u64(100_000),
        )],
        &memo,
    );
    verify_swap_funding_proposal(&proposal, &memo, &funded).unwrap();
    assert!(verify_swap_funding_proposal(&proposal, &memo, &stale).is_err());
    let other = MemoBytes::from_bytes(&RefundMemo::new(key.index() + 1).encode()).unwrap();
    assert!(verify_swap_funding_proposal(&proposal, &other, &funded).is_err());

    // Storing the funding transaction starts its key above the scanned chain, so no
    // block is rescanned, and opens the funded quote until the provider reports.
    let row = |conn: &Connection, deposit: &str| -> (i64, u8) {
        conn.query_row(
            "SELECT observed_at, expectation FROM ironwood_swap_operations
                 WHERE operation_id = ?1",
            [deposit],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
    };
    let conn = st.wallet().conn();
    assert_eq!(active_from(conn, key), Some(u32::from(tip) + 1));
    assert_eq!(active_from(conn, unfunded), None);
    assert_eq!(row(conn, &funded), (0, 0));
    assert_eq!(row(conn, &stale), (0, 1));

    let (mined, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks(mined, 1);
    // The key already scans from before its funding block, so recovery queues no sweep.
    assert_eq!(recover_memos(&mut st, account), 0);
    let db = st.wallet_mut().db_mut();
    assert!(!db.swap_history_pending(account, mined).unwrap());
    assert_eq!(
        db.close_finished_swap_keys_at(account, now, mined).unwrap(),
        0
    );
    let finished = now + 7_200;
    db.observe_swap_operation(
        account,
        key,
        &funded,
        Terminal(ReceiptExpectation::None),
        finished,
    )
    .unwrap();
    // The swap is over; the stale quote does not hold the key open.
    assert_eq!(
        db.close_finished_swap_keys_at(account, finished, mined)
            .unwrap(),
        1
    );
    assert_eq!(active_from(&db.conn, unfunded), None);
}

#[test]
fn reissued_refund_key_sweeps_history_before_its_scan_start() {
    use zakura_swap_receiving::RefundMemo;
    let (mut st, _) = ironwood_funded_wallet();
    let account = st.test_account().unwrap().id();
    let network = *st.network();
    let memo = MemoBytes::from_bytes(&RefundMemo::new(0).encode()).unwrap();
    let deposit = Address::Transparent(TransparentAddress::PublicKeyHash([7; 20]));
    let (_, _, mined) = send_with_change_memo(
        &mut st,
        vec![Payment::without_memo(
            deposit.to_zcash_address(&network),
            Zatoshis::const_from_u64(100_000),
        )],
        &memo,
    );
    // A restored wallet can issue the memo's index again before recovering the memo.
    let db = st.wallet_mut().db_mut();
    let key = db
        .reserve_swap_receiving_key_from(account, Purpose::Refund, mined + 1)
        .unwrap();
    assert_eq!(key.key_id().index(), 0);
    assert_eq!(recover_memos(&mut st, account), 0);
    assert_eq!(refund_keys(&st), [(0, u32::from(mined), true)]);
    assert!(
        st.wallet()
            .db()
            .swap_history_pending(account, mined)
            .unwrap()
    );
}

#[test]
fn refund_memos_restore_keys_whatever_the_funding_outputs() {
    use zakura_swap_receiving::RefundMemo;
    let memo = MemoBytes::from_bytes(&RefundMemo::new(7).encode()).unwrap();
    let transparent = |byte| Address::Transparent(TransparentAddress::PublicKeyHash([byte; 20]));
    let receiver = orchard::keys::FullViewingKey::from(
        &orchard::keys::SpendingKey::from_bytes([0xf5; 32]).unwrap(),
    )
    .address_at(0u32, Scope::External);
    let shielded =
        Address::Unified(UnifiedAddress::from_receivers(Some(receiver), None, None).unwrap());
    let payment = |address: &Address, network: &LocalNetwork| {
        Payment::without_memo(
            address.to_zcash_address(network),
            Zatoshis::const_from_u64(100_000),
        )
    };

    for recipients in [vec![shielded], vec![transparent(7), transparent(8)]] {
        let (mut st, _) = ironwood_funded_wallet();
        let account = st.test_account().unwrap().id();
        let network = *st.network();
        let payments = recipients.iter().map(|a| payment(a, &network)).collect();
        let (_, _, mined) = send_with_change_memo(&mut st, payments, &memo);
        assert_eq!(recover_memos(&mut st, account), 0);
        assert_eq!(refund_keys(&st), [(7, u32::from(mined), true)]);
        assert!(!st.wallet().db().swap_refund_memos_pending(account).unwrap());
    }
}

/// A refund record retrieved over Enhance PIR restores its key from the memo alone.
/// A funding transaction flagged as having transparent outputs takes the public path
/// for its history first, as any such transaction does.
#[test]
fn refund_memo_over_pir_restores_its_key_without_the_raw_transaction() {
    use zakura_swap_receiving::RefundMemo;
    use zcash_client_backend::data_api::enhance_pir::{
        EnhancePirRead, EnhancePirWork, EnhancePirWrite, EnhanceRecord, EnhanceRecordParts,
        EnhanceTransactionMetadata, EnhancementMode, TransactionEnhancementWork,
    };

    for (version, flagged) in [(1, true), (1, false), (2, false)] {
        let (mut st, first) = ironwood_funded_wallet();
        let network = *st.network();
        let account = st.test_account().cloned().unwrap();
        let deposit = Address::Transparent(TransparentAddress::PublicKeyHash([7; 20]))
            .to_zcash_address(&network);
        let mut record = RefundMemo::new(7).encode();
        record[5] = version;
        let memo = MemoBytes::from_bytes(&record).unwrap();
        let (_, txid, mined) = send_with_change_memo(
            &mut st,
            vec![Payment::without_memo(
                deposit.clone(),
                Zatoshis::const_from_u64(985_000),
            )],
            &memo,
        );
        let tx = st.wallet().get_transaction(txid).unwrap().unwrap();
        let fee: u64 = st
            .wallet()
            .conn()
            .query_row(
                "SELECT fee FROM transactions WHERE txid=?1",
                [txid.as_ref()],
                |r| r.get(0),
            )
            .unwrap();

        // Restore privately. Compact blocks carry no transparent data.
        let seed = SecretVec::new(st.test_seed().unwrap().expose_secret().clone());
        let _old_wallet = st.reset();
        let (restored, _) = st
            .wallet_mut()
            .create_account("restored", &seed, account.birthday(), None)
            .unwrap();
        st.wallet_mut()
            .db_mut()
            .set_enhancement_mode(EnhancementMode::PrivateIronwood);
        st.wallet_mut().update_chain_tip(mined).unwrap();
        st.scan_cached_blocks(first, (u32::from(mined) - u32::from(first) + 1) as usize);

        let requests: Vec<_> = st
            .wallet()
            .db()
            .transaction_enhancement_work()
            .unwrap()
            .into_iter()
            .filter_map(|work| match work {
                TransactionEnhancementWork::Private(EnhancePirWork::Query(r))
                    if r.request_id().txid() == txid =>
                {
                    Some(r)
                }
                _ => None,
            })
            .collect();
        assert!(!requests.is_empty());

        // Genuine ciphertexts; only the server's transparent flag varies.
        let bundle = tx.ironwood_bundle().unwrap();
        let metadata =
            EnhanceTransactionMetadata::new(u32::from(tx.expiry_height()), Some(fee)).unwrap();
        let batch: Vec<_> = requests
            .iter()
            .map(|r| {
                let action = &bundle.actions()[r.request_id().output_index() as usize];
                let note = action.encrypted_note();
                (
                    *r,
                    EnhanceRecord::from_parts(EnhanceRecordParts {
                        enc_ciphertext_suffix: note.enc_ciphertext[52..].try_into().unwrap(),
                        cv_net: action.cv_net().to_bytes(),
                        out_ciphertext: note.out_ciphertext,
                        has_transparent_inputs: false,
                        has_transparent_outputs: flagged,
                        metadata,
                    }),
                )
            })
            .collect();
        st.wallet_mut()
            .db_mut()
            .apply_ironwood_enhance_records(&batch)
            .unwrap();

        let memo_stored: bool = st
            .wallet()
            .conn()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM ironwood_received_notes n
                 JOIN transactions t ON t.id_tx = n.transaction_id
                 WHERE t.txid = ?1 AND n.memo IS NOT NULL)",
                [txid.as_ref()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(memo_stored, !flagged, "version={version} flagged={flagged}");
        if flagged {
            assert!(
                st.wallet()
                    .db()
                    .transaction_enhancement_work()
                    .unwrap()
                    .iter()
                    .any(
                        |w| matches!(w, TransactionEnhancementWork::Public(p) if p.txid() == txid)
                    ),
                "version={version}"
            );
            decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, Some(mined)).unwrap();
        }
        let unreadable = recover_memos(&mut st, restored);
        if version == 1 {
            assert_eq!(unreadable, 0);
            assert_eq!(refund_keys(&st), [(7, u32::from(mined), true)]);
        } else {
            // A newer record cannot be read here. It may hold a refund index, so
            // refund issuance waits for an upgrade instead of failing sync.
            assert_eq!(unreadable, 1);
            assert!(refund_keys(&st).is_empty());
            assert!(matches!(
                st.wallet_mut()
                    .db_mut()
                    .reserve_swap_refund_key(restored, mined),
                Err(Error::ReservationPolicy(ReservationPolicy::Unreadable))
            ));
        }
    }
}

#[test]
fn missing_funding_memos_block_refund_issuance() {
    let (mut st, _) = ironwood_funded_wallet();
    let account = st.test_account().unwrap().id();
    let network = *st.network();
    let tip = st.wallet().chain_height().unwrap().unwrap();
    let now = unix_now(&test_clock());
    let deposit = Address::Transparent(TransparentAddress::PublicKeyHash([7; 20]));
    let encoded = deposit.encode(&network);
    let db = st.wallet_mut().db_mut();
    let key = db.reserve_swap_refund_key(account, tip).unwrap().key_id();
    db.record_swap_refund_quote(account, key.index(), &encoded, now + 3_600, now)
        .unwrap();
    let memo = db
        .swap_funding_memo(account, key.index(), &encoded)
        .unwrap();
    let (_, _, mined) = send_with_change_memo(
        &mut st,
        vec![Payment::without_memo(
            deposit.to_zcash_address(&network),
            Zatoshis::const_from_u64(100_000),
        )],
        &memo,
    );
    // A restored wallet's compact scan stores the change before enhancement
    // retrieves its memo.
    let (note, stored): (i64, Vec<u8>) = st
        .wallet()
        .conn()
        .query_row(
            "SELECT id, memo FROM ironwood_received_notes
             WHERE recipient_key_scope = 1 AND substr(memo, 1, 5) = X'FF5A535750'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let set_memo = |st: &mut TestState<_, TestDb, _>, memo: Option<&[u8]>| {
        st.wallet()
            .conn()
            .execute(
                "UPDATE ironwood_received_notes SET memo = ?2 WHERE id = ?1",
                rusqlite::params![note, memo],
            )
            .unwrap();
    };
    set_memo(&mut st, None);
    assert!(matches!(
        st.wallet_mut()
            .db_mut()
            .reserve_swap_refund_key(account, mined),
        Err(Error::ReservationPolicy(ReservationPolicy::Coverage))
    ));
    // Issuance recovers the memo first, so it never reissues the funded index.
    set_memo(&mut st, Some(&stored));
    assert_eq!(
        st.wallet_mut()
            .db_mut()
            .reserve_swap_refund_key(account, mined)
            .unwrap()
            .key_id(),
        KeyId::new(Purpose::Refund, key.index() + 1)
    );
}

/// A quote binds to a refund key reserved here that is still open; the key need not
/// scan yet, since only its funding transaction starts it.
#[test]
fn refund_quote_needs_an_open_reserved_refund_key_and_a_canonical_transparent_deposit() {
    let (mut st, _) = ironwood_funded_wallet();
    let account = st.test_account().unwrap().id();
    let network = *st.network();
    let tip = st.wallet().chain_height().unwrap().unwrap();
    let now = unix_now(&test_clock());
    let p2pkh = Address::Transparent(TransparentAddress::PublicKeyHash([7; 20])).encode(&network);
    let parent = FullViewingKey::from(st.test_account().unwrap().usk().orchard());
    let unified = Address::Unified(
        UnifiedAddress::from_receivers(Some(parent.address_at(0u32, Scope::External)), None, None)
            .unwrap(),
    )
    .encode(&network);
    let mainnet = Address::Transparent(TransparentAddress::PublicKeyHash([7; 20]))
        .encode(&zcash_protocol::consensus::MainNetwork);
    let tex = Address::Tex([7; 20]).encode(&network);
    let db = st.wallet_mut().db_mut();
    assert!(
        db.record_swap_refund_quote(account, 0, &p2pkh, now + 60, now)
            .is_err()
    );
    for _ in 0..2 {
        db.reserve_swap_refund_key(account, tip).unwrap();
    }
    let padded = format!(" {p2pkh}");
    for bad in [&unified, &tex, &mainnet, &padded] {
        assert!(
            db.record_swap_refund_quote(account, 0, bad, now + 60, now)
                .is_err()
        );
    }
    assert!(
        db.record_swap_refund_quote(account, 0, &p2pkh, now, now)
            .is_err()
    );
    for _ in 0..2 {
        db.record_swap_refund_quote(account, 0, &p2pkh, now + 60, now)
            .unwrap();
    }
    assert!(
        db.record_swap_refund_quote(account, 1, &p2pkh, now + 60, now)
            .is_err()
    );
    assert!(db.swap_funding_memo(account, 0, &p2pkh).is_ok());
    // A closed key would miss the refund.
    db.conn
        .execute(
            "UPDATE ironwood_receiving_keys SET closed_at = ?1 WHERE purpose = 0",
            [now],
        )
        .unwrap();
    assert!(db.swap_funding_memo(account, 0, &p2pkh).is_err());
}
