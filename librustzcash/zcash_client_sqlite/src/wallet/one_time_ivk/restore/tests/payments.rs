use super::*;
use orchard::{
    note::{NoteVersion, RandomSeed, Rho},
    value::NoteValue,
};
use zcash_primitives::transaction::TxId;

/// A candidate claiming an authentic 30,000-zatoshi note to `key` at `height`, in a
/// transaction `[8; 32]` that no block holds.
fn claim(st: &State, key: &OneTimeKey, height: BlockHeight) -> PendingPayment {
    let rho = Rho::from_bytes(&[9; 32]).unwrap();
    let rseed = RandomSeed::from_bytes([7; 32], &rho).unwrap();
    let value = NoteValue::from_raw(30_000);
    let note = Note::from_parts(key.receiver(), value, rho, rseed, NoteVersion::V3).unwrap();
    PendingPayment {
        txid: TxId::from_bytes([8; 32]),
        action_index: 0,
        height,
        block_hash: st.wallet().get_block_hash(height).unwrap().unwrap(),
        tx_index: 1,
        position: 0,
        encrypted_note: encrypt_note(note),
    }
}

/// Queuing a candidate authenticates its note and block (an authentic ciphertext alone is
/// not evidence that its note is on chain), is idempotent, refuses a conflicting claim,
/// and rolls back with its transaction. A queued candidate survives a reopen without
/// crediting the note or advancing allocation, and one whose block is rewound is dropped.
#[test]
fn directory_payment_queue_authenticates_retries_and_survives_reopen_without_credit() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let key = watch(st.wallet_mut().db_mut(), account, 0, start());
    let id = key.key_id();
    let (height, _) = st.generate_empty_block();
    st.scan_cached_blocks_with_one_time_ivks(height, 1);
    let candidate = claim(&st, &key, height);
    let mut bytes = *candidate.encrypted_note.to_bytes();
    bytes[147] ^= 1;
    let tampered = PendingPayment {
        encrypted_note: EncryptedNote::from_bytes(bytes),
        ..candidate.clone()
    };
    let db = st.wallet_mut().db_mut();
    assert!(queue_payment(db, account, id, &tampered).is_err());
    assert!(pending(db, account, id).is_empty());
    queue_payment(db, account, id, &candidate).unwrap();
    queue_payment(db, account, id, &candidate).unwrap();
    let conflict = PendingPayment {
        position: 1,
        ..candidate.clone()
    };
    let wrong_block = PendingPayment {
        block_hash: BlockHash([99; 32]),
        ..candidate.clone()
    };
    for bad in [conflict, wrong_block] {
        assert!(queue_payment(db, account, id, &bad).is_err());
    }
    let rollback: Result<(), SqliteClientError> = db.transactionally_with_extension(|db, _| {
        let second = PendingPayment {
            txid: TxId::from_bytes([10; 32]),
            ..candidate.clone()
        };
        store::restore::payments::queue_payment(db.conn.0, db.params, account, id, &second)?;
        Err(corrupt("rollback fixture"))
    });
    assert!(rollback.is_err());
    reopen(&mut st);
    assert!(pending(st.wallet().db(), account, id) == [candidate.clone()]);
    assert!(!key_state(st.wallet().db(), id).1);
    let sql = "SELECT COUNT(*) FROM ironwood_received_notes";
    assert_eq!(value::<u64>(st.wallet().conn(), sql, []), 0);

    let (orphan_height, _) = st.generate_empty_block();
    st.scan_cached_blocks_with_one_time_ivks(orphan_height, 1);
    let orphan = PendingPayment {
        txid: TxId::from_bytes([12; 32]),
        ..claim(&st, &key, orphan_height)
    };
    queue_payment(st.wallet_mut().db_mut(), account, id, &orphan).unwrap();
    st.truncate_to_height_retaining_cache(height);
    assert!(pending(st.wallet().db(), account, id) == [candidate]);
    assert_eq!(all_keys(st.wallet().db(), account).unwrap().len(), 1);
}

/// A candidate's absence of a spend is known only from nullifiers retained contiguously
/// through the anchor: it is unspent with full coverage, unknown once they are pruned or
/// their blocks rewound (dropping the coverage), spent when the nullifier map holds its
/// spend, and deferred at an anchor off the chain. Checking spentness imports no note.
#[test]
fn directory_payment_absence_requires_retained_contiguous_nullifiers() {
    use zcash_client_backend::data_api::ll::LowLevelWalletWrite;
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let key = reserve_key(st.wallet_mut().db_mut(), account, Purpose::Refund, start());
    let id = key.key_id();
    let (first, _) = st.generate_empty_block();
    let (last, _) = st.generate_empty_block();
    st.scan_cached_blocks_with_one_time_ivks(first, 2);
    let candidate = claim(&st, &key, first);
    let through = tip(&st);
    let status = |st: &mut State, through: ChainPoint| {
        spend_status(st.wallet_mut().db_mut(), account, id, &candidate, through)
    };
    assert_eq!(status(&mut st, through), Ok(SpendStatus::Unspent));
    let db = st.wallet_mut().db_mut();
    let pruned = db.transactionally_with_extension(|db, _| db.prune_tracked_nullifiers(0));
    pruned.unwrap();
    assert_eq!(status(&mut st, through), Ok(SpendStatus::Unknown));

    let recovered = candidate.encrypted_note.decrypt(&parent(&st), id).unwrap();
    let (nf, spend_txid) = (recovered.nullifier().to_bytes(), TxId::from_bytes([11; 32]));
    let spends = [(1u16.into(), spend_txid, vec![nf])];
    let tx = st.wallet_mut().conn_mut().transaction().unwrap();
    let ironwood = zcash_protocol::ShieldedPool::Ironwood;
    crate::wallet::insert_nullifier_map(&tx, last, ironwood, &spends).unwrap();
    tx.commit().unwrap();
    assert_eq!(status(&mut st, through), Ok(SpendStatus::Spent(spend_txid)));
    let mut wrong = through;
    wrong.hash.0[0] ^= 1;
    assert_eq!(status(&mut st, wrong), Err(SweepDeferral::UnknownAnchor));

    st.truncate_to_height_retaining_cache(first);
    assert_eq!(status(&mut st, through), Ok(SpendStatus::Unknown));
    let sql = "SELECT COUNT(*) FROM ironwood_nullifier_scan_blocks WHERE height > ?1";
    assert_eq!(value::<u64>(st.wallet().conn(), sql, [u32::from(first)]), 0);
    let sql = "SELECT COUNT(*) FROM ironwood_received_notes";
    assert_eq!(value::<u64>(st.wallet().conn(), sql, []), 0);
}
