use super::*;
use rusqlite::params;

#[test]
fn exact_key_access_ignores_unrelated_history_and_validates_the_requested_key() {
    let mut st = wallet(false);
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    let wanted = reserve_key(db, account, Purpose::Refund, start());
    let (account_ref, _) = account_key(db.conn.borrow(), &db.params, account).unwrap();

    // Synthetic metadata avoids 10,000 KDFs in the fixture. These invalid receivers
    // also make any accidental reconstruction of unrelated keys fail immediately.
    tx(db, |c, _| {
        let mut insert = c.prepare(
            "INSERT INTO ironwood_receiving_keys
            (account_id,purpose,key_index,receiver,scan_from,advances_allocation)
            VALUES(?1,0,?2,zeroblob(43),100,1)",
        )?;
        for index in 1u64..=10_000 {
            insert.execute(params![account_ref.0, index.to_be_bytes()])?;
        }
        Ok(())
    })
    .unwrap();
    for found in [
        get_key(db, account, wanted.key_id()).unwrap().unwrap(),
        db.get_dynamic_key_for_receiver(account, &wanted.receiver())
            .unwrap()
            .unwrap(),
    ] {
        assert_eq!(found.key_id(), wanted.key_id());
        assert_eq!(
            found.full_viewing_key().to_bytes(),
            wanted.full_viewing_key().to_bytes()
        );
    }
    assert!(
        get_key(db, account, KeyId::new(Purpose::Receive, 0))
            .unwrap()
            .is_none()
    );
    assert!(
        get_key(db, account, KeyId::new(Purpose::Refund, 10_001))
            .unwrap()
            .is_none()
    );
    assert!(get_key(db, account, KeyId::new(Purpose::Refund, 1)).is_err());
    assert!(all_keys(db, account).is_err());

    // Selecting an existing receiver must still validate the stored key identity.
    db.conn
        .borrow()
        .execute(
            "UPDATE ironwood_receiving_keys SET key_index=?1
        WHERE account_id=?2 AND key_index=?3",
            params![20_000u64.to_be_bytes(), account_ref.0, 0u64.to_be_bytes()],
        )
        .unwrap();
    assert!(
        db.get_dynamic_key_for_receiver(account, &wanted.receiver())
            .is_err()
    );
}

#[test]
fn exact_key_access_keeps_accounts_and_reservations_separate() {
    let mut st = wallet(false);
    let account = st.test_account().unwrap().id();
    let seed = SecretVec::new(st.test_seed().unwrap().expose_secret().clone());
    let birthday = st.test_account().unwrap().birthday().clone();
    let db = st.wallet_mut().db_mut();
    let reservation = prepare_from(db, account, 1_000_000, 100_000.into(), None)
        .unwrap()
        .unwrap();
    let (other, _) = db.create_account("other", &seed, &birthday, None).unwrap();
    assert!(get_key(db, other, reservation.key_id()).unwrap().is_none());
    assert!(
        db.get_dynamic_key_for_receiver(other, &reservation.receiver())
            .unwrap()
            .is_none()
    );
    let unrelated = reserve_key(db, account, Purpose::Refund, start());
    db.conn
        .borrow()
        .execute(
            "UPDATE ironwood_receiving_keys SET receiver=zeroblob(43)
        WHERE purpose=0 AND key_index=?1",
            [unrelated.key_id().index().to_be_bytes()],
        )
        .unwrap();
    let found = get_key(db, account, reservation.key_id()).unwrap().unwrap();
    assert_eq!(found.key_id(), reservation.key_id());
    assert_eq!(found.receiver(), reservation.receiver());
}

#[test]
fn transaction_keys_exclude_unscanned_history_and_preserve_self_payments() {
    use zcash_primitives::transaction::TxId;
    let mut st = wallet(false);
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    let historical = recover(db, account, KeyId::new(Purpose::Refund, 70), start());
    let active = reserve_key(db, account, Purpose::Refund, start());
    let txid = TxId::from_bytes([17; 32]);
    let keys = db
        .get_dynamic_transaction_keys(txid, Some(start()), &[])
        .unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].key_id(), active.key_id());
    // An ordinary OVK can identify a self-payment before compact scanning, even
    // when the receiving key was recovered without being scanned.
    let keys = db
        .get_dynamic_transaction_keys(txid, None, &[historical.receiver()])
        .unwrap();
    assert_eq!(keys.len(), 2);
    assert!(keys.iter().any(|k| k.key_id() == historical.key_id()));
    // A closed key stops being tried on unrelated transactions.
    db.conn
        .borrow()
        .execute(
            "UPDATE ironwood_receiving_keys SET closed_at = 1 WHERE purpose = 0 AND key_index = ?1",
            [active.key_id().index().to_be_bytes()],
        )
        .unwrap();
    assert!(
        db.get_dynamic_transaction_keys(txid, Some(start()), &[])
            .unwrap()
            .is_empty()
    );
}

#[test]
fn unscanned_transaction_keys_follow_pending_and_imported_output_identity() {
    let (mut st, key, candidate, through, path) = super::apply::fixture();
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    assert!(db.get_dynamic_scanning_keys().unwrap().is_empty());
    let known = db
        .get_dynamic_transaction_keys(candidate.txid, Some(through.height), &[])
        .unwrap();
    assert_eq!(known.len(), 1);
    assert_eq!(known[0].key_id(), key.key_id());
    assert!(
        db.get_dynamic_transaction_keys(
            zcash_primitives::transaction::TxId::from_bytes([45; 32]),
            Some(through.height),
            &[]
        )
        .unwrap()
        .is_empty()
    );
    apply_payment(
        db,
        account,
        key.key_id(),
        &candidate,
        through,
        (through, &path),
    )
    .unwrap();
    assert!(pending(db, account, key.key_id()).is_empty());
    let known = db
        .get_dynamic_transaction_keys(candidate.txid, Some(through.height), &[])
        .unwrap();
    assert_eq!(known.len(), 1);
    assert_eq!(known[0].key_id(), key.key_id());
}
