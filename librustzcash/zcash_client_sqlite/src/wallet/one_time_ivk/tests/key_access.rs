use super::*;
use rusqlite::params;
use zcash_primitives::transaction::TxId;

/// Looking a key up derives and checks only that key, against its stored receiver and
/// the parent of its own account, and registration never replaces a corrupted receiver.
#[test]
fn key_lookups_validate_only_the_requested_key() {
    let mut st = wallet(false);
    let account = st.test_account().unwrap().id();
    let parent = parent(&st);
    let db = st.wallet_mut().db_mut();
    let wanted = reserve_key(db, account, Purpose::Refund, start());
    let corrupted = watch(db, account, 0, start()).key_id();
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
    let sql = "UPDATE ironwood_receiving_keys SET receiver = zeroblob(43) WHERE purpose = 1";
    exec(&db.conn, sql, []);
    for found in [
        get_key(db, account, wanted.key_id()).unwrap().unwrap(),
        db.get_one_time_key_for_receiver(account, &wanted.receiver())
            .unwrap()
            .unwrap(),
    ] {
        assert_eq!(found.key_id(), wanted.key_id());
        assert_eq!(
            found.full_viewing_key().to_bytes(),
            wanted.full_viewing_key().to_bytes()
        );
    }
    let absent = KeyId::new(Purpose::Refund, 10_001);
    assert!(get_key(db, account, absent).unwrap().is_none());
    assert!(get_key(db, account, KeyId::new(Purpose::Refund, 1)).is_err());
    assert!(matches!(
        all_keys(db, account),
        Err(SqliteClientError::CorruptedData(_))
    ));
    // Repeated recovery neither replaces the corrupted receiver nor promotes its key.
    let registered = tx(db, |c, p| {
        register(c, p, account, corrupted, start(), true, Discovery::Sweep, 0)
    });
    assert!(matches!(
        registered,
        Err(SqliteClientError::CorruptedData(_))
    ));
    assert!(!key_state(db, corrupted).1);

    // A note's key is re-derived only from its own account's parent.
    let id = key_ref(&db.conn, account, wanted.key_id()).unwrap();
    assert_eq!(note_key(&db.conn, id, &parent).unwrap().0, wanted.key_id());
    let other = FullViewingKey::from(&orchard::keys::SpendingKey::from_bytes([9; 32]).unwrap());
    assert!(note_key(&db.conn, id, &other).is_err());
    // Selecting an existing receiver must still validate the stored key identity.
    exec(
        &db.conn,
        "UPDATE ironwood_receiving_keys SET key_index=?1 WHERE account_id=?2 AND key_index=?3",
        params![20_000u64.to_be_bytes(), account_ref.0, 0u64.to_be_bytes()],
    );
    let found = db.get_one_time_key_for_receiver(account, &wanted.receiver());
    assert!(found.is_err());
    assert!(note_key(&db.conn, id, &parent).is_err());
}

#[test]
fn transaction_keys_exclude_unscanned_history_and_preserve_self_payments() {
    let mut st = wallet(false);
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    let historical = recover(db, account, KeyId::new(Purpose::Refund, 70), start());
    let active = reserve_key(db, account, Purpose::Refund, start());
    let txid = TxId::from_bytes([17; 32]);
    let keys = db
        .get_one_time_transaction_keys(txid, Some(start()), &[])
        .unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].key_id(), active.key_id());
    // An ordinary OVK can identify a self-payment before compact scanning, even
    // when the receiving key was recovered without being scanned.
    let keys = db
        .get_one_time_transaction_keys(txid, None, &[historical.receiver()])
        .unwrap();
    assert_eq!(keys.len(), 2);
    assert!(keys.iter().any(|k| k.key_id() == historical.key_id()));
    // A closed key stops being tried on unrelated transactions.
    let sql =
        "UPDATE ironwood_receiving_keys SET closed_at = 1 WHERE purpose = 0 AND key_index = ?1";
    exec(&db.conn, sql, [active.key_id().index().to_be_bytes()]);
    let keys = db.get_one_time_transaction_keys(txid, Some(start()), &[]);
    assert!(keys.unwrap().is_empty());
}

#[test]
fn unscanned_transaction_keys_follow_pending_and_imported_output_identity() {
    let (mut st, key, candidate, through, path) = store::restore::tests::apply::fixture();
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    assert!(db.get_one_time_scanning_keys().unwrap().is_empty());
    let keys_for = |db: &Db, txid| {
        let keys = db.get_one_time_transaction_keys(txid, Some(through.height), &[]);
        keys.unwrap().iter().map(|k| k.key_id()).collect::<Vec<_>>()
    };
    assert_eq!(keys_for(db, candidate.txid), [key.key_id()]);
    assert!(keys_for(db, TxId::from_bytes([45; 32])).is_empty());
    apply(db, account, key.key_id(), &candidate, through, &path);
    assert!(pending(db, account, key.key_id()).is_empty());
    assert_eq!(keys_for(db, candidate.txid), [key.key_id()]);
}
