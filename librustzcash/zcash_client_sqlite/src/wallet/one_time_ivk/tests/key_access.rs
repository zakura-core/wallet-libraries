use super::*;
use rusqlite::params;

/// Looking a key up derives and checks only that key, against its stored receiver and
/// the parent of its own account, and registration never replaces a corrupted receiver.
#[test]
fn key_lookups_validate_only_the_requested_key() {
    let mut st = wallet(false);
    let account = st.test_account().unwrap().id();
    let parent = parent(&st);
    let db = st.wallet_mut().db_mut();
    let wanted = reserve_key(db, account, Purpose::Refund, start());
    let corrupted = KeyId::new(Purpose::Receive, 0);
    tx(db, |c, p| register(c, p, account, corrupted)).unwrap();
    let (account_ref, _) = account_key(db.conn.borrow(), &db.params, account).unwrap();

    // Synthetic metadata avoids 10,000 KDFs in the fixture. These invalid receivers
    // also make any accidental reconstruction of unrelated keys fail immediately.
    tx(db, |c, _| {
        let mut insert = c.prepare(
            "INSERT INTO ironwood_one_time_keys
            (account_id,purpose,key_index,receiver)
            VALUES(?1,0,?2,zeroblob(43))",
        )?;
        for index in 1u64..=10_000 {
            insert.execute(params![account_ref.0, index.to_be_bytes()])?;
        }
        Ok(())
    })
    .unwrap();
    let sql = "UPDATE ironwood_one_time_keys SET receiver = zeroblob(43) WHERE purpose = 1";
    exec(&db.conn, sql, []);
    for found in [
        get_key(db, account, wanted.key_id()).unwrap().unwrap(),
        key_for_receiver(db, account, &wanted.receiver())
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
    let registered = tx(db, |c, p| register(c, p, account, corrupted));
    assert!(matches!(
        registered,
        Err(SqliteClientError::CorruptedData(_))
    ));

    // A note's key is re-derived only from its own account's parent.
    let id = key_ref(&db.conn, account, wanted.key_id()).unwrap();
    assert_eq!(note_key(&db.conn, id, &parent).unwrap().0, wanted.key_id());
    let other = FullViewingKey::from(&orchard::keys::SpendingKey::from_bytes([9; 32]).unwrap());
    assert!(note_key(&db.conn, id, &other).is_err());
    // Selecting an existing receiver must still validate the stored key identity.
    exec(
        &db.conn,
        "UPDATE ironwood_one_time_keys SET key_index=?1 WHERE account_id=?2 AND key_index=?3",
        params![20_000u64.to_be_bytes(), account_ref.0, 0u64.to_be_bytes()],
    );
    let found = key_for_receiver(db, account, &wanted.receiver());
    assert!(found.is_err());
    assert!(note_key(&db.conn, id, &parent).is_err());
}
