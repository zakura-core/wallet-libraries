use std::sync::{Arc, Barrier};

use secrecy::{ExposeSecret, SecretVec};
use zcash_client_backend::data_api::{
    WalletWrite,
    testing::{TestBuilder, TestState},
};
use zcash_primitives::block::BlockHash;
use zcash_protocol::local_consensus::LocalNetwork;

use crate::testing::db::{TestDb, TestDbFactory, test_clock, test_rng};

use super::*;

fn wallet(file_backed: bool) -> TestState<(), TestDb, LocalNetwork> {
    TestBuilder::new()
        .with_data_store_factory(if file_backed {
            TestDbFactory::file_backed()
        } else {
            TestDbFactory::default()
        })
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build()
}

fn start() -> BlockHeight {
    BlockHeight::from_u32(100)
}

#[test]
fn reservations_survive_reopen_and_keep_purposes_and_accounts_separate() {
    let mut st = wallet(true);
    let account = st.test_account().unwrap().id();
    let refund = st
        .wallet_mut()
        .db_mut()
        .reserve_swap_receiving_key(account, Purpose::Refund, start())
        .unwrap();
    let incoming = st
        .wallet_mut()
        .db_mut()
        .reserve_swap_receiving_key(account, Purpose::Receive, start())
        .unwrap();
    assert_eq!(refund.key_id(), KeyId::new(Purpose::Refund, 0));
    assert_eq!(incoming.key_id(), KeyId::new(Purpose::Receive, 0));
    assert_ne!(refund.receiver(), incoming.receiver());

    let path = st.wallet().data_file_path().to_owned();
    let network = *st.network();
    // Close the original connection while keeping the fixture's temporary file alive.
    drop(std::mem::replace(
        st.wallet_mut().conn_mut(),
        Connection::open_in_memory().unwrap(),
    ));
    let mut reopened = WalletDb::for_path(path, network, test_clock(), test_rng()).unwrap();
    let keys = reopened.get_swap_receiving_keys(account).unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(
        keys[0].full_viewing_key().to_bytes(),
        refund.full_viewing_key().to_bytes()
    );
    assert_eq!(keys[1].receiver(), incoming.receiver());
    assert_eq!(
        reopened
            .reserve_swap_receiving_key(account, Purpose::Refund, start())
            .unwrap()
            .key_id()
            .index(),
        1
    );

    let seed = SecretVec::new(st.test_seed().unwrap().expose_secret().clone());
    let birthday = st.test_account().unwrap().birthday().clone();
    let (other, _) = reopened
        .create_account("other", &seed, &birthday, None)
        .unwrap();
    let key = reopened
        .reserve_swap_receiving_key(other, Purpose::Refund, start())
        .unwrap();
    assert_eq!(key.key_id().index(), 0);
    assert_ne!(key.receiver(), refund.receiver());
}

#[test]
fn lookahead_does_not_skip_unissued_addresses_and_recovery_promotes_it() {
    let mut st = wallet(false);
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    for index in 0..20 {
        assert!(
            !db.watch_swap_receive_key(account, index, start())
                .unwrap()
                .advances_allocation()
        );
    }
    assert_eq!(
        db.reserve_swap_receiving_key(account, Purpose::Receive, start())
            .unwrap()
            .key_id()
            .index(),
        0
    );
    let key_id = KeyId::new(Purpose::Receive, 18);
    let recovered = db
        .recover_swap_receiving_key(account, key_id, 80.into())
        .unwrap();
    assert!(recovered.advances_allocation());
    let repeated = db.watch_swap_receive_key(account, 18, 120.into()).unwrap();
    assert!(repeated.advances_allocation());
    assert_eq!(repeated.scan_from(), BlockHeight::from_u32(80));
    assert_eq!(db.get_swap_receiving_keys(account).unwrap().len(), 20);
    assert_eq!(
        db.reserve_swap_receiving_key(account, Purpose::Receive, start())
            .unwrap()
            .key_id()
            .index(),
        19
    );
    assert_eq!(
        db.reserve_swap_receiving_key(account, Purpose::Refund, start())
            .unwrap()
            .key_id()
            .index(),
        0
    );
}

#[test]
fn recovered_indices_use_full_u64_order_and_never_wrap() {
    let mut st = wallet(false);
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    for index in [256, 1, i64::MAX as u64, u64::MAX - 1, 255] {
        db.recover_swap_receiving_key(account, KeyId::new(Purpose::Refund, index), start())
            .unwrap();
    }
    assert_eq!(
        db.reserve_swap_receiving_key(account, Purpose::Refund, start())
            .unwrap()
            .key_id()
            .index(),
        u64::MAX
    );
    assert!(matches!(
        db.reserve_swap_receiving_key(account, Purpose::Refund, start()),
        Err(Error::IndexExhausted)
    ));
    assert_eq!(db.get_swap_receiving_keys(account).unwrap().len(), 6);
}

#[test]
fn operation_and_reservation_commit_or_roll_back_together() {
    let mut st = wallet(false);
    let account = st.test_account().unwrap().id();
    st.wallet()
        .conn()
        .execute_batch("CREATE TABLE ext_swap_operations (key_index BLOB NOT NULL)")
        .unwrap();
    let db = st.wallet_mut().db_mut();
    let result = db.transactionally_with_extension(|tx, ext| {
        let key = tx.reserve_swap_receiving_key(account, Purpose::Refund, start())?;
        ext.execute(
            "INSERT INTO ext_swap_operations VALUES (?1)",
            [&key.key_id().index().to_le_bytes()],
        )?;
        Err::<(), Error>(corrupt("fixture operation write failed"))
    });
    assert!(result.is_err());
    assert!(db.get_swap_receiving_keys(account).unwrap().is_empty());
    let key = db
        .transactionally_with_extension(|tx, ext| {
            let key = tx.reserve_swap_receiving_key(account, Purpose::Refund, start())?;
            ext.execute(
                "INSERT INTO ext_swap_operations VALUES (?1)",
                [&key.key_id().index().to_le_bytes()],
            )?;
            Ok::<_, Error>(key)
        })
        .unwrap();
    assert_eq!(key.key_id().index(), 0);
    assert_eq!(
        st.wallet()
            .conn()
            .query_row::<u32, _, _>("SELECT COUNT(*) FROM ext_swap_operations", [], |r| r.get(0))
            .unwrap(),
        1
    );
}

#[test]
fn concurrent_connections_never_return_the_same_reservation() {
    let st = wallet(true);
    let account = st.test_account().unwrap().id();
    let barrier = Arc::new(Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let path = st.wallet().data_file_path().to_owned();
            let network = *st.network();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut db = WalletDb::for_path(path, network, test_clock(), test_rng()).unwrap();
                barrier.wait();
                for _ in 0..20 {
                    match db.reserve_swap_receiving_key(account, Purpose::Refund, start()) {
                        Ok(key) => return key.key_id().index(),
                        Err(Error::Wallet(SqliteClientError::DbError(
                            rusqlite::Error::SqliteFailure(e, _),
                        ))) if e.code == rusqlite::ErrorCode::DatabaseBusy => {
                            std::thread::sleep(std::time::Duration::from_millis(5));
                        }
                        Err(e) => panic!("unexpected allocation failure: {e}"),
                    }
                }
                panic!("reservation remained busy");
            })
        })
        .collect();
    let mut indices: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    indices.sort();
    assert_eq!(indices, [0, 1]);
}

#[test]
fn corrupted_receiver_is_not_replaced_or_silently_skipped() {
    let mut st = wallet(false);
    let account = st.test_account().unwrap().id();
    st.wallet_mut()
        .db_mut()
        .watch_swap_receive_key(account, 0, start())
        .unwrap();
    st.wallet()
        .conn()
        .execute(
            "UPDATE ironwood_receiving_keys SET receiver = zeroblob(43)",
            [],
        )
        .unwrap();
    assert!(matches!(
        st.wallet().db().get_swap_receiving_keys(account),
        Err(Error::Wallet(SqliteClientError::CorruptedData(_)))
    ));
    assert!(matches!(
        st.wallet_mut()
            .db_mut()
            .reserve_swap_receiving_key(account, Purpose::Receive, start()),
        Err(Error::Wallet(SqliteClientError::CorruptedData(_)))
    ));
    let allocated: bool = st
        .wallet()
        .conn()
        .query_row(
            "SELECT advances_allocation FROM ironwood_receiving_keys",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!allocated);
}

#[test]
fn account_deletion_cascades_and_unknown_accounts_cannot_reserve() {
    let mut st = wallet(false);
    let account = st.test_account().unwrap().id();
    st.wallet_mut()
        .db_mut()
        .reserve_swap_receiving_key(account, Purpose::Refund, start())
        .unwrap();
    st.wallet_mut().delete_account(account).unwrap();
    assert_eq!(
        st.wallet()
            .conn()
            .query_row::<u32, _, _>("SELECT COUNT(*) FROM ironwood_receiving_keys", [], |r| r
                .get(0))
            .unwrap(),
        0
    );
    assert!(matches!(
        st.wallet_mut()
            .db_mut()
            .reserve_swap_receiving_key(account, Purpose::Refund, start()),
        Err(Error::Wallet(SqliteClientError::AccountUnknown))
    ));
}
