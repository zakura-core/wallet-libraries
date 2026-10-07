use std::sync::{Arc, Barrier};

use incrementalmerkletree::Hashable;
use orchard::{
    note::Note,
    note_encryption::{CompactAction, IronwoodDomain, IronwoodNoteEncryption},
    tree::{MerkleHashOrchard, MerklePath},
};
use prost::Message;
use secrecy::{ExposeSecret, SecretVec};
use zakura_swap_receiving::recovery::EncryptedNote;
use zcash_client_backend::data_api::transparent_ledger::ChainPoint;
use zcash_client_backend::{
    data_api::{
        WalletRead, WalletWrite,
        testing::{AddressType, IronwoodFvk, TestBuilder, TestState},
    },
    proto::compact_formats::CompactBlock,
};
use zcash_note_encryption::{Domain, try_compact_note_decryption};
use zcash_primitives::block::BlockHash;
use zcash_protocol::{local_consensus::LocalNetwork, value::Zatoshis};

use crate::testing::db::{TestDb, TestDbFactory, test_clock, test_rng};

use super::*;

/// A test wallet with a block cache.
type State = TestState<crate::testing::BlockCache, TestDb, LocalNetwork>;

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

/// A file-backed wallet with a block cache and Ironwood active from its first block.
fn ironwood_wallet() -> State {
    let activation = BlockHeight::from_u32(100_000);
    TestBuilder::new()
        .with_network(LocalNetwork {
            nu6: Some(activation),
            nu6_1: Some(activation),
            nu6_2: Some(activation),
            nu6_3: Some(activation),
            ..TestBuilder::<(), ()>::DEFAULT_NETWORK
        })
        .with_data_store_factory(TestDbFactory::file_backed())
        .with_block_cache(crate::testing::BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build()
}

/// An Ironwood wallet scanned through one empty block, so it is at its tip.
fn scanned_wallet() -> State {
    let mut st = ironwood_wallet();
    st.generate_and_scan_empty_blocks(1);
    st
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
        .reserve_swap_receiving_key_from(account, Purpose::Refund, start())
        .unwrap();
    let incoming = st
        .wallet_mut()
        .db_mut()
        .reserve_swap_receiving_key_from(account, Purpose::Receive, start())
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
            .reserve_swap_receiving_key_from(account, Purpose::Refund, start())
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
        .reserve_swap_receiving_key_from(other, Purpose::Refund, start())
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
        db.watch_swap_receive_key(account, index, start()).unwrap();
        assert!(
            !db.swap_key_state(account, KeyId::new(Purpose::Receive, index))
                .1
        );
    }
    let key_id = KeyId::new(Purpose::Receive, 18);
    db.recover_swap_receiving_key(account, key_id, 80.into())
        .unwrap();
    assert!(db.swap_key_state(account, key_id).1);
    db.watch_swap_receive_key(account, 18, 120.into()).unwrap();
    assert_eq!(
        db.swap_key_state(account, key_id),
        (BlockHeight::from_u32(80), true)
    );
    assert_eq!(db.get_swap_receiving_keys(account).unwrap().len(), 20);
    // The unswept lookahead index 19 waits for its sweep rather than being skipped.
    assert!(matches!(
        db.reserve_swap_receiving_key_from(account, Purpose::Receive, start()),
        Err(Error::ReservationPolicy(ReservationPolicy::Gap))
    ));
    assert_eq!(
        db.reserve_swap_receiving_key_from(account, Purpose::Refund, start())
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
        db.reserve_swap_receiving_key_from(account, Purpose::Refund, start())
            .unwrap()
            .key_id()
            .index(),
        u64::MAX
    );
    assert!(matches!(
        db.reserve_swap_receiving_key_from(account, Purpose::Refund, start()),
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
        let key = tx.reserve_swap_receiving_key_from(
            account,
            Purpose::Refund,
            start(),
            super::Discovery::Scan,
        )?;
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
            let key = tx.reserve_swap_receiving_key_from(
                account,
                Purpose::Refund,
                start(),
                super::Discovery::Scan,
            )?;
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
                    match db.reserve_swap_receiving_key_from(account, Purpose::Refund, start()) {
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
        st.wallet_mut().db_mut().reserve_swap_receiving_key_from(
            account,
            Purpose::Receive,
            start()
        ),
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
        .reserve_swap_receiving_key_from(account, Purpose::Refund, start())
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
            .reserve_swap_receiving_key_from(account, Purpose::Refund, start()),
        Err(Error::Wallet(SqliteClientError::AccountUnknown))
    ));
}

#[test]
fn maintained_lookahead_extends_only_above_a_restored_key() {
    let mut st = wallet(false);
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    db.maintain_swap_receive_lookahead(account, 20, start())
        .unwrap();
    db.maintain_swap_receive_lookahead(account, 20, start())
        .unwrap();
    assert_eq!(db.get_swap_receiving_keys(account).unwrap().len(), 20);
    assert!(
        db.get_swap_receiving_keys(account)
            .unwrap()
            .iter()
            .all(|k| !db.swap_key_state(account, k.key_id()).1)
    );
    db.recover_swap_receiving_key(account, KeyId::new(Purpose::Receive, 19), start())
        .unwrap();
    db.maintain_swap_receive_lookahead(account, 20, start())
        .unwrap();
    let keys = db.get_swap_receiving_keys(account).unwrap();
    assert_eq!(keys.len(), 40);
    assert_eq!(keys.last().unwrap().key_id().index(), 39);
}

/// An accepted quote outcome with these deposit instructions.
fn accepted(address: &str, memo: Option<&str>, deadline: i64) -> QuoteOutcome {
    QuoteOutcome::Accepted(ReceiveDeposit {
        address: address.into(),
        memo: memo.map(Into::into),
        deadline,
    })
}

/// The wallet's fully scanned tip.
fn tip(st: &State) -> ChainPoint {
    let block = st.wallet().block_fully_scanned().unwrap().unwrap();
    ChainPoint {
        height: block.block_height(),
        hash: block.block_hash(),
    }
}

/// The swap key of each unspent Ironwood note at `height`, `None` for ordinary notes.
fn unspent_keys(st: &State, height: BlockHeight) -> Vec<Option<KeyId>> {
    st.wallet()
        .db()
        .get_unspent_ironwood_notes_at_historical_height(st.test_account().unwrap().id(), height)
        .unwrap()
        .iter()
        .map(|n| n.swap_key_id())
        .collect()
}

/// A sweep's view of a receiver a swap reached recently, so its key keeps scanning.
const WATCHED: ProviderView = ProviderView {
    recent: true,
    seen: false,
};

/// Keys the scanner trial-decrypts with.
fn scanning_keys(st: &State) -> Vec<KeyId> {
    let keys = st.wallet().get_swap_scanning_keys().unwrap();
    keys.iter().map(|k| k.key_id()).collect()
}

/// Pays `key` in a new scanned block and returns the output as a directory
/// candidate. The output must be the chain's first Ironwood leaf.
fn pay_candidate(st: &mut State, key: KeyId) -> PendingPayment {
    let fvk = key
        .derive(&FullViewingKey::from(
            st.test_account().unwrap().usk().orchard(),
        ))
        .unwrap();
    let (height, _, _) = st.generate_next_block(
        &IronwoodFvk(fvk.clone()),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(100_000),
    );
    st.scan_cached_blocks(height, 1);
    let data: Vec<u8> = st
        .cache()
        .0
        .query_row(
            "SELECT data FROM compactblocks WHERE height = ?1",
            [u32::from(height)],
            |r| r.get(0),
        )
        .unwrap();
    let block = CompactBlock::decode(data.as_slice()).unwrap();
    let tx = &block.vtx[0];
    let action = CompactAction::try_from(&tx.ironwood_actions[0]).unwrap();
    let (note, _) = try_compact_note_decryption(
        &IronwoodDomain::for_compact_action(&action),
        &fvk.to_ivk(Scope::External).prepare(),
        &action,
    )
    .unwrap();
    let encrypted_note = encrypt_note(note);
    assert_eq!(
        &encrypted_note.to_bytes()[96..148],
        tx.ironwood_actions[0].ciphertext.as_slice()
    );
    PendingPayment {
        txid: tx.txid(),
        action_index: 0,
        height,
        block_hash: block.hash(),
        tx_index: tx.index.try_into().unwrap(),
        position: 0,
        encrypted_note,
    }
}

/// Starts or extends trial decryption of `key` from `from`, as registration and
/// finished refund sweeps do.
fn activate_key(st: &mut State, key: KeyId, from: BlockHeight) {
    let account = st.test_account().unwrap().id();
    st.wallet_mut()
        .db_mut()
        .transactionally::<_, _, Error>(|db| {
            let id = super::payments::key_ref(db.conn.0, account, key)?;
            activate(db.conn.0, id, from)
        })
        .unwrap();
}

/// Encrypts `note` with a `[4; 512]` memo, as a directory candidate carries it.
fn encrypt_note(note: Note) -> EncryptedNote {
    let enc = IronwoodNoteEncryption::new(None, note, [4; 512]);
    let bytes = enc.encrypt_note_plaintext();
    EncryptedNote::from_parts(
        note.rho().to_bytes(),
        orchard::note::ExtractedNoteCommitment::from(note.commitment()).to_bytes(),
        IronwoodDomain::epk_bytes(enc.epk()).0,
        bytes[..52].try_into().unwrap(),
        bytes[52..].try_into().unwrap(),
    )
}

/// The authentication path of the first leaf in an otherwise empty tree.
fn first_leaf_path() -> MerklePath {
    MerklePath::from_parts(
        0,
        std::array::from_fn(|level| MerkleHashOrchard::empty_root((level as u8).into())),
    )
}

mod apply;
mod enhancement;
mod key_access;
mod lifecycle;
mod payments;
mod planner;
mod reservations;
mod retention;
mod scanning;

impl<C: Borrow<Connection>, P: Parameters, CL, R> WalletDb<C, P, CL, R> {
    /// Every key registered to `account` by purpose and index, each re-derived and
    /// checked against its stored receiver.
    fn get_swap_receiving_keys(&self, account: AccountUuid) -> Result<Vec<RegisteredKey>, Error> {
        let conn = self.conn.borrow();
        let (account_ref, parent) = account_key(conn, &self.params, account)?;
        let mut stmt = conn.prepare(
            "SELECT purpose, key_index, receiver FROM ironwood_receiving_keys
             WHERE account_id = ?1 ORDER BY purpose, key_index",
        )?;
        let mut rows = stmt.query([account_ref.0])?;
        let mut keys = Vec::new();
        while let Some(row) = rows.next()? {
            keys.push(registered_key(row, account, &parent)?);
        }
        Ok(keys)
    }

    /// The key registered to `account` as `key_id`, re-derived and checked.
    fn get_swap_receiving_key(
        &self,
        account: AccountUuid,
        key_id: KeyId,
    ) -> Result<Option<RegisteredKey>, Error> {
        self.swap_receiving_key_matching(
            account,
            "k.purpose=?2 AND k.key_index=?3",
            rusqlite::params![
                account.0,
                purpose_code(key_id.purpose()),
                key_id.index().to_be_bytes()
            ],
        )
    }

    /// `key`'s stored scan start and whether it advances allocation.
    fn swap_key_state(&self, account: AccountUuid, key: KeyId) -> (BlockHeight, bool) {
        self.conn
            .borrow()
            .query_row(
                "SELECT k.scan_from, k.advances_allocation FROM ironwood_receiving_keys k
                 JOIN accounts a ON a.id = k.account_id
                 WHERE a.uuid = ?1 AND k.purpose = ?2 AND k.key_index = ?3",
                rusqlite::params![
                    account.0,
                    purpose_code(key.purpose()),
                    key.index().to_be_bytes()
                ],
                |r| Ok((BlockHeight::from(r.get::<_, u32>(0)?), r.get(1)?)),
            )
            .unwrap()
    }

    /// `key`'s last queued lookup, if it is still on the wallet's chain.
    fn swap_lookup_coverage(
        &self,
        account: AccountUuid,
        key: KeyId,
    ) -> Result<Option<ChainPoint>, Error> {
        let conn = self.conn.borrow();
        let id = super::payments::key_ref(conn, account, key)?;
        let lookup = conn.query_row(
            "SELECT lookup_height, lookup_hash FROM ironwood_swap_sweeps
             WHERE receiving_key_id = ?1",
            [id],
            |r| Ok(super::planner::anchor(r.get(0)?, r.get(1)?)),
        )?;
        super::planner::canonical(conn, lookup)
    }
}

impl<C: BorrowMut<Connection>, P: Parameters, CL: Clock, R> WalletDb<C, P, CL, R> {
    /// Reserves the next index, scanned at once from `scan_from`, without readiness
    /// checks.
    pub(crate) fn reserve_swap_receiving_key_from(
        &mut self,
        account: AccountUuid,
        purpose: Purpose,
        scan_from: BlockHeight,
    ) -> Result<RegisteredKey, Error> {
        self.transactionally(|wdb| {
            wdb.reserve_swap_receiving_key_from(account, purpose, scan_from, Discovery::Scan)
        })
    }

    /// Registers a key as recovered evidence would, from `scan_from`. A key this wallet
    /// never scanned is queued for a receiver-directory sweep.
    fn recover_swap_receiving_key(
        &mut self,
        account: AccountUuid,
        key_id: KeyId,
        scan_from: BlockHeight,
    ) -> Result<RegisteredKey, Error> {
        self.transactionally(|wdb| {
            let now = unix_now(&wdb.clock);
            let registered = register(
                wdb.conn.0,
                &wdb.params,
                account,
                key_id,
                scan_from,
                true,
                Discovery::Sweep,
                now,
            )?;
            Ok(registered.1)
        })
    }

    /// See [`WalletDb::watch_swap_receive_key`] on a transaction-backed handle.
    fn watch_swap_receive_key(
        &mut self,
        account: AccountUuid,
        index: u64,
        scan_from: BlockHeight,
    ) -> Result<RegisteredKey, Error> {
        self.transactionally(|wdb| wdb.watch_swap_receive_key(account, index, scan_from))
    }

    /// See [`WalletDb::maintain_swap_receive_lookahead`] on a transaction-backed handle.
    fn maintain_swap_receive_lookahead(
        &mut self,
        account: AccountUuid,
        count: u32,
        scan_from: BlockHeight,
    ) -> Result<(), Error> {
        self.transactionally(|db| db.maintain_swap_receive_lookahead(account, count, scan_from))
    }

    /// Reserves like [`WalletDb::prepare_swap_receive_reservation`], scanning a new key
    /// from `scan_from`, without the readiness checks or lookahead registration.
    fn prepare_swap_receive_reservation_from(
        &mut self,
        account: AccountUuid,
        now: i64,
        scan_from: BlockHeight,
    ) -> Result<ReceiveReservation, Error> {
        let id = self.transactionally(|db| {
            super::reservations::prepare(db.conn.0, &db.params, account, now, scan_from)
        })?;
        self.swap_receive_reservation(account, id)
    }

    /// See [`WalletDb::queue_swap_payment`] on a transaction-backed handle.
    fn queue_swap_payment(
        &mut self,
        account: AccountUuid,
        key: KeyId,
        candidate: &PendingPayment,
    ) -> Result<(), Error> {
        self.transactionally(|db| db.queue_swap_payment(account, key, candidate))
    }

    /// See [`WalletDb::queue_swap_lookup`] on a transaction-backed handle.
    fn queue_swap_lookup(
        &mut self,
        account: AccountUuid,
        key: KeyId,
        anchor: ChainPoint,
        payments: &[PendingPayment],
    ) -> Result<(), Error> {
        self.transactionally(|db| db.queue_swap_lookup(account, key, anchor, payments))
    }

    /// Authenticates `candidate` and checks its spend evidence.
    fn swap_payment_spend_status(
        &mut self,
        account: AccountUuid,
        key: KeyId,
        candidate: &PendingPayment,
        through: ChainPoint,
    ) -> Result<SpendStatus, Error> {
        self.transactionally(|db| {
            let (_, note) =
                super::payments::authenticate(db.conn.0, &db.params, account, key, candidate)?;
            super::payments::spend_status(db.conn.0, candidate, note.nullifier(), through)
        })
    }

    /// Retains `account`'s Ironwood spend evidence, as maintenance does.
    fn retain_swap_spend_history(&mut self, account: AccountUuid) -> Result<(), Error> {
        self.transactionally(|db| {
            super::retention::retain_spend_history(db.conn.0, &db.params, account)
        })
    }

    /// [`WalletDb::close_finished_swap_keys`] with `tip`'s block time set to `now`, as
    /// when the caller's clock agrees with the chain.
    fn close_finished_swap_keys_at(
        &mut self,
        account: AccountUuid,
        now: i64,
        tip: BlockHeight,
    ) -> Result<usize, Error> {
        self.conn.borrow_mut().execute(
            "UPDATE blocks SET time = ?2 WHERE height = ?1",
            rusqlite::params![u32::from(tip), now],
        )?;
        self.close_finished_swap_keys(account, now, tip)
    }

    /// Records `status` for `operation` at Unix time `now`, without a quote deadline.
    fn observe_swap_operation(
        &mut self,
        account: AccountUuid,
        key: KeyId,
        operation: &str,
        status: zakura_swap_receiving::lifecycle::OperationStatus,
        now: i64,
    ) -> Result<(), Error> {
        let observation = zakura_swap_receiving::lifecycle::Observation {
            status,
            deadline: None,
        };
        self.record_swap_observation(account, key, operation, observation, now)
    }

    /// Registers incoming `indices` as addresses that were quoted and then abandoned,
    /// which issuance reuses only when nothing else is left.
    fn abandon_receive_indices(
        &mut self,
        account: AccountUuid,
        indices: std::ops::Range<u64>,
        scan_from: BlockHeight,
    ) -> Result<(), Error> {
        self.transactionally(|wdb| {
            for index in indices {
                let (id, _) = register(
                    wdb.conn.0,
                    &wdb.params,
                    account,
                    KeyId::new(Purpose::Receive, index),
                    scan_from,
                    true,
                    Discovery::Scan,
                    0,
                )?;
                wdb.conn.0.execute(
                    "UPDATE ironwood_receiving_keys SET quoted = 1, closed_at = 0 WHERE id = ?1",
                    [id],
                )?;
            }
            Ok(())
        })
    }

    /// Finishes `key`'s sweep after an empty lookup at `anchor`.
    fn finish_sweep(
        &mut self,
        account: AccountUuid,
        key: KeyId,
        anchor: ChainPoint,
    ) -> Result<(), Error> {
        self.queue_swap_lookup(account, key, anchor, &[])?;
        match self.apply_swap_sweep(account, key, anchor, anchor, WATCHED, |_, _| None)? {
            PaymentApplication::Applied => Ok(()),
            _ => Err(corrupt("sweep has unapplied candidates")),
        }
    }
}
