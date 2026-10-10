use std::sync::{Arc, Barrier};

use incrementalmerkletree::Hashable;
use orchard::{
    note::Note,
    note_encryption::{CompactAction, IronwoodDomain, IronwoodNoteEncryption},
    tree::{MerkleHashOrchard, MerklePath},
};
use prost::Message;
use secrecy::{ExposeSecret, SecretVec};
use zakura_dynamic_ivk::{
    lifecycle::{Observation, OperationStatus},
    recovery::EncryptedNote,
};
use zcash_client_backend::{
    data_api::{
        WalletRead, WalletWrite,
        dynamic_ivk::{
            DirectoryPayment, DiscoveryWork, DynamicIvkRead as _, DynamicIvkWrite as _,
            MAX_PUBLICATION_LAG, PaymentApplication, SweepDeferral,
        },
        testing::{AddressType, IronwoodFvk, TestBuilder, TestRng, TestState},
        transparent_ledger::ChainPoint,
    },
    proto::compact_formats::CompactBlock,
};
use zcash_note_encryption::{Domain, try_compact_note_decryption};
use zcash_primitives::block::BlockHash;
use zcash_protocol::{local_consensus::LocalNetwork, value::Zatoshis};

use super::*;
use crate::testing::db::{TestDb, TestDbFactory, test_clock, test_rng};
use crate::util::testing::FixedClock;
/// The module under test, whose submodule names the test modules shadow.
use crate::wallet::dynamic_ivk as store;

/// A test wallet with a block cache.
type State = TestState<crate::testing::BlockCache, TestDb, LocalNetwork>;
/// The test wallet's database handle.
type Db = WalletDb<Connection, LocalNetwork, FixedClock, TestRng>;
/// A result that may wait on a reservation policy.
type Policy<T> = Result<Result<T, ReservationPolicy>, SqliteClientError>;

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
    st.generate_and_scan_empty_blocks_with_dynamic_ivks(1);
    st
}

fn start() -> BlockHeight {
    BlockHeight::from_u32(100)
}

/// The test clock's time, which registration stamps on keys.
fn clock_now() -> i64 {
    unix_now(&test_clock())
}

/// Runs `f` in one wallet transaction.
fn tx<A>(
    db: &mut Db,
    f: impl FnOnce(&rusqlite::Transaction<'_>, &LocalNetwork) -> Result<A, SqliteClientError>,
) -> Result<A, SqliteClientError> {
    db.transactionally(|db| f(db.conn.0, db.params))
}

/// Reserves `account`'s next `purpose` index, scanned at once from `from`, without
/// readiness checks.
fn reserve(
    db: &mut Db,
    account: AccountUuid,
    purpose: Purpose,
    from: BlockHeight,
) -> Policy<DynamicKey> {
    tx(db, |c, p| {
        reserve_next(c, p, account, purpose, from, Discovery::Scan, clock_now())
    })
}

/// [`reserve`], expecting a key.
pub(crate) fn reserve_key(
    db: &mut Db,
    account: AccountUuid,
    purpose: Purpose,
    from: BlockHeight,
) -> DynamicKey {
    reserve(db, account, purpose, from).unwrap().unwrap()
}

/// Registers incoming lookahead key `index` for a sweep, expecting payments from `from`.
fn watch(db: &mut Db, account: AccountUuid, index: u64, from: BlockHeight) -> DynamicKey {
    tx(db, |c, p| {
        store::recovery::watch_receive_key(c, p, account, index, from, clock_now())
    })
    .unwrap()
}

/// Registers `key` as recovered evidence would, from `from`. A key this wallet never
/// scanned is queued for a receiver-directory sweep.
fn recover(db: &mut Db, account: AccountUuid, key: KeyId, from: BlockHeight) -> DynamicKey {
    tx(db, |c, p| {
        register(
            c,
            p,
            account,
            key,
            from,
            true,
            Discovery::Sweep,
            clock_now(),
        )
    })
    .unwrap()
    .1
}

/// Keeps `count` incoming lookahead keys expecting payments from `from`.
fn lookahead(db: &mut Db, account: AccountUuid, count: u32, from: BlockHeight) {
    tx(db, |c, p| {
        store::recovery::maintain_receive_lookahead(c, p, account, count, from, clock_now())
    })
    .unwrap()
}

/// Reserves like `WalletDb::prepare_receive_reservation`, scanning a new key from `from`,
/// without readiness checks, reaping or lookahead registration.
fn prepare_from(
    db: &mut Db,
    account: AccountUuid,
    now: i64,
    from: BlockHeight,
    seen: Option<&ProviderSeen<'_>>,
) -> Policy<DynamicKey> {
    tx(db, |c, p| {
        store::reservations::prepare(c, p, account, now, from, seen)
    })
}

/// Queues a complete lookup of `key` at `anchor` that found `payments`. A deferral is
/// an error here.
fn queue_lookup(
    db: &mut Db,
    account: AccountUuid,
    key: KeyId,
    anchor: ChainPoint,
    payments: &[PendingPayment],
) -> Result<(), SqliteClientError> {
    tx(db, |c, p| {
        store::planner::queue_lookup(c, p, account, key, anchor, payments, true)
    })?
    .map_err(|deferral| corrupt(&format!("{deferral:?}")))
}

/// Authenticates and queues `candidate` for `key`.
fn queue_payment(
    db: &mut Db,
    account: AccountUuid,
    key: KeyId,
    candidate: &PendingPayment,
) -> Result<(), SqliteClientError> {
    tx(db, |c, p| {
        store::payments::queue_payment(c, p, account, key, candidate)
    })
}

/// Authenticates `candidate` and checks its spend evidence through `through`.
fn spend_status(
    db: &mut Db,
    account: AccountUuid,
    key: KeyId,
    candidate: &PendingPayment,
    through: ChainPoint,
) -> Result<SpendStatus, SweepDeferral> {
    tx(db, |c, p| {
        let (_, note) = store::payments::authenticate(c, p, account, key, candidate)?;
        store::payments::spend_status(c, candidate, note.nullifier(), through)
    })
    .unwrap()
}

/// Retains `account`'s Ironwood spend evidence, as maintenance does.
fn retain(db: &mut Db, account: AccountUuid) {
    tx(db, |c, p| {
        store::retention::retain_spend_history(c, p, account)
    })
    .unwrap()
}

/// Releases retained nullifiers at `through`, keeping `lookahead` incoming keys.
fn finish_recovery(
    db: &mut Db,
    account: AccountUuid,
    through: ChainPoint,
    lookahead: u32,
) -> Result<bool, SqliteClientError> {
    tx(db, |c, p| {
        store::retention::finish_nullifier_recovery(c, p, account, through, lookahead, clock_now())
    })
}

/// Starts or extends trial decryption of `key` from `from`, as registration and
/// finished refund sweeps do.
fn activate_key(db: &mut Db, account: AccountUuid, key: KeyId, from: BlockHeight) {
    assert!(tx(db, |c, _| activate(c, key_ref(c, account, key)?, from)).unwrap());
}

/// `account`'s queued candidates for `key`.
fn pending(db: &Db, account: AccountUuid, key: KeyId) -> Vec<PendingPayment> {
    store::payments::pending_payments(&db.conn, account, key).unwrap()
}

/// Applies queued `candidate` with `path` at `anchor`.
fn apply_payment(
    db: &mut Db,
    account: AccountUuid,
    key: KeyId,
    candidate: &PendingPayment,
    through: ChainPoint,
    (anchor, path): (ChainPoint, &MerklePath),
) -> Result<PaymentApplication, SqliteClientError> {
    tx(db, |c, p| {
        store::apply::apply_payment(c, p, account, key, candidate, through, (anchor, path))
    })
    .map(|applied| applied.expect("the payment's blocks are on the wallet's chain"))
}

/// Finishes `key`'s sweep after an empty lookup at `anchor`, for an unseen receiver.
fn finish_sweep(db: &mut Db, account: AccountUuid, key: KeyId, anchor: ChainPoint) {
    queue_lookup(db, account, key, anchor, &[]).unwrap();
    let applied = db.apply_dynamic_sweep(account, key, anchor, anchor, false, |_, _| None);
    assert_eq!(applied.unwrap(), Ok(PaymentApplication::Applied));
}

/// Records `observation` for `key`'s operation `reference` at `now`.
fn observe_with(
    db: &mut Db,
    account: AccountUuid,
    key: KeyId,
    reference: &str,
    observation: Observation,
    now: i64,
) -> Result<(), SqliteClientError> {
    tx(db, |c, _| {
        store::lifecycle::record_refund(c, key_ref(c, account, key)?, reference, observation, now)
    })
}

/// Records `status` for `key`'s operation `reference` at `now`, without a deadline.
fn observe(
    db: &mut Db,
    account: AccountUuid,
    key: KeyId,
    reference: &str,
    status: OperationStatus,
    now: i64,
) -> Result<(), SqliteClientError> {
    let observation = Observation {
        status,
        deadline: None,
    };
    observe_with(db, account, key, reference, observation, now)
}

/// [`WalletDb::close_finished_dynamic_keys`] with `tip`'s block time set to `now`, as
/// when the caller's clock agrees with the chain.
fn close_at(db: &mut Db, account: AccountUuid, now: i64, tip: BlockHeight) -> usize {
    db.conn
        .execute(
            "UPDATE blocks SET time = ?2 WHERE height = ?1",
            rusqlite::params![u32::from(tip), now],
        )
        .unwrap();
    db.close_finished_dynamic_keys(account, now, tip).unwrap()
}

/// Every key registered to `account` by purpose and index, each re-derived and checked
/// against its stored receiver.
fn all_keys(db: &Db, account: AccountUuid) -> Result<Vec<DynamicKey>, SqliteClientError> {
    keys_where(&db.conn, &db.params, account, "1", [account.0])
}

/// The key registered to `account` as `key`, re-derived and checked.
fn get_key(
    db: &Db,
    account: AccountUuid,
    key: KeyId,
) -> Result<Option<DynamicKey>, SqliteClientError> {
    let (purpose, index) = (purpose_code(key.purpose()), key.index().to_be_bytes());
    let selected = "k.purpose = ?2 AND k.key_index = ?3";
    key_matching(
        &db.conn,
        &db.params,
        account,
        selected,
        rusqlite::params![account.0, purpose, index],
    )
}

/// `key`'s stored scan start and whether it advances allocation.
fn key_state(db: &Db, key: KeyId) -> (BlockHeight, bool) {
    db.conn
        .query_row(
            "SELECT scan_from, advances_allocation FROM ironwood_receiving_keys
             WHERE purpose = ?1 AND key_index = ?2",
            rusqlite::params![purpose_code(key.purpose()), key.index().to_be_bytes()],
            |r| Ok((BlockHeight::from(r.get::<_, u32>(0)?), r.get(1)?)),
        )
        .unwrap()
}

/// `key`'s last queued lookup, if it is still on the wallet's chain.
fn lookup_coverage(db: &Db, account: AccountUuid, key: KeyId) -> Option<ChainPoint> {
    let id = key_ref(&db.conn, account, key).unwrap();
    let lookup = db
        .conn
        .query_row(
            "SELECT lookup_height, lookup_hash FROM ironwood_dynamic_sweeps
             WHERE receiving_key_id = ?1",
            [id],
            |r| Ok(store::planner::anchor(r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    store::planner::canonical(&db.conn, lookup).unwrap()
}

/// An accepted operation outcome with these deposit instructions.
fn accepted(address: &str, memo: Option<&str>, deadline: i64) -> OperationOutcome {
    OperationOutcome::Accepted(ReceiveDeposit {
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

/// The dynamic key of each unspent Ironwood note at `height`, `None` for ordinary notes.
fn unspent_keys(st: &State, height: BlockHeight) -> Vec<Option<KeyId>> {
    st.wallet()
        .db()
        .get_unspent_ironwood_notes_at_historical_height(st.test_account().unwrap().id(), height)
        .unwrap()
        .iter()
        .map(|n| n.dynamic_key_id())
        .collect()
}

/// Keys the scanner trial-decrypts with.
fn scanning_keys(st: &State) -> Vec<KeyId> {
    let keys = st.wallet().get_dynamic_scanning_keys().unwrap();
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
    st.scan_cached_blocks_with_dynamic_ivks(height, 1);
    let candidate = candidate_at(st, height, &fvk);
    assert_eq!(candidate.position, 0);
    candidate
}

/// The first output to `fvk`'s external address in cached block `height`, as a directory
/// candidate whose note data carries [`encrypt_note`]'s memo.
fn candidate_at(st: &State, height: BlockHeight, fvk: &FullViewingKey) -> PendingPayment {
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
    let ivk = fvk.to_ivk(Scope::External).prepare();
    let actions: u32 = block
        .vtx
        .iter()
        .map(|tx| tx.ironwood_actions.len() as u32)
        .sum();
    let mut position = block
        .chain_metadata
        .as_ref()
        .unwrap()
        .ironwood_commitment_tree_size
        - actions;
    for tx in &block.vtx {
        for (index, compact) in tx.ironwood_actions.iter().enumerate() {
            let action = CompactAction::try_from(compact).unwrap();
            let domain = IronwoodDomain::for_compact_action(&action);
            if let Some((note, _)) = try_compact_note_decryption(&domain, &ivk, &action) {
                let encrypted_note = encrypt_note(note);
                assert_eq!(
                    &encrypted_note.to_bytes()[96..148],
                    compact.ciphertext.as_slice()
                );
                return PendingPayment {
                    txid: tx.txid(),
                    action_index: index.try_into().unwrap(),
                    height,
                    block_hash: block.hash(),
                    tx_index: tx.index.try_into().unwrap(),
                    position,
                    encrypted_note,
                };
            }
            position += 1;
        }
    }
    panic!("no output to the key in block {height}");
}

/// A transaction another wallet built, paying 50,000 zatoshis to `to` with `memo` from
/// its own Ironwood funds, so this wallet neither funded nor stored it.
fn external_payment(
    to: orchard::Address,
    memo: &zcash_protocol::memo::MemoBytes,
) -> zcash_primitives::transaction::Transaction {
    use std::convert::Infallible;
    use zcash_client_backend::{
        data_api::wallet::{ConfirmationsPolicy, input_selection::GreedyInputSelector},
        fees::{DustOutputPolicy, StandardFeeRule, standard},
        wallet::OvkPolicy,
    };
    use zcash_keys::address::{Address, UnifiedAddress};
    use zip321::{Payment, TransactionRequest};
    let mut funder = ironwood_wallet();
    let birthday = funder.test_account().unwrap().birthday().clone();
    let (account, usk) = funder
        .wallet_mut()
        .db_mut()
        .create_account("funder", &SecretVec::new(vec![7; 32]), &birthday, None)
        .unwrap();
    let (height, _, _) = funder.generate_next_block(
        &IronwoodFvk(FullViewingKey::from(usk.orchard())),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(1_000_000),
    );
    funder.scan_cached_blocks_with_dynamic_ivks(height, 1);
    funder.generate_and_scan_empty_blocks_with_dynamic_ivks(5);
    let network = *funder.network();
    let address = Address::Unified(UnifiedAddress::from_receivers(Some(to), None, None).unwrap());
    let request = TransactionRequest::new(vec![
        Payment::new(
            address.to_zcash_address(&network),
            Some(Zatoshis::const_from_u64(50_000)),
            Some(memo.clone()),
            None,
            None,
            vec![],
        )
        .unwrap(),
    ])
    .unwrap();
    let strategy = standard::SingleOutputChangeStrategy::<TestDb>::new(
        StandardFeeRule::Zip317,
        None,
        zcash_protocol::ShieldedPool::Orchard,
        DustOutputPolicy::default(),
    );
    let proposal = funder
        .propose_transfer(
            account,
            &GreedyInputSelector::new(),
            &strategy,
            request,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();
    let created = funder
        .create_proposed_transactions::<Infallible, _, Infallible, _>(
            &usk,
            OvkPolicy::Sender,
            &proposal,
        )
        .unwrap();
    funder
        .wallet()
        .get_transaction(created[0])
        .unwrap()
        .unwrap()
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

#[test]
fn reservations_survive_reopen_and_keep_purposes_and_accounts_separate() {
    let mut st = wallet(true);
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    let refund = reserve_key(db, account, Purpose::Refund, start());
    let incoming = reserve_key(db, account, Purpose::Receive, start());
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
    let keys = all_keys(&reopened, account).unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(
        keys[0].full_viewing_key().to_bytes(),
        refund.full_viewing_key().to_bytes()
    );
    assert_eq!(keys[1].receiver(), incoming.receiver());
    let next = reserve_key(&mut reopened, account, Purpose::Refund, start());
    assert_eq!(next.key_id().index(), 1);

    let seed = SecretVec::new(st.test_seed().unwrap().expose_secret().clone());
    let birthday = st.test_account().unwrap().birthday().clone();
    let (other, _) = reopened
        .create_account("other", &seed, &birthday, None)
        .unwrap();
    let key = reserve_key(&mut reopened, other, Purpose::Refund, start());
    assert_eq!(key.key_id().index(), 0);
    assert_ne!(key.receiver(), refund.receiver());
}

#[test]
fn lookahead_does_not_skip_unissued_addresses_and_recovery_promotes_it() {
    let mut st = wallet(false);
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    for index in 0..20 {
        watch(db, account, index, start());
        assert!(!key_state(db, KeyId::new(Purpose::Receive, index)).1);
    }
    let key_id = KeyId::new(Purpose::Receive, 18);
    recover(db, account, key_id, 80.into());
    assert!(key_state(db, key_id).1);
    watch(db, account, 18, 120.into());
    assert_eq!(key_state(db, key_id), (BlockHeight::from_u32(80), true));
    assert_eq!(all_keys(db, account).unwrap().len(), 20);
    // The unswept lookahead index 19 waits for its sweep rather than being skipped.
    assert!(matches!(
        reserve(db, account, Purpose::Receive, start()),
        Ok(Err(ReservationPolicy::Gap))
    ));
    let refund = reserve_key(db, account, Purpose::Refund, start());
    assert_eq!(refund.key_id().index(), 0);
}

#[test]
fn recovered_indices_use_full_u64_order_and_never_wrap() {
    let mut st = wallet(false);
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    for index in [256, 1, i64::MAX as u64, u64::MAX - 1, 255] {
        recover(db, account, KeyId::new(Purpose::Refund, index), start());
    }
    let last = reserve_key(db, account, Purpose::Refund, start());
    assert_eq!(last.key_id().index(), u64::MAX);
    assert!(matches!(
        reserve(db, account, Purpose::Refund, start()),
        Err(SqliteClientError::DynamicIvkIndexExhausted)
    ));
    assert_eq!(all_keys(db, account).unwrap().len(), 6);
}

#[test]
fn operation_and_reservation_commit_or_roll_back_together() {
    let mut st = wallet(false);
    let account = st.test_account().unwrap().id();
    st.wallet()
        .conn()
        .execute_batch("CREATE TABLE ext_operations (key_index BLOB NOT NULL)")
        .unwrap();
    let db = st.wallet_mut().db_mut();
    let reserve_with = |db: &mut Db, fail: bool| {
        db.transactionally_with_extension(|tx, ext| {
            let (conn, params) = (tx.conn.0, tx.params);
            let key = reserve_next(
                conn,
                params,
                account,
                Purpose::Refund,
                start(),
                Discovery::Scan,
                0,
            )?
            .unwrap();
            ext.execute(
                "INSERT INTO ext_operations VALUES (?1)",
                [&key.key_id().index().to_le_bytes()],
            )?;
            if fail {
                return Err(corrupt("fixture operation write failed"));
            }
            Ok(key)
        })
    };
    assert!(reserve_with(db, true).is_err());
    assert!(all_keys(db, account).unwrap().is_empty());
    assert_eq!(reserve_with(db, false).unwrap().key_id().index(), 0);
    assert_eq!(
        st.wallet()
            .conn()
            .query_row::<u32, _, _>("SELECT COUNT(*) FROM ext_operations", [], |r| r.get(0))
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
                    match reserve(&mut db, account, Purpose::Refund, start()) {
                        Ok(Ok(key)) => return key.key_id().index(),
                        Err(SqliteClientError::DbError(rusqlite::Error::SqliteFailure(e, _)))
                            if e.code == rusqlite::ErrorCode::DatabaseBusy =>
                        {
                            std::thread::sleep(std::time::Duration::from_millis(5));
                        }
                        _ => panic!("unexpected allocation failure"),
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
    watch(st.wallet_mut().db_mut(), account, 0, start());
    st.wallet()
        .conn()
        .execute(
            "UPDATE ironwood_receiving_keys SET receiver = zeroblob(43)",
            [],
        )
        .unwrap();
    let db = st.wallet_mut().db_mut();
    assert!(matches!(
        all_keys(db, account),
        Err(SqliteClientError::CorruptedData(_))
    ));
    let key = KeyId::new(Purpose::Receive, 0);
    assert!(matches!(
        tx(db, |c, p| register(
            c,
            p,
            account,
            key,
            start(),
            true,
            Discovery::Sweep,
            0
        )),
        Err(SqliteClientError::CorruptedData(_))
    ));
    assert!(!key_state(db, KeyId::new(Purpose::Receive, 0)).1);
}

#[test]
fn account_deletion_cascades_and_unknown_accounts_cannot_reserve() {
    let mut st = wallet(false);
    let account = st.test_account().unwrap().id();
    reserve_key(st.wallet_mut().db_mut(), account, Purpose::Refund, start());
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
        reserve(st.wallet_mut().db_mut(), account, Purpose::Refund, start()),
        Err(SqliteClientError::AccountUnknown)
    ));
}

#[test]
fn maintained_lookahead_extends_only_above_a_restored_key() {
    let mut st = wallet(false);
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    lookahead(db, account, 20, start());
    lookahead(db, account, 20, start());
    let keys = all_keys(db, account).unwrap();
    assert_eq!(keys.len(), 20);
    assert!(keys.iter().all(|k| !key_state(db, k.key_id()).1));
    recover(db, account, KeyId::new(Purpose::Receive, 19), start());
    lookahead(db, account, 20, start());
    let keys = all_keys(db, account).unwrap();
    assert_eq!(keys.len(), 40);
    assert_eq!(keys.last().unwrap().key_id().index(), 39);
}
