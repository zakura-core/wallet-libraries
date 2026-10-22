pub(super) use std::{
    borrow::Borrow,
    sync::{Arc, Barrier},
};

pub(super) use orchard::{
    note::Note,
    note_encryption::{CompactAction, IronwoodDomain, IronwoodNoteEncryption},
    tree::{MerkleHashOrchard, MerklePath},
};
pub(super) use prost::Message;
pub(super) use secrecy::{ExposeSecret, SecretVec};
pub(super) use zakura_one_time_ivk::swap::{Observation, OperationStatus};
pub(super) use zcash_client_backend::{
    data_api::{
        WalletRead, WalletWrite,
        one_time_ivk::restore::{
            DirectoryPayment, DirectoryRecord, PublicationEnd, recovery::EncryptedNote,
        },
        testing::{AddressType, IronwoodFvk, TestBuilder, TestRng, TestState},
        transparent_ledger::ChainPoint,
    },
    proto::compact_formats::CompactBlock,
};
pub(super) use zcash_note_encryption::{Domain, try_compact_note_decryption};
pub(super) use zcash_primitives::block::BlockHash;
pub(super) use zcash_protocol::{local_consensus::LocalNetwork, value::Zatoshis};

pub(super) use super::{restore::payments::PendingPayment, swap::*, *};
pub(super) use crate::WalletDb;
pub(super) use crate::testing::db::{TestDb, TestDbFactory, test_clock, test_rng};
pub(super) use crate::util::testing::FixedClock;
/// The module under test, whose submodule names the test modules shadow.
pub(super) use crate::wallet::one_time_ivk as store;

/// A test wallet with a block cache.
pub(super) type State = TestState<crate::testing::BlockCache, TestDb, LocalNetwork>;
/// The test wallet's database handle.
pub(super) type Db = WalletDb<Connection, LocalNetwork, FixedClock, TestRng>;
/// A result that may wait on a reservation policy.
pub(super) type Policy<T> = Result<Result<T, ReservationPolicy>, SqliteClientError>;

pub(super) fn wallet(file_backed: bool) -> TestState<(), TestDb, LocalNetwork> {
    TestBuilder::new()
        .with_data_store_factory(if file_backed {
            TestDbFactory::file_backed()
        } else {
            TestDbFactory::default()
        })
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build()
}

/// The test network with Ironwood active from the test account's birthday.
pub(super) fn ironwood_network() -> LocalNetwork {
    let activation = Some(BlockHeight::from_u32(100_000));
    LocalNetwork {
        nu6: activation,
        nu6_1: activation,
        nu6_2: activation,
        nu6_3: activation,
        ..TestBuilder::<(), ()>::DEFAULT_NETWORK
    }
}

/// A file-backed wallet with a block cache and Ironwood active from its first block.
pub(super) fn ironwood_wallet() -> State {
    TestBuilder::new()
        .with_network(ironwood_network())
        .with_data_store_factory(TestDbFactory::file_backed())
        .with_block_cache(crate::testing::BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build()
}

/// An Ironwood wallet scanned through one empty block, so it is at its tip, whose account
/// was created from a fresh seed, so issuance waits for no discovery.
pub(super) fn scanned_wallet() -> State {
    let mut st = restored_wallet();
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    db.set_one_time_recovery_enabled(account, true).unwrap();
    st
}

/// An Ironwood wallet scanned through one empty block, whose account was restored, so
/// issuance waits for its discovery.
pub(super) fn restored_wallet() -> State {
    let mut st = ironwood_wallet();
    st.generate_and_scan_empty_blocks(1);
    st
}

pub(super) fn start() -> BlockHeight {
    BlockHeight::from_u32(100)
}

/// The test clock's time.
pub(super) fn clock_now() -> i64 {
    unix_now(&test_clock())
}

/// Runs `f` in one wallet transaction.
pub(super) fn tx<A>(
    db: &mut Db,
    f: impl FnOnce(&rusqlite::Transaction<'_>, &LocalNetwork) -> Result<A, SqliteClientError>,
) -> Result<A, SqliteClientError> {
    db.transactionally(|db| f(db.conn.0, db.params))
}

/// Registers `account`'s next `purpose` index as issuance allocates it, scanned at once
/// from `from`, without readiness checks.
pub(super) fn reserve(
    db: &mut Db,
    account: AccountUuid,
    purpose: Purpose,
    from: BlockHeight,
) -> Result<OneTimeKey, SqliteClientError> {
    let now = clock_now();
    tx(db, |c, p| reserve_in(c, p, account, purpose, from, now))
}

/// [`reserve`] within transaction `c`.
pub(super) fn reserve_in(
    c: &rusqlite::Transaction<'_>,
    p: &LocalNetwork,
    account: AccountUuid,
    purpose: Purpose,
    from: BlockHeight,
    now: i64,
) -> Result<OneTimeKey, SqliteClientError> {
    let (owner, _) = account_key(c, p, account)?;
    let last: Option<Vec<u8>> = c.query_row(
        "SELECT MAX(key_index) FROM ironwood_one_time_keys
        WHERE account_id = ?1 AND purpose = ?2 AND reserved_at IS NOT NULL",
        rusqlite::params![owner.0, purpose_code(purpose)?],
        |r| r.get(0),
    )?;
    let index = if purpose == Purpose::Refund {
        store::swap::funding::next_refund_index(c, p, account)?
    } else {
        last.map(|bytes| index_after(decode_index(bytes)?, 1))
            .transpose()?
            .unwrap_or(0)
    };
    let (id, key) = register(c, p, account, KeyId::new(purpose, index))?;
    c.execute(
        "UPDATE ironwood_one_time_keys SET reserved_at = ?2 WHERE id = ?1",
        rusqlite::params![id, now],
    )?;
    if purpose == Purpose::Refund {
        store::restore::queue::funded(c, id, from)?;
    }
    Ok(key)
}

/// [`reserve`], expecting a key.
pub(crate) fn reserve_key(
    db: &mut Db,
    account: AccountUuid,
    purpose: Purpose,
    from: BlockHeight,
) -> OneTimeKey {
    reserve(db, account, purpose, from).unwrap()
}

/// Registers `key` as a restore discovers it, from `from`, with its history due for a
/// lookup unless this wallet scanned it.
pub(super) fn recover(
    db: &mut Db,
    account: AccountUuid,
    key: KeyId,
    from: BlockHeight,
) -> OneTimeKey {
    tx(db, |c, p| {
        let (id, key) = register(c, p, account, key)?;
        if key.key_id().purpose() == Purpose::Refund {
            store::restore::queue::funded(c, id, from)?;
        }
        Ok(key)
    })
    .unwrap()
}

/// Reserves the next refund identity using ordinary funding history.
pub(super) fn reserve_refund(
    db: &mut Db,
    account: AccountUuid,
    tip: BlockHeight,
) -> Policy<OneTimeKey> {
    db.reserve_refund_key(account, tip)
}

/// Records `observation` for `key`'s operation `reference` at `now`, adding the
/// operation with `deadline` if new.
pub(super) fn observe_with(
    db: &mut Db,
    account: AccountUuid,
    key: KeyId,
    (reference, deadline): (&str, i64),
    observation: Observation,
    now: i64,
) -> Result<(), SqliteClientError> {
    tx(db, |c, _| {
        let key = key_ref(c, account, key)?;
        let id = c.query_row(
            "SELECT id FROM ironwood_one_time_operations
             WHERE one_time_key_id = ?1 AND reference = ?2",
            rusqlite::params![key, reference],
            |r| r.get(0),
        );
        let id = match id.optional()? {
            Some(id) => id,
            None => c.query_row(
                "INSERT INTO ironwood_one_time_operations
                    (one_time_key_id, reference, deadline, begun_at)
                 VALUES (?1, ?2, ?3, ?4) RETURNING id",
                rusqlite::params![key, reference, deadline, now],
                |r| r.get(0),
            )?,
        };
        store::swap::lifecycle::record(c, id, &observation, now).map(|_| ())
    })
}

/// Records `status`, without a deposit, for `key`'s operation `reference` at `now`,
/// adding it with the test clock's time as its deadline if new.
pub(super) fn observe(
    db: &mut Db,
    account: AccountUuid,
    key: KeyId,
    reference: &str,
    status: OperationStatus,
    now: i64,
) -> Result<(), SqliteClientError> {
    let observation = Observation {
        status,
        funded: false,
        receipts: vec![],
    };
    let operation = (reference, clock_now());
    observe_with(db, account, key, operation, observation, now)
}

/// Sets the latest block's time to `now`, as when the caller's clock agrees with the
/// chain. Test blocks otherwise carry time 0, which bounds every provider deadline check.
pub(super) fn chain_agrees(db: &Db, now: i64) {
    let sql = "UPDATE blocks SET time = ?1 WHERE height = (SELECT MAX(height) FROM blocks)";
    exec(&db.conn, sql, [now]);
}

/// Every key registered to `account` by purpose and index, each re-derived and checked
/// against its stored receiver.
pub(super) fn all_keys(
    db: &Db,
    account: AccountUuid,
) -> Result<Vec<OneTimeKey>, SqliteClientError> {
    keys_where(&db.conn, &db.params, account, "1", [account.0])
}

/// The key registered to `account` as `key`, re-derived and checked.
pub(super) fn get_key(
    db: &Db,
    account: AccountUuid,
    key: KeyId,
) -> Result<Option<OneTimeKey>, SqliteClientError> {
    let (purpose, index) = (purpose_code(key.purpose())?, key.index().to_be_bytes());
    let selected = "k.purpose = ?2 AND k.key_index = ?3";
    key_matching(
        &db.conn,
        &db.params,
        account,
        selected,
        rusqlite::params![account.0, purpose, index],
    )
}

/// The key registered to `account` for `receiver`, re-derived and checked.
pub(super) fn key_for_receiver(
    db: &Db,
    account: AccountUuid,
    receiver: &orchard::Address,
) -> Result<Option<OneTimeKey>, SqliteClientError> {
    let selected = "k.receiver = ?2";
    let receiver = receiver.to_raw_address_bytes();
    key_matching(
        &db.conn,
        &db.params,
        account,
        selected,
        rusqlite::params![account.0, receiver],
    )
}

/// An accepted operation outcome with these deposit instructions.
pub(super) fn accepted(address: &str, memo: Option<&str>, deadline: i64) -> OperationOutcome {
    OperationOutcome::Accepted(ReceiveDeposit {
        address: address.into(),
        memo: memo.map(Into::into),
        deadline,
    })
}

/// The wallet's fully scanned tip.
pub(super) fn tip(st: &State) -> ChainPoint {
    let block = st.wallet().block_fully_scanned().unwrap().unwrap();
    ChainPoint {
        height: block.block_height(),
        hash: block.block_hash(),
    }
}

/// The one-time key of each unspent Ironwood note at `height`, `None` for ordinary notes.
pub(super) fn unspent_keys(st: &State, height: BlockHeight) -> Vec<Option<KeyId>> {
    let notes = notes(st, height);
    notes.iter().map(|n| n.one_time_key_id()).collect()
}

/// The first output to `fvk`'s external address in cached block `height`, as a directory
/// candidate.
pub(super) fn candidate_at(
    st: &State,
    height: BlockHeight,
    fvk: &FullViewingKey,
) -> PendingPayment {
    let sql = "SELECT data FROM compactblocks WHERE height = ?1";
    let data: Vec<u8> = value(&st.cache().0, sql, [u32::from(height)]);
    let block = CompactBlock::decode(data.as_slice()).unwrap();
    let ivk = fvk.to_ivk(Scope::External).prepare();
    let actions = block.vtx.iter().map(|tx| tx.ironwood_actions.len() as u32);
    let size = block
        .chain_metadata
        .as_ref()
        .unwrap()
        .ironwood_commitment_tree_size;
    let mut position = size - actions.sum::<u32>();
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
pub(super) fn external_payment(
    to: orchard::Address,
    memo: &zcash_protocol::memo::MemoBytes,
) -> zcash_primitives::transaction::Transaction {
    external_payment_with(to, memo, vec![])
}

/// [`external_payment`], also making the `also` payments.
pub(super) fn external_payment_with(
    to: orchard::Address,
    memo: &zcash_protocol::memo::MemoBytes,
    also: Vec<zip321::Payment>,
) -> zcash_primitives::transaction::Transaction {
    let mut funder = ironwood_wallet();
    let birthday = funder.test_account().unwrap().birthday().clone();
    let (account, usk) = funder
        .wallet_mut()
        .db_mut()
        .create_account("funder", &SecretVec::new(vec![7; 32]), &birthday, None)
        .unwrap();
    pay(&mut funder, &FullViewingKey::from(usk.orchard()), 1_000_000);
    funder.generate_and_scan_empty_blocks(5);
    let payments = std::iter::once(payment(&unified(to), 50_000, Some(memo)));
    let change = (None, zcash_protocol::ShieldedPool::Orchard);
    let (_, txid) = transfer(
        &mut funder,
        (account, &usk),
        payments.chain(also).collect(),
        change,
    );
    let db = funder.wallet();
    db.get_transaction(txid.unwrap()).unwrap().unwrap()
}

/// Encrypts `note` as a directory candidate carries it: its compact Action.
pub(super) fn encrypt_note(note: Note) -> EncryptedNote {
    let enc = IronwoodNoteEncryption::new(None, note, [4; 512]);
    let bytes = enc.encrypt_note_plaintext();
    EncryptedNote::from_parts(
        note.rho().to_bytes(),
        orchard::note::ExtractedNoteCommitment::from(note.commitment()).to_bytes(),
        IronwoodDomain::epk_bytes(enc.epk()).0,
        bytes[..52].try_into().unwrap(),
    )
}

/// `candidate` as the directory reports it.
pub(super) fn directory_answer(candidate: &PendingPayment) -> DirectoryPayment {
    let note = candidate.encrypted_note.to_bytes();
    DirectoryPayment {
        height: u32::from(candidate.height),
        block_hash: candidate.block_hash.0,
        txid: *candidate.txid.as_ref(),
        tx_index: candidate.tx_index.into(),
        action_index: candidate.action_index,
        position: candidate.position.into(),
        action_nullifier: note[..32].try_into().unwrap(),
        cmx: note[32..64].try_into().unwrap(),
        ephemeral_key: note[64..96].try_into().unwrap(),
        ciphertext_prefix: note[96..].try_into().unwrap(),
    }
}

/// Reopens `st`'s wallet database from its file.
pub(super) fn reopen<C>(st: &mut TestState<C, TestDb, LocalNetwork>) {
    let path = st.wallet().data_file_path().to_owned();
    let reopened = WalletDb::for_path(path, *st.network(), test_clock(), test_rng()).unwrap();
    *st.wallet_mut().db_mut() = reopened;
}

/// The test account's Orchard FVK, which its one-time keys derive from.
pub(super) fn parent<C>(st: &TestState<C, TestDb, LocalNetwork>) -> FullViewingKey {
    FullViewingKey::from(st.test_account().unwrap().usk().orchard())
}

/// The test account's key `key`, derived without registering it.
pub(super) fn derive<C>(st: &TestState<C, TestDb, LocalNetwork>, key: KeyId) -> FullViewingKey {
    key.derive(&parent(st)).unwrap()
}

/// Mines and scans a block paying `value` to `fvk`'s default address, returning its
/// height.
pub(super) fn pay(st: &mut State, fvk: &FullViewingKey, value: u64) -> BlockHeight {
    let recipient = IronwoodFvk(fvk.clone());
    let value = Zatoshis::const_from_u64(value);
    let (height, _, _) = st.generate_next_block(&recipient, AddressType::DefaultExternal, value);
    scan_and_recover(st, height, 1);
    height
}

/// Gives synthetic payment transactions non-coinbase indexes before either scanner sees them.
pub(super) fn payment_indexes(st: &State, from: BlockHeight, count: usize) {
    let blocks: Vec<(u32, Vec<u8>)> = rows(
        &st.cache().0,
        "SELECT height, data FROM compactblocks WHERE height >= ?1 ORDER BY height LIMIT ?2",
        rusqlite::params![u32::from(from), count],
    );
    for (height, bytes) in blocks {
        let mut block = CompactBlock::decode(bytes.as_slice()).unwrap();
        if block.vtx.iter().any(|tx| tx.index == 0) {
            for transaction in &mut block.vtx {
                transaction.index += 1;
            }
            exec(
                &st.cache().0,
                "UPDATE compactblocks SET data = ?1 WHERE height = ?2",
                rusqlite::params![block.encode_to_vec(), height],
            );
        }
    }
}

/// Scans ordinary keys, then supplies independently built directory answers for registered receivers.
/// Feature scenario tests separately exercise the actual encrypted transport and publisher.
pub(crate) fn scan_and_recover(st: &mut State, from: BlockHeight, count: usize) {
    payment_indexes(st, from, count);
    st.scan_cached_blocks(from, count);
    let accounts: Vec<AccountUuid> = column(st.wallet().conn(), "SELECT uuid FROM accounts", [])
        .into_iter()
        .map(AccountUuid)
        .collect();
    for account in accounts {
        let publication = store::restore::tests::discovery::publication_at(st, tip(st).height);
        let db = st.wallet_mut().db_mut();
        db.set_one_time_recovery_enabled(account, true).unwrap();
        assert!(
            db.begin_one_time_recovery(account, publication, false)
                .unwrap()
        );
        tx(db, |conn, _| {
            let ids: Vec<i64> = conn.prepare("SELECT k.id FROM ironwood_one_time_keys k JOIN accounts a ON a.id = k.account_id
                WHERE a.uuid = ?1 AND (k.purpose = 1 OR k.funding_height IS NOT NULL)")?
                .query_map([account.0], |r| r.get(0))?.collect::<Result<_, _>>()?;
            for id in ids { store::restore::queue::enqueue(conn, id, 0, u32::from(publication.end.height), 1)?; }
            Ok(())
        }).unwrap();
        store::restore::tests::discovery::drain(st, account, publication);
    }
}

/// `receiver` as a unified address.
pub(super) fn unified(receiver: orchard::Address) -> zcash_keys::address::Address {
    use zcash_keys::address::{Address, UnifiedAddress};
    Address::Unified(UnifiedAddress::from_receivers(Some(receiver), None, None).unwrap())
}

/// A receiver no test wallet holds.
pub(super) fn foreign_receiver() -> orchard::Address {
    let key = orchard::keys::SpendingKey::from_bytes([0xf5; 32]).unwrap();
    FullViewingKey::from(&key).address_at(0u32, Scope::External)
}

/// The P2PKH address whose key hash repeats `byte`.
pub(super) fn p2pkh(byte: u8) -> zcash_keys::address::Address {
    use transparent::address::TransparentAddress;
    zcash_keys::address::Address::Transparent(TransparentAddress::PublicKeyHash([byte; 20]))
}

/// A payment of `value` zatoshis to `to`, with `memo` if any.
pub(super) fn payment(
    to: &zcash_keys::address::Address,
    value: u64,
    memo: Option<&zcash_protocol::memo::MemoBytes>,
) -> zip321::Payment {
    let to = to.to_zcash_address(&ironwood_network());
    let value = Some(Zatoshis::const_from_u64(value));
    zip321::Payment::new(to, value, memo.cloned(), None, None, vec![]).unwrap()
}

/// A proposal the test store made.
pub(super) type Proposal = zcash_client_backend::proposal::Proposal<
    zcash_client_backend::fees::StandardFeeRule,
    crate::ReceivedNoteId,
>;

/// Proposes and creates, without mining, a transaction from `account` paying `payments`
/// with change in `pool` carrying `memo`. Returns the proposal and the transaction's
/// ID, or the store's error.
pub(super) fn transfer(
    st: &mut State,
    (account, usk): (AccountUuid, &zcash_keys::keys::UnifiedSpendingKey),
    payments: Vec<zip321::Payment>,
    (memo, pool): (
        Option<&zcash_protocol::memo::MemoBytes>,
        zcash_protocol::ShieldedPool,
    ),
) -> (
    Proposal,
    Result<zcash_primitives::transaction::TxId, SqliteClientError>,
) {
    use std::convert::Infallible;
    use zcash_client_backend::{
        data_api::{
            error::Error,
            wallet::{ConfirmationsPolicy, input_selection::GreedyInputSelector},
        },
        fees::{DustOutputPolicy, StandardFeeRule, standard::SingleOutputChangeStrategy},
        wallet::OvkPolicy,
    };
    let strategy = SingleOutputChangeStrategy::<TestDb>::new(
        StandardFeeRule::Zip317,
        memo.cloned(),
        pool,
        DustOutputPolicy::default(),
    );
    let request = zip321::TransactionRequest::new(payments).unwrap();
    let selector = GreedyInputSelector::new();
    let policy = ConfirmationsPolicy::MIN;
    let proposal = st
        .propose_transfer(account, &selector, &strategy, request, policy)
        .unwrap();
    let created = st
        .create_proposed_transactions::<Infallible, _, Infallible, _>(
            usk,
            OvkPolicy::Sender,
            &proposal,
        )
        .map(|created| created[0])
        .map_err(|e| match e {
            Error::DataSource(e) => e,
            _ => panic!("transaction creation failed outside the store"),
        });
    (proposal, created)
}

/// Spends `value` from the test account to [`foreign_receiver`] with ordinary Orchard
/// change, then mines and scans the transaction. Returns its proposal and height.
pub(super) fn spend_to_foreign(st: &mut State, value: u64) -> (Proposal, BlockHeight) {
    let account = st.test_account().cloned().unwrap();
    let to = payment(&unified(foreign_receiver()), value, None);
    let change = (None, zcash_protocol::ShieldedPool::Orchard);
    let (proposal, txid) = transfer(st, (account.id(), account.usk()), vec![to], change);
    let (height, _) = st.generate_next_block_including(txid.unwrap());
    scan_and_recover(st, height, 1);
    (proposal, height)
}

/// The value `sql` selects with `params`.
pub(super) fn value<T: rusqlite::types::FromSql>(
    conn: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
) -> T {
    conn.query_row(sql, params, |r| r.get(0)).unwrap()
}

/// The row `sql` selects with `params`, as a tuple.
pub(super) fn row<T>(conn: &Connection, sql: &str, params: impl rusqlite::Params) -> T
where
    T: for<'r> TryFrom<&'r rusqlite::Row<'r>, Error = rusqlite::Error>,
{
    conn.query_row(sql, params, |r| T::try_from(r)).unwrap()
}

/// The rows `sql` selects with `params`, as tuples.
pub(super) fn rows<T>(conn: &Connection, sql: &str, params: impl rusqlite::Params) -> Vec<T>
where
    T: for<'r> TryFrom<&'r rusqlite::Row<'r>, Error = rusqlite::Error>,
{
    let mut stmt = conn.prepare(sql).unwrap();
    let rows = stmt.query_map(params, |r| T::try_from(r)).unwrap();
    rows.collect::<Result<_, _>>().unwrap()
}

/// The values `sql` selects with `params`.
pub(super) fn column<T: rusqlite::types::FromSql>(
    conn: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
) -> Vec<T> {
    let mut stmt = conn.prepare(sql).unwrap();
    let values = stmt.query_map(params, |r| r.get(0)).unwrap();
    values.collect::<Result<_, _>>().unwrap()
}

/// Executes `sql` with `params`.
pub(super) fn exec(conn: &Connection, sql: &str, params: impl rusqlite::Params) {
    conn.execute(sql, params).unwrap();
}

/// The test account's unspent Ironwood notes at `height`.
pub(super) fn notes(
    st: &State,
    height: BlockHeight,
) -> Vec<zcash_client_backend::wallet::ReceivedNote<crate::ReceivedNoteId, Note>> {
    let account = st.test_account().unwrap().id();
    let db = st.wallet().db();
    db.get_unspent_ironwood_notes_at_historical_height(account, height)
        .unwrap()
}

mod enhancement;
mod journal;
mod key_access;
mod marker;
mod scanning;
mod selection;

/// Reservations survive a reopen, and each purpose and account has its own index space,
/// whose keys another account cannot look up.
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

    reopen(&mut st);
    let db = st.wallet_mut().db_mut();
    let keys = all_keys(db, account).unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(
        keys[0].full_viewing_key().to_bytes(),
        refund.full_viewing_key().to_bytes()
    );
    assert_eq!(keys[1].receiver(), incoming.receiver());
    let next = reserve_key(db, account, Purpose::Refund, start());
    assert_eq!(next.key_id().index(), 1);

    let seed = SecretVec::new(st.test_seed().unwrap().expose_secret().clone());
    let birthday = st.test_account().unwrap().birthday().clone();
    let db = st.wallet_mut().db_mut();
    let (other, _) = db.create_account("other", &seed, &birthday, None).unwrap();
    for key in [&refund, &incoming] {
        assert!(get_key(db, other, key.key_id()).unwrap().is_none());
        let found = key_for_receiver(db, other, &key.receiver());
        assert!(found.unwrap().is_none());
    }
    let key = reserve_key(db, other, Purpose::Refund, start());
    assert_eq!(key.key_id().index(), 0);
    assert_ne!(key.receiver(), refund.receiver());
}

/// Two accounts register the same key identity, and a payment to the second account's
/// key is stored under that account and key, never checked against the first's.
#[test]
fn a_payment_matches_the_key_of_its_own_account() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let seed = SecretVec::new(st.test_seed().unwrap().expose_secret().clone());
    let birthday = st.test_account().unwrap().birthday().clone();
    let from = st.wallet().chain_height().unwrap().unwrap() + 1;
    let db = st.wallet_mut().db_mut();
    let (other, _) = db.create_account("other", &seed, &birthday, None).unwrap();
    let mine = reserve_key(db, account, Purpose::Receive, from);
    let theirs = reserve_key(db, other, Purpose::Receive, from);
    assert_eq!(mine.key_id(), theirs.key_id());
    // Adding an account schedules its birthday history before it can have a fully scanned tip.
    st.scan_cached_blocks(BlockHeight::from_u32(100_000), 1);
    pay(&mut st, theirs.full_viewing_key(), 10_000);
    let sql = "SELECT a.uuid = ?1, k.account_id = n.account_id, n.value
               FROM ironwood_received_notes n JOIN accounts a ON a.id = n.account_id
               JOIN ironwood_one_time_keys k ON k.id = n.one_time_key_id";
    let stored: Vec<(bool, bool, i64)> = rows(st.wallet().conn(), sql, [other.0]);
    assert_eq!(stored, [(true, true, 10_000)]);
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
        Err(SqliteClientError::InvalidOneTimeIvkInput(_))
    ));
    assert_eq!(all_keys(db, account).unwrap().len(), 6);
}

#[test]
fn operation_and_reservation_commit_or_roll_back_together() {
    let mut st = wallet(false);
    let account = st.test_account().unwrap().id();
    let schema = "CREATE TABLE ext_operations (key_index BLOB NOT NULL)";
    st.wallet().conn().execute_batch(schema).unwrap();
    let db = st.wallet_mut().db_mut();
    let reserve_with = |db: &mut Db, fail: bool| {
        db.transactionally_with_extension(|tx, ext| {
            let (conn, params) = (tx.conn.0, tx.params);
            let key = reserve_in(conn, params, account, Purpose::Refund, start(), 0)?;
            let index = key.key_id().index().to_le_bytes();
            ext.execute("INSERT INTO ext_operations VALUES (?1)", [&index])?;
            if fail {
                return Err(corrupt("fixture operation write failed"));
            }
            Ok(key)
        })
    };
    assert!(reserve_with(db, true).is_err());
    assert!(all_keys(db, account).unwrap().is_empty());
    assert_eq!(reserve_with(db, false).unwrap().key_id().index(), 0);
    let count: u32 = value(
        st.wallet().conn(),
        "SELECT COUNT(*) FROM ext_operations",
        [],
    );
    assert_eq!(count, 1);
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
                // A loaded CI runner can hold the other writer's lock far longer than a
                // fixed retry count allows, so retry until a generous deadline instead.
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
                while std::time::Instant::now() < deadline {
                    match reserve(&mut db, account, Purpose::Refund, start()) {
                        Ok(key) => return key.key_id().index(),
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
fn account_deletion_cascades_and_unknown_accounts_cannot_reserve() {
    let mut st = wallet(false);
    let account = st.test_account().unwrap().id();
    reserve_key(st.wallet_mut().db_mut(), account, Purpose::Refund, start());
    st.wallet_mut().delete_account(account).unwrap();
    let sql = "SELECT COUNT(*) FROM ironwood_one_time_keys";
    assert_eq!(value::<u32>(st.wallet().conn(), sql, []), 0);
    assert!(matches!(
        reserve(st.wallet_mut().db_mut(), account, Purpose::Refund, start()),
        Err(SqliteClientError::AccountUnknown)
    ));
}

/// A key with a note can't be deleted alone, but deleting its account removes both,
/// also when the notes go only by the account's own cascade.
#[test]
fn a_key_with_notes_is_deleted_only_with_its_account() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let from = st.wallet().chain_height().unwrap().unwrap() + 1;
    let key = reserve_key(st.wallet_mut().db_mut(), account, Purpose::Refund, from);
    pay(&mut st, key.full_viewing_key(), 10_000);
    let count = |st: &State, table: &str| {
        let sql = format!("SELECT COUNT(*) FROM {table}");
        value::<u32>(st.wallet().conn(), &sql, [])
    };
    let sql = "SELECT COUNT(*) FROM ironwood_received_notes WHERE one_time_key_id IS NOT NULL";
    assert_eq!(value::<u32>(st.wallet().conn(), sql, []), 1);
    let conn = st.wallet().conn();
    let deleted = conn.execute("DELETE FROM ironwood_one_time_keys", []);
    assert!(matches!(deleted, Err(rusqlite::Error::SqliteFailure(e, _))
        if e.code == rusqlite::ErrorCode::ConstraintViolation));
    conn.execute_batch("SAVEPOINT s; DELETE FROM accounts; ROLLBACK TO s; RELEASE s;")
        .unwrap();
    assert_eq!(count(&st, "ironwood_one_time_keys"), 5);
    st.wallet_mut().delete_account(account).unwrap();
    assert_eq!(count(&st, "ironwood_one_time_keys"), 0);
    assert_eq!(count(&st, "ironwood_received_notes"), 0);
}
