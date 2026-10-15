pub(super) use std::sync::{Arc, Barrier};

pub(super) use incrementalmerkletree::Hashable;
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
        one_time_ivk::{
            OneTimeIvkRead as _,
            restore::{
                DirectoryPayment, DiscoveryWork, MAX_PUBLICATION_LAG, OneTimeIvkRestoreRead as _,
                OneTimeIvkRestoreWrite as _, PaymentApplication, SweepDeferral,
                recovery::EncryptedNote,
            },
        },
        testing::{AddressType, IronwoodFvk, TestBuilder, TestRng, TestState},
        transparent_ledger::ChainPoint,
    },
    proto::compact_formats::CompactBlock,
};
pub(super) use zcash_note_encryption::{Domain, try_compact_note_decryption};
pub(super) use zcash_primitives::block::BlockHash;
pub(super) use zcash_protocol::{local_consensus::LocalNetwork, value::Zatoshis};

pub(super) use super::{
    restore::payments::{PendingPayment, SpendStatus},
    swap::*,
    *,
};
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

/// An Ironwood wallet scanned through one empty block, so it is at its tip.
pub(super) fn scanned_wallet() -> State {
    let mut st = ironwood_wallet();
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    st
}

pub(super) fn start() -> BlockHeight {
    BlockHeight::from_u32(100)
}

/// The test clock's time, which registration stamps on keys.
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
    let index = if purpose == Purpose::Refund {
        store::swap::funding::next_refund_index(c, p, account, None, now)?.unwrap()
    } else {
        let sql = "SELECT MAX(k.key_index) FROM ironwood_one_time_keys k
                   JOIN accounts a ON a.id = k.account_id
                   WHERE a.uuid = ?1 AND k.purpose = 1 AND k.advances_allocation = 1";
        let last: Option<Vec<u8>> = c.query_row(sql, [account.0], |r| r.get(0))?;
        last.map_or(Ok(0), |bytes| index_after(decode_index(bytes)?, 1))?
    };
    let key = KeyId::new(purpose, index);
    register(c, p, account, key, from, true, Discovery::Scan, now).map(|(_, key)| key)
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

/// Registers incoming lookahead key `index` for a sweep, expecting payments from `from`.
pub(super) fn watch(
    db: &mut Db,
    account: AccountUuid,
    index: u64,
    from: BlockHeight,
) -> OneTimeKey {
    tx(db, |c, p| {
        store::restore::recovery::watch_receive_key(c, p, account, index, from, clock_now())
    })
    .unwrap()
}

/// Registers `key` as recovered evidence would, from `from`. A key this wallet never
/// scanned is queued for a receiver-directory sweep.
pub(super) fn recover(
    db: &mut Db,
    account: AccountUuid,
    key: KeyId,
    from: BlockHeight,
) -> OneTimeKey {
    let (sweep, now) = (Discovery::Sweep, clock_now());
    tx(db, |c, p| {
        register(c, p, account, key, from, true, sweep, now)
    })
    .unwrap()
    .1
}

/// Keeps the incoming lookahead keys.
pub(super) fn lookahead(db: &mut Db, account: AccountUuid) {
    use store::restore::recovery::maintain_receive_lookahead as maintain;
    let now = clock_now();
    tx(db, |c, p| maintain(c, p, account, now)).unwrap()
}

/// Reserves like `WalletDb::prepare_receive_reservation`, scanning a new key from `from`,
/// without readiness checks, reaping or lookahead registration.
pub(super) fn prepare_from(
    db: &mut Db,
    account: AccountUuid,
    now: i64,
    from: BlockHeight,
    seen: Option<&ProviderSeen<'_>>,
) -> Policy<OneTimeKey> {
    tx(db, |c, p| {
        if let Some(seen) = seen {
            let (owner, _) = account_key(c, p, account)?;
            store::swap::reservations::record_seen(c, owner.0, seen)?;
        }
        store::swap::reservations::prepare(c, p, account, now, from, seen)
    })
}

/// Queues a complete lookup of `key` at `anchor` that found `payments`. A deferral is
/// an error here.
pub(super) fn queue_lookup(
    db: &mut Db,
    account: AccountUuid,
    key: KeyId,
    anchor: ChainPoint,
    payments: &[PendingPayment],
) -> Result<(), SqliteClientError> {
    tx(db, |c, p| {
        store::restore::planner::queue_lookup(c, p, account, key, anchor, payments)
    })?
    .map_err(|deferral| corrupt(&format!("{deferral:?}")))
}

/// Authenticates and queues `candidate` for `key`.
pub(super) fn queue_payment(
    db: &mut Db,
    account: AccountUuid,
    key: KeyId,
    candidate: &PendingPayment,
) -> Result<(), SqliteClientError> {
    tx(db, |c, p| {
        store::restore::payments::queue_payment(c, p, account, key, candidate)
    })
}

/// Authenticates `candidate` and checks its spend evidence through `through`.
pub(super) fn spend_status(
    db: &mut Db,
    account: AccountUuid,
    key: KeyId,
    candidate: &PendingPayment,
    through: ChainPoint,
) -> Result<SpendStatus, SweepDeferral> {
    tx(db, |c, p| {
        let (_, note) = store::restore::payments::authenticate(c, p, account, key, candidate)?;
        store::restore::payments::spend_status(c, candidate, note.nullifier(), through)
    })
    .unwrap()
}

/// Retains `account`'s Ironwood spend evidence, as maintenance does.
pub(super) fn retain(db: &mut Db, account: AccountUuid) {
    tx(db, |c, p| {
        store::restore::retention::retain_spend_history(c, p, account)
    })
    .unwrap()
}

/// Releases retained nullifiers at `through`.
pub(super) fn finish_recovery(
    db: &mut Db,
    account: AccountUuid,
    through: ChainPoint,
) -> Result<bool, SqliteClientError> {
    use store::restore::retention::finish_nullifier_recovery as finish;
    let now = clock_now();
    tx(db, |c, p| finish(c, p, account, through, now))
}

/// Starts or extends trial decryption of `key` from `from`, as registration and
/// finished refund sweeps do.
pub(super) fn activate_key(db: &mut Db, account: AccountUuid, key: KeyId, from: BlockHeight) {
    assert!(tx(db, |c, _| activate(c, key_ref(c, account, key)?, from)).unwrap());
}

/// `account`'s queued candidates for `key`.
pub(super) fn pending(db: &Db, account: AccountUuid, key: KeyId) -> Vec<PendingPayment> {
    store::restore::payments::pending_payments(&db.conn, account, key).unwrap()
}

/// Applies queued `candidate` with `path` at `anchor`.
pub(super) fn apply_payment(
    db: &mut Db,
    account: AccountUuid,
    key: KeyId,
    candidate: &PendingPayment,
    through: ChainPoint,
    (anchor, path): (ChainPoint, &MerklePath),
) -> Result<PaymentApplication, SqliteClientError> {
    use store::restore::apply::apply_payment as apply;
    let (mode, anchored) = (db.transparent_ledger_mode, (anchor, path));
    let session = db.enhance_pir_session.clone();
    tx(db, |c, p| {
        apply(
            c,
            &Default::default(),
            p,
            mode,
            &session,
            account,
            key,
            candidate,
            through,
            anchored,
        )
    })
    .map(|applied| applied.expect("the payment's blocks are on the wallet's chain"))
}

/// Finishes `key`'s sweep after an empty lookup at `anchor`.
pub(super) fn finish_sweep(db: &mut Db, account: AccountUuid, key: KeyId, anchor: ChainPoint) {
    queue_lookup(db, account, key, anchor, &[]).unwrap();
    let applied = db.apply_one_time_sweep(account, key, anchor, anchor, WATCHED, |_, _| None);
    assert_eq!(applied.unwrap(), Ok(PaymentApplication::Applied));
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
        store::swap::lifecycle::record(c, id, observation, now).map(|_| ())
    })
}

/// Records `status`, without a deposit, for `key`'s operation `reference` at `now`,
/// adding it with the deadline registration time if new.
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
    };
    let operation = (reference, clock_now());
    observe_with(db, account, key, operation, observation, now)
}

/// [`WalletDb::close_finished_one_time_keys`] with `tip`'s block time set to `now`, as
/// when the caller's clock agrees with the chain.
pub(super) fn close_at(db: &mut Db, account: AccountUuid, now: i64, tip: BlockHeight) -> usize {
    let sql = "UPDATE blocks SET time = ?2 WHERE height = ?1";
    exec(&db.conn, sql, rusqlite::params![u32::from(tip), now]);
    db.close_finished_one_time_keys(account, now, tip).unwrap()
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

/// `key`'s stored scan start and whether it advances allocation.
pub(super) fn key_state(db: &Db, key: KeyId) -> (BlockHeight, bool) {
    let sql = "SELECT scan_from, advances_allocation FROM ironwood_one_time_keys
               WHERE purpose = ?1 AND key_index = ?2";
    let purpose = purpose_code(key.purpose()).unwrap();
    let params = rusqlite::params![purpose, key.index().to_be_bytes()];
    let (from, advances): (u32, bool) = row(&db.conn, sql, params);
    (from.into(), advances)
}

/// `key`'s last queued lookup, if it is still on the wallet's chain.
pub(super) fn lookup_coverage(db: &Db, account: AccountUuid, key: KeyId) -> Option<ChainPoint> {
    let id = key_ref(&db.conn, account, key).unwrap();
    let sql = "SELECT lookup_height, lookup_hash FROM ironwood_one_time_sweeps
               WHERE one_time_key_id = ?1";
    let (height, hash) = row(&db.conn, sql, [id]);
    let lookup = store::restore::planner::anchor(height, hash);
    store::restore::planner::canonical(&db.conn, lookup).unwrap()
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

/// A sweep's `recent` flag for a receiver a swap may still pay, so its key keeps
/// scanning.
pub(super) const WATCHED: bool = true;

/// Keys the scanner trial-decrypts with.
pub(super) fn scanning_keys(st: &State) -> Vec<KeyId> {
    let keys = st.wallet().get_one_time_scanning_keys().unwrap();
    keys.iter().map(|k| k.key_id()).collect()
}

/// Pays `key` in a new scanned block and returns the output as a directory
/// candidate. The output must be the chain's first Ironwood leaf.
pub(super) fn pay_candidate(st: &mut State, key: KeyId) -> PendingPayment {
    let fvk = derive(st, key);
    let height = pay(st, &fvk, 100_000);
    let candidate = candidate_at(st, height, &fvk);
    assert_eq!(candidate.position, 0);
    candidate
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
    funder.generate_and_scan_empty_blocks_with_one_time_ivks(5);
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

/// The authentication path of the first leaf in an otherwise empty tree.
pub(super) fn first_leaf_path() -> MerklePath {
    MerklePath::from_parts(
        0,
        std::array::from_fn(|level| MerkleHashOrchard::empty_root((level as u8).into())),
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
    st.scan_cached_blocks_with_one_time_ivks(height, 1);
    height
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
    st.scan_cached_blocks_with_one_time_ivks(height, 1);
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

/// [`apply_payment`] with `path` at `through`.
pub(super) fn apply(
    db: &mut Db,
    account: AccountUuid,
    key: KeyId,
    candidate: &PendingPayment,
    through: ChainPoint,
    path: &MerklePath,
) -> PaymentApplication {
    apply_payment(db, account, key, candidate, through, (through, path)).unwrap()
}

/// The wallet's Ironwood nullifier retention height.
pub(super) fn retention_height(st: &State) -> Option<BlockHeight> {
    crate::wallet::ironwood_nullifier_retention_height(st.wallet().conn()).unwrap()
}

mod enhancement;
mod key_access;
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
        let found = db.get_one_time_key_for_receiver(other, &key.receiver());
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
    pay(&mut st, theirs.full_viewing_key(), 10_000);
    let sql = "SELECT a.uuid = ?1, k.account_id = n.account_id, n.value
               FROM ironwood_received_notes n JOIN accounts a ON a.id = n.account_id
               JOIN ironwood_one_time_keys k ON k.id = n.one_time_key_id";
    let stored: Vec<(bool, bool, i64)> = rows(st.wallet().conn(), sql, [other.0]);
    assert_eq!(stored, [(true, true, 10_000)]);
}

/// Lookahead keys wait for their sweeps without advancing allocation, so issuance never
/// skips them; recovery evidence promotes a key and only widens its history, and the
/// lookahead extends only above the highest recovered index.
#[test]
fn lookahead_waits_for_sweeps_and_extends_above_recovered_keys() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    let window = RECEIVE_GAP_LIMIT;
    lookahead(db, account);
    lookahead(db, account);
    let keys = all_keys(db, account).unwrap();
    assert_eq!(keys.len() as u64, window);
    assert!(keys.iter().all(|k| !key_state(db, k.key_id()).1));
    let key_id = KeyId::new(Purpose::Receive, window - 2);
    recover(db, account, key_id, 80.into());
    assert!(key_state(db, key_id).1);
    watch(db, account, window - 2, 120.into());
    assert_eq!(key_state(db, key_id), (BlockHeight::from_u32(80), true));
    assert_eq!(all_keys(db, account).unwrap().len() as u64, window);
    // The unswept lookahead's top index waits for its sweep rather than being skipped.
    let issued = prepare_from(db, account, clock_now(), start(), None);
    assert_eq!(issued.unwrap().err(), Some(ReservationPolicy::Gap));
    let refund = reserve_key(db, account, Purpose::Refund, start());
    assert_eq!(refund.key_id().index(), 0);
    recover(
        db,
        account,
        KeyId::new(Purpose::Receive, window - 1),
        start(),
    );
    lookahead(db, account);
    let keys = all_keys(db, account).unwrap();
    let incoming = keys
        .iter()
        .filter(|k| k.key_id().purpose() == Purpose::Receive);
    assert_eq!(incoming.count() as u64, 2 * window);
    assert_eq!(keys.last().unwrap().key_id().index(), 2 * window - 1);
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
                for _ in 0..20 {
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
    assert_eq!(count(&st, "ironwood_one_time_keys"), 1);
    st.wallet_mut().delete_account(account).unwrap();
    assert_eq!(count(&st, "ironwood_one_time_keys"), 0);
    assert_eq!(count(&st, "ironwood_received_notes"), 0);
}
