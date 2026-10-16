//! Restore sweeps end to end: a restored wallet looks up its one-time keys in a receiver
//! directory served in process, over the service's routes and real PIR, and imports
//! what it finds only after checking it against its own chain. The service's own HTTP
//! router is tested against these clients in wallet-pir.

use std::{
    cell::RefCell,
    num::NonZeroU32,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use orchard::keys::{FullViewingKey, Scope};
use receiver_directory::{
    RawRecord,
    snapshot::{Manifest, PROFILE, ProviderSet, Snapshot},
};
use receiver_pir::{MIN_ROWS, server::Server};
use zakura_one_time_ivk::swap::RESTORE_WATCH_SECS;
use zakura_pir_receiver::{
    DirectoryError, EarlyRestore, Error, FIRST_WINDOW, GAP, MAX_KEYS, Swept, Transport, WriteLock,
    begin_early_restore, fetch_seen, sweep,
};
use zakura_receiver_crypto::{
    Payment, Receiver, Record,
    witness::{Publication, WitnessSnapshot},
};
use zcash_client_backend::data_api::{
    Account as _, WalletRead as _, WalletWrite as _,
    chain::BlockSource as _,
    one_time_ivk::{
        OneTimeIvkRead as _,
        restore::{
            OneTimeIvkRestoreRead as _, OneTimeIvkRestoreWrite as _, PaymentApplication,
            SweepDeferral,
        },
    },
    testing::{AddressType, IronwoodFvk, TestBuilder, TestRng, TestState},
    transparent_ledger::ChainPoint,
};
use zcash_client_sqlite::{
    AccountUuid, WalletDb,
    error::SqliteClientError,
    testing::{
        BlockCache,
        db::{TestDb, TestDbFactory},
    },
    util::SystemClock,
    wallet::one_time_ivk::{
        KeyId, Purpose,
        swap::{ProviderSeen, RECEIVE_GAP_LIMIT},
    },
};
use zcash_primitives::block::BlockHash;
use zcash_protocol::{consensus::BlockHeight, local_consensus::LocalNetwork, value::Zatoshis};

/// Asserts that a value matches a pattern, showing the value otherwise.
macro_rules! assert_matches {
    ($value:expr, $($pattern:tt)+) => {
        match &$value {
            value => assert!(matches!(value, $($pattern)+), "{value:?}"),
        }
    };
}

type State = TestState<BlockCache, TestDb, LocalNetwork>;

/// The genesis hash the fixture's publications commit to.
const GENESIS: [u8; 32] = [9; 32];
/// The origin requests name. The transport serves them in process.
const ORIGIN: &str = "https://receiver.test";
/// Ironwood activation, the history every publication must cover.
const ACTIVATION: u32 = 100_000;
/// The caller's clock.
const NOW: i64 = 1_700_000_000;
/// The payout's value.
const VALUE: u64 = 100_000;

/// A wallet with Ironwood active from its first block, stored as `factory` makes it. Its
/// incoming lookahead is registered before it scans, as a restore does, so scanning keeps
/// the spend evidence sweeps need.
fn ironwood_wallet_in(factory: TestDbFactory) -> State {
    let activation = BlockHeight::from_u32(ACTIVATION);
    let mut st = TestBuilder::new()
        .with_network(LocalNetwork {
            nu6: Some(activation),
            nu6_1: Some(activation),
            nu6_2: Some(activation),
            nu6_3: Some(activation),
            ..TestBuilder::<(), ()>::DEFAULT_NETWORK
        })
        .with_data_store_factory(factory)
        .with_block_cache(BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();
    let account = st.test_account().unwrap().id();
    restore(&mut st, account);
    st
}

/// The wallet's fully scanned tip.
fn tip(st: &State) -> ChainPoint {
    let block = st.wallet().block_fully_scanned().unwrap().unwrap();
    ChainPoint {
        height: block.block_height(),
        hash: block.block_hash(),
    }
}

/// The test account's Orchard key, which its one-time keys derive from.
fn parent(st: &State) -> FullViewingKey {
    FullViewingKey::from(st.test_account().unwrap().usk().orchard())
}

/// The receiver of one-time key `key` under the Orchard key `parent`.
fn key_receiver(parent: &FullViewingKey, key: KeyId) -> Receiver {
    let fvk = key.derive(parent).unwrap();
    Receiver::from_bytes(fvk.address_at(0u32, Scope::External).to_raw_address_bytes()).unwrap()
}

/// The receiver of the test account's incoming one-time key `index`.
fn receiver(st: &State, index: u64) -> Receiver {
    key_receiver(&parent(st), KeyId::new(Purpose::Receive, index))
}

/// Pays incoming one-time key `index` under the Orchard key `parent` in a new block left
/// unscanned, and returns the payment as the directory lists it. The output is the
/// chain's Ironwood leaf at `position`, which is the number of earlier Ironwood outputs.
fn pay_unscanned_to(st: &mut State, parent: &FullViewingKey, index: u64, position: u64) -> Record {
    let key = KeyId::new(Purpose::Receive, index);
    let fvk = key.derive(parent).unwrap();
    let (height, _, _) = st.generate_next_block(
        &IronwoodFvk(fvk),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(VALUE),
    );
    let block = cached(st, height);
    let tx = &block.vtx[0];
    let compact = &tx.ironwood_actions[0];
    Record {
        receiver: key_receiver(parent, key),
        page: 0,
        total: 1,
        payment: Payment {
            height: u32::from(height),
            block_hash: block.hash().0,
            txid: *tx.txid().as_ref(),
            // The mock block has no coinbase; the directory refuses index 0 as one.
            tx_index: u32::try_from(tx.index).unwrap() + 1,
            action_index: 0,
            position,
            action_nullifier: compact.nullifier.as_slice().try_into().unwrap(),
            cmx: compact.cmx.as_slice().try_into().unwrap(),
            ephemeral_key: compact.ephemeral_key.as_slice().try_into().unwrap(),
            ciphertext_prefix: compact.ciphertext.as_slice().try_into().unwrap(),
        },
    }
}

/// [`pay_unscanned_to`] for the test account.
fn pay_unscanned(st: &mut State, index: u64, position: u64) -> Record {
    let parent = parent(st);
    pay_unscanned_to(st, &parent, index, position)
}

/// [`pay_unscanned`], then scans the payment's block. Scanning cannot find it: a restored
/// key is swept before it is ever scanned.
fn pay_restored_key(st: &mut State, index: u64, position: u64) -> Record {
    let record = pay_unscanned(st, index, position);
    st.scan_cached_blocks_with_one_time_ivks(BlockHeight::from(record.payment.height), 1);
    record
}

/// The cached block at `height`.
fn cached(
    st: &State,
    height: BlockHeight,
) -> zcash_client_backend::proto::compact_formats::CompactBlock {
    let mut block = None;
    st.cache()
        .with_blocks::<_, ()>(Some(height), Some(1), |cb| {
            block = Some(cb);
            Ok(())
        })
        .unwrap();
    block.unwrap()
}

/// A restored wallet at its fully scanned tip, after payments to its incoming keys.
struct Restored {
    st: State,
    account: AccountUuid,
    through: ChainPoint,
    /// The payments as the directory lists them, in chain order.
    records: Vec<Record>,
}

/// Pays incoming key `paid[i]` as the chain's Ironwood output `i`, each payment a page of
/// its key's lookup, then scans one more block and registers the restored lookahead.
fn restored(paid: &[u64]) -> Restored {
    let mut st = ironwood_wallet_in(TestDbFactory::default());
    let account = st.test_account().unwrap().id();
    let mut records = Vec::new();
    for (position, index) in (0..).zip(paid) {
        let mut record = pay_restored_key(&mut st, *index, position);
        let pages = |paid: &[u64]| paid.iter().filter(|i| *i == index).count();
        record.page = pages(&paid[..records.len()]).try_into().unwrap();
        record.total = pages(paid).try_into().unwrap();
        records.push(record);
    }
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    restore(&mut st, account);
    let through = tip(&st);
    Restored {
        st,
        account,
        through,
        records,
    }
}

/// The test account's total balance in zatoshis.
fn balance(st: &State) -> u64 {
    st.get_total_balance(st.test_account().unwrap().id())
        .into_u64()
}

/// Whether the test account still has sweeps or queued payments through `through`.
fn pending(st: &State, through: ChainPoint) -> bool {
    let account = st.test_account().unwrap().id();
    let db = st.wallet().db();
    db.one_time_history_pending(account, through.height)
        .unwrap()
}

/// The indices of the keys the wallet scans with, in order.
fn scanning(st: &State) -> Vec<u64> {
    let keys = st.wallet().get_one_time_scanning_keys().unwrap();
    let mut indices: Vec<_> = keys.iter().map(|k| k.key_id().index()).collect();
    indices.sort();
    indices
}

/// A swap provider's sets: an empty recent set covering the wallet's restore watch, and
/// every receiver it ever had, from a feed that started long before [`NOW`] and last
/// read the provider a minute before it.
fn provider(seen: &[Receiver]) -> Vec<ProviderSet> {
    provider_named("near-intents", seen)
}

/// [`provider`]'s sets for the provider `name`.
fn provider_named(name: &str, seen: &[Receiver]) -> Vec<ProviderSet> {
    let since_unix = NOW - 2 * RESTORE_WATCH_SECS;
    let until_unix = NOW - 60;
    vec![
        ProviderSet {
            label: format!("{name}/recent"),
            window_secs: Some(RESTORE_WATCH_SECS.try_into().unwrap()),
            since_unix,
            until_unix,
            receivers: Vec::new(),
        },
        ProviderSet {
            label: format!("{name}/seen"),
            window_secs: None,
            since_unix,
            until_unix,
            receivers: seen.iter().map(|r| *r.as_bytes()).collect(),
        },
    ]
}

/// A publication of `records` ending at `end`, with the common witnesses over the
/// chain's Ironwood `commitments`, if any, and the swap `provider` sets in its filters,
/// served by the receiver service's routes.
fn publish(
    records: &[Record],
    commitments: &[[u8; 32]],
    end: ChainPoint,
    provider: &[ProviderSet],
) -> Routes {
    let raw: Vec<_> = records.iter().map(raw_record).collect();
    publish_raw(&raw, commitments, end, provider)
}

/// [`publish`]es row slots as given, whether or not a publisher would accept them.
fn publish_raw(
    records: &[RawRecord],
    commitments: &[[u8; 32]],
    end: ChainPoint,
    provider: &[ProviderSet],
) -> Routes {
    let manifest = Manifest {
        profile: PROFILE.into(),
        genesis: GENESIS,
        start_height: ACTIVATION,
        start_parent: [0; 32],
        start_position: 0,
        end_height: end.height.into(),
        end_hash: end.hash.0,
        end_position: commitments.len() as u64,
        rows: MIN_ROWS,
        salt: [5; 32],
        records: 0,
        data_sha256: [0; 32],
        filters: Vec::new(),
        filters_sha256: [0; 32],
    };
    let snapshot = Snapshot::build(manifest, records, provider).unwrap();
    let positions = records
        .iter()
        .map(|record| u32::try_from(record.payment.position).unwrap())
        .collect();
    // A chain without Ironwood outputs has no witnesses to serve.
    let witnesses = (!commitments.is_empty()).then(|| {
        WitnessSnapshot::build(&publication(&snapshot.manifest), commitments, &positions)
            .unwrap()
            .encode()
    });
    Routes::new(Server::new(snapshot).unwrap(), witnesses)
}

/// `record`'s row slot, which the publisher writes after validating it.
fn raw_record(record: &Record) -> RawRecord {
    RawRecord::decode(&record.encode().unwrap())
        .unwrap()
        .unwrap()
}

/// The fields of `manifest` its witness file binds to.
fn publication(manifest: &Manifest) -> Publication {
    Publication {
        genesis: manifest.genesis,
        directory_revision: manifest.revision().unwrap(),
        end_height: manifest.end_height,
        end_hash: manifest.end_hash,
        start_position: manifest.start_position,
        end_position: manifest.end_position,
        records: manifest.records,
    }
}

/// One publication's receiver routes, answered as the receiver service answers them:
/// its manifest, PIR setup, rows, filters and witnesses, and real PIR evaluation of
/// each encrypted query. A session it does not serve is gone (410).
struct Routes {
    server: Server,
    id: String,
    witnesses: Option<Vec<u8>>,
}

impl Routes {
    fn new(server: Server, witnesses: Option<Vec<u8>>) -> Self {
        Self {
            id: hex::encode(server.id()),
            server,
            witnesses,
        }
    }

    /// The status and body for `method` on `path`.
    fn answer(&self, method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
        let route = path.strip_prefix("/v1/receiver/").unwrap_or(path);
        if (method, route) == ("POST", "query") {
            return match self.server.respond(body) {
                Ok(response) => (200, response),
                Err(receiver_pir::Error::Revision) => (410, Vec::new()),
                Err(receiver_pir::Error::Malformed) => (400, Vec::new()),
                Err(_) => (500, Vec::new()),
            };
        }
        if (method, route) == ("GET", "init") {
            return (200, serde_json::to_vec(self.server.manifest()).unwrap());
        }
        let Some((material, id)) = route.split_once('/').filter(|_| method == "GET") else {
            return (404, Vec::new());
        };
        if hex::decode(id).ok().filter(|id| id.len() == 32).is_none() {
            return (400, Vec::new());
        }
        if id != self.id {
            return (410, Vec::new());
        }
        match material {
            "public" => (200, self.server.public().to_vec()),
            "rows" => (200, self.server.rows().to_vec()),
            "filters" => (200, self.server.filters().to_vec()),
            "witness" => match &self.witnesses {
                Some(bytes) => (200, bytes.clone()),
                None => (503, Vec::new()),
            },
            _ => (404, Vec::new()),
        }
    }
}

/// Serves a [`publish`]ed publication of `records`, the chain's only Ironwood outputs,
/// ending at `end`, with a provider that has seen nothing.
fn serve(records: &[Record], end: ChainPoint) -> Directory {
    let commitments: Vec<_> = records.iter().map(|record| record.payment.cmx).collect();
    Directory::new(publish(records, &commitments, end, &provider(&[])))
}

/// Serves a directory's routes in process and records every request.
struct Directory {
    routes: Routes,
    requests: Mutex<Vec<String>>,
}

impl Directory {
    /// Serves `routes` at [`ORIGIN`].
    fn new(routes: Routes) -> Self {
        Self {
            routes,
            requests: Mutex::new(Vec::new()),
        }
    }

    /// Every request so far, as method and path.
    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }

    /// Sends one request to the routes, failing over `limit` bytes as a transport must.
    async fn send(
        &self,
        method: &str,
        url: &str,
        body: Vec<u8>,
        limit: usize,
    ) -> Result<Vec<u8>, DirectoryError> {
        let path = url
            .strip_prefix(ORIGIN)
            .expect("requests stay on the origin");
        self.requests
            .lock()
            .unwrap()
            .push(format!("{method} {path}"));
        let (status, body) = self.routes.answer(method, path, &body);
        if body.len() > limit {
            return Err(DirectoryError::Transport("response over its limit".into()));
        }
        match status {
            200 => Ok(body),
            409 | 410 => Err(DirectoryError::Revision),
            status => Err(DirectoryError::Transport(format!("HTTP {status}"))),
        }
    }
}

impl Transport for Directory {
    async fn get(&self, url: &str, limit: usize) -> Result<Vec<u8>, DirectoryError> {
        self.send("GET", url, Vec::new(), limit).await
    }

    async fn post(
        &self,
        url: &str,
        body: Vec<u8>,
        limit: usize,
    ) -> Result<Vec<u8>, DirectoryError> {
        self.send("POST", url, body, limit).await
    }
}

/// The receiver lookups `directory` has served.
fn lookups(directory: &Directory) -> usize {
    let requests = directory.requests();
    requests
        .iter()
        .filter(|r| *r == "POST /v1/receiver/query")
        .count()
}

/// A test needs no lock: nothing else writes to its wallet.
struct NoLock;

impl WriteLock for NoLock {
    fn write<T>(&self, _: &'static str, write: impl FnOnce() -> T) -> T {
        write()
    }
}

/// Records each write's label.
#[derive(Default)]
struct Labels(RefCell<Vec<&'static str>>);

impl WriteLock for Labels {
    fn write<T>(&self, label: &'static str, write: impl FnOnce() -> T) -> T {
        self.0.borrow_mut().push(label);
        write()
    }
}

/// Registers the restored incoming lookahead, as a restore does at the tip.
fn restore(st: &mut State, account: AccountUuid) {
    st.wallet_mut()
        .db_mut()
        .maintain_one_time_ivks(account)
        .unwrap();
}

/// Runs one sweep of the test account through `through` at `now`.
async fn run(
    st: &mut State,
    through: ChainPoint,
    directory: impl Transport,
    lock: &impl WriteLock,
    now: i64,
) -> Result<Swept<SqliteClientError>, Error<SqliteClientError>> {
    let network = *st.network();
    let account = st.test_account().unwrap().id();
    sweep(
        st.wallet_mut().db_mut(),
        &network,
        account,
        through,
        GENESIS,
        ORIGIN,
        directory,
        lock,
        now,
    )
    .await
}

/// [`run`]s without a lock, expecting no key deferred.
async fn run_clean(
    st: &mut State,
    through: ChainPoint,
    directory: impl Transport,
    now: i64,
) -> Swept<SqliteClientError> {
    let swept = run(st, through, directory, &NoLock, now).await.unwrap();
    assert!(swept.deferred.is_empty(), "{:?}", swept.deferred);
    swept
}

/// Runs sweeps at [`NOW`] until none is pending, expecting no deferral, and returns how
/// many keys each run finished.
async fn settle(st: &mut State, through: ChainPoint, directory: &Directory) -> Vec<usize> {
    let mut finished = Vec::new();
    for _ in 0..20 {
        let swept = run_clean(st, through, directory, NOW).await;
        finished.push(swept.finished);
        if !swept.pending {
            return finished;
        }
    }
    panic!("sweeps are still pending after 20 runs");
}

/// A restore sweep imports every payment to a key, each a page of its lookup, then moves
/// the lookahead past the paid and `seen` indices, one batch per run, so later runs find a payment far past the first batch. Every request
/// stays on the service's routes: a wallet without payments downloads only a manifest and
/// the filters, and a few pages cost less over PIR than the row file, unlike many more.
#[tokio::test]
async fn a_restore_sweep_imports_every_payment_and_moves_the_lookahead_past_it() {
    for (paid, seen, row_file) in [
        (vec![], 0, false),
        (vec![3], 0, false),
        (vec![1; 2], 0, false),
        (vec![1; 65], 0, true),
        // The set is finite, so an unbounded run would stop past it instead of hanging.
        (vec![100], 200, false),
    ] {
        let mut r = restored(&paid);
        assert_eq!(balance(&r.st), 0);
        let seen: Vec<_> = (0..seen).map(|i| receiver(&r.st, i)).collect();
        let commitments: Vec<_> = r.records.iter().map(|r| r.payment.cmx).collect();
        let sets = provider(&seen);
        let directory = Directory::new(publish(&r.records, &commitments, r.through, &sets));
        let runs = settle(&mut r.st, r.through, &directory).await;
        // Each run sweeps at most one batch, and later runs progress.
        assert!(runs.iter().all(|f| (1..=64).contains(f)), "{runs:?}");
        let finished: usize = runs.iter().sum();
        // The first window, then, in later runs, the keys above it that the paid and seen
        // indices bring in.
        let past = paid
            .last()
            .map_or(0, |index| index + 1)
            .max(seen.len() as u64);
        assert_eq!(finished as u64, RECEIVE_GAP_LIMIT + past, "{paid:?}");
        assert_eq!(balance(&r.st), paid.len() as u64 * VALUE);
        let requests = directory.requests();
        let routes =
            |r: &String| r.starts_with("GET /v1/receiver/") || r == "POST /v1/receiver/query";
        assert!(requests.iter().all(routes), "{requests:?}");
        let rows = |r: &String| r.starts_with("GET /v1/receiver/rows/");
        assert_eq!(requests.iter().any(rows), row_file, "{requests:?}");
        if paid.is_empty() {
            // No PIR session or witnesses, and no second run.
            assert_eq!(requests.len(), 2, "{requests:?}");
            assert!(requests[1].starts_with("GET /v1/receiver/filters/"));
        }
    }
}

/// A key closed after its sweep is checked against each newer publication's paid filter,
/// so a payment after the first publication's anchor is found once a publication shows
/// it, and not before. A publication already checked costs only its manifest, and a key
/// with a known payment is not swept again.
#[tokio::test]
async fn a_newer_paid_filter_finds_a_payment_to_a_closed_key() {
    let mut r = restored(&[]);
    let directory = serve(&[], r.through);
    settle(&mut r.st, r.through, &directory).await;
    assert!(scanning(&r.st).is_empty());

    // The closed key misses a payment, which the same publication cannot show.
    let record = pay_restored_key(&mut r.st, 0, 0);
    let through = tip(&r.st);
    let before = directory.requests().len();
    let swept = run(&mut r.st, through, &directory, &NoLock, NOW).await;
    assert!(!swept.unwrap().pending);
    assert_eq!(directory.requests()[before..], ["GET /v1/receiver/init"]);
    assert_eq!(balance(&r.st), 0);

    let directory = serve(std::slice::from_ref(&record), through);
    // The paid key, then the lookahead key its index brings in.
    let runs = settle(&mut r.st, through, &directory).await;
    assert_eq!(runs.iter().sum::<usize>(), 2);
    assert_eq!(balance(&r.st), VALUE);

    // A later publication still holds the paid key, but it is not looked up again.
    r.st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    let later = tip(&r.st);
    let directory = serve(std::slice::from_ref(&record), later);
    let swept = run(&mut r.st, later, &directory, &NoLock, NOW).await;
    let swept = swept.unwrap();
    assert_eq!((swept.finished, swept.pending), (0, false));
    assert!(directory.requests().iter().all(|r| !r.starts_with("POST")));
}

/// A directory that is down: it counts requests and fails each one.
#[derive(Default)]
struct Down(Mutex<usize>);

impl Down {
    /// Counts a request and fails it.
    fn fail(&self) -> Result<Vec<u8>, DirectoryError> {
        *self.0.lock().unwrap() += 1;
        Err(DirectoryError::Transport("down".into()))
    }
}

impl Transport for Down {
    async fn get(&self, _: &str, _: usize) -> Result<Vec<u8>, DirectoryError> {
        self.fail()
    }

    async fn post(&self, _: &str, _: Vec<u8>, _: usize) -> Result<Vec<u8>, DirectoryError> {
        self.fail()
    }
}

/// No publication is newer than the tip, so a run at an unchanged tip whose closed keys
/// were all checked there makes no request, and succeeds while the directory is down.
#[tokio::test]
async fn closed_keys_checked_at_the_tip_need_no_request() {
    let mut r = restored(&[]);
    let directory = serve(&[], r.through);
    settle(&mut r.st, r.through, &directory).await;
    assert!(scanning(&r.st).is_empty());
    let down = Down::default();
    let swept = run_clean(&mut r.st, r.through, &down, NOW).await;
    assert_eq!((swept.finished, swept.pending), (0, false));
    assert_eq!(*down.0.lock().unwrap(), 0);
}

/// After its sweep, a key keeps scanning only if a provider's recent set holds its
/// receiver, and every key does unless each provider has a recent set.
#[tokio::test]
async fn only_recently_quoted_addresses_keep_scanning_after_their_sweep() {
    for (case, expected) in [
        ("quoted", vec![2]),
        ("both recent", vec![]),
        ("one recent", (0..RECEIVE_GAP_LIMIT).collect()),
    ] {
        let mut r = restored(&[]);
        let sets = if case == "quoted" {
            // The old device quoted addresses 0 and 2, and 2 only today.
            let mut sets = provider(&[receiver(&r.st, 0), receiver(&r.st, 2)]);
            sets[0].receivers = vec![*receiver(&r.st, 2).as_bytes()];
            sets
        } else {
            // Provider `b` publishes only its seen set in the last case.
            let mut sets = provider_named("a", &[]);
            let b = provider_named("b", &[]).into_iter();
            sets.extend(b.skip(usize::from(case == "one recent")));
            sets
        };
        let directory = Directory::new(publish(&[], &[], r.through, &sets));
        settle(&mut r.st, r.through, &directory).await;
        assert_eq!(scanning(&r.st), expected, "{case}");
    }
}

/// Records each write's label, and arms `fail` for the first write labelled `label`,
/// which the wallet's commit hook then fails.
struct FailFirst {
    label: &'static str,
    fail: Arc<AtomicBool>,
    labels: RefCell<Vec<&'static str>>,
}

impl WriteLock for FailFirst {
    fn write<T>(&self, label: &'static str, write: impl FnOnce() -> T) -> T {
        let mut labels = self.labels.borrow_mut();
        if label == self.label && !labels.contains(&label) {
            self.fail.store(true, Ordering::SeqCst);
        }
        labels.push(label);
        drop(labels);
        write()
    }
}

/// A failed wallet write stops the run with the wallet's error and leases no later key,
/// whether it is a key's lease, before its lookup, or the queue or apply step after it.
#[tokio::test]
async fn a_failed_wallet_write_stops_the_run() {
    let attempt = "one_time_sweep.attempt";
    for label in [attempt, "one_time_sweep.queue", "one_time_sweep.apply"] {
        let mut r = restored(&[0]);
        let directory = serve(&r.records, r.through);
        let lock = FailFirst {
            label,
            fail: Arc::default(),
            labels: RefCell::default(),
        };
        let fail = lock.fail.clone();
        // Returning true turns the commit into a rollback, which fails the write.
        r.st.wallet()
            .conn()
            .commit_hook(Some(move || fail.swap(false, Ordering::SeqCst)));
        let result = run(&mut r.st, r.through, &directory, &lock, NOW).await;
        assert_matches!(result, Err(Error::Wallet(_)));
        let labels = lock.labels.take();
        assert_eq!(labels.last(), Some(&label), "{labels:?}");
        let leased = labels.iter().filter(|l| **l == attempt).count();
        assert_eq!(leased, 1, "{labels:?}");
        assert_eq!(
            lookups(&directory),
            usize::from(label != attempt),
            "{label}"
        );
    }
}

/// Only the wallet's steps check, under its write lock, that `through` is its fully
/// scanned chain tip. Off it, whether the chain moved past `through` or a block below the
/// tip is unscanned, a run prepares no sweep, so it makes no request and leases no
/// attempt, and releases nothing. Once scanning catches up, the sweep runs at once,
/// without backoff.
#[tokio::test]
async fn a_run_off_the_scanned_tip_leases_and_requests_nothing() {
    let mut r = restored(&[0]);
    let stale = r.through;
    // A block below the tip is not scanned yet.
    r.st.generate_empty_block();
    let (top, _) = r.st.generate_empty_block();
    r.st.scan_cached_blocks_with_one_time_ivks(top, 1);
    let block = r.st.wallet().block_metadata(top).unwrap().unwrap();
    let through = ChainPoint {
        height: top,
        hash: block.block_hash(),
    };
    let directory = serve(&r.records, through);
    for through in [stale, through] {
        let lock = Labels::default();
        let swept = run(&mut r.st, through, &directory, &lock, NOW)
            .await
            .unwrap();
        assert!(swept.deferred.is_empty(), "{:?}", swept.deferred);
        assert!(swept.pending);
        let labels = ["one_time_sweep.due", "one_time_sweep.release"];
        assert_eq!(*lock.0.borrow(), labels);
        let requests = directory.requests();
        assert!(requests.is_empty(), "{requests:?}");
    }
    r.st.scan_cached_blocks_with_one_time_ivks(top - 1, 1);
    run_clean(&mut r.st, through, &directory, NOW).await;
    settle(&mut r.st, through, &directory).await;
    assert_eq!(balance(&r.st), VALUE);
}

/// Another handle on the wallet's file, as another writer holds.
type OtherWriter = WalletDb<rusqlite::Connection, LocalNetwork, SystemClock, TestRng>;

/// Runs `other` just before release, as another writer may while the sweep holds no
/// lock.
struct WriterBeforeRelease<F>(RefCell<Option<F>>);

impl<F: FnOnce()> WriteLock for WriterBeforeRelease<F> {
    fn write<T>(&self, label: &'static str, write: impl FnOnce() -> T) -> T {
        if label == "one_time_sweep.release"
            && let Some(other) = self.0.borrow_mut().take()
        {
            other();
        }
        write()
    }
}

/// Release runs only at the fully scanned chain tip, which the wallet checks under its
/// lock, since another writer may move the tip while the sweep's lookups run without it.
/// Each case sweeps against a publication `behind` blocks below the tip, with another
/// writer moving the chain through a second handle just before release, and judges
/// whether release ran by the account's retention height.
#[tokio::test]
async fn release_runs_only_at_the_fully_scanned_tip() {
    for (case, behind, expected) in [
        ("an unmoved tip", 0, true),
        ("an advanced tip", 0, false),
        ("a reorg that rewound the tip", 0, false),
        // The tip is back at `through`'s height, but its block is not scanned yet.
        ("a replaced block", 0, false),
        // Finishing keys against a publication behind `through` rescans the blocks
        // after it, lowering the fully scanned height without moving the tip.
        ("a rescan the sweep queued", 1, false),
    ] {
        let mut st = ironwood_wallet_in(TestDbFactory::file_backed());
        let network = *st.network();
        st.generate_and_scan_empty_blocks_with_one_time_ivks(2);
        let account = st.test_account().unwrap().id();
        restore(&mut st, account);
        let through = tip(&st);
        let path = st.wallet().conn().path().unwrap().to_owned();
        let mut handle =
            OtherWriter::for_path(path, network, SystemClock, TestRng::seed_from_u64(0)).unwrap();
        let h = through.height;
        let other = || match case {
            "an advanced tip" => handle.update_chain_tip(h + 1).unwrap(),
            "a reorg that rewound the tip" => {
                handle.truncate_to_height(h - 1).unwrap();
            }
            "a replaced block" => {
                handle.truncate_to_height(h - 1).unwrap();
                handle.update_chain_tip(h).unwrap();
            }
            _ => {}
        };
        let lock = WriterBeforeRelease(RefCell::new(Some(other)));
        let retention = |st: &State| -> u32 {
            let sql = "SELECT nullifier_retention_height FROM ironwood_one_time_spend_retention";
            st.wallet().conn().query_row(sql, [], |r| r.get(0)).unwrap()
        };
        let before = retention(&st);
        let height = through.height - behind;
        let hash = st.wallet().get_block_hash(height).unwrap().unwrap();
        // Without a recent set, every key keeps scanning from the block after the end.
        let end = ChainPoint { height, hash };
        let directory = Directory::new(publish(&[], &[], end, &provider(&[])[1..]));
        let swept = run(&mut st, through, &directory, &lock, NOW).await.unwrap();
        assert_eq!(swept.finished as u64, RECEIVE_GAP_LIMIT);
        assert_eq!(retention(&st) != before, expected, "{case}");
    }
}

/// Runs `other` just before the first lookup is queued, as another writer may while the
/// sweep holds no lock.
struct WriterBeforeQueue<F>(RefCell<Option<F>>, RefCell<Vec<&'static str>>);

impl<F: FnOnce()> WriteLock for WriterBeforeQueue<F> {
    fn write<T>(&self, label: &'static str, write: impl FnOnce() -> T) -> T {
        self.1.borrow_mut().push(label);
        if label == "one_time_sweep.queue"
            && let Some(other) = self.0.borrow_mut().take()
        {
            other();
        }
        write()
    }
}

/// A reorg that drops the publication's anchor after the sweep accepted it stops the run
/// at the key whose lookup it deferred: every later key would be deferred the same way, so
/// none is leased or backed off.
#[tokio::test]
async fn a_reorged_publication_anchor_leases_no_further_key() {
    let mut st = ironwood_wallet_in(TestDbFactory::file_backed());
    let network = *st.network();
    st.generate_and_scan_empty_blocks_with_one_time_ivks(2);
    let account = st.test_account().unwrap().id();
    restore(&mut st, account);
    let through = tip(&st);
    let path = st.wallet().conn().path().unwrap().to_owned();
    let mut handle =
        OtherWriter::for_path(path, network, SystemClock, TestRng::seed_from_u64(0)).unwrap();
    let other = || {
        handle.truncate_to_height(through.height - 1).unwrap();
    };
    let lock = WriterBeforeQueue(RefCell::new(Some(other)), RefCell::default());
    // No key is paid, so no lookup checks the tip before it is leased.
    let directory = Directory::new(publish(&[], &[], through, &provider(&[])[1..]));
    let swept = run(&mut st, through, &directory, &lock, NOW).await.unwrap();
    let labels = lock.1.take();
    let leased = labels.iter().filter(|l| **l == "one_time_sweep.attempt");
    assert_eq!(leased.count(), 1, "{labels:?}");
    let unknown = |e: &_| matches!(e, Error::Deferred(SweepDeferral::UnknownAnchor));
    assert_matches!(swept.deferred[..], [(_, e)] if unknown(e));
    assert_eq!(swept.finished, 0);
}

/// Seen sets must commit to the wallet's genesis, as a sweep's publication must: another
/// network's sets say nothing about this network's quotes. A publication without seen
/// sets, or with a provider that has a recent set but no seen set, may omit any receiver,
/// so issuance refuses it as sweeps do. Once every provider has a dated seen set, the
/// sets cover the quote times they all cover, and hold what any of them holds.
#[tokio::test]
async fn seen_sets_need_this_network_and_every_provider() {
    let r = restored(&[]);
    // Provider `a` has its seen set only if `a_seen`. `b` has only a seen set, from a
    // later feed start and a later read.
    let sets = |a_seen: bool| {
        let mut sets = provider_named("a", &[receiver(&r.st, 0)]);
        sets.truncate(1 + usize::from(a_seen));
        let mut b = provider_named("b", &[receiver(&r.st, 1)]).pop().unwrap();
        b.since_unix = NOW - RESTORE_WATCH_SECS;
        b.until_unix = NOW - 30;
        sets.push(b);
        sets
    };
    for sets in [sets(false), Vec::new()] {
        let directory = Directory::new(publish(&[], &[], r.through, &sets));
        let refused = fetch_seen(ORIGIN, &directory, GENESIS).await;
        assert!(matches!(refused, Err(DirectoryError::Malformed)));
    }

    let directory = Directory::new(publish(&[], &[], r.through, &sets(true)));
    let refused = fetch_seen(ORIGIN, &directory, [8; 32]).await;
    let coverage = |e: &_| matches!(e, receiver_directory::Error::Coverage);
    assert_matches!(refused.err(), Some(DirectoryError::Directory(e)) if coverage(e));
    let seen = fetch_seen(ORIGIN, &directory, GENESIS).await.unwrap();
    assert_eq!(
        (seen.since(), seen.until()),
        (NOW - RESTORE_WATCH_SECS, NOW - 60)
    );
    let held = [0, 1, 2].map(|index| *receiver(&r.st, index).as_bytes());
    assert_eq!(seen.contains(&held), [true, true, false]);
}

/// Issuance takes [`fetch_seen`]'s sets as its [`ProviderSeen`]: a refund address they
/// hold is never issued.
#[tokio::test]
async fn issuance_skips_a_refund_address_in_the_fetched_seen_sets() {
    let mut r = restored(&[]);
    let parent = FullViewingKey::from(r.st.test_account().unwrap().usk().orchard());
    let refund = KeyId::new(Purpose::Refund, 0).derive(&parent).unwrap();
    let address = refund.address_at(0u32, Scope::External);
    let held = Receiver::from_bytes(address.to_raw_address_bytes()).unwrap();
    let sets = provider(&[held]);
    let directory = Directory::new(publish(&[], &[], r.through, &sets));
    let seen = fetch_seen(ORIGIN, &directory, GENESIS).await.unwrap();
    let contains = |receivers: &[[u8; 43]]| seen.contains(receivers);
    let seen = ProviderSeen {
        since: seen.since(),
        until: seen.until(),
        contains: &contains,
    };
    let db = r.st.wallet_mut().db_mut();
    let key = db.reserve_refund_key(r.account, r.through.height, Some(&seen));
    assert_eq!(
        key.unwrap().unwrap().key_id(),
        KeyId::new(Purpose::Refund, 1)
    );
}

/// Which part of a sweep fails.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Fault {
    /// Queries fail after the session was accepted.
    Queries,
    /// The witness snapshot is malformed, so no session opens.
    Witnesses,
    /// Queries after the first fail at the transport.
    LaterQueries,
}

/// A directory with `fault`.
struct Faulty {
    directory: Directory,
    fault: Fault,
}

impl Transport for Faulty {
    async fn get(&self, url: &str, limit: usize) -> Result<Vec<u8>, DirectoryError> {
        if matches!(self.fault, Fault::Witnesses) && url.contains("/v1/receiver/witness/") {
            return Ok(vec![0]);
        }
        self.directory.get(url, limit).await
    }

    async fn post(
        &self,
        url: &str,
        body: Vec<u8>,
        limit: usize,
    ) -> Result<Vec<u8>, DirectoryError> {
        match self.fault {
            Fault::Queries => return Err(DirectoryError::Revision),
            Fault::LaterQueries
                if url.ends_with("/v1/receiver/query") && lookups(&self.directory) > 0 =>
            {
                return Err(DirectoryError::Transport("down".into()));
            }
            _ => {}
        }
        self.directory.post(url, body, limit).await
    }
}

/// A session that fails to open fails the run before any key is leased. A revoked session
/// stops the run at the key whose lookup failed: every later key would fail the same way,
/// so none is leased or backed off.
#[tokio::test]
async fn a_run_wide_directory_failure_leases_no_further_key() {
    for fault in [Fault::Queries, Fault::Witnesses] {
        // The batch's first two keys are paid, so each needs a lookup.
        let mut r = restored(&[0, 1]);
        let directory = Faulty {
            directory: serve(&r.records, r.through),
            fault,
        };
        let lock = Labels::default();
        let result = run(&mut r.st, r.through, &directory, &lock, NOW).await;
        let labels = lock.0.take();
        let leased = labels.iter().filter(|l| **l == "one_time_sweep.attempt");
        let opened = fault == Fault::Queries;
        assert_eq!(leased.count(), usize::from(opened), "{fault:?}: {labels:?}");
        if opened {
            let swept = result.unwrap();
            let revoked = |e: &_| matches!(e, Error::Directory(DirectoryError::Revision));
            assert_matches!(swept.deferred[..], [(k, e)] if k.index() == 0 && revoked(e));
            assert_eq!((swept.finished, swept.pending), (0, true));
        } else {
            assert_matches!(result, Err(Error::Directory(_)));
        }
        assert_eq!(balance(&r.st), 0);
        let due: Vec<_> =
            r.st.wallet_mut()
                .db_mut()
                .prepare_one_time_sweeps(r.account, r.through, NOW, NonZeroU32::new(64).unwrap())
                .unwrap()
                .unwrap()
                .iter()
                .map(|item| item.key.index())
                .collect();
        assert!(
            due.contains(&0) != opened && due.contains(&1),
            "{fault:?}: {due:?}"
        );
    }
}

/// A payment the directory serves with a noncanonical note commitment or Action
/// nullifier, or an invalid ephemeral key, is refused once looked up, before anything
/// is queued or credited: the directory crates parse records structurally only.
#[tokio::test]
async fn a_forged_payment_is_refused() {
    let forgeries: [fn(&mut RawRecord); 3] = [
        |r| r.payment.cmx = [0xff; 32],
        |r| r.payment.action_nullifier = [0xff; 32],
        |r| r.payment.ephemeral_key = [0xff; 32],
    ];
    for (case, forge) in forgeries.into_iter().enumerate() {
        let mut r = restored(&[0]);
        let commitments: Vec<_> = r.records.iter().map(|r| r.payment.cmx).collect();
        let mut raw = raw_record(&r.records[0]);
        forge(&mut raw);
        let directory =
            Directory::new(publish_raw(&[raw], &commitments, r.through, &provider(&[])));
        let swept = run(&mut r.st, r.through, &directory, &NoLock, NOW)
            .await
            .unwrap();
        let malformed = |e: &_| {
            matches!(
                e,
                Error::Directory(DirectoryError::Directory(
                    receiver_directory::Error::Malformed
                ))
            )
        };
        assert_matches!(swept.deferred[..], [(k, e)] if k.index() == 0 && malformed(e));
        assert_eq!(lookups(&directory), 1, "case {case}");
        assert_eq!(balance(&r.st), 0, "case {case}");
        assert!(pending(&r.st, r.through), "case {case}");
    }
}

/// A finished key's rescan stops the run before another paid key is leased, so a later
/// paid key is not backed off and is due again, at the same time, once the rescan is
/// scanned.
#[tokio::test]
async fn a_rescan_a_finished_key_queued_backs_off_no_later_paid_key() {
    let mut r = restored(&[0, 1, 2]);
    let through = r.through;
    let height = through.height - 1;
    let hash = r.st.wallet().get_block_hash(height).unwrap().unwrap();
    let commitments: Vec<_> = r.records.iter().map(|r| r.payment.cmx).collect();
    // Without a recent set, a finished key scans, and so rescans, from `height + 1`.
    let sets = &provider(&[])[1..];
    let end = ChainPoint { height, hash };
    let directory = Directory::new(publish(&r.records, &commitments, end, sets));
    let mut runs = Vec::new();
    for _ in 0..20 {
        if tip(&r.st) != through {
            r.st.scan_cached_blocks_with_one_time_ivks(through.height, 1);
        }
        let swept = run_clean(&mut r.st, through, &directory, NOW).await;
        runs.push(swept.finished);
        if !swept.pending {
            break;
        }
    }
    // Each paid key after the first waits for the rescan its predecessor queued.
    assert_eq!(runs[..2], [1, 1], "{runs:?}");
    assert_eq!(balance(&r.st), 3 * VALUE);
}

/// How a sweep refuses an unusable publication.
type Refusal = fn(&Error<SqliteClientError>) -> bool;

/// A publication the wallet cannot use, now or at all, is refused before any key is
/// leased, so every due key stays due and the next run asks again: one ending above the
/// wallet's scanned tip, one off its chain, one ending at the wallet's block but short of
/// its last Ironwood output, whose omitted payments neither a lookup nor a rescan would
/// find, and one that may omit any seen receiver.
#[tokio::test]
async fn an_unusable_publication_is_refused_before_leasing_any_key() {
    let malformed: Refusal = |e| matches!(e, Error::Directory(DirectoryError::Malformed));
    let rows: [(&str, Refusal); 5] = [
        ("ahead", |e| {
            matches!(e, Error::Deferred(SweepDeferral::UnknownAnchor))
        }),
        ("off chain", |e| matches!(e, Error::Directory(_))),
        ("short", |e| matches!(e, Error::Unavailable(_))),
        ("unseen provider", malformed),
        ("no seen sets", malformed),
    ];
    for (case, refused) in rows {
        let mut r = restored(&[0]);
        let (records, through) = (&r.records[..], r.through);
        let directory = match case {
            "ahead" => serve(
                records,
                ChainPoint {
                    height: through.height + 1,
                    hash: BlockHash([1; 32]),
                },
            ),
            "off chain" => serve(
                records,
                ChainPoint {
                    hash: BlockHash([1; 32]),
                    ..through
                },
            ),
            // Without the chain's one Ironwood output.
            "short" => serve(&[], through),
            // A provider with a recent set but no seen set, or no provider at all.
            _ => {
                let mut sets = provider(&[]);
                sets.truncate(usize::from(case == "unseen provider"));
                let commitments = [records[0].payment.cmx];
                Directory::new(publish(records, &commitments, through, &sets))
            }
        };
        let lock = Labels::default();
        let result = run(&mut r.st, through, &directory, &lock, NOW).await;
        assert!(result.as_ref().is_err_and(refused), "{case}: {result:?}");
        assert_eq!(lock.0.take(), ["one_time_sweep.due"], "{case}");
        assert_eq!(directory.requests(), ["GET /v1/receiver/init"], "{case}");
        assert!(pending(&r.st, through));
        let _ = run(&mut r.st, through, &directory, &NoLock, NOW).await;
        assert_eq!(directory.requests().len(), 2, "{case}");
    }
}

/// A payment that must wait leaves its key deferred with why, and the key's next attempt,
/// after its backoff, queues the newer publication's answer in place of the waiting
/// candidate: here a paid-filter miss, which drops it.
#[tokio::test]
async fn a_waiting_payment_takes_the_next_attempts_answer() {
    let mut r = restored(&[0]);
    let (record, through) = (r.records[0].clone(), r.through);
    // Without checkpoints, the wallet can check no inclusion path.
    let wipe = "DELETE FROM ironwood_tree_checkpoints";
    r.st.wallet().conn().execute_batch(wipe).unwrap();
    let a = serve(std::slice::from_ref(&record), through);
    let swept = run(&mut r.st, through, &a, &NoLock, NOW).await.unwrap();
    let waiting = PaymentApplication::AwaitingWitness;
    assert_matches!(swept.deferred[..], [(k, Error::Queued(d))] if k.index() == 0 && *d == waiting);
    assert!(swept.pending);

    let b = Directory::new(publish(&[], &[record.payment.cmx], through, &provider(&[])));
    run_clean(&mut r.st, through, &b, NOW + 60).await;
    settle(&mut r.st, through, &b).await;
    assert_eq!(balance(&r.st), 0);
    assert_eq!(lookups(&b), 0, "{:?}", b.requests());
}

/// An early restore registers the account's keys from the publication's filters before
/// the scan, then looks up only the paid ones while it runs: a payment whose block the
/// scan already passed is inserted with its witness, and one ahead of it is found by the
/// scan in its block. Every payment is credited by the end of the scan, with no sweep
/// left, and the directory serves a manifest, the filters, one PIR session and a lookup
/// per paid key.
#[tokio::test]
async fn an_early_restore_credits_payments_as_the_scan_covers_them() {
    let mut st = ironwood_wallet_in(TestDbFactory::default());
    let account = st.test_account().unwrap().id();
    let first = pay_unscanned(&mut st, 3, 0);
    let second = pay_unscanned(&mut st, 40, 1);
    let end = unscanned_end(&mut st);
    let directory = serve(&[first.clone(), second], end);
    let network = *st.network();
    let db = st.wallet_mut().db_mut();
    let lock = Labels::default();
    let early = begin_early_restore(
        db, &network, account, GENESIS, ORIGIN, &directory, &lock, NOW,
    )
    .await
    .unwrap()
    .expect("nothing is scanned yet");
    // The scan passes the first payment before the lookups come in.
    let paid_at = BlockHeight::from(first.payment.height);
    st.scan_cached_blocks_with_one_time_ivks(paid_at, 1);
    let notes = "SELECT COUNT(*) FROM ironwood_received_notes";
    assert_eq!(column::<i64>(&st, notes), [0]);
    let db = st.wallet_mut().db_mut();
    let looked_up = early.look_up(db, &lock).await.unwrap();
    assert!(looked_up.failed.is_empty(), "{:?}", looked_up.failed);
    st.scan_cached_blocks_with_one_time_ivks(paid_at + 1, 2);
    assert_eq!(balance(&st), 2 * VALUE);
    let through = tip(&st);
    assert_eq!(through, end);
    assert!(!pending(&st, through));
    assert!(scanning(&st).is_empty());
    assert_eq!(lookups(&directory), 2, "{:?}", directory.requests());
    assert_eq!(
        lock.0.take(),
        [
            "one_time_early_restore.begin",
            "one_time_early_restore.lookup",
            "one_time_early_restore.lookup"
        ]
    );
    // A sweep run afterwards has nothing to do and asks nothing.
    let before = directory.requests().len();
    run_clean(&mut st, through, &directory, NOW).await;
    assert_eq!(directory.requests().len(), before);
}

/// Mines an empty block left unscanned and returns it as a publication's end. The
/// wallet learns it as its chain tip, as sync does before an early restore begins.
fn unscanned_end(st: &mut State) -> ChainPoint {
    let (height, _) = st.generate_empty_block();
    st.wallet_mut().db_mut().update_chain_tip(height).unwrap();
    ChainPoint {
        height,
        hash: cached(st, height).hash(),
    }
}

/// On a network without Ironwood, an early restore fails before asking the directory
/// anything.
#[tokio::test]
async fn an_early_restore_without_ironwood_asks_nothing() {
    let mut st = ironwood_wallet_in(TestDbFactory::default());
    let account = st.test_account().unwrap().id();
    unscanned_end(&mut st);
    let network = LocalNetwork {
        nu6_3: None,
        ..*st.network()
    };
    let down = Down::default();
    let db = st.wallet_mut().db_mut();
    let result =
        begin_early_restore(db, &network, account, GENESIS, ORIGIN, &down, &NoLock, NOW).await;
    assert!(matches!(result, Err(Error::Unavailable(_))));
    assert_eq!(*down.0.lock().unwrap(), 0);
}

/// Begins `account`'s early restore against the publication `directory` serves, at
/// [`NOW`], if the wallet allows one.
async fn begin<T: Transport>(
    st: &mut State,
    account: AccountUuid,
    directory: T,
) -> Option<EarlyRestore<'static, T, AccountUuid>> {
    let network = *st.network();
    let db = st.wallet_mut().db_mut();
    begin_early_restore(
        db, &network, account, GENESIS, ORIGIN, directory, &NoLock, NOW,
    )
    .await
    .unwrap()
}

/// The first column of `sql`'s rows in the wallet's database.
fn column<T: rusqlite::types::FromSql>(st: &State, sql: &str) -> Vec<T> {
    let conn = st.wallet().conn();
    let mut statement = conn.prepare(sql).unwrap();
    let rows = statement.query_map([], |r| r.get(0)).unwrap();
    rows.collect::<Result<_, _>>().unwrap()
}

/// The indices of the wallet's registered one-time keys for `purpose`, in order.
fn registered(st: &State, purpose: Purpose) -> Vec<u64> {
    let code = u8::from(purpose == Purpose::Receive);
    let sql = format!(
        "SELECT key_index FROM ironwood_one_time_keys WHERE purpose = {code} ORDER BY key_index"
    );
    let indices = column::<Vec<u8>>(st, &sql).into_iter();
    indices
        .map(|bytes| u64::from_be_bytes(bytes.try_into().unwrap()))
        .collect()
}

/// Two accounts restore early in one sync against one publication. Each is credited its
/// own payment once, both restores accept the publication with nothing left to sweep,
/// and the directory serves one lookup per paid key. A third account, whose history the
/// scan has already reached, does not begin and asks the directory nothing.
#[tokio::test]
async fn two_accounts_restore_early_in_one_sync() {
    let mut st = ironwood_wallet_in(TestDbFactory::default());
    let a = st.test_account().unwrap().id();
    let (b, usk) = st.create_account_from_test_seed("b");
    let (c, _) = st.create_account_from_test_seed("c");
    restore(&mut st, b);
    restore(&mut st, c);
    let first = pay_unscanned(&mut st, 3, 0);
    let second = pay_unscanned_to(&mut st, &FullViewingKey::from(usk.orchard()), 5, 1);
    let end = unscanned_end(&mut st);
    let directory = serve(&[first.clone(), second], end);
    let early_a = begin(&mut st, a, &directory).await.unwrap();
    let early_b = begin(&mut st, b, &directory).await.unwrap();
    let start = |st: &State| st.wallet().db().one_time_early_restore_start(c).unwrap();
    assert!(start(&st).is_some());

    // The first batch passes the first payment before the lookups come in.
    let paid_at = BlockHeight::from(first.payment.height);
    st.scan_cached_blocks_with_one_time_ivks(paid_at, 1);
    assert_eq!(start(&st), None);
    let down = Down::default();
    assert!(begin(&mut st, c, &down).await.is_none());
    assert_eq!(*down.0.lock().unwrap(), 0);
    for early in [early_a, early_b] {
        let db = st.wallet_mut().db_mut();
        let looked_up = early.look_up(db, &NoLock).await.unwrap();
        assert!(looked_up.failed.is_empty(), "{:?}", looked_up.failed);
    }
    st.scan_cached_blocks_with_one_time_ivks(paid_at + 1, 2);
    let through = tip(&st);
    assert_eq!(through, end);
    for account in [a, b] {
        assert_eq!(st.get_total_balance(account).into_u64(), VALUE);
        let db = st.wallet().db();
        assert!(!db.one_time_history_pending(account, end.height).unwrap());
    }
    let sql = "SELECT state FROM ironwood_one_time_restores ORDER BY account_id";
    assert_eq!(column::<u8>(&st, sql), [1, 1]);
    assert_eq!(lookups(&directory), 2, "{:?}", directory.requests());
}

/// Pays incoming keys 2, 7 and 11 in unscanned blocks, then restores early through a
/// directory whose lookups fail at the transport after the first, scans through the
/// publication's end, and settles restore sweeps. A lookup that fails at the transport
/// stops the early lookups, listing that key and every later one as failed. The scan
/// credits the one payment recorded, and the sweeps find the rest, so each payment is
/// credited once. A rewind below the end then reopens every key's sweep, whether the
/// early restore or a sweep finished it.
#[tokio::test]
async fn keys_after_an_early_lookup_transport_failure_are_left_to_sweeps() {
    let mut st = ironwood_wallet_in(TestDbFactory::default());
    let account = st.test_account().unwrap().id();
    let mut records = Vec::new();
    for (position, index) in (0..).zip([2, 7, 11]) {
        records.push(pay_unscanned(&mut st, index, position));
    }
    let end = unscanned_end(&mut st);
    let directory = Faulty {
        directory: serve(&records, end),
        fault: Fault::LaterQueries,
    };
    let early = begin(&mut st, account, &directory).await.unwrap();
    let db = st.wallet_mut().db_mut();
    let looked_up = early.look_up(db, &NoLock).await.unwrap();
    assert_eq!(lookups(&directory.directory), 1);
    let failed: Vec<_> = looked_up.failed.iter().map(|(k, _)| k.index()).collect();
    assert_eq!(failed, [7, 11]);
    let transport = |e: &_| matches!(e, Error::Directory(DirectoryError::Transport(_)));
    assert_matches!(looked_up.failed[..], [(_, e), (_, Error::Unavailable(_))] if transport(e));

    let from = BlockHeight::from(records[0].payment.height);
    st.scan_cached_blocks_with_one_time_ivks(from, 4);
    let through = tip(&st);
    assert_eq!(through, end);
    assert_eq!(balance(&st), VALUE);
    assert!(pending(&st, through));
    settle(&mut st, through, &directory.directory).await;
    assert_eq!(balance(&st), 3 * VALUE);
    // The recorded key is not looked up again.
    let lookups = lookups(&directory.directory);
    assert_eq!(lookups, 3, "{:?}", directory.directory.requests());

    let wallet = st.wallet_mut();
    wallet.truncate_to_height(through.height - 1).unwrap();
    let rewound = tip(&st);
    let limit = NonZeroU32::new(1_000).unwrap();
    let db = st.wallet_mut().db_mut();
    let due = db.prepare_one_time_sweeps(account, rewound, NOW, limit);
    let due = due.unwrap().unwrap();
    let due: Vec<_> = due.iter().map(|w| w.key.index()).collect();
    assert!([2, 7, 11].iter().all(|i| due.contains(i)), "{due:?}");
}

/// An early restore checks the first [`FIRST_WINDOW`] incoming keys, then keeps going
/// until [`GAP`] keys in a row are neither seen nor paid, and registers every incoming
/// key it checked. Here keys 99 and 159 were seen and 129 was paid, so keys 0 to 189 are
/// registered and only 129 is looked up.
#[tokio::test]
async fn an_early_restore_looks_ahead_past_each_used_incoming_key() {
    let mut st = ironwood_wallet_in(TestDbFactory::default());
    let account = st.test_account().unwrap().id();
    let used = [0, 1, 2].map(|i| FIRST_WINDOW - 1 + i * GAP);
    let paid = pay_unscanned(&mut st, used[1], 0);
    let end = unscanned_end(&mut st);
    let seen = [receiver(&st, used[0]), receiver(&st, used[2])];
    let commitments = [paid.payment.cmx];
    let records = std::slice::from_ref(&paid);
    let directory = Directory::new(publish(records, &commitments, end, &provider(&seen)));
    let early = begin(&mut st, account, &directory).await.unwrap();
    let expected: Vec<_> = (0..=used[2] + GAP).collect();
    assert_eq!(registered(&st, Purpose::Receive), expected);
    assert!(registered(&st, Purpose::Refund).is_empty());
    let db = st.wallet_mut().db_mut();
    let looked_up = early.look_up(db, &NoLock).await.unwrap();
    assert!(looked_up.failed.is_empty(), "{:?}", looked_up.failed);
    assert_eq!(lookups(&directory), 1);
}

/// An early restore registers a refund key only when a seen set or the paid filter holds
/// it, and registering one keeps issuance from reusing its index. Refund key 7, which a
/// provider saw, is registered and the next refund issued is 8. Refund key 3, in no
/// filter, is not registered.
#[tokio::test]
async fn an_early_restore_registers_only_used_refund_keys() {
    let mut st = ironwood_wallet_in(TestDbFactory::default());
    let account = st.test_account().unwrap().id();
    let end = unscanned_end(&mut st);
    let refund = |index| key_receiver(&parent(&st), KeyId::new(Purpose::Refund, index));
    let directory = Directory::new(publish(&[], &[], end, &provider(&[refund(7)])));
    begin(&mut st, account, &directory).await.unwrap();
    assert_eq!(registered(&st, Purpose::Refund), [7]);

    st.scan_cached_blocks_with_one_time_ivks(end.height, 1);
    let db = st.wallet_mut().db_mut();
    let issued = db.reserve_refund_key(account, end.height, None);
    assert_eq!(
        issued.unwrap().unwrap().key_id(),
        KeyId::new(Purpose::Refund, 8)
    );
}

/// An early restore checks at most [`MAX_KEYS`] keys in a purpose, even while used keys
/// keep moving its lookahead. A payment beyond them is not looked up early, and restore
/// sweeps after the scan find it.
#[tokio::test]
async fn an_early_restore_checks_at_most_max_keys() {
    let mut st = ironwood_wallet_in(TestDbFactory::default());
    let account = st.test_account().unwrap().id();
    let paid = pay_unscanned(&mut st, MAX_KEYS + 50, 0);
    let end = unscanned_end(&mut st);
    // A key seen every 25, within the gap, keeps the lookahead moving through the payment.
    let seen: Vec<_> = (0..MAX_KEYS + 50)
        .step_by(25)
        .map(|index| receiver(&st, index))
        .collect();
    let commitments = [paid.payment.cmx];
    let records = std::slice::from_ref(&paid);
    let directory = Directory::new(publish(records, &commitments, end, &provider(&seen)));
    let early = begin(&mut st, account, &directory).await.unwrap();
    let expected: Vec<_> = (0..MAX_KEYS).collect();
    assert_eq!(registered(&st, Purpose::Receive), expected);
    // The paid filter's false matches among the checked keys are looked up and found
    // unpaid.
    let db = st.wallet_mut().db_mut();
    let looked_up = early.look_up(db, &NoLock).await.unwrap();
    assert!(looked_up.failed.is_empty(), "{:?}", looked_up.failed);

    let from = BlockHeight::from(paid.payment.height);
    st.scan_cached_blocks_with_one_time_ivks(from, 2);
    assert_eq!(balance(&st), 0);
    settle(&mut st, end, &directory).await;
    assert_eq!(balance(&st), VALUE);
}

/// Without a current recent set from every provider, an early restore treats every key it
/// registers as recent, so each scans from the block after the publication's end. With
/// one from every provider, no key outside the recent sets scans.
#[tokio::test]
async fn without_every_recent_set_every_early_restored_key_scans_after_the_end() {
    for complete in [true, false] {
        let mut st = ironwood_wallet_in(TestDbFactory::default());
        let account = st.test_account().unwrap().id();
        let end = unscanned_end(&mut st);
        // A seen refund key, so both purposes are registered.
        let refund = key_receiver(&parent(&st), KeyId::new(Purpose::Refund, 0));
        let sets = provider(&[refund]);
        let sets = if complete { &sets[..] } else { &sets[1..] };
        let directory = Directory::new(publish(&[], &[], end, sets));
        begin(&mut st, account, &directory).await.unwrap();
        let active = column::<Option<u32>>(&st, "SELECT active_from FROM ironwood_one_time_keys");
        assert_eq!(active.len() as u64, FIRST_WINDOW + 1);
        let expected = (!complete).then(|| u32::from(end.height) + 1);
        assert!(
            active.iter().all(|a| *a == expected),
            "{complete}: {active:?}"
        );
    }
}
