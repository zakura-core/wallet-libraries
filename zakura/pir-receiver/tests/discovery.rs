//! Discovery end to end: a restored wallet checks its one-time keys against a receiver
//! directory served in process, over the service's routes and real PIR, and imports what
//! it finds only after checking it against its own chain. The service's own HTTP router
//! is tested against these clients in wallet-pir.

use std::sync::Mutex;

use orchard::keys::{FullViewingKey, Scope};
use receiver_directory::{
    RawRecord,
    snapshot::{Manifest, PROFILE, ProviderSet, Snapshot},
};
use receiver_pir::{MIN_ROWS, server::Server};
use zakura_one_time_ivk::swap::RESTORE_WATCH_SECS;
use zakura_pir_receiver::{
    DirectoryError, Discovered, Error, FIRST_WINDOW, Transport, WriteLock, discover, fetch_seen,
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
            EnumerationCursor, FilterCheck, OneTimeIvkRestoreRead as _,
            OneTimeIvkRestoreWrite as _, PublicationEnd,
        },
    },
    testing::{AddressType, IronwoodFvk, TestBuilder, TestState},
    transparent_ledger::ChainPoint,
};
use zcash_client_sqlite::{
    AccountUuid,
    error::SqliteClientError,
    testing::{
        BlockCache,
        db::{TestDb, TestDbFactory},
    },
    wallet::one_time_ivk::{KeyId, Purpose, swap::ProviderSeen},
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

/// A restored wallet with Ironwood active from its first block, stored as `factory` makes
/// it.
fn ironwood_wallet_in(factory: TestDbFactory) -> State {
    let activation = BlockHeight::from_u32(ACTIVATION);
    TestBuilder::new()
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
        .build()
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

/// [`pay_unscanned`], then scans the payment's block. Scanning cannot find it: discovery
/// has not registered the key yet.
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
/// its key's lookup, scanning each before discovery knows the key, then scans one more
/// block.
fn restored(paid: &[u64]) -> Restored {
    let mut st = ironwood_wallet_in(TestDbFactory::default());
    let account = st.test_account().unwrap().id();
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    let mut records = Vec::new();
    for (position, index) in (0..).zip(paid) {
        let mut record = pay_restored_key(&mut st, *index, position);
        let pages = |paid: &[u64]| paid.iter().filter(|i| *i == index).count();
        record.page = pages(&paid[..records.len()]).try_into().unwrap();
        record.total = pages(paid).try_into().unwrap();
        records.push(record);
    }
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
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

/// The value of the wallet's one-time-key notes, which needs no wallet summary.
fn one_time_value(st: &State) -> u64 {
    st.wallet()
        .conn()
        .query_row(
            "SELECT COALESCE(SUM(value), 0) FROM ironwood_received_notes
             WHERE one_time_key_id IS NOT NULL",
            [],
            |r| r.get(0),
        )
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
    // Each record's row slot, which the publisher writes after validating it.
    let records: Vec<_> = records
        .iter()
        .map(|record| {
            RawRecord::decode(&record.encode().unwrap())
                .unwrap()
                .unwrap()
        })
        .collect();
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
    let snapshot = Snapshot::build(manifest, &records, provider).unwrap();
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
/// its manifest, PIR setup, filters and witnesses, and real PIR evaluation of
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

/// Runs discovery for `account` at [`NOW`].
async fn run(
    st: &mut State,
    account: AccountUuid,
    directory: impl Transport,
) -> Result<Discovered<SqliteClientError>, Error<SqliteClientError>> {
    let network = *st.network();
    discover(
        st.wallet_mut().db_mut(),
        &network,
        account,
        GENESIS,
        ORIGIN,
        directory,
        &NoLock,
        NOW,
    )
    .await
}

/// [`run`]s for the test account, expecting no failed key.
async fn run_clean(st: &mut State, directory: impl Transport) -> Discovered<SqliteClientError> {
    let account = st.test_account().unwrap().id();
    let found = run(st, account, directory).await.unwrap();
    assert!(found.failed.is_empty(), "{:?}", found.failed);
    found
}

/// The `purpose` key indices registered in the wallet, in order.
fn registered(st: &State, purpose: Purpose) -> Vec<u64> {
    let code = match purpose {
        Purpose::Refund => 0,
        _ => 1,
    };
    let sql = format!(
        "SELECT key_index FROM ironwood_one_time_keys WHERE purpose = {code} ORDER BY key_index"
    );
    let conn = st.wallet().conn();
    let mut stmt = conn.prepare(&sql).unwrap();
    let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0)).unwrap();
    rows.map(|r| u64::from_be_bytes(r.unwrap().try_into().unwrap()))
        .collect()
}

/// A late restore pages through each paid key's history and imports every payment once the
/// scan covers it, with no further request once discovery is complete. Keys the filters
/// do not mark are never registered.
#[tokio::test]
async fn discovery_imports_every_late_payment() {
    let mut r = restored(&[0, 3, 3, 40]);
    let directory = serve(&r.records, r.through);
    let found = run_clean(&mut r.st, &directory).await;
    assert!(found.complete);
    assert_eq!((found.lookups, found.witnesses), (0, 0));
    assert_eq!(balance(&r.st), 4 * VALUE);
    // One query per page, and one more for each key's empty first page is never needed.
    assert_eq!(lookups(&directory), 4);
    assert_eq!(registered(&r.st, Purpose::Receive), [0, 3, 40]);
    assert!(registered(&r.st, Purpose::Refund).is_empty());

    let requests = directory.requests().len();
    let found = run_clean(&mut r.st, &directory).await;
    assert!(found.complete);
    assert_eq!(
        directory.requests().len(),
        requests,
        "a run with nothing due makes no request"
    );
}

/// A recheck checks a closed key far past the first window of unused keys again, without
/// walking the keys between, so a payment after it closed is found.
#[tokio::test]
async fn a_closed_key_past_a_filter_gap_is_rechecked() {
    closed_key_paid_later(false).await;
}

/// A fresh account asked to recheck finds the payment and completes once its discovery has
/// nothing left to run.
#[tokio::test]
async fn a_fresh_account_completes_once_its_recheck_finishes() {
    closed_key_paid_later(true).await;
}

/// Closes an incoming key far past the first window unpaid, pays it, rechecks and runs
/// discovery, expecting it to find the payment and complete. A `fresh` account is declared
/// fresh first.
async fn closed_key_paid_later(fresh: bool) {
    let mut st = ironwood_wallet_in(TestDbFactory::default());
    let account = st.test_account().unwrap().id();
    if fresh {
        st.wallet_mut()
            .db_mut()
            .mark_one_time_account_fresh(account)
            .unwrap();
    }
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    let index = 1_000_000_000;
    // An earlier pass saw the key unpaid, so it closed.
    let end = tip(&st);
    let tree_size: u64 = st
        .wallet()
        .conn()
        .query_row(
            "SELECT ironwood_commitment_tree_size FROM blocks WHERE height = ?1",
            [u32::from(end.height)],
            |r| r.get(0),
        )
        .unwrap();
    let earlier = PublicationEnd {
        height: end.height,
        hash: end.hash.0,
        tree_size,
    };
    let seen = FilterCheck {
        key: KeyId::new(Purpose::Receive, index),
        seen: true,
        paid: false,
        recent: false,
    };
    let done = EnumerationCursor {
        next: index + 1,
        reach: index + 1,
    };
    let db = st.wallet_mut().db_mut();
    for (purpose, checks) in [(Purpose::Receive, vec![seen]), (Purpose::Refund, vec![])] {
        assert!(
            db.record_one_time_filter_checks(account, earlier, purpose, &checks, done, true, NOW)
                .unwrap()
        );
    }

    let record = pay_restored_key(&mut st, index, 0);
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    // Only Check swap history looks for a payment to a closed key.
    let db = st.wallet_mut().db_mut();
    db.recheck_one_time_key_history(account).unwrap();
    let directory = serve(&[record], tip(&st));
    let found = run_clean(&mut st, &directory).await;
    assert!(found.complete);
    assert_eq!(balance(&st), VALUE);
}

/// A wallet with no payments downloads only the manifest and the filters, and is complete
/// once its publication matches its chain.
#[tokio::test]
async fn a_wallet_without_payments_downloads_only_the_filters() {
    let mut r = restored(&[]);
    let directory = serve(&[], r.through);
    let found = run_clean(&mut r.st, &directory).await;
    assert!(found.complete);
    let requests = directory.requests();
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert!(requests[0].ends_with("/init"));
    assert!(requests[1].contains("/filters/"));
}

/// A restore that runs before the scan reaches its payments records them as hints, and the
/// scan finds the notes itself, judging the publication as it stores its last block.
#[tokio::test]
async fn payments_ahead_of_the_scan_are_found_by_it() {
    let mut st = ironwood_wallet_in(TestDbFactory::default());
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    let first = pay_unscanned(&mut st, 2, 0);
    let second = pay_unscanned(&mut st, 7, 1);
    let end_height = BlockHeight::from(second.payment.height);
    st.wallet_mut().update_chain_tip(end_height).unwrap();
    let end = ChainPoint {
        height: end_height,
        hash: BlockHash(second.payment.block_hash),
    };
    let start = BlockHeight::from(first.payment.height);
    let directory = serve(&[first, second], end);
    let found = run_clean(&mut st, &directory).await;
    assert!(!found.complete, "the publication waits for the scan");
    assert_eq!(found.witnesses, 0);
    assert_eq!(one_time_value(&st), 0);
    st.scan_cached_blocks_with_one_time_ivks(start, 2);
    assert_eq!(one_time_value(&st), 2 * VALUE);
    let account = st.test_account().unwrap().id();
    let status = st.wallet().db().one_time_discovery(account, NOW).unwrap();
    assert!(status.unwrap().complete);
}

/// A payment the key cannot decrypt is the directory's error: the wallet refuses the
/// answer, imports nothing, and backs the lookup off.
#[tokio::test]
async fn a_forged_payment_is_refused() {
    let mut r = restored(&[4]);
    let mut forged = r.records[0].clone();
    forged.payment.ciphertext_prefix[0] ^= 1;
    let directory = serve(&[forged], r.through);
    let found = run(&mut r.st, r.account, &directory).await.unwrap();
    assert!(!found.complete);
    assert_eq!(found.failed.len(), 1);
    assert_eq!(balance(&r.st), 0);
    // Backed off, so an immediate rerun makes no lookup.
    let before = lookups(&directory);
    run(&mut r.st, r.account, &directory).await.unwrap();
    assert_eq!(lookups(&directory), before);
}

/// A publication above the wallet's chain tip waits for the wallet to learn that tip.
#[tokio::test]
async fn a_publication_ahead_of_the_wallet_waits() {
    let mut r = restored(&[]);
    let ahead = ChainPoint {
        height: r.through.height + 5,
        hash: BlockHash([7; 32]),
    };
    let directory = serve(&[], ahead);
    let refused = run(&mut r.st, r.account, &directory).await;
    assert_matches!(refused, Err(Error::Unavailable(_)));
}

/// Unless every provider's recent set is current, discovery watches every key it checks
/// from the publication's end; with them, only the keys they list, up to the filters'
/// false positives.
#[tokio::test]
async fn without_every_recent_set_every_checked_key_scans_after_the_end() {
    for complete in [true, false] {
        let mut r = restored(&[]);
        let refund = key_receiver(&parent(&r.st), KeyId::new(Purpose::Refund, 0));
        let sets = provider(&[refund]);
        let sets = if complete { &sets[..] } else { &sets[1..] };
        let directory = Directory::new(publish(&[], &[], r.through, sets));
        run_clean(&mut r.st, &directory).await;
        let incoming = registered(&r.st, Purpose::Receive).len() as u64;
        if complete {
            // The filters' false positives register a few keys at most.
            assert!(incoming < 5, "{incoming}");
            assert!(scanning(&r.st).len() < 5);
        } else {
            assert_eq!(incoming, FIRST_WINDOW);
            assert_eq!(scanning(&r.st).len() as u64, FIRST_WINDOW + 1);
        }
    }
}

/// Two accounts discover their histories independently.
#[tokio::test]
async fn two_accounts_discover_independently() {
    let mut r = restored(&[]);
    let seed = secrecy::SecretVec::new(vec![3; 32]);
    let birthday = r.st.test_account().unwrap().birthday().clone();
    let (other, usk) =
        r.st.wallet_mut()
            .db_mut()
            .create_account("other", &seed, &birthday, None)
            .unwrap();
    let other_parent = FullViewingKey::from(usk.orchard());
    let paid = pay_unscanned_to(&mut r.st, &other_parent, 1, 0);
    // The new account sends the scan back to its birthday, at Ironwood activation.
    let blocks = paid.payment.height - ACTIVATION + 1;
    r.st.scan_cached_blocks_with_one_time_ivks(BlockHeight::from(ACTIVATION), blocks as usize);
    r.st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    let directory = serve(&[paid], tip(&r.st));
    run_clean(&mut r.st, &directory).await;
    let found = run(&mut r.st, other, &directory).await.unwrap();
    assert!(found.failed.is_empty(), "{:?}", found.failed);
    assert!(found.complete);
    let other_balance = r.st.get_total_balance(other).into_u64();
    assert_eq!(other_balance, VALUE);
    assert_eq!(balance(&r.st), 0);
}

/// Seen sets must commit to the wallet's genesis, as discovery's publication must: another
/// network's sets say nothing about this network's quotes. A publication without seen
/// sets, or with a provider that has a recent set but no seen set, may omit any receiver,
/// so issuance refuses it as discovery does. Once every provider has a dated seen set, the
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
    // Issuance waits for the restored account's discovery.
    run_clean(&mut r.st, &directory).await;
    let seen = fetch_seen(ORIGIN, &directory, GENESIS).await.unwrap();
    let contains = |receivers: &[[u8; 43]]| seen.contains(receivers);
    let seen = ProviderSeen {
        since: seen.since(),
        until: seen.until(),
        contains: &contains,
    };
    let db = r.st.wallet_mut().db_mut();
    let key = db.reserve_refund_key(r.account, r.through.height, Some(&seen));
    // Discovery registered the seen refund index, so issuance takes the next one.
    assert_eq!(
        key.unwrap().unwrap().key_id(),
        KeyId::new(Purpose::Refund, 1)
    );
}

/// A key issuance registers for a lookup after the pass finished, from a provider's seen
/// set, waits without a lookup request for a publication that reaches the blocks the
/// wallet scanned without it. That publication's lookup finds its payment without starting
/// a new pass.
#[tokio::test]
async fn a_key_registered_after_the_pass_waits_for_a_newer_publication() {
    let mut r = restored(&[]);
    let first = serve(&[], r.through);
    assert!(run_clean(&mut r.st, &first).await.complete);
    let record = pay_restored_key(&mut r.st, 0, 0);
    r.st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    let through = tip(&r.st);
    let sets = provider(&[receiver(&r.st, 0)]);
    let seen = Directory::new(publish(&[], &[], through, &sets));
    let seen = fetch_seen(ORIGIN, &seen, GENESIS).await.unwrap();
    let contains = |receivers: &[[u8; 43]]| seen.contains(receivers);
    let seen = ProviderSeen {
        since: seen.since(),
        until: seen.until(),
        contains: &contains,
    };
    let db = r.st.wallet_mut().db_mut();
    let issued = db.prepare_receive_reservation(r.account, NOW, through.height, Some(&seen));
    assert_eq!(issued.unwrap().unwrap().key_id().index(), 1);

    let requests = first.requests().len();
    let found = run_clean(&mut r.st, &first).await;
    assert!(!found.complete);
    assert_eq!(found.lookups, 0);
    assert_eq!(first.requests().len(), requests + 1, "only the manifest");

    let newer = serve(&[record], through);
    let found = run_clean(&mut r.st, &newer).await;
    assert!(found.complete);
    assert_eq!(balance(&r.st), VALUE);
    let requests = newer.requests();
    assert!(
        !requests.iter().any(|r| r.contains("/filters/")),
        "{requests:?}"
    );
}
