//! Discovery end to end: a restored wallet checks its one-time keys against a receiver
//! directory served in process, over the service's routes and real PIR, and imports what
//! it finds only after checking it against its own chain. The service's own HTTP router
//! is tested against these clients in wallet-pir.

use orchard::keys::{FullViewingKey, Scope};
use std::sync::Mutex;
use zakura_pir_client::receiver::{
    RawRecord,
    crypto::{Payment, Receiver, Record},
    inventory::{FilterRef, Inventory, Shard},
    lookup, lookup_pages, publication as wallet_publication,
    session::{Error as DirectoryError, MIN_ROWS, Publication},
    shards::{Coverage, ShardFilter},
    snapshot::{Manifest, PROFILE, Snapshot},
    transport::{Inventories, InventoryClient, Transport},
    witness,
};
use zakura_pir_publisher::receiver::{
    snapshot::{SnapshotPublisherExt, assign_ordinals},
    witness::{TablePublisherExt, payloads},
};
use zakura_pir_query_server::receiver::server::{Server, WitnessServer};
use zcash_client_backend::data_api::{
    Account as _, WalletRead as _,
    chain::BlockSource as _,
    one_time_ivk::restore::RECOVERY_PAGE_LIMIT,
    testing::{AddressType, IronwoodFvk, TestBuilder, TestRng, TestState},
    transparent_ledger::ChainPoint,
};
use zcash_client_sqlite::{
    AccountUuid, WalletDb,
    testing::{
        BlockCache,
        db::{TestDb, TestDbFactory},
    },
    util::testing::FixedClock,
    wallet::one_time_ivk::{KeyId, Purpose},
};
use zcash_primitives::block::BlockHash;
use zcash_protocol::{consensus::BlockHeight, local_consensus::LocalNetwork, value::Zatoshis};

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
        ordinal: 0,
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
    st.scan_cached_blocks(BlockHeight::from(record.payment.height), 1);
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
    restored_in(TestDbFactory::default(), paid)
}

/// [`restored`], with the wallet stored as `factory` makes it.
fn restored_in(factory: TestDbFactory, paid: &[u64]) -> Restored {
    let mut st = ironwood_wallet_in(factory);
    let account = st.test_account().unwrap().id();
    st.generate_and_scan_empty_blocks(1);
    let mut records = Vec::new();
    for (position, index) in (0..).zip(paid) {
        let mut record = pay_restored_key(&mut st, *index, position);
        let pages = |paid: &[u64]| paid.iter().filter(|i| *i == index).count();
        record.page = pages(&paid[..records.len()]).try_into().unwrap();
        record.total = pages(paid).try_into().unwrap();
        records.push(record);
    }
    st.generate_and_scan_empty_blocks(1);
    let through = tip(&st);
    Restored {
        st,
        account,
        through,
        records,
    }
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

/// One planned shard: its last block, whether it is sealed (with a filter when
/// `filter`), and how many segments its records split across.
#[derive(Clone, Copy)]
struct Plan {
    end: BlockHeight,
    sealed: bool,
    filter: bool,
    segments: usize,
}

impl Plan {
    /// A sealed shard ending at `end`, with one segment and a filter.
    fn sealed(end: BlockHeight) -> Self {
        Self {
            end,
            sealed: true,
            filter: true,
            segments: 1,
        }
    }

    /// The recent tier ending at `end`, with one segment and no filter.
    fn recent(end: BlockHeight) -> Self {
        Self {
            end,
            sealed: false,
            filter: false,
            segments: 1,
        }
    }
}

/// The block identity and Ironwood tree size at `height` in `st`'s cached chain.
fn block_at(st: &State, height: BlockHeight) -> ([u8; 32], u64) {
    let block = cached(st, height);
    (
        block.hash().0,
        block
            .chain_metadata
            .unwrap()
            .ironwood_commitment_tree_size
            .into(),
    )
}

/// Publishes `records`, the chain's indexed Ironwood outputs, as contiguous shards following
/// `plans` with the production snapshot, witness, filter and inventory builders. Every
/// witness table is built at the last shard's end. `segment_of` picks a record's segment
/// within its shard; pages are segment-local.
fn publish_with(
    st: &State,
    records: &[Record],
    plans: &[Plan],
    segment_of: &dyn Fn(&Record) -> usize,
) -> Routes {
    publish_revision(st, records, plans, segment_of, 0)
}

/// [`publish_with`] under correction generation `revision`.
fn publish_revision(
    st: &State,
    records: &[Record],
    plans: &[Plan],
    segment_of: &dyn Fn(&Record) -> usize,
    revision: u64,
) -> Routes {
    let last = plans.last().unwrap().end;
    let mut commitments = vec![];
    st.cache()
        .with_blocks::<_, ()>(None, None, |block| {
            if block.height() <= last {
                for tx in &block.vtx {
                    for action in &tx.ironwood_actions {
                        commitments.push(action.cmx.as_slice().try_into().unwrap());
                    }
                }
            }
            Ok(())
        })
        .unwrap();
    let (last_hash, last_size) = block_at(st, last);
    let mut routes = Routes::default();
    let mut shards = vec![];
    let (mut start, mut parent, mut position) = (ACTIVATION, [0; 32], 0);
    for plan in plans {
        let (end_hash, end_position) = block_at(st, plan.end);
        let mut segments = vec![];
        let in_shard: Vec<_> = records
            .iter()
            .filter(|r| (start..=u32::from(plan.end)).contains(&r.payment.height))
            .collect();
        for index in 0..plan.segments {
            let mut raw: Vec<RawRecord> = vec![];
            for record in in_shard
                .iter()
                .filter(|r| segment_of(r) % plan.segments == index)
            {
                let mut r = RawRecord::decode(&record.encode().unwrap())
                    .unwrap()
                    .unwrap();
                r.page = raw.iter().filter(|o| o.receiver == r.receiver).count() as u32;
                raw.push(r);
            }
            for i in 0..raw.len() {
                let receiver = raw[i].receiver;
                raw[i].total = raw.iter().filter(|o| o.receiver == receiver).count() as u32;
            }
            assign_ordinals(&mut raw);
            let snapshot = Snapshot::build(
                Manifest {
                    profile: PROFILE.into(),
                    history_revision: revision,
                    genesis: GENESIS,
                    start_height: start,
                    start_parent: parent,
                    start_position: position,
                    end_height: plan.end.into(),
                    end_hash,
                    end_position,
                    rows: MIN_ROWS,
                    salt: [5 + index as u8; 32],
                    records: 0,
                    data_sha256: [0; 32],
                },
                &raw,
            )
            .unwrap();
            let mut positions: Vec<_> = raw.iter().map(|r| r.payment.position).collect();
            positions.sort_unstable();
            let table = witness::Table::build(
                witness::Manifest {
                    profile: witness::PROFILE.into(),
                    genesis: GENESIS,
                    history_revision: revision,
                    payments: snapshot.manifest.revision().unwrap(),
                    payloads: 0,
                    rows: MIN_ROWS,
                    tree_height: last.into(),
                    tree_hash: last_hash,
                    tree_size: last_size,
                    data_sha256: [0; 32],
                },
                &payloads(&commitments[..last_size as usize], &positions).unwrap(),
            )
            .unwrap();
            let payments = Server::new(snapshot).unwrap();
            let witnesses = WitnessServer::new(table, &payments).unwrap();
            segments.push(Publication {
                payments: payments.manifest().clone(),
                witnesses: witnesses.manifest().clone(),
            });
            routes.payments.push(payments);
            routes.witnesses.push(witnesses);
        }
        let coverage = Coverage {
            start_height: start,
            end_height: plan.end.into(),
            end_hash,
        };
        let filter = (plan.sealed && plan.filter).then(|| {
            let filter = ShardFilter::build(
                GENESIS,
                revision,
                coverage,
                in_shard.iter().map(|r| r.receiver.as_bytes()),
            )
            .unwrap();
            routes
                .filters
                .push((filter.digest(), filter.bytes().to_vec()));
            FilterRef {
                digest: filter.digest(),
                bytes: filter.bytes().len() as u32,
                receivers: filter.receivers() as u32,
            }
        });
        shards.push(Shard {
            index: 0,
            sealed: plan.sealed,
            start_height: start,
            start_parent: parent,
            start_position: position,
            end_height: plan.end.into(),
            end_hash,
            end_position,
            segments,
            filter,
        });
        (start, parent, position) = (u32::from(plan.end) + 1, end_hash, end_position);
    }
    routes.inventory = Some(Inventory::build(GENESIS, revision, shards).unwrap());
    routes
}

/// One inventory's receiver routes, answered as the receiver service answers them: its
/// head and chunks, shard filters by digest, session setup and real PIR evaluation of each
/// encrypted payment or witness query. A session it does not serve is gone (410).
#[derive(Default)]
struct Routes {
    inventory: Option<Inventory>,
    payments: Vec<Server>,
    witnesses: Vec<WitnessServer>,
    filters: Vec<([u8; 32], Vec<u8>)>,
}

impl Routes {
    /// The status and body for `method` on `path`.
    fn answer(&self, method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
        let route = path.strip_prefix("/v1/receiver/").unwrap_or(path);
        let inventory = self.inventory.as_ref().unwrap();
        if (method, route) == ("POST", "query") {
            let session = body.get(4..36);
            let response = if let Some(w) =
                self.witnesses.iter().find(|w| session == Some(&w.id()[..]))
            {
                w.respond(body)
            } else if let Some(p) = self.payments.iter().find(|p| session == Some(&p.id()[..])) {
                p.respond(body)
            } else {
                Err(DirectoryError::Revision)
            };
            return match response {
                Ok(response) => (200, response),
                Err(DirectoryError::Revision) => (410, Vec::new()),
                Err(DirectoryError::Malformed) => (400, Vec::new()),
                Err(_) => (500, Vec::new()),
            };
        }
        if method != "GET" {
            return (404, Vec::new());
        }
        if route == "inventory" {
            return (200, serde_json::to_vec(inventory.head()).unwrap());
        }
        let parts: Vec<_> = route.split('/').collect();
        match parts.as_slice() {
            ["inventory", id, chunk] => {
                if *id != hex::encode(inventory.head().inventory) {
                    return (410, Vec::new());
                }
                let chunks = inventory.chunks().unwrap();
                match chunk.parse::<usize>().ok().and_then(|i| chunks.get(i)) {
                    Some(chunk) => (200, serde_json::to_vec(chunk).unwrap()),
                    None => (404, Vec::new()),
                }
            }
            ["shard-filters", digest] => self
                .filters
                .iter()
                .find(|(d, _)| hex::encode(d) == *digest)
                .map_or((404, Vec::new()), |(_, f)| (200, f.clone())),
            ["public", id] => {
                let public = self
                    .payments
                    .iter()
                    .find(|p| hex::encode(p.id()) == *id)
                    .map(|p| p.public())
                    .or_else(|| {
                        self.witnesses
                            .iter()
                            .find(|w| hex::encode(w.id()) == *id)
                            .map(|w| w.public())
                    });
                public.map_or((410, Vec::new()), |p| (200, p.to_vec()))
            }
            _ => (404, Vec::new()),
        }
    }
}

/// Serves `records`, the chain's only Ironwood outputs, as one recent tier ending at `end`.
fn serve(st: &State, records: &[Record], end: ChainPoint) -> Directory {
    Directory::new(publish_with(
        st,
        records,
        &[Plan::recent(end.height)],
        &|_| 0,
    ))
}

/// Serves a directory's routes in process and records every request.
struct Directory {
    routes: Mutex<Routes>,
    requests: Mutex<Vec<String>>,
}

impl Directory {
    /// Serves `routes` at [`ORIGIN`].
    fn new(routes: Routes) -> Self {
        Self {
            routes: Mutex::new(routes),
            requests: Mutex::new(Vec::new()),
        }
    }

    /// Replaces the served inventory; the old one's objects are gone.
    fn replace(&self, routes: Routes) {
        *self.routes.lock().unwrap() = routes;
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
        let (status, body) = self.routes.lock().unwrap().answer(method, path, &body);
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
    /// Fetches bounded common session material.
    async fn get(&self, url: &str, limit: usize) -> Result<Vec<u8>, DirectoryError> {
        self.send("GET", url, Vec::new(), limit).await
    }

    /// Evaluates an encrypted receiver query.
    async fn post(
        &self,
        url: &str,
        body: Vec<u8>,
        limit: usize,
    ) -> Result<Vec<u8>, DirectoryError> {
        self.send("POST", url, body, limit).await
    }
}

/// The encrypted queries `directory` has served, payment and witness alike.
fn lookups(directory: &Directory) -> usize {
    let requests = directory.requests();
    requests
        .iter()
        .filter(|r| *r == "POST /v1/receiver/query")
        .count()
}

/// Captures the served inventory only after checking its end against the wallet's chain,
/// reading sealed shards' filters.
async fn connect(directory: &Directory, end: ChainPoint) -> InventoryClient<&Directory> {
    connect_with(directory, end, true).await
}

/// [`connect`], reading every required segment blind unless `filters`.
async fn connect_with(
    directory: &Directory,
    end: ChainPoint,
    filters: bool,
) -> InventoryClient<&Directory> {
    let head = Inventories::head(ORIGIN, &directory, &GENESIS)
        .await
        .unwrap();
    let inventory = Inventories::capture(ORIGIN, &directory, head)
        .await
        .unwrap();
    inventory
        .accept(&GENESIS, ACTIVATION, end.height.into(), &end.hash.0)
        .unwrap();
    InventoryClient::new(ORIGIN, directory, inventory, filters)
}

/// Completes bounded wallet work through encrypted payment and witness queries.
async fn drain(st: &mut State, account: AccountUuid, client: &InventoryClient<&Directory>) {
    for _ in 0..256 {
        let status = st.wallet().db().one_time_recovery(account, NOW).unwrap();
        if let Some(work) = status.lookups.first() {
            let page = lookup(client, work).await.unwrap();
            assert!(
                st.wallet_mut()
                    .db_mut()
                    .record_one_time_lookup(account, work, &page, NOW)
                    .unwrap()
            );
        } else if let Some(request) = status.witnesses.first() {
            let answer = witness(client, request).await.unwrap();
            assert!(
                st.wallet_mut()
                    .db_mut()
                    .record_one_time_witness(account, status.token, *request, &answer, NOW)
                    .unwrap()
            );
        } else {
            return;
        }
    }
    panic!("bounded fixture did not settle");
}

/// Starts recovery without retaining a database handle across network work.
fn begin(r: &mut Restored, client: &InventoryClient<&Directory>, direct: bool) {
    let db = r.st.wallet_mut().db_mut();
    db.set_one_time_recovery_enabled(r.account, true).unwrap();
    assert!(
        db.begin_one_time_recovery(r.account, wallet_publication(client.inventory()), direct)
            .unwrap()
    );
}

/// Seed discovery walks four genuine empty indexes and retrieves every page of a paid key.
#[tokio::test]
async fn seed_recovery_pages_history_and_stops_at_four_empty_indexes() {
    let mut r = restored(&[0, 3, 3, 40]);
    let directory = serve(&r.st, &r.records, r.through);
    let client = connect(&directory, r.through).await;
    begin(&mut r, &client, true);
    drain(&mut r.st, r.account, &client).await;
    let status =
        r.st.wallet()
            .db()
            .one_time_recovery(r.account, NOW)
            .unwrap();
    assert!(status.restore_complete);
    assert_eq!(status.restore_next, 8);
    assert_eq!(one_time_value(&r.st), 3 * VALUE);
    // Nine payment pages, then one witness query for each of the three payments.
    assert_eq!(lookups(&directory), 12);
    let queries = lookups(&directory);
    begin(&mut r, &client, true);
    drain(&mut r.st, r.account, &client).await;
    assert_eq!(
        lookups(&directory),
        queries,
        "same frontier is not queried twice"
    );
    let next =
        r.st.wallet_mut()
            .db_mut()
            .prepare_receive_reservation(r.account, NOW)
            .unwrap()
            .unwrap();
    assert_eq!(next.key_id().index(), 1, "the lowest unpaid hole is reused");
}

/// A positive hint without a payment needs one empty PIR answer and cannot advance issuance.
#[tokio::test]
async fn a_positive_hint_without_payment_settles_with_one_empty_query() {
    use zakura_pir_client::receiver::blocks::{Batch, BlockFilter, BlockId};
    let mut r = restored(&[]);
    let initial = serve(&r.st, &[], r.through);
    let client = connect(&initial, r.through).await;
    begin(&mut r, &client, true);
    drain(&mut r.st, r.account, &client).await;
    assert_eq!(lookups(&initial), 4);
    r.st.generate_and_scan_empty_blocks(1);
    let end = tip(&r.st);
    let (token, receivers) = r.st.wallet().db().one_time_receivers(r.account).unwrap();
    let receiver = &receivers[0];
    // A deliberately overinclusive hint exercises the same path as a GCS false positive.
    let filter = BlockFilter::build(
        &GENESIS,
        BlockId {
            height: end.height.into(),
            hash: end.hash.0,
        },
        r.through.hash.0,
        [&receiver.receiver],
    )
    .unwrap();
    let bytes = Batch::new(GENESIS, 0, vec![filter])
        .unwrap()
        .encode()
        .unwrap();
    let batch = Batch::decode(&bytes).unwrap();
    assert_eq!(batch.matches(0, &[receiver.receiver]).unwrap(), [true]);
    assert!(
        r.st.wallet_mut()
            .db_mut()
            .record_one_time_filters(r.account, token, 0, &[end], &[receiver.key])
            .unwrap()
    );
    let directory = serve(&r.st, &[], end);
    let client = connect(&directory, end).await;
    drain(&mut r.st, r.account, &client).await;
    let status =
        r.st.wallet()
            .db()
            .one_time_recovery(r.account, NOW)
            .unwrap();
    assert!(status.lookups.is_empty() && status.witnesses.is_empty());
    assert_eq!(status.restore_next, 4);
    assert_eq!(one_time_value(&r.st), 0);
    assert_eq!(lookups(&directory), 1);
    drain(&mut r.st, r.account, &client).await;
    assert_eq!(lookups(&directory), 1, "the empty answer settles the hint");
    let next =
        r.st.wallet_mut()
            .db_mut()
            .prepare_receive_reservation(r.account, NOW)
            .unwrap()
            .unwrap();
    assert_eq!(next.key_id().index(), 0);
}

/// A caller-supplied manual bound reaches beyond the seed gap and admits old repeat payments.
#[tokio::test]
async fn manual_bound_crosses_a_gap() {
    let mut r = restored(&[5]);
    let directory = serve(&r.st, &r.records, r.through);
    let client = connect(&directory, r.through).await;
    begin(&mut r, &client, true);
    drain(&mut r.st, r.account, &client).await;
    assert_eq!(one_time_value(&r.st), 0);
    assert!(
        r.st.wallet_mut()
            .db_mut()
            .check_one_time_history(r.account, wallet_publication(client.inventory()), Some(6))
            .unwrap()
    );
    drain(&mut r.st, r.account, &client).await;
    assert_eq!(one_time_value(&r.st), VALUE);
    assert!(
        !r.st
            .wallet()
            .db()
            .one_time_recovery(r.account, NOW)
            .unwrap()
            .manual
            .unwrap()
            .active
    );
}

/// A response obtained before disabling the feature cannot import funds or finish a lookup.
#[tokio::test]
async fn disabling_fences_a_held_encrypted_response() {
    let mut r = restored(&[0]);
    let directory = serve(&r.st, &r.records, r.through);
    let client = connect(&directory, r.through).await;
    begin(&mut r, &client, true);
    let work =
        r.st.wallet()
            .db()
            .one_time_recovery(r.account, NOW)
            .unwrap()
            .lookups
            .remove(0);
    let page = lookup(&client, &work).await.unwrap();
    r.st.wallet_mut()
        .db_mut()
        .set_one_time_recovery_enabled(r.account, false)
        .unwrap();
    assert!(
        !r.st
            .wallet_mut()
            .db_mut()
            .record_one_time_lookup(r.account, &work, &page, NOW)
            .unwrap()
    );
    assert_eq!(one_time_value(&r.st), 0);
    assert!(
        r.st.wallet()
            .db()
            .one_time_recovery(r.account, NOW)
            .unwrap()
            .lookups
            .is_empty()
    );
    begin(&mut r, &client, true);
    drain(&mut r.st, r.account, &client).await;
    assert_eq!(one_time_value(&r.st), VALUE);
}

/// A structurally valid row for the wrong receiver fails note authentication before admission.
#[tokio::test]
async fn a_forged_payment_is_not_an_empty_answer() {
    let mut r = restored(&[1]);
    r.records[0].receiver = receiver(&r.st, 0);
    let directory = serve(&r.st, &r.records, r.through);
    let client = connect(&directory, r.through).await;
    begin(&mut r, &client, true);
    let work =
        r.st.wallet()
            .db()
            .one_time_recovery(r.account, NOW)
            .unwrap()
            .lookups
            .remove(0);
    let page = lookup(&client, &work).await.unwrap();
    assert!(
        r.st.wallet_mut()
            .db_mut()
            .record_one_time_lookup(r.account, &work, &page, NOW)
            .is_err()
    );
    let status =
        r.st.wallet()
            .db()
            .one_time_recovery(r.account, NOW)
            .unwrap();
    assert_eq!(status.restore_gap, 0);
    assert_eq!(one_time_value(&r.st), 0);
    assert_eq!(status.lookups[0], work);
}

/// A candidate read under a replaced session never reinterprets its ordinal in the new
/// session's witness table: it is read again there, then admitted.
#[tokio::test]
async fn a_replaced_session_reads_the_payment_again_for_its_witness() {
    let mut r = restored(&[2, 0]);
    let old = serve(&r.st, &r.records, r.through);
    let client = connect(&old, r.through).await;
    begin(&mut r, &client, true);
    let work =
        r.st.wallet()
            .db()
            .one_time_recovery(r.account, NOW)
            .unwrap()
            .lookups
            .into_iter()
            .find(|w| w.work.key == KeyId::new(Purpose::Receive, 0))
            .unwrap();
    let page = lookup(&client, &work).await.unwrap();
    assert!(
        r.st.wallet_mut()
            .db_mut()
            .record_one_time_lookup(r.account, &work, &page, NOW)
            .unwrap()
    );
    let status =
        r.st.wallet()
            .db()
            .one_time_recovery(r.account, NOW)
            .unwrap();
    let request = status.witnesses[0];
    assert_eq!(request.ordinal, 1, "ordinals rank payments by position");
    // A later publication covers one more block; its payment session differs.
    r.st.generate_and_scan_empty_blocks(1);
    let end = tip(&r.st);
    let directory = serve(&r.st, &r.records, end);
    let current = connect(&directory, end).await;
    assert!(matches!(
        witness(&current, &request).await,
        Err(DirectoryError::Revision)
    ));
    assert!(
        r.st.wallet_mut()
            .db_mut()
            .refresh_one_time_witness(r.account, status.token, request)
            .unwrap()
    );
    let status =
        r.st.wallet()
            .db()
            .one_time_recovery(r.account, NOW)
            .unwrap();
    assert!(status.witnesses.is_empty(), "the old binding is gone");
    assert!(
        status
            .lookups
            .iter()
            .any(|w| w.work.key == KeyId::new(Purpose::Receive, 0) && w.cursor.is_none())
    );
    drain(&mut r.st, r.account, &current).await;
    assert_eq!(one_time_value(&r.st), 2 * VALUE);
}

/// Validated shard filters stand in for PIR on sealed shards that exclude a receiver,
/// while the recent tier is always read. Blind reads cover every required segment. Both
/// routes recover the same payment.
#[tokio::test]
async fn shard_filters_skip_sealed_shards_that_exclude_a_receiver() {
    for filters in [true, false] {
        let mut r = restored(&[0]);
        let paid = BlockHeight::from(r.records[0].payment.height);
        let plans = [Plan::sealed(paid), Plan::recent(r.through.height)];
        let directory = Directory::new(publish_with(&r.st, &r.records, &plans, &|_| 0));
        let client = connect_with(&directory, r.through, filters).await;
        begin(&mut r, &client, true);
        drain(&mut r.st, r.account, &client).await;
        assert_eq!(one_time_value(&r.st), VALUE);
        assert!(
            r.st.wallet()
                .db()
                .one_time_recovery(r.account, NOW)
                .unwrap()
                .restore_complete
        );
        // I0 reads both shards and its witness. I1 to I4 skip the sealed shard by filter,
        // or read it blind.
        let expected = if filters { 2 + 4 + 1 } else { 2 * 5 + 1 };
        assert_eq!(lookups(&directory), expected, "filters: {filters}");
        let fetched = directory
            .requests()
            .iter()
            .filter(|r| r.starts_with("GET /v1/receiver/shard-filters/"))
            .count();
        assert_eq!(fetched, usize::from(filters), "one fetch serves every key");
    }
}

/// A filter that fails its digest is never a negative: the shard is read over PIR.
#[tokio::test]
async fn a_substituted_shard_filter_falls_back_to_pir() {
    let mut r = restored(&[0]);
    let paid = BlockHeight::from(r.records[0].payment.height);
    let plans = [Plan::sealed(paid), Plan::recent(r.through.height)];
    let mut routes = publish_with(&r.st, &r.records, &plans, &|_| 0);
    // Serve an empty set under the digest the inventory names.
    let empty = ShardFilter::build(
        GENESIS,
        0,
        Coverage {
            start_height: ACTIVATION,
            end_height: paid.into(),
            end_hash: block_at(&r.st, paid).0,
        },
        [],
    )
    .unwrap();
    routes.filters[0].1 = empty.bytes().to_vec();
    let directory = Directory::new(routes);
    let client = connect(&directory, r.through).await;
    begin(&mut r, &client, true);
    drain(&mut r.st, r.account, &client).await;
    assert_eq!(one_time_value(&r.st), VALUE);
    assert_eq!(lookups(&directory), 2 * 5 + 1);
}

/// A shard too large for one table splits into segments with local pages. A receiver
/// only in the last segment is still found, and every segment is read before the shard
/// counts as covered.
#[tokio::test]
async fn a_receiver_only_in_the_last_segment_of_an_oversized_shard_is_found() {
    let mut r = restored(&[1, 0]);
    let last = BlockHeight::from(r.records[1].payment.height);
    let target = r.records[1].receiver;
    let plans = [
        Plan {
            end: last,
            sealed: true,
            filter: true,
            segments: 2,
        },
        Plan::recent(r.through.height),
    ];
    let directory = Directory::new(publish_with(&r.st, &r.records, &plans, &|record| {
        usize::from(record.receiver == target)
    }));
    let client = connect(&directory, r.through).await;
    begin(&mut r, &client, true);
    drain(&mut r.st, r.account, &client).await;
    assert_eq!(one_time_value(&r.st), 2 * VALUE);
    assert!(
        r.st.wallet()
            .db()
            .one_time_recovery(r.account, NOW)
            .unwrap()
            .restore_complete
    );
}

/// After direct catch-up completes a receiver through one inventory's end, a payment just
/// past that point lands in a newly sealed shard that straddles it. The whole shard is
/// required, so its filter matches and the payment is read; shards wholly below are not.
#[tokio::test]
async fn a_payment_in_a_shard_straddling_the_completion_point_is_found() {
    let mut r = restored(&[]);
    let first = Directory::new(publish_with(
        &r.st,
        &[],
        &[Plan::recent(r.through.height)],
        &|_| 0,
    ));
    let client = connect(&first, r.through).await;
    begin(&mut r, &client, true);
    drain(&mut r.st, r.account, &client).await;
    assert_eq!(lookups(&first), 4);
    let completed = r.through.height;
    let payment = pay_restored_key(&mut r.st, 0, 0);
    r.st.generate_and_scan_empty_blocks(2);
    let end = tip(&r.st);
    let records = [payment];
    // The sealed shard covers from activation through the payment's next block, straddling
    // the completion point; the recent tier holds the last block.
    let plans = [Plan::sealed(end.height - 1), Plan::recent(end.height)];
    let directory = Directory::new(publish_with(&r.st, &records, &plans, &|_| 0));
    let client = connect(&directory, end).await;
    let status =
        r.st.wallet()
            .db()
            .one_time_recovery(r.account, NOW)
            .unwrap();
    assert!(status.lookups.is_empty());
    begin(&mut r, &client, true);
    let queued =
        r.st.wallet()
            .db()
            .one_time_recovery(r.account, NOW)
            .unwrap();
    assert!(
        queued.lookups.iter().all(|w| w.from == completed + 1),
        "catch-up continues after the completed span"
    );
    drain(&mut r.st, r.account, &client).await;
    assert_eq!(one_time_value(&r.st), VALUE);
    // I0 reads the straddling shard, the recent tier and its witness; I1 to I3 only the
    // recent tier. I4 joins the window once the payment is mined and reads the recent tier.
    assert_eq!(lookups(&directory), 3 + 4);
}

/// An inventory replaced between reading a payment and reading its witness: the old
/// sessions are gone, so neither a held lookup nor the witness completes anything. The
/// candidate stays pending and is read again in the new inventory's sealed segment.
#[tokio::test]
async fn inventory_replacement_between_payment_and_witness_keeps_the_payment_pending() {
    let mut r = restored(&[1, 0]);
    let directory = serve(&r.st, &r.records, r.through);
    let old = connect(&directory, r.through).await;
    begin(&mut r, &old, true);
    let status =
        r.st.wallet()
            .db()
            .one_time_recovery(r.account, NOW)
            .unwrap();
    let key0 = status
        .lookups
        .iter()
        .find(|w| w.work.key == KeyId::new(Purpose::Receive, 0))
        .unwrap()
        .clone();
    let page = lookup(&old, &key0).await.unwrap();
    assert!(
        r.st.wallet_mut()
            .db_mut()
            .record_one_time_lookup(r.account, &key0, &page, NOW)
            .unwrap()
    );
    let held =
        r.st.wallet()
            .db()
            .one_time_recovery(r.account, NOW)
            .unwrap()
            .lookups
            .into_iter()
            .find(|w| w.work.key == KeyId::new(Purpose::Receive, 1))
            .unwrap();
    // The publisher seals the paid blocks into a two-segment shard and drops the old
    // inventory's sessions.
    let last = BlockHeight::from(r.records[1].payment.height);
    let plans = [
        Plan {
            end: last,
            sealed: true,
            filter: true,
            segments: 2,
        },
        Plan::recent(r.through.height),
    ];
    let target = r.records[1].receiver;
    directory.replace(publish_with(&r.st, &r.records, &plans, &|record| {
        usize::from(record.receiver == target)
    }));
    assert!(matches!(
        lookup(&old, &held).await,
        Err(DirectoryError::Revision)
    ));
    let status =
        r.st.wallet()
            .db()
            .one_time_recovery(r.account, NOW)
            .unwrap();
    let request = status.witnesses[0];
    assert!(matches!(
        witness(&old, &request).await,
        Err(DirectoryError::Revision)
    ));
    assert_eq!(one_time_value(&r.st), 0);
    assert!(
        r.st.wallet_mut()
            .db_mut()
            .refresh_one_time_witness(r.account, status.token, request)
            .unwrap()
    );
    let current = connect(&directory, r.through).await;
    drain(&mut r.st, r.account, &current).await;
    assert_eq!(one_time_value(&r.st), 2 * VALUE);
    assert!(
        r.st.wallet()
            .db()
            .one_time_recovery(r.account, NOW)
            .unwrap()
            .restore_complete
    );
}

/// A correction that adds a previously omitted payment invalidates a held empty answer
/// from the old generation; the corrected inventory's sealed shard yields the payment.
#[tokio::test]
async fn a_correction_adding_an_omitted_payment_voids_held_empties() {
    let mut r = restored(&[0]);
    let paid = BlockHeight::from(r.records[0].payment.height);
    let plans = [Plan::sealed(paid), Plan::recent(r.through.height)];
    let omitted = Directory::new(publish_with(&r.st, &[], &plans, &|_| 0));
    let client = connect(&omitted, r.through).await;
    begin(&mut r, &client, true);
    let work =
        r.st.wallet()
            .db()
            .one_time_recovery(r.account, NOW)
            .unwrap()
            .lookups
            .remove(0);
    let mut held = vec![];
    let mut step = work.clone();
    loop {
        let page = lookup(&client, &step).await.unwrap();
        let next = page.next.clone();
        held.push(page);
        match next {
            Some(cursor) => step.cursor = Some(cursor),
            None => break,
        }
    }
    let corrected = Directory::new(publish_revision(&r.st, &r.records, &plans, &|_| 0, 1));
    let client = connect(&corrected, r.through).await;
    assert!(
        r.st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(r.account, wallet_publication(client.inventory()), true)
            .unwrap()
    );
    assert!(
        !r.st
            .wallet_mut()
            .db_mut()
            .record_one_time_lookup(r.account, &work, &held[0], NOW)
            .unwrap()
    );
    drain(&mut r.st, r.account, &client).await;
    assert_eq!(one_time_value(&r.st), VALUE);
}

/// Shard filters are kept within a byte budget: a restore needing more filters than fit
/// evicts and fetches them again, and still recovers every payment.
#[tokio::test]
async fn recovery_continues_across_more_filters_than_the_cache_holds() {
    let mut r = restored(&[0, 2, 1]);
    let height = |i: usize| BlockHeight::from(r.records[i].payment.height);
    let plans = [
        Plan::sealed(height(0)),
        Plan::sealed(height(1)),
        Plan::sealed(height(2)),
        Plan::recent(r.through.height),
    ];
    let routes = publish_with(&r.st, &r.records, &plans, &|_| 0);
    let largest = routes.filters.iter().map(|(_, f)| f.len()).max().unwrap();
    let directory = Directory::new(routes);
    let client = connect(&directory, r.through)
        .await
        .with_filter_budget(largest);
    begin(&mut r, &client, true);
    drain(&mut r.st, r.account, &client).await;
    assert_eq!(one_time_value(&r.st), 3 * VALUE);
    let fetched = directory
        .requests()
        .iter()
        .filter(|r| r.starts_with("GET /v1/receiver/shard-filters/"))
        .count();
    assert!(fetched > 3, "evicted filters are fetched again: {fetched}");
}

/// Opened segment sessions are kept within a byte budget: a blind restore across more
/// segments than fit evicts sessions and opens them again, and still recovers every payment.
#[tokio::test]
async fn a_blind_restore_reopens_segments_beyond_the_session_budget() {
    let mut r = restored(&[0, 2, 1]);
    let height = |i: usize| BlockHeight::from(r.records[i].payment.height);
    let plans = [
        Plan::sealed(height(0)),
        Plan::sealed(height(1)),
        Plan::sealed(height(2)),
        Plan::recent(r.through.height),
    ];
    let directory = Directory::new(publish_with(&r.st, &r.records, &plans, &|_| 0));
    let one_segment = 2 * zakura_pir_client::receiver::native::public_bytes(MIN_ROWS).unwrap();
    let client = connect_with(&directory, r.through, false)
        .await
        .with_segment_budget(one_segment);
    begin(&mut r, &client, true);
    drain(&mut r.st, r.account, &client).await;
    assert_eq!(one_time_value(&r.st), 3 * VALUE);
    let setups = directory
        .requests()
        .iter()
        .filter(|r| r.starts_with("GET /v1/receiver/public/"))
        .count();
    assert!(
        setups > 2 * plans.len(),
        "evicted sessions reopen: {setups}"
    );
}

/// The key's due lookup in `r`'s wallet.
fn due(
    r: &Restored,
    key: KeyId,
) -> zcash_client_backend::data_api::one_time_ivk::restore::LookupWork {
    r.st.wallet()
        .db()
        .one_time_recovery(r.account, NOW)
        .unwrap()
        .lookups
        .into_iter()
        .find(|work| work.work.key == key)
        .unwrap()
}

/// A lookup resumed from a cursor its inventory no longer serves starts over. An incomplete
/// inventory listed key 0's payment B as its first page, and the wallet saved a cursor
/// after it. The replacement inventory lists the earlier payment A first and B second. The
/// saved cursor names the old inventory, so the lookup reads the key's history again from
/// its start without counting the mismatch as empty history or moving completion progress,
/// and finds both payments.
#[tokio::test]
async fn a_lookup_whose_cursor_record_changed_starts_over() {
    use zcash_client_backend::data_api::one_time_ivk::restore::{LookupCursor, LookupPage};
    let mut r = restored(&[0, 0]);
    let directory = serve(&r.st, &r.records, r.through);
    let old = connect(&directory, r.through).await;
    begin(&mut r, &old, true);
    let key = KeyId::new(Purpose::Receive, 0);
    let work = due(&r, key);
    let read = lookup(&old, &work).await.unwrap();
    let mut second = r.records[1].clone();
    second.page = 0;
    let first = RawRecord::decode(&second.encode().unwrap())
        .unwrap()
        .unwrap();
    let incomplete = LookupPage {
        records: vec![first.clone()],
        checked_through: None,
        next: Some(LookupCursor {
            inventory: read.publication.id,
            shard: 0,
            segment: 0,
            last: Some(first.clone()),
        }),
        ..read
    };
    assert!(
        r.st.wallet_mut()
            .db_mut()
            .record_one_time_lookup(r.account, &work, &incomplete, NOW)
            .unwrap()
    );
    let resumed = due(&r, key);
    assert_eq!(resumed.cursor.as_ref().unwrap().last, Some(first));
    let before =
        r.st.wallet()
            .db()
            .one_time_recovery(r.account, NOW)
            .unwrap();

    r.st.generate_and_scan_empty_blocks(1);
    let end = tip(&r.st);
    directory.replace(publish_with(
        &r.st,
        &r.records,
        &[Plan::recent(end.height)],
        &|_| 0,
    ));
    let current = connect(&directory, end).await;
    let page = lookup(&current, &resumed).await.unwrap();
    assert_eq!(page.records.len(), 2);
    assert!(page.complete());
    assert!(
        r.st.wallet_mut()
            .db_mut()
            .record_one_time_lookup(r.account, &resumed, &page, NOW)
            .unwrap()
    );
    let after =
        r.st.wallet()
            .db()
            .one_time_recovery(r.account, NOW)
            .unwrap();
    assert_eq!(
        (
            after.restore_next,
            after.restore_gap,
            after.restore_complete
        ),
        (
            before.restore_next,
            before.restore_gap,
            before.restore_complete
        )
    );
    begin(&mut r, &current, true);
    drain(&mut r.st, r.account, &current).await;
    assert_eq!(one_time_value(&r.st), 2 * VALUE);
}

/// A lookup the wallet refuses is deferred with a backoff, without counting it as empty
/// history: it is not due again until the delay has passed.
#[tokio::test]
async fn a_refused_lookup_backs_off_before_its_retry() {
    let mut r = restored(&[1]);
    r.records[0].receiver = receiver(&r.st, 0);
    let directory = serve(&r.st, &r.records, r.through);
    let client = connect(&directory, r.through).await;
    begin(&mut r, &client, true);
    let key = KeyId::new(Purpose::Receive, 0);
    let work = due(&r, key);
    let page = lookup(&client, &work).await.unwrap();
    assert!(
        r.st.wallet_mut()
            .db_mut()
            .record_one_time_lookup(r.account, &work, &page, NOW)
            .is_err()
    );
    r.st.wallet_mut()
        .db_mut()
        .defer_one_time_lookup(r.account, &work, NOW)
        .unwrap();
    let due_at = |r: &Restored, now: i64| {
        r.st.wallet()
            .db()
            .one_time_recovery(r.account, now)
            .unwrap()
            .lookups
            .iter()
            .any(|w| w.work.key == key)
    };
    assert!(!due_at(&r, NOW));
    assert!(!due_at(&r, NOW + 59));
    assert!(due_at(&r, NOW + 60));
    assert_eq!(
        r.st.wallet()
            .db()
            .one_time_recovery(r.account, NOW)
            .unwrap()
            .restore_gap,
        0
    );
}

/// An inventory ending above the wallet's scanned tip waits for the wallet to learn that
/// tip: it starts no recovery work.
#[tokio::test]
async fn a_publication_ahead_of_the_wallet_waits() {
    let mut r = restored(&[0]);
    for _ in 0..5 {
        r.st.generate_empty_block();
    }
    let height = r.through.height + 5;
    let ahead = ChainPoint {
        height,
        hash: BlockHash(cached(&r.st, height).hash().0),
    };
    let directory = serve(&r.st, &r.records, ahead);
    let client = connect(&directory, ahead).await;
    let db = r.st.wallet_mut().db_mut();
    db.set_one_time_recovery_enabled(r.account, true).unwrap();
    let before = db.one_time_recovery(r.account, NOW).unwrap();
    assert!(
        !db.begin_one_time_recovery(r.account, wallet_publication(client.inventory()), true)
            .unwrap()
    );
    let after = db.one_time_recovery(r.account, NOW).unwrap();
    assert_eq!(after, before);
    assert!(after.filter_frontier.is_none() && after.witnesses.is_empty());
}

/// Screening a round's due lookups together traverses each sealed shard's filter once
/// for every receiver, and the lookups that follow read the remembered answers instead of
/// traversing it again.
#[tokio::test]
async fn screening_a_round_traverses_each_filter_once() {
    let mut r = restored(&[0]);
    let paid = BlockHeight::from(r.records[0].payment.height);
    let plans = [Plan::sealed(paid), Plan::recent(r.through.height)];
    let directory = Directory::new(publish_with(&r.st, &r.records, &plans, &|_| 0));
    let client = connect(&directory, r.through).await;
    begin(&mut r, &client, true);
    let works =
        r.st.wallet()
            .db()
            .one_time_recovery(r.account, NOW)
            .unwrap()
            .lookups;
    assert!(works.len() > 1);
    zakura_pir_client::receiver::screen(&client, &works).await;
    assert_eq!(client.filter_traversals(), 1);
    for work in &works {
        lookup(&client, work).await.unwrap();
    }
    assert_eq!(client.filter_traversals(), 1);
    drain(&mut r.st, r.account, &client).await;
    assert_eq!(one_time_value(&r.st), VALUE);
}

/// Drops `st`'s wallet handle and opens its database file again, keeping only what the
/// wallet persisted.
fn reopen(st: &mut State) {
    let path = st.wallet().conn().path().unwrap().to_owned();
    let clock = FixedClock::new(std::time::SystemTime::UNIX_EPOCH);
    let reopened =
        WalletDb::for_path(path, *st.network(), clock, TestRng::seed_from_u64(0)).unwrap();
    *st.wallet_mut().db_mut() = reopened;
}

/// One address paid more times than a step may read, all in one segment, is recovered
/// across capped steps. The first step stops mid-segment, the wallet restarts from what it
/// recorded, and each later step resumes after the last page the previous one read. A cap
/// above [`RECOVERY_PAGE_LIMIT`] reads that many, and an uncapped step finishes the
/// segment. Every page is queried once and every payment is credited once.
#[tokio::test]
async fn capped_steps_recover_a_long_history_across_a_restart() {
    use std::num::NonZeroUsize;
    let payments = 2 * 7 + RECOVERY_PAGE_LIMIT + 2;
    let mut r = restored_in(TestDbFactory::file_backed(), &vec![0; payments]);
    let directory = serve(&r.st, &r.records, r.through);
    let client = connect(&directory, r.through).await;
    begin(&mut r, &client, true);
    let key = KeyId::new(Purpose::Receive, 0);
    let seven = NonZeroUsize::new(7).unwrap();
    let mut read = vec![];

    // Reads and records one step for the key, checking it resumes after the last page read
    // and leaves the wallet holding exactly its continuation.
    async fn step(
        r: &mut Restored,
        directory: &Directory,
        client: &InventoryClient<&Directory>,
        key: KeyId,
        cap: Option<NonZeroUsize>,
        read: &mut Vec<RawRecord>,
    ) -> zcash_client_backend::data_api::one_time_ivk::restore::LookupPage {
        let work = due(r, key);
        assert_eq!(
            work.cursor.as_ref().and_then(|c| c.last.as_ref()),
            read.last(),
            "the step resumes after the last recorded page"
        );
        let queries = lookups(directory);
        let page = match cap {
            Some(cap) => lookup_pages(client, &work, cap).await.unwrap(),
            None => lookup(client, &work).await.unwrap(),
        };
        assert_eq!(lookups(directory) - queries, page.records.len());
        assert!(
            r.st.wallet_mut()
                .db_mut()
                .record_one_time_lookup(r.account, &work, &page, NOW)
                .unwrap()
        );
        let pending =
            r.st.wallet()
                .db()
                .one_time_recovery(r.account, NOW)
                .unwrap()
                .lookups
                .into_iter()
                .find(|work| work.work.key == key);
        assert_eq!(pending.and_then(|work| work.cursor), page.next);
        read.extend(page.records.iter().cloned());
        page
    }

    let first = step(&mut r, &directory, &client, key, Some(seven), &mut read).await;
    assert_eq!(first.records.len(), 7);
    let next = first.next.clone().unwrap();
    assert_eq!((next.shard, next.segment), (0, 0));
    assert_eq!(first.checked_through, None);

    // A restart keeps only the recorded cursor, so the second step resumes from it.
    drop(client);
    reopen(&mut r.st);
    let client = connect(&directory, r.through).await;
    let first_work = {
        let mut work = due(&r, key);
        work.cursor = None;
        work
    };
    assert_eq!(
        step(&mut r, &directory, &client, key, Some(seven), &mut read)
            .await
            .records
            .len(),
        7
    );
    // A late callback for the first step cannot record its pages again.
    assert!(
        !r.st
            .wallet_mut()
            .db_mut()
            .record_one_time_lookup(r.account, &first_work, &first, NOW)
            .unwrap()
    );
    let wide = step(
        &mut r,
        &directory,
        &client,
        key,
        NonZeroUsize::new(usize::MAX),
        &mut read,
    )
    .await;
    assert_eq!(wide.records.len(), RECOVERY_PAGE_LIMIT);
    assert!(!wide.complete());
    let last = step(&mut r, &directory, &client, key, None, &mut read).await;
    assert_eq!(last.records.len(), 2);
    assert!(last.complete());
    assert_eq!(
        read.iter().map(|r| r.page).collect::<Vec<_>>(),
        (0..payments as u32).collect::<Vec<_>>()
    );
    assert!(read.iter().all(|r| r.total == payments as u32));

    drain(&mut r.st, r.account, &client).await;
    assert_eq!(one_time_value(&r.st), payments as u64 * VALUE);
    let notes: usize =
        r.st.wallet()
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM ironwood_received_notes WHERE one_time_key_id IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
    assert_eq!(notes, payments);
}
