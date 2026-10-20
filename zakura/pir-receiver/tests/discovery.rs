//! Discovery end to end: a restored wallet checks its one-time keys against a receiver
//! directory served in process, over the service's routes and real PIR, and imports what
//! it finds only after checking it against its own chain. The service's own HTTP router
//! is tested against these clients in wallet-pir.

use orchard::keys::{FullViewingKey, Scope};
use receiver_directory::{
    RawRecord,
    snapshot::{Manifest, PROFILE, Snapshot},
};
use receiver_pir::{AcceptedCoverage, MIN_ROWS, server::Server, transport::DirectoryClient};
use std::sync::Mutex;
use zakura_pir_receiver::{
    DirectoryError, Transport, lookup, publication as wallet_publication, witnesses,
};
use zakura_receiver_crypto::{
    Payment, Receiver, Record,
    witness::{Publication, WitnessSnapshot},
};
use zcash_client_backend::data_api::{
    Account as _, WalletRead as _,
    chain::BlockSource as _,
    testing::{AddressType, IronwoodFvk, TestBuilder, TestState},
    transparent_ledger::ChainPoint,
};
use zcash_client_sqlite::{
    AccountUuid,
    testing::{
        BlockCache,
        db::{TestDb, TestDbFactory},
    },
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
    let mut st = ironwood_wallet_in(TestDbFactory::default());
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

/// Publishes full payment history and common proofs with the production snapshot builder.
fn publish(records: &[Record], commitments: &[[u8; 32]], end: ChainPoint) -> Routes {
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
        history_revision: 0,
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
    };
    let snapshot = Snapshot::build(manifest, &records).unwrap();
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
/// its manifest, PIR setup and witnesses, and real PIR evaluation of
/// each encrypted query. A session it does not serve is gone (410).
struct Routes {
    server: Server,
    id: String,
    witnesses: Option<Vec<u8>>,
}

impl Routes {
    /// Binds routes to one immutable publication.
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
            "witness" => match &self.witnesses {
                Some(bytes) => (200, bytes.clone()),
                None => (503, Vec::new()),
            },
            _ => (404, Vec::new()),
        }
    }
}

/// Serves a [`publish`]ed publication of `records`, the chain's only Ironwood outputs,
/// ending at `end`.
fn serve(records: &[Record], end: ChainPoint) -> Directory {
    let commitments: Vec<_> = records.iter().map(|record| record.payment.cmx).collect();
    Directory::new(publish(records, &commitments, end))
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

/// The receiver lookups `directory` has served.
fn lookups(directory: &Directory) -> usize {
    let requests = directory.requests();
    requests
        .iter()
        .filter(|r| *r == "POST /v1/receiver/query")
        .count()
}

/// Opens a session only after selecting its endpoint from the wallet's chain.
async fn connect(directory: &Directory, end: ChainPoint) -> DirectoryClient<&Directory> {
    let manifest = DirectoryClient::fetch_manifest(ORIGIN, &directory)
        .await
        .unwrap();
    DirectoryClient::connect_manifest(
        ORIGIN,
        directory,
        AcceptedCoverage {
            genesis: GENESIS,
            required_start: ACTIVATION,
            height: end.height.into(),
            hash: end.hash.0,
        },
        manifest,
    )
    .await
    .unwrap()
}

/// Completes bounded wallet work through encrypted queries and independently built proofs.
async fn drain(st: &mut State, account: AccountUuid, client: &DirectoryClient<&Directory>) {
    let publication = wallet_publication(client.manifest()).unwrap();
    let mut proofs = None;
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
            if proofs.is_none() {
                proofs = Some(witnesses(client).await.unwrap());
            }
            let path = proofs
                .as_ref()
                .unwrap()
                .path(request.position, request.cmx)
                .unwrap();
            assert!(
                st.wallet_mut()
                    .db_mut()
                    .record_one_time_witness(
                        account,
                        status.token,
                        *request,
                        ChainPoint {
                            height: publication.end.height,
                            hash: BlockHash(publication.end.hash)
                        },
                        path,
                        NOW
                    )
                    .unwrap()
            );
        } else {
            return;
        }
    }
    panic!("bounded fixture did not settle");
}

/// Starts recovery without retaining a database handle across network work.
fn begin(r: &mut Restored, client: &DirectoryClient<&Directory>, direct: bool) {
    let db = r.st.wallet_mut().db_mut();
    db.set_one_time_recovery_enabled(r.account, true).unwrap();
    assert!(
        db.begin_one_time_recovery(
            r.account,
            wallet_publication(client.manifest()).unwrap(),
            direct
        )
        .unwrap()
    );
}

/// Seed discovery walks four genuine empty indexes and retrieves every page of a paid key.
#[tokio::test]
async fn seed_recovery_pages_history_and_stops_at_four_empty_indexes() {
    let mut r = restored(&[0, 3, 3, 40]);
    let directory = serve(&r.records, r.through);
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
    assert_eq!(lookups(&directory), 9);
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
    use receiver_directory::blocks::{Batch, BlockFilter, BlockId};
    let mut r = restored(&[]);
    let initial = serve(&[], r.through);
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
    let directory = serve(&[], end);
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
    let directory = serve(&r.records, r.through);
    let client = connect(&directory, r.through).await;
    begin(&mut r, &client, true);
    drain(&mut r.st, r.account, &client).await;
    assert_eq!(one_time_value(&r.st), 0);
    assert!(
        r.st.wallet_mut()
            .db_mut()
            .check_one_time_history(
                r.account,
                wallet_publication(client.manifest()).unwrap(),
                Some(6)
            )
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
    let directory = serve(&r.records, r.through);
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
    let directory = serve(&r.records, r.through);
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
