//! Restore sweeps end to end: a restored wallet looks up its swap keys in a receiver
//! directory served in process, over the service's own routes and real PIR, and
//! imports what it finds only after checking it against its own chain.

use std::{collections::BTreeMap, sync::Mutex};

use axum::{Router, body::Body, http::Request};
use orchard::{
    keys::{FullViewingKey, Scope},
    note_encryption::{CompactAction, IronwoodDomain, IronwoodNoteEncryption},
};
use receiver_directory::{
    Payment, Receiver, Record,
    snapshot::{Manifest, PROFILE, Snapshot},
    witness::WitnessSnapshot,
};
use receiver_pir::{MIN_ROWS, server::Server};
use receiver_pir_server::{Publication, Publications, router_with_publications};
use tower::ServiceExt as _;
use zakura_pir_enhance::{
    ClientError,
    transport::{Request as EnhanceRequest, ResponseBody, Transport as EnhanceTransport},
};
use zakura_pir_receiver::{
    DirectoryError, EnhanceNotes, Error, NoteSource, Transport, WriteLock, sweep,
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
    wallet::swap_receiving::{KeyId, Purpose, RECEIVE_GAP_LIMIT},
};
use zcash_note_encryption::{Domain as _, try_compact_note_decryption};
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

/// A wallet with Ironwood active from its first block.
fn ironwood_wallet() -> State {
    let activation = BlockHeight::from_u32(ACTIVATION);
    TestBuilder::new()
        .with_network(LocalNetwork {
            nu6: Some(activation),
            nu6_1: Some(activation),
            nu6_2: Some(activation),
            nu6_3: Some(activation),
            ..TestBuilder::<(), ()>::DEFAULT_NETWORK
        })
        .with_data_store_factory(TestDbFactory::default())
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

/// Pays incoming swap key `index` in a new scanned block, before any restore has
/// registered the key, so scanning cannot find it. Returns the payment as the
/// directory lists it and its note data. The output is the chain's Ironwood leaf at
/// `position`, which is the number of earlier Ironwood outputs.
fn pay_restored_key(st: &mut State, index: u64, position: u64) -> (Record, [u8; 528]) {
    let parent = FullViewingKey::from(st.test_account().unwrap().usk().orchard());
    let fvk = KeyId::new(Purpose::Receive, index).derive(&parent).unwrap();
    let (height, _, _) = st.generate_next_block(
        &IronwoodFvk(fvk.clone()),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(VALUE),
    );
    st.scan_cached_blocks(height, 1);
    let mut block = None;
    st.cache()
        .with_blocks::<_, ()>(Some(height), Some(1), |cb| {
            block = Some(cb);
            Ok(())
        })
        .unwrap();
    let block = block.unwrap();
    let tx = &block.vtx[0];
    let compact = &tx.ironwood_actions[0];
    let action = CompactAction::try_from(compact).unwrap();
    let (note, _) = try_compact_note_decryption(
        &IronwoodDomain::for_compact_action(&action),
        &fvk.to_ivk(Scope::External).prepare(),
        &action,
    )
    .unwrap();
    // Encrypting the note again reproduces the output, with a known memo.
    let encryption = IronwoodNoteEncryption::new(None, note, [4; 512]);
    let ciphertext = encryption.encrypt_note_plaintext();
    assert_eq!(&ciphertext[..52], compact.ciphertext.as_slice());
    let receiver = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
    let record = Record {
        receiver: Receiver::from_bytes(receiver).unwrap(),
        page: 0,
        total: 1,
        payment: Payment {
            height: u32::from(height),
            block_hash: block.hash().0,
            txid: *tx.txid().as_ref(),
            tx_index: tx.index.try_into().unwrap(),
            action_index: 0,
            position,
            action_nullifier: compact.nullifier.as_slice().try_into().unwrap(),
            cmx: compact.cmx.as_slice().try_into().unwrap(),
            ephemeral_key: IronwoodDomain::epk_bytes(encryption.epk()).0,
            ciphertext_prefix: ciphertext[..52].try_into().unwrap(),
        },
    };
    (record, ciphertext[52..].try_into().unwrap())
}

/// A publication of `records` ending at `end`, with the common witnesses over the
/// chain's Ironwood `commitments`, served by the receiver service's routes.
fn publish(records: &[Record], commitments: &[[u8; 32]], end: ChainPoint) -> Router {
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
    };
    let snapshot = Snapshot::build(manifest, records).unwrap();
    let positions = records
        .iter()
        .map(|record| u32::try_from(record.payment.position).unwrap())
        .collect();
    let witnesses = WitnessSnapshot::build(&snapshot.manifest, commitments, &positions).unwrap();
    let publication =
        Publication::new(Server::new(snapshot).unwrap(), Some(witnesses.encode())).unwrap();
    let publications = Publications::default();
    assert!(publications.publish(publication, publications.epoch()));
    router_with_publications(publications)
}

/// Serves a directory's routes in process and records every request.
struct Directory {
    router: Router,
    requests: Mutex<Vec<String>>,
}

impl Directory {
    /// Serves `router` at [`ORIGIN`].
    fn new(router: Router) -> Self {
        Self {
            router,
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
        let request = Request::builder()
            .method(method)
            .uri(path)
            .body(Body::from(body))
            .unwrap();
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status().as_u16();
        let body = axum::body::to_bytes(response.into_body(), limit)
            .await
            .map_err(|_| DirectoryError::Transport("response over its limit".into()))?;
        match status {
            200 => Ok(body.to_vec()),
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

/// Note data from a fixed map, recording each request that needs some.
struct Notes {
    data: BTreeMap<u64, [u8; 528]>,
    requested: Vec<Vec<u64>>,
}

impl<W> NoteSource<W> for Notes {
    async fn note_data(
        &mut self,
        _: &W,
        positions: Vec<u64>,
    ) -> Result<BTreeMap<u64, [u8; 528]>, Error> {
        if !positions.is_empty() {
            self.requested.push(positions.clone());
        }
        Ok(positions
            .into_iter()
            .filter_map(|position| Some((position, *self.data.get(&position)?)))
            .collect())
    }
}

/// A test needs no lock: nothing else writes to its wallet.
struct NoLock;

impl WriteLock for NoLock {
    fn write<T>(&self, _: &'static str, write: impl FnOnce() -> T) -> T {
        write()
    }
}

/// Registers the restored incoming lookahead, as a restore does at the tip.
fn restore(st: &mut State, account: AccountUuid) {
    st.wallet_mut()
        .db_mut()
        .maintain_swap_receiving(account)
        .unwrap();
}

#[tokio::test]
async fn a_restore_sweep_finds_a_payout_and_moves_the_lookahead_past_it() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let paid = 3;
    let (record, note_data) = pay_restored_key(&mut st, paid, 0);
    st.generate_and_scan_empty_blocks(1);
    restore(&mut st, account);
    let through = tip(&st);
    assert_eq!(st.get_total_balance(account), Zatoshis::ZERO);
    let directory = Directory::new(publish(
        std::slice::from_ref(&record),
        &[record.payment.cmx],
        through,
    ));
    let mut notes = Notes {
        data: BTreeMap::from([(record.payment.position, note_data)]),
        requested: Vec::new(),
    };
    let swept = sweep(
        st.wallet_mut().db_mut(),
        &[account],
        through,
        GENESIS,
        ORIGIN,
        &directory,
        &mut notes,
        &NoLock,
        NOW,
    )
    .await
    .unwrap();
    assert!(swept.deferred.is_empty(), "{:?}", swept.deferred);
    assert!(!swept.pending);
    // The first window, then the keys above it that the paid index brings in.
    assert_eq!(swept.finished as u64, RECEIVE_GAP_LIMIT + paid + 1);
    assert_eq!(notes.requested, [vec![record.payment.position]]);
    assert_eq!(
        st.get_total_balance(account),
        Zatoshis::const_from_u64(VALUE)
    );
    // Lookups and the common witnesses go over the service's routes only.
    assert!(
        directory
            .requests()
            .iter()
            .all(|r| r.starts_with("GET /v1/receiver/") || r == "POST /v1/receiver/query"),
        "{:?}",
        directory.requests()
    );

    // A later run finds every sweep finished and asks the directory nothing.
    let before = directory.requests();
    let swept = sweep(
        st.wallet_mut().db_mut(),
        &[account],
        through,
        GENESIS,
        ORIGIN,
        &directory,
        &mut notes,
        &NoLock,
        NOW,
    )
    .await
    .unwrap();
    assert_eq!(swept.finished, 0);
    assert!(!swept.pending);
    assert_eq!(directory.requests(), before);
}

#[tokio::test]
async fn a_key_paid_twice_is_imported_in_full() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let paid = 2;
    let (mut first, first_data) = pay_restored_key(&mut st, paid, 0);
    let (mut second, second_data) = pay_restored_key(&mut st, paid, 1);
    first.total = 2;
    second.page = 1;
    second.total = 2;
    st.generate_and_scan_empty_blocks(1);
    restore(&mut st, account);
    let through = tip(&st);
    let directory = Directory::new(publish(
        &[first.clone(), second.clone()],
        &[first.payment.cmx, second.payment.cmx],
        through,
    ));
    let mut notes = Notes {
        data: BTreeMap::from([(0, first_data), (1, second_data)]),
        requested: Vec::new(),
    };
    let swept = sweep(
        st.wallet_mut().db_mut(),
        &[account],
        through,
        GENESIS,
        ORIGIN,
        &directory,
        &mut notes,
        &NoLock,
        NOW,
    )
    .await
    .unwrap();
    assert!(swept.deferred.is_empty(), "{:?}", swept.deferred);
    assert!(!swept.pending);
    assert_eq!(notes.requested, [vec![0, 1]]);
    assert_eq!(
        st.get_total_balance(account),
        Zatoshis::const_from_u64(2 * VALUE)
    );
    // Two pages cost less over PIR than the row file.
    let requests = directory.requests();
    assert!(
        !requests
            .iter()
            .any(|r| r.starts_with("GET /v1/receiver/rows/")),
        "{requests:?}"
    );
}

#[tokio::test]
async fn a_long_history_takes_its_note_data_in_batches() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let paid = 1;
    // One more payment than a batch of note data holds.
    let count = 65;
    let mut records = Vec::new();
    let mut data = BTreeMap::new();
    for position in 0..count {
        let (mut record, note_data) = pay_restored_key(&mut st, paid, position);
        record.page = position.try_into().unwrap();
        record.total = count.try_into().unwrap();
        records.push(record);
        data.insert(position, note_data);
    }
    st.generate_and_scan_empty_blocks(1);
    restore(&mut st, account);
    let through = tip(&st);
    let commitments: Vec<_> = records.iter().map(|record| record.payment.cmx).collect();
    let directory = Directory::new(publish(&records, &commitments, through));
    let mut notes = Notes {
        data,
        requested: Vec::new(),
    };
    let swept = sweep(
        st.wallet_mut().db_mut(),
        &[account],
        through,
        GENESIS,
        ORIGIN,
        &directory,
        &mut notes,
        &NoLock,
        NOW,
    )
    .await
    .unwrap();
    assert!(swept.deferred.is_empty(), "{:?}", swept.deferred);
    assert!(!swept.pending);
    let batches: Vec<_> = notes.requested.iter().map(Vec::len).collect();
    assert_eq!(batches, [64, 1]);
    assert_eq!(
        st.get_total_balance(account),
        Zatoshis::const_from_u64(count * VALUE)
    );
}

/// A directory whose queries fail after it accepted the session.
struct FailingQueries(Directory);

impl Transport for FailingQueries {
    async fn get(&self, url: &str, limit: usize) -> Result<Vec<u8>, DirectoryError> {
        self.0.get(url, limit).await
    }

    async fn post(&self, url: &str, _: Vec<u8>, _: usize) -> Result<Vec<u8>, DirectoryError> {
        self.0.requests.lock().unwrap().push(format!("POST {url}"));
        Err(DirectoryError::Revision)
    }
}

#[tokio::test]
async fn a_revoked_session_stops_the_run_before_leasing_more_keys() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let (record, _) = pay_restored_key(&mut st, 3, 0);
    st.generate_and_scan_empty_blocks(1);
    restore(&mut st, account);
    let through = tip(&st);
    let directory = FailingQueries(Directory::new(publish(
        std::slice::from_ref(&record),
        &[record.payment.cmx],
        through,
    )));
    let mut notes = Notes {
        data: BTreeMap::new(),
        requested: Vec::new(),
    };
    let swept = sweep(
        st.wallet_mut().db_mut(),
        &[account],
        through,
        GENESIS,
        ORIGIN,
        &directory,
        &mut notes,
        &NoLock,
        NOW,
    )
    .await
    .unwrap();
    assert_eq!(swept.finished, 0);
    assert_eq!(swept.deferred.len(), 1);
    assert!(swept.pending);
    let posts = directory
        .0
        .requests()
        .iter()
        .filter(|r| r.starts_with("POST"))
        .count();
    assert_eq!(posts, 1);
}

#[tokio::test]
async fn a_publication_off_the_wallets_chain_is_refused_before_any_lookup() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let (record, note_data) = pay_restored_key(&mut st, 0, 0);
    st.generate_and_scan_empty_blocks(1);
    restore(&mut st, account);
    let through = tip(&st);
    let other = ChainPoint {
        hash: BlockHash([1; 32]),
        ..through
    };
    let directory = Directory::new(publish(
        std::slice::from_ref(&record),
        &[record.payment.cmx],
        other,
    ));
    let mut notes = Notes {
        data: BTreeMap::from([(record.payment.position, note_data)]),
        requested: Vec::new(),
    };
    let result = sweep(
        st.wallet_mut().db_mut(),
        &[account],
        through,
        GENESIS,
        ORIGIN,
        &directory,
        &mut notes,
        &NoLock,
        NOW,
    )
    .await;
    assert!(matches!(result, Err(Error::Directory(_))), "{result:?}");
    assert_eq!(directory.requests(), ["GET /v1/receiver/init"]);
    assert!(notes.requested.is_empty());
    assert!(
        st.wallet()
            .db()
            .swap_history_pending(account, through.height)
            .unwrap()
    );
}

/// An Enhance transport that must not be used.
struct NoEnhance;

impl EnhanceTransport for NoEnhance {
    async fn execute(&self, _: EnhanceRequest) -> Result<ResponseBody, ClientError> {
        panic!("no Enhance request was needed");
    }
}

#[tokio::test]
async fn enhance_notes_open_no_session_until_a_payment_needs_note_data() {
    let st = ironwood_wallet();
    let mut notes = EnhanceNotes::new("https://enhance.test", &NoEnhance);
    let data = notes.note_data(st.wallet().db(), Vec::new()).await.unwrap();
    assert!(data.is_empty());
}
