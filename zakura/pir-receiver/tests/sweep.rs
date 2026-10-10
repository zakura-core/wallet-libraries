//! Restore sweeps end to end: a restored wallet looks up its dynamic keys in a receiver
//! directory served in process, over the service's own routes and real PIR, and
//! imports what it finds only after checking it against its own chain.

use std::{cell::Cell, collections::BTreeMap, sync::Mutex};

use axum::{Router, body::Body, http::Request};
use base64::Engine as _;
use orchard::{
    keys::{FullViewingKey, Scope},
    note_encryption::{CompactAction, IronwoodDomain, IronwoodNoteEncryption},
};
use receiver_directory::{
    Payment, Receiver, Record,
    snapshot::{Manifest, PROFILE, ProviderSet, Snapshot},
    witness::WitnessSnapshot,
};
use receiver_pir::{MIN_ROWS, server::Server};
use receiver_pir_server::{Publication, Publications, router_with_publications};
use sha2::{Digest as _, Sha256};
use tower::ServiceExt as _;
use zakura_dynamic_ivk::lifecycle::RESTORE_WATCH_SECS;
use zakura_pir_enhance::{
    ClientError, QueryBinding, ShardSession,
    transport::{Request as EnhanceRequest, ResponseBody, Transport as EnhanceTransport},
    types,
};
use zakura_pir_receiver::{
    DirectoryError, EnhanceNotes, Error, NoteSource, Transport, WriteLock, fetch_seen, sweep,
};
use zcash_client_backend::data_api::{
    Account as _, WalletRead as _,
    chain::BlockSource as _,
    dynamic_ivk::{DynamicIvkRead, DynamicIvkWrite as _},
    testing::{AddressType, IronwoodFvk, TestBuilder, TestState},
    transparent_ledger::ChainPoint,
};
use zcash_client_sqlite::{
    AccountUuid,
    testing::{
        BlockCache,
        db::{TestDb, TestDbFactory},
    },
    wallet::dynamic_ivk::{KeyId, ProviderSeen, Purpose, RECEIVE_GAP_LIMIT},
};
use zcash_note_encryption::{Domain as _, try_compact_note_decryption};
use zcash_primitives::block::BlockHash;
use zcash_protocol::{
    consensus::{BlockHeight, NetworkType, NetworkUpgrade, Parameters},
    local_consensus::LocalNetwork,
    value::Zatoshis,
};

#[path = "../../pir-enhance/src/test_support.rs"]
mod test_support;

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

/// Pays incoming dynamic key `index` in a new scanned block, before any restore has
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
    st.scan_cached_blocks_with_dynamic_ivks(height, 1);
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
            // The mock block has no coinbase; the directory refuses index 0 as one.
            tx_index: u32::try_from(tx.index).unwrap() + 1,
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

/// A swap provider's sets: an empty recent set, which wallets do not read, and every
/// receiver it ever had, from a feed that started long before [`NOW`] and last read the
/// provider a minute before it.
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
            receivers: seen.to_vec(),
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
) -> Router {
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
        WitnessSnapshot::build(&snapshot.manifest, commitments, &positions)
            .unwrap()
            .encode()
    });
    let publication = Publication::new(Server::new(snapshot).unwrap(), witnesses).unwrap();
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

impl<W: DynamicIvkRead> NoteSource<W> for Notes {
    async fn note_data(
        &mut self,
        _: &W,
        positions: Vec<u64>,
    ) -> Result<BTreeMap<u64, [u8; 528]>, Error<W::Error>> {
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
        .maintain_dynamic_ivks(account)
        .unwrap();
}

#[tokio::test]
async fn a_restore_sweep_finds_a_payout_and_moves_the_lookahead_past_it() {
    let mut st = ironwood_wallet();
    let network = *st.network();
    let account = st.test_account().unwrap().id();
    let paid = 3;
    let (record, note_data) = pay_restored_key(&mut st, paid, 0);
    st.generate_and_scan_empty_blocks_with_dynamic_ivks(1);
    restore(&mut st, account);
    let through = tip(&st);
    assert_eq!(st.get_total_balance(account), Zatoshis::ZERO);
    let directory = Directory::new(publish(
        std::slice::from_ref(&record),
        &[record.payment.cmx],
        through,
        &provider(&[]),
    ));
    let mut notes = Notes {
        data: BTreeMap::from([(record.payment.position, note_data)]),
        requested: Vec::new(),
    };
    let swept = sweep(
        st.wallet_mut().db_mut(),
        &network,
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
        &network,
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
    let network = *st.network();
    let account = st.test_account().unwrap().id();
    let paid = 2;
    let (mut first, first_data) = pay_restored_key(&mut st, paid, 0);
    let (mut second, second_data) = pay_restored_key(&mut st, paid, 1);
    first.total = 2;
    second.page = 1;
    second.total = 2;
    st.generate_and_scan_empty_blocks_with_dynamic_ivks(1);
    restore(&mut st, account);
    let through = tip(&st);
    let directory = Directory::new(publish(
        &[first.clone(), second.clone()],
        &[first.payment.cmx, second.payment.cmx],
        through,
        &provider(&[]),
    ));
    let mut notes = Notes {
        data: BTreeMap::from([(0, first_data), (1, second_data)]),
        requested: Vec::new(),
    };
    let swept = sweep(
        st.wallet_mut().db_mut(),
        &network,
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
    let network = *st.network();
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
    st.generate_and_scan_empty_blocks_with_dynamic_ivks(1);
    restore(&mut st, account);
    let through = tip(&st);
    let commitments: Vec<_> = records.iter().map(|record| record.payment.cmx).collect();
    let directory = Directory::new(publish(&records, &commitments, through, &provider(&[])));
    let mut notes = Notes {
        data,
        requested: Vec::new(),
    };
    let swept = sweep(
        st.wallet_mut().db_mut(),
        &network,
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

#[tokio::test]
async fn a_wallet_without_payments_downloads_only_the_filters() {
    let mut st = ironwood_wallet();
    let network = *st.network();
    let account = st.test_account().unwrap().id();
    st.generate_and_scan_empty_blocks_with_dynamic_ivks(1);
    restore(&mut st, account);
    let through = tip(&st);
    let directory = Directory::new(publish(&[], &[], through, &provider(&[])));
    let mut notes = Notes {
        data: BTreeMap::new(),
        requested: Vec::new(),
    };
    let swept = sweep(
        st.wallet_mut().db_mut(),
        &network,
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
    assert_eq!(swept.finished as u64, RECEIVE_GAP_LIMIT);
    assert!(!swept.pending);
    // No PIR session, witnesses or note data: one manifest and one filter file.
    let requests = directory.requests();
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert!(requests[1].starts_with("GET /v1/receiver/filters/"));
    assert!(notes.requested.is_empty());
    // Every swept key keeps scanning, so a payment after the publication is found.
    let scanning = st.wallet().get_dynamic_scanning_keys().unwrap().len();
    assert_eq!(scanning as u64, RECEIVE_GAP_LIMIT);
    pay_restored_key(&mut st, 0, 0);
    assert_eq!(
        st.get_total_balance(account),
        Zatoshis::const_from_u64(VALUE)
    );
}

#[tokio::test]
async fn seen_addresses_keep_scanning_and_are_never_issued_again() {
    let mut st = ironwood_wallet();
    let network = *st.network();
    let account = st.test_account().unwrap().id();
    st.generate_and_scan_empty_blocks_with_dynamic_ivks(1);
    restore(&mut st, account);
    let through = tip(&st);
    let parent = FullViewingKey::from(st.test_account().unwrap().usk().orchard());
    let receiver = |key: KeyId| {
        let address = key
            .derive(&parent)
            .unwrap()
            .address_at(0u32, Scope::External);
        Receiver::from_bytes(address.to_raw_address_bytes()).unwrap()
    };
    // The old device quoted addresses 0 and 2.
    let (old, quoted) = (
        KeyId::new(Purpose::Receive, 0),
        KeyId::new(Purpose::Receive, 2),
    );
    let directory = Directory::new(publish(
        &[],
        &[],
        through,
        &provider(&[receiver(old), receiver(quoted)]),
    ));
    let mut notes = Notes {
        data: BTreeMap::new(),
        requested: Vec::new(),
    };
    let swept = sweep(
        st.wallet_mut().db_mut(),
        &network,
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
    // The seen address 2 moves the lookahead, and every swept key keeps scanning.
    let scanning = st.wallet().get_dynamic_scanning_keys().unwrap().len();
    assert_eq!(scanning as u64, RECEIVE_GAP_LIMIT + 3);
    // Issuance reads the same seen set, skips both, and takes the lowest address the
    // provider never had.
    let seen = fetch_seen(ORIGIN, &directory).await.unwrap();
    assert_eq!(
        (seen.since(), seen.until()),
        (NOW - 2 * RESTORE_WATCH_SECS, NOW - 60)
    );
    let bytes = |key: KeyId| *receiver(key).as_bytes();
    assert_eq!(
        seen.contains(&[bytes(old), bytes(KeyId::new(Purpose::Receive, 1))]),
        [true, false]
    );
    let contains = |receivers: &[[u8; 43]]| seen.contains(receivers);
    let view = ProviderSeen {
        since: seen.since(),
        until: seen.until(),
        contains: &contains,
    };
    let issued = st
        .wallet_mut()
        .db_mut()
        .prepare_receive_reservation(account, NOW, through.height, Some(&view))
        .unwrap()
        .unwrap();
    assert_eq!(issued.key_id(), KeyId::new(Purpose::Receive, 1));
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
    let network = *st.network();
    let account = st.test_account().unwrap().id();
    // The first key in the batch is paid, so it needs the failing lookup.
    let (record, _) = pay_restored_key(&mut st, 0, 0);
    st.generate_and_scan_empty_blocks_with_dynamic_ivks(1);
    restore(&mut st, account);
    let through = tip(&st);
    let directory = FailingQueries(Directory::new(publish(
        std::slice::from_ref(&record),
        &[record.payment.cmx],
        through,
        &provider(&[]),
    )));
    let mut notes = Notes {
        data: BTreeMap::new(),
        requested: Vec::new(),
    };
    let swept = sweep(
        st.wallet_mut().db_mut(),
        &network,
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
    let network = *st.network();
    let account = st.test_account().unwrap().id();
    let (record, note_data) = pay_restored_key(&mut st, 0, 0);
    st.generate_and_scan_empty_blocks_with_dynamic_ivks(1);
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
        &provider(&[]),
    ));
    let mut notes = Notes {
        data: BTreeMap::from([(record.payment.position, note_data)]),
        requested: Vec::new(),
    };
    let result = sweep(
        st.wallet_mut().db_mut(),
        &network,
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
            .dynamic_history_pending(account, through.height)
            .unwrap()
    );
    // Every due key backed off, so the directory is not asked again until a minute on.
    for (now, requests) in [(NOW, 1), (NOW + 60, 2)] {
        let _ = sweep(
            st.wallet_mut().db_mut(),
            &network,
            &[account],
            through,
            GENESIS,
            ORIGIN,
            &directory,
            &mut notes,
            &NoLock,
            now,
        )
        .await;
        assert_eq!(directory.requests().len(), requests);
    }
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
    let mut notes = EnhanceNotes::new("https://enhance.test", &NoEnhance, st.network());
    let data = notes.note_data(st.wallet().db(), Vec::new()).await.unwrap();
    assert!(data.is_empty());
}

/// The test network's upgrades under mainnet's network type, the only one Enhance PIR
/// accepts.
#[derive(Clone)]
struct EnhanceNetwork(LocalNetwork);

impl Parameters for EnhanceNetwork {
    fn network_type(&self) -> NetworkType {
        NetworkType::Main
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        self.0.activation_height(nu)
    }
}

/// An Enhance service over an all-zero database whose first query is refused with
/// `status`. It counts manifest fetches and queries.
struct RefusingEnhance {
    manifest: Vec<u8>,
    session: Vec<u8>,
    rows: u64,
    status: Cell<Option<u16>>,
    inits: Cell<usize>,
    queries: Cell<usize>,
}

impl RefusingEnhance {
    /// A service whose manifest ends at `anchor`, covering `records` Ironwood outputs.
    fn new(anchor: ChainPoint, records: u64, status: u16) -> Self {
        let public = |rows| vec![0; types::session_public_len(rows).unwrap()];
        let mut manifest = test_support::synthetic_manifest(
            records,
            |shard| hex::encode(Sha256::digest(public(shard.logical_rows))),
            &"00".repeat(32),
        );
        let rows = manifest.coverage.shards[0].logical_rows;
        manifest.anchor_height = u32::from(anchor.height).into();
        manifest.anchor_block_hash = anchor.hash.to_string();
        let session = ShardSession {
            session_id: hex::encode(manifest.session_id(0).unwrap()),
            generation: manifest.generation,
            shard_id: 0,
            params: types::parameters(rows).unwrap(),
            public_params_base64: base64::engine::general_purpose::STANDARD.encode(public(rows)),
        };
        Self {
            manifest: serde_json::to_vec(&manifest).unwrap(),
            session: serde_json::to_vec(&session).unwrap(),
            rows,
            status: Cell::new(Some(status)),
            inits: Cell::new(0),
            queries: Cell::new(0),
        }
    }
}

impl EnhanceTransport for RefusingEnhance {
    async fn execute(&self, request: EnhanceRequest) -> Result<ResponseBody, ClientError> {
        let bytes = if request.url.ends_with("/v1/enhance/init") {
            self.inits.set(self.inits.get() + 1);
            self.manifest.clone()
        } else if request.url.contains("/v1/enhance/session/") {
            self.session.clone()
        } else if request.url.ends_with("/v1/enhance/query") {
            self.queries.set(self.queries.get() + 1);
            if let Some(status) = self.status.take() {
                return Err(ClientError::HttpStatus(status));
            }
            // Zero public material and a zero response decode to an all-zero row.
            let mut response = QueryBinding::decode(&request.body).unwrap().encode();
            response.resize(types::response_len(self.rows).unwrap(), 0);
            response
        } else {
            panic!("unexpected endpoint: {}", request.url);
        };
        let mut body = request.response_body();
        body.extend(&bytes)?;
        Ok(body.finish())
    }
}

#[tokio::test]
async fn enhance_notes_accept_fresh_routing_after_a_refused_query() {
    for status in [409, 410] {
        let mut st = ironwood_wallet();
        pay_restored_key(&mut st, 0, 0);
        let anchor = tip(&st);
        let records = st
            .wallet()
            .block_metadata(anchor.height)
            .unwrap()
            .unwrap()
            .ironwood_tree_size()
            .unwrap();
        let enhance = RefusingEnhance::new(anchor, records.into(), status);
        let network = EnhanceNetwork(*st.network());
        let mut notes = EnhanceNotes::new("https://enhance.test", &enhance, &network);
        let refused = notes.note_data(st.wallet().db(), vec![0]).await;
        assert!(
            matches!(refused, Err(Error::NoteData(ClientError::HttpStatus(s))) if s == status),
            "{refused:?}"
        );
        // The same notes fetch and accept the routing again before the next batch.
        let data = notes.note_data(st.wallet().db(), vec![0]).await.unwrap();
        assert_eq!(data, BTreeMap::from([(0, [0; 528])]));
        assert_eq!((enhance.inits.get(), enhance.queries.get()), (2, 2));
    }
}
