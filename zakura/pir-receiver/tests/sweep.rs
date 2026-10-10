//! Restore sweeps end to end: a restored wallet looks up its dynamic keys in a receiver
//! directory served in process, over the service's own routes and real PIR, and
//! imports what it finds only after checking it against its own chain.

use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    num::NonZeroU32,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

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
    dynamic_ivk::{DynamicIvkRead, DynamicIvkWrite as _, PaymentApplication},
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
    pay_restored_key_of(st, &parent, index, position)
}

/// [`pay_restored_key`] for the account whose Orchard viewing key is `parent`.
fn pay_restored_key_of(
    st: &mut State,
    parent: &FullViewingKey,
    index: u64,
    position: u64,
) -> (Record, [u8; 528]) {
    let fvk = KeyId::new(Purpose::Receive, index).derive(parent).unwrap();
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
    let finished = settle(&mut st, &[account], through, &directory, &mut notes).await;
    // The first window, then, in a later run, the keys above it that the paid index
    // brings in.
    assert_eq!(finished as u64, RECEIVE_GAP_LIMIT + paid + 1);
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
    settle(&mut st, &[account], through, &directory, &mut notes).await;
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
    st.generate_and_scan_empty_blocks_with_dynamic_ivks(1);
    restore(&mut st, account);
    let through = tip(&st);
    let commitments: Vec<_> = records.iter().map(|record| record.payment.cmx).collect();
    let directory = Directory::new(publish(&records, &commitments, through, &provider(&[])));
    let mut notes = Notes {
        data,
        requested: Vec::new(),
    };
    settle(&mut st, &[account], through, &directory, &mut notes).await;
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
    settle(&mut st, &[account], through, &directory, &mut notes).await;
    // The seen address 2 moves the lookahead, and every swept key keeps scanning.
    let scanning = st.wallet().get_dynamic_scanning_keys().unwrap().len();
    assert_eq!(scanning as u64, RECEIVE_GAP_LIMIT + 3);
    // Issuance reads the same seen set, skips both, and takes the lowest address the
    // provider never had.
    let seen = fetch_seen(ORIGIN, &directory, GENESIS).await.unwrap();
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

/// A seen hit counts from the attempt that observes it. When publication A's seen set
/// holds a receiver whose payment it then misstates, a later publication whose seen set
/// misses the receiver and whose lookup finds nothing does not make it issuable.
#[tokio::test]
async fn a_seen_hit_outlives_a_rejected_payment_and_a_later_miss() {
    let mut st = ironwood_wallet();
    let network = *st.network();
    let account = st.test_account().unwrap().id();
    let key = KeyId::new(Purpose::Receive, 0);
    let (record, note_data) = pay_restored_key(&mut st, key.index(), 0);
    st.generate_and_scan_empty_blocks_with_dynamic_ivks(1);
    restore(&mut st, account);
    let through = tip(&st);
    let seen = |st: &State| -> bool {
        st.wallet()
            .conn()
            .query_row(
                "SELECT provider_seen FROM ironwood_receiving_keys
                 WHERE purpose = 1 AND key_index = ?1",
                [key.index().to_be_bytes()],
                |r| r.get(0),
            )
            .unwrap()
    };
    let mut notes = Notes {
        data: BTreeMap::from([(record.payment.position, note_data)]),
        requested: Vec::new(),
    };
    // Publication A's witnesses are over another tree, so its payment is rejected.
    let a = Directory::new(publish(
        std::slice::from_ref(&record),
        &[record.payment.cmx, [1; 32]],
        through,
        &provider(&[record.receiver]),
    ));
    let swept = sweep(
        st.wallet_mut().db_mut(),
        &network,
        &[account],
        through,
        GENESIS,
        ORIGIN,
        &a,
        &mut notes,
        &NoLock,
        NOW,
    )
    .await
    .unwrap();
    assert!(
        matches!(
            &swept.deferred[..],
            [(_, deferred, Error::Queued(PaymentApplication::Rejected))] if *deferred == key
        ),
        "{:?}",
        swept.deferred
    );
    assert!(seen(&st));

    let b = Directory::new(publish(&[], &[], through, &provider(&[])));
    let later = NOW + 3_600;
    let swept = sweep(
        st.wallet_mut().db_mut(),
        &network,
        &[account],
        through,
        GENESIS,
        ORIGIN,
        &b,
        &mut notes,
        &NoLock,
        later,
    )
    .await
    .unwrap();
    assert!(swept.deferred.is_empty(), "{:?}", swept.deferred);
    assert!(!swept.pending);
    assert!(seen(&st));
    let fetched = fetch_seen(ORIGIN, &b, GENESIS).await.unwrap();
    let contains = |receivers: &[[u8; 43]]| fetched.contains(receivers);
    let view = ProviderSeen {
        since: fetched.since(),
        until: fetched.until(),
        contains: &contains,
    };
    let issued = st
        .wallet_mut()
        .db_mut()
        .prepare_receive_reservation(account, later, through.height, Some(&view))
        .unwrap()
        .unwrap();
    assert_eq!(issued.key_id(), KeyId::new(Purpose::Receive, 1));
}

/// Records each write's label, and arms `fail` for the first attempt's write, which
/// the wallet's commit hook then fails.
struct FailFirstAttempt {
    fail: Arc<AtomicBool>,
    labels: RefCell<Vec<&'static str>>,
}

impl WriteLock for FailFirstAttempt {
    fn write<T>(&self, label: &'static str, write: impl FnOnce() -> T) -> T {
        let mut labels = self.labels.borrow_mut();
        if label == "dynamic_sweep.attempt" && !labels.contains(&label) {
            self.fail.store(true, Ordering::SeqCst);
        }
        labels.push(label);
        drop(labels);
        write()
    }
}

/// A failure to lease an attempt stops the run with the wallet's error, before that
/// key's lookup and without retrying it.
#[tokio::test]
async fn a_failed_attempt_write_stops_the_run() {
    let mut st = ironwood_wallet();
    let network = *st.network();
    let account = st.test_account().unwrap().id();
    let (record, note_data) = pay_restored_key(&mut st, 0, 0);
    st.generate_and_scan_empty_blocks_with_dynamic_ivks(1);
    restore(&mut st, account);
    let through = tip(&st);
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
    let lock = FailFirstAttempt {
        fail: Arc::new(AtomicBool::new(false)),
        labels: RefCell::new(Vec::new()),
    };
    let fail = lock.fail.clone();
    // Returning true turns the commit into a rollback, which fails the write.
    st.wallet()
        .conn()
        .commit_hook(Some(move || fail.swap(false, Ordering::SeqCst)));
    let result = sweep(
        st.wallet_mut().db_mut(),
        &network,
        &[account],
        through,
        GENESIS,
        ORIGIN,
        &directory,
        &mut notes,
        &lock,
        NOW,
    )
    .await;
    assert!(matches!(result, Err(Error::Wallet(_))), "{result:?}");
    assert_eq!(
        *lock.labels.borrow(),
        ["dynamic_sweep.due", "dynamic_sweep.attempt"]
    );
    assert!(
        directory.requests().iter().all(|r| !r.starts_with("POST")),
        "{:?}",
        directory.requests()
    );
    assert!(notes.requested.is_empty());
}

/// Another network's seen sets say nothing about this network's quotes, so a
/// publication committing to another genesis is refused as a sweep refuses it.
#[tokio::test]
async fn seen_sets_of_another_network_are_refused() {
    let mut st = ironwood_wallet();
    st.generate_and_scan_empty_blocks_with_dynamic_ivks(1);
    let directory = Directory::new(publish(&[], &[], tip(&st), &provider(&[])));
    let refused = fetch_seen(ORIGIN, &directory, [8; 32]).await;
    assert!(
        matches!(
            refused,
            Err(DirectoryError::Directory(
                receiver_directory::Error::Coverage
            ))
        ),
        "{:?}",
        refused.err()
    );
    assert!(fetch_seen(ORIGIN, &directory, GENESIS).await.is_ok());
}

/// A provider with a recent set but no seen set may have had any receiver, so issuance
/// and sweeps both refuse the publication until every provider has a dated seen set.
/// The sets then cover the quote times they all cover, and hold what any of them holds.
#[tokio::test]
async fn every_provider_with_sets_needs_a_seen_set() {
    let mut st = ironwood_wallet();
    let network = *st.network();
    let account = st.test_account().unwrap().id();
    st.generate_and_scan_empty_blocks_with_dynamic_ivks(1);
    restore(&mut st, account);
    let through = tip(&st);
    let parent = FullViewingKey::from(st.test_account().unwrap().usk().orchard());
    let receiver = |index| {
        let fvk = KeyId::new(Purpose::Receive, index).derive(&parent).unwrap();
        Receiver::from_bytes(fvk.address_at(0u32, Scope::External).to_raw_address_bytes()).unwrap()
    };
    // Provider `a` has its seen set only if `a_seen`. `b` has only a seen set, from a
    // later feed start and a later read.
    let sets = |a_seen: bool| {
        let mut sets = provider_named("a", &[receiver(0)]);
        sets.truncate(1 + usize::from(a_seen));
        let mut b = provider_named("b", &[receiver(1)]).pop().unwrap();
        b.since_unix = NOW - RESTORE_WATCH_SECS;
        b.until_unix = NOW - 30;
        sets.push(b);
        sets
    };
    let directory = Directory::new(publish(&[], &[], through, &sets(false)));
    let refused = fetch_seen(ORIGIN, &directory, GENESIS).await;
    assert!(matches!(refused, Err(DirectoryError::Malformed)));
    let mut notes = Notes {
        data: BTreeMap::new(),
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
    assert!(
        matches!(result, Err(Error::Directory(DirectoryError::Malformed))),
        "{result:?}"
    );
    // A publication without provider sets is refused too.
    let directory = Directory::new(publish(&[], &[], through, &[]));
    let refused = fetch_seen(ORIGIN, &directory, GENESIS).await;
    assert!(matches!(refused, Err(DirectoryError::Malformed)));

    let directory = Directory::new(publish(&[], &[], through, &sets(true)));
    let seen = fetch_seen(ORIGIN, &directory, GENESIS).await.unwrap();
    assert_eq!(
        (seen.since(), seen.until()),
        (NOW - RESTORE_WATCH_SECS, NOW - 60)
    );
    let held = [0, 1, 2].map(|index| *receiver(index).as_bytes());
    assert_eq!(seen.contains(&held), [true, true, false]);
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

/// A directory whose witness snapshot is malformed, so no session opens.
struct MalformedWitnesses(Directory);

impl Transport for MalformedWitnesses {
    async fn get(&self, url: &str, limit: usize) -> Result<Vec<u8>, DirectoryError> {
        if url.contains("/v1/receiver/witness/") {
            self.0.requests.lock().unwrap().push(format!("GET {url}"));
            return Ok(vec![0]);
        }
        self.0.get(url, limit).await
    }

    async fn post(
        &self,
        url: &str,
        body: Vec<u8>,
        limit: usize,
    ) -> Result<Vec<u8>, DirectoryError> {
        self.0.post(url, body, limit).await
    }
}

/// A session that fails to open stops the run, so later paid keys are neither leased
/// nor backed off.
#[tokio::test]
async fn a_failed_session_open_stops_the_run_before_leasing_more_keys() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    // The batch's first two keys are paid, so each needs the session.
    let records: Vec<_> = (0..2)
        .map(|index| pay_restored_key(&mut st, index, index).0)
        .collect();
    st.generate_and_scan_empty_blocks_with_dynamic_ivks(1);
    restore(&mut st, account);
    let through = tip(&st);
    let cmxs: Vec<_> = records.iter().map(|record| record.payment.cmx).collect();
    let directory = MalformedWitnesses(Directory::new(publish(
        &records,
        &cmxs,
        through,
        &provider(&[]),
    )));
    let mut notes = Notes {
        data: BTreeMap::new(),
        requested: Vec::new(),
    };
    let swept = run(&mut st, &[account], through, &directory, &mut notes, NOW)
        .await
        .unwrap();
    assert!(
        matches!(
            &swept.deferred[..],
            [(_, key, Error::Directory(_))] if *key == KeyId::new(Purpose::Receive, 0)
        ),
        "{:?}",
        swept.deferred
    );
    assert_eq!(swept.finished, 0);
    let due = st
        .wallet_mut()
        .db_mut()
        .prepare_dynamic_sweeps(account, through, NOW, NonZeroU32::new(64).unwrap())
        .unwrap()
        .unwrap();
    let due = |index| {
        due.iter()
            .any(|item| item.key == KeyId::new(Purpose::Receive, index))
    };
    assert!(!due(0));
    assert!(due(1));
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

/// Runs one sweep of `accounts` through `through` at `now`.
async fn run(
    st: &mut State,
    accounts: &[AccountUuid],
    through: ChainPoint,
    directory: impl Transport,
    notes: &mut Notes,
    now: i64,
) -> Result<
    zakura_pir_receiver::Swept<AccountUuid, zcash_client_sqlite::error::SqliteClientError>,
    Error<zcash_client_sqlite::error::SqliteClientError>,
> {
    let network = *st.network();
    sweep(
        st.wallet_mut().db_mut(),
        &network,
        accounts,
        through,
        GENESIS,
        ORIGIN,
        directory,
        notes,
        &NoLock,
        now,
    )
    .await
}

/// Runs sweeps at [`NOW`] until none is pending, expecting no deferral, and returns how
/// many keys they finished.
async fn settle(
    st: &mut State,
    accounts: &[AccountUuid],
    through: ChainPoint,
    directory: &Directory,
    notes: &mut Notes,
) -> usize {
    let mut finished = 0;
    for _ in 0..20 {
        let swept = run(st, accounts, through, directory, notes, NOW)
            .await
            .unwrap();
        assert!(swept.deferred.is_empty(), "{:?}", swept.deferred);
        finished += swept.finished;
        if !swept.pending {
            return finished;
        }
    }
    panic!("sweeps are still pending after 20 runs");
}

/// A queued candidate that defers is replaced by each later attempt's answer from the
/// publication it uses: a corrected payment is recovered, and a paid-filter miss drops
/// the candidate, whatever made it wait.
#[tokio::test]
async fn a_deferred_candidate_takes_each_publications_current_answer() {
    use PaymentApplication::{AwaitingScan, AwaitingSpendHistory, AwaitingWitness};
    for (deferral, corrected) in [
        (AwaitingScan, true),
        (AwaitingScan, false),
        (AwaitingWitness, false),
        (AwaitingSpendHistory, false),
    ] {
        let mut st = ironwood_wallet();
        let account = st.test_account().unwrap().id();
        let key = KeyId::new(Purpose::Receive, 0);
        let (record, note_data) = pay_restored_key(&mut st, key.index(), 0);
        st.generate_and_scan_empty_blocks_with_dynamic_ivks(1);
        restore(&mut st, account);
        let mut through = tip(&st);
        let mut first = record.clone();
        let mut commitments = vec![record.payment.cmx];
        match deferral {
            // A block below the tip is not scanned yet.
            AwaitingScan => {
                st.generate_empty_block();
                let (top, _) = st.generate_empty_block();
                st.scan_cached_blocks_with_dynamic_ivks(top, 1);
                let block = st.wallet().block_metadata(top).unwrap().unwrap();
                through = ChainPoint {
                    height: top,
                    hash: block.block_hash(),
                };
                if corrected {
                    // Publication A misplaces the payment in another tree.
                    first.payment.position = 1;
                    commitments.insert(0, [1; 32]);
                }
            }
            AwaitingWitness => {
                st.wallet()
                    .conn()
                    .execute("DELETE FROM ironwood_tree_checkpoints", [])
                    .unwrap();
            }
            _ => {
                st.wallet()
                    .conn()
                    .execute_batch(
                        "DELETE FROM nullifier_map; DELETE FROM ironwood_nullifier_scan_blocks;",
                    )
                    .unwrap();
            }
        }
        let mut notes = Notes {
            data: BTreeMap::from([(0, note_data), (1, note_data)]),
            requested: Vec::new(),
        };
        let a = Directory::new(publish(&[first], &commitments, through, &provider(&[])));
        let swept = run(&mut st, &[account], through, &a, &mut notes, NOW)
            .await
            .unwrap();
        assert!(
            matches!(
                &swept.deferred[..],
                [(_, k, Error::Queued(d))] if *k == key && *d == deferral
            ),
            "{deferral:?}: {:?}",
            swept.deferred
        );
        assert!(swept.pending);
        if deferral == AwaitingScan {
            st.scan_cached_blocks_with_dynamic_ivks(through.height - 1, 1);
        }

        // Publication B, after the attempt's backoff.
        let b = if corrected {
            publish(
                std::slice::from_ref(&record),
                &[record.payment.cmx],
                through,
                &provider(&[]),
            )
        } else {
            publish(&[], &[], through, &provider(&[]))
        };
        let b = Directory::new(b);
        let swept = run(&mut st, &[account], through, &b, &mut notes, NOW + 60)
            .await
            .unwrap();
        assert!(
            swept.deferred.is_empty(),
            "{deferral:?}: {:?}",
            swept.deferred
        );
        settle(&mut st, &[account], through, &b, &mut notes).await;
        let value = if corrected { VALUE } else { 0 };
        assert_eq!(
            st.get_total_balance(account),
            Zatoshis::const_from_u64(value),
            "{deferral:?}"
        );
    }
}

/// An unchanged answer reuses the queued candidate's note data.
#[tokio::test]
async fn an_unchanged_answer_reuses_queued_note_data() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let (record, note_data) = pay_restored_key(&mut st, 0, 0);
    st.generate_and_scan_empty_blocks_with_dynamic_ivks(1);
    restore(&mut st, account);
    let through = tip(&st);
    st.wallet()
        .conn()
        .execute_batch("DELETE FROM nullifier_map; DELETE FROM ironwood_nullifier_scan_blocks;")
        .unwrap();
    let mut notes = Notes {
        data: BTreeMap::from([(record.payment.position, note_data)]),
        requested: Vec::new(),
    };
    let directory = Directory::new(publish(
        std::slice::from_ref(&record),
        &[record.payment.cmx],
        through,
        &provider(&[]),
    ));
    let swept = run(&mut st, &[account], through, &directory, &mut notes, NOW)
        .await
        .unwrap();
    assert!(
        matches!(
            &swept.deferred[..],
            [(
                _,
                _,
                Error::Queued(PaymentApplication::AwaitingSpendHistory)
            )]
        ),
        "{:?}",
        swept.deferred
    );
    // The replay the deferral queued is still unscanned.
    let swept = run(
        &mut st,
        &[account],
        through,
        &directory,
        &mut notes,
        NOW + 60,
    )
    .await
    .unwrap();
    assert!(
        matches!(
            &swept.deferred[..],
            [(_, _, Error::Queued(PaymentApplication::AwaitingScan))]
        ),
        "{:?}",
        swept.deferred
    );
    let posts = directory
        .requests()
        .iter()
        .filter(|r| *r == "POST /v1/receiver/query")
        .count();
    assert!(posts >= 2, "{:?}", directory.requests());
    assert_eq!(notes.requested, [vec![record.payment.position]]);
}

/// The receiver of `account_fvk`'s incoming dynamic key `index`.
fn incoming_receiver(account_fvk: &FullViewingKey, index: u64) -> Receiver {
    let fvk = KeyId::new(Purpose::Receive, index)
        .derive(account_fvk)
        .unwrap();
    Receiver::from_bytes(fvk.address_at(0u32, Scope::External).to_raw_address_bytes()).unwrap()
}

/// A seen set that holds every restored receiver moves the lookahead after each batch,
/// so a run sweeps at most one batch per account and leaves the new keys pending. Later
/// runs progress and find a payment far past the first batch.
#[tokio::test]
async fn each_run_sweeps_one_batch_and_later_runs_progress() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let paid = 100;
    let (record, note_data) = pay_restored_key(&mut st, paid, 0);
    st.generate_and_scan_empty_blocks_with_dynamic_ivks(1);
    restore(&mut st, account);
    let through = tip(&st);
    let parent = FullViewingKey::from(st.test_account().unwrap().usk().orchard());
    // The set is finite, so an unbounded run stops past it instead of hanging.
    let seen: Vec<_> = (0..200).map(|i| incoming_receiver(&parent, i)).collect();
    let directory = Directory::new(publish(
        std::slice::from_ref(&record),
        &[record.payment.cmx],
        through,
        &provider(&seen),
    ));
    let mut notes = Notes {
        data: BTreeMap::from([(record.payment.position, note_data)]),
        requested: Vec::new(),
    };
    let mut runs = 0;
    loop {
        let swept = run(&mut st, &[account], through, &directory, &mut notes, NOW)
            .await
            .unwrap();
        runs += 1;
        assert!(swept.deferred.is_empty(), "{:?}", swept.deferred);
        assert!(
            (1..=64).contains(&swept.finished),
            "run {runs} finished {}",
            swept.finished
        );
        if !swept.pending {
            break;
        }
        assert!(runs < 20);
    }
    assert!(runs > 1);
    assert_eq!(
        st.get_total_balance(account),
        Zatoshis::const_from_u64(VALUE)
    );
}

/// Accounts share key identities, so each deferred key names its account.
#[tokio::test]
async fn each_deferred_key_names_its_account() {
    let mut st = ironwood_wallet();
    let first = st.test_account().unwrap().id();
    let (second, usk) = st.create_account_from_test_seed("second");
    let key = KeyId::new(Purpose::Receive, 0);
    let (paid_first, first_data) = pay_restored_key(&mut st, key.index(), 0);
    let second_fvk = FullViewingKey::from(usk.orchard());
    let (paid_second, second_data) = pay_restored_key_of(&mut st, &second_fvk, 0, 1);
    st.generate_and_scan_empty_blocks_with_dynamic_ivks(1);
    restore(&mut st, first);
    restore(&mut st, second);
    let through = tip(&st);
    // The first payment waits for spend history, and the replay that queues makes the
    // second wait for scanning.
    st.wallet()
        .conn()
        .execute_batch("DELETE FROM nullifier_map; DELETE FROM ironwood_nullifier_scan_blocks;")
        .unwrap();
    let directory = Directory::new(publish(
        &[paid_first.clone(), paid_second.clone()],
        &[paid_first.payment.cmx, paid_second.payment.cmx],
        through,
        &provider(&[]),
    ));
    let mut notes = Notes {
        data: BTreeMap::from([(0, first_data), (1, second_data)]),
        requested: Vec::new(),
    };
    let swept = run(
        &mut st,
        &[first, second],
        through,
        &directory,
        &mut notes,
        NOW,
    )
    .await
    .unwrap();
    let deferred: Vec<_> = swept
        .deferred
        .iter()
        .map(|(account, key, e)| match e {
            Error::Queued(application) => (*account, *key, *application),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        deferred,
        [
            (first, key, PaymentApplication::AwaitingSpendHistory),
            (second, key, PaymentApplication::AwaitingScan),
        ]
    );
}
