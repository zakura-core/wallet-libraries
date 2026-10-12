//! Restore sweeps end to end: a restored wallet looks up its one-time keys in a receiver
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
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use sha2::{Digest as _, Sha256};
use tower::ServiceExt as _;
use zakura_one_time_ivk::swap::RESTORE_WATCH_SECS;
use zakura_pir_enhance::{
    ClientError, QueryBinding, ShardSession,
    transport::{Request as EnhanceRequest, ResponseBody, Transport as EnhanceTransport},
    types,
};
use zakura_pir_receiver::{
    DirectoryError, EnhanceNotes, Error, NoteSource, Swept, Transport, WriteLock, fetch_seen, sweep,
};
use zcash_client_backend::data_api::{
    Account as _, WalletRead as _, WalletWrite as _,
    chain::BlockSource as _,
    one_time_ivk::{
        OneTimeIvkRead as _,
        restore::{OneTimeIvkRestoreRead, OneTimeIvkRestoreWrite as _, PaymentApplication},
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
    util::{SystemClock, testing::FixedClock},
    wallet::one_time_ivk::{
        KeyId, Purpose,
        swap::{ProviderSeen, RECEIVE_GAP_LIMIT},
    },
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
/// The wallet a test sweeps.
type Wallet = WalletDb<rusqlite::Connection, LocalNetwork, FixedClock, TestRng>;

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
    ironwood_wallet_in(TestDbFactory::default())
}

/// [`ironwood_wallet`] stored as `factory` makes it. Its incoming lookahead is registered
/// before it scans, as a restore does, so scanning keeps the spend evidence sweeps need.
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

/// The receiver of the test account's incoming one-time key `index`.
fn receiver(st: &State, index: u64) -> Receiver {
    let parent = FullViewingKey::from(st.test_account().unwrap().usk().orchard());
    let fvk = KeyId::new(Purpose::Receive, index).derive(&parent).unwrap();
    Receiver::from_bytes(fvk.address_at(0u32, Scope::External).to_raw_address_bytes()).unwrap()
}

/// Pays incoming one-time key `index` in a new scanned block. Scanning cannot find it: a
/// restored key is swept before it is ever scanned. Returns the payment as the
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
    st.scan_cached_blocks_with_one_time_ivks(height, 1);
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
    let record = Record {
        receiver: receiver(st, index),
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

/// Note data from a fixed map, recording each request.
struct Notes {
    data: BTreeMap<u64, [u8; 528]>,
    requested: Vec<Vec<u64>>,
}

impl Notes {
    /// Serves `data`, keyed by position.
    fn new(data: BTreeMap<u64, [u8; 528]>) -> Self {
        Self {
            data,
            requested: Vec::new(),
        }
    }
}

impl<W: OneTimeIvkRestoreRead> NoteSource<W> for Notes {
    async fn note_data(
        &mut self,
        _: &W,
        positions: Vec<u64>,
    ) -> Result<BTreeMap<u64, [u8; 528]>, Error<W::Error>> {
        self.requested.push(positions.clone());
        Ok(positions
            .into_iter()
            .filter_map(|position| Some((position, *self.data.get(&position)?)))
            .collect())
    }
}

/// A note source that cannot serve the wallet's chain.
struct NoNotes;

impl<W: OneTimeIvkRestoreRead> NoteSource<W> for NoNotes {
    async fn note_data(
        &mut self,
        _: &W,
        _: Vec<u64>,
    ) -> Result<BTreeMap<u64, [u8; 528]>, Error<W::Error>> {
        Err(Error::NotesUnavailable("no note data"))
    }
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
async fn run<N: NoteSource<Wallet>>(
    st: &mut State,
    through: ChainPoint,
    directory: impl Transport,
    notes: &mut N,
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
        notes,
        lock,
        now,
    )
    .await
}

/// Runs sweeps at [`NOW`] until none is pending, expecting no deferral, and returns how
/// many keys they finished.
async fn settle(
    st: &mut State,
    through: ChainPoint,
    directory: &Directory,
    notes: &mut Notes,
) -> usize {
    let mut finished = 0;
    for _ in 0..20 {
        let swept = run(st, through, directory, notes, &NoLock, NOW)
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

#[tokio::test]
async fn a_restore_sweep_finds_a_payout_and_moves_the_lookahead_past_it() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let paid = 3;
    let (record, note_data) = pay_restored_key(&mut st, paid, 0);
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    restore(&mut st, account);
    let through = tip(&st);
    assert_eq!(st.get_total_balance(account), Zatoshis::ZERO);
    let directory = Directory::new(publish(
        std::slice::from_ref(&record),
        &[record.payment.cmx],
        through,
        &provider(&[]),
    ));
    let mut notes = Notes::new(BTreeMap::from([(record.payment.position, note_data)]));
    let finished = settle(&mut st, through, &directory, &mut notes).await;
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
}

/// Every page of a key's lookup is imported, with note data in batches of 64. A few
/// pages cost less over PIR than the row file, and many more.
#[tokio::test]
async fn every_payment_to_a_key_is_imported_in_note_data_batches() {
    for (count, batches, row_file) in [(2, vec![2], false), (65, vec![64, 1], true)] {
        let mut st = ironwood_wallet();
        let account = st.test_account().unwrap().id();
        let mut records = Vec::new();
        let mut data = BTreeMap::new();
        for position in 0..count {
            let (mut record, note_data) = pay_restored_key(&mut st, 1, position);
            record.page = position.try_into().unwrap();
            record.total = count.try_into().unwrap();
            records.push(record);
            data.insert(position, note_data);
        }
        st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
        restore(&mut st, account);
        let through = tip(&st);
        let commitments: Vec<_> = records.iter().map(|record| record.payment.cmx).collect();
        let directory = Directory::new(publish(&records, &commitments, through, &provider(&[])));
        let mut notes = Notes::new(data);
        settle(&mut st, through, &directory, &mut notes).await;
        let sizes: Vec<_> = notes.requested.iter().map(Vec::len).collect();
        assert_eq!(sizes, batches);
        assert_eq!(
            st.get_total_balance(account),
            Zatoshis::const_from_u64(count * VALUE)
        );
        let requests = directory.requests();
        let rows = |r: &String| r.starts_with("GET /v1/receiver/rows/");
        assert_eq!(requests.iter().any(rows), row_file, "{requests:?}");
    }
}

/// Note data keyed by the position after each requested one, counting the requests.
struct Mislabeled {
    data: [u8; 528],
    calls: usize,
}

impl<W: OneTimeIvkRestoreRead> NoteSource<W> for Mislabeled {
    async fn note_data(
        &mut self,
        _: &W,
        positions: Vec<u64>,
    ) -> Result<BTreeMap<u64, [u8; 528]>, Error<W::Error>> {
        self.calls += 1;
        assert!(self.calls <= 3, "the sweep keeps asking for {positions:?}");
        Ok(positions.into_iter().map(|p| (p + 1, self.data)).collect())
    }
}

#[tokio::test]
async fn note_data_for_other_positions_is_missing_data() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let paid = 1;
    let (record, note_data) = pay_restored_key(&mut st, paid, 0);
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    restore(&mut st, account);
    let through = tip(&st);
    let directory = Directory::new(publish(
        std::slice::from_ref(&record),
        &[record.payment.cmx],
        through,
        &provider(&[]),
    ));
    let mut notes = Mislabeled {
        data: note_data,
        calls: 0,
    };
    let swept = run(&mut st, through, &directory, &mut notes, &NoLock, NOW)
        .await
        .unwrap();
    assert_eq!(notes.calls, 1);
    assert!(
        matches!(
            swept.deferred.as_slice(),
            [(key, Error::Unavailable("note data is missing for a directory payment"))]
                if key.index() == paid
        ),
        "{:?}",
        swept.deferred
    );
    assert_eq!(st.get_total_balance(account), Zatoshis::ZERO);
}

#[tokio::test]
async fn a_wallet_without_payments_downloads_only_the_filters() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    restore(&mut st, account);
    let through = tip(&st);
    let directory = Directory::new(publish(&[], &[], through, &provider(&[])));
    let swept = run(&mut st, through, &directory, &mut NoNotes, &NoLock, NOW)
        .await
        .unwrap();
    assert!(swept.deferred.is_empty(), "{:?}", swept.deferred);
    assert_eq!(swept.finished as u64, RECEIVE_GAP_LIMIT);
    assert!(!swept.pending);
    // No PIR session, witnesses or note data: one manifest and one filter file.
    let requests = directory.requests();
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert!(requests[1].starts_with("GET /v1/receiver/filters/"));
}

/// A key closed after its sweep is checked against each newer publication's paid filter,
/// so a payment after the first publication's anchor is found once a publication shows
/// it, and not before. A publication already checked costs only its manifest, and a key
/// with a known payment is not swept again.
#[tokio::test]
async fn a_newer_paid_filter_finds_a_payment_to_a_closed_key() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    restore(&mut st, account);
    let first = tip(&st);
    let directory = Directory::new(publish(&[], &[], first, &provider(&[])));
    let mut notes = Notes::new(BTreeMap::new());
    settle(&mut st, first, &directory, &mut notes).await;
    assert!(st.wallet().get_one_time_scanning_keys().unwrap().is_empty());

    // The closed key misses a payment, which the same publication cannot show.
    let (record, note_data) = pay_restored_key(&mut st, 0, 0);
    let through = tip(&st);
    let before = directory.requests().len();
    let swept = run(&mut st, through, &directory, &mut notes, &NoLock, NOW).await;
    assert!(!swept.unwrap().pending);
    assert_eq!(directory.requests()[before..], ["GET /v1/receiver/init"]);
    assert_eq!(st.get_total_balance(account), Zatoshis::ZERO);

    let directory = Directory::new(publish(
        std::slice::from_ref(&record),
        &[record.payment.cmx],
        through,
        &provider(&[]),
    ));
    notes.data.insert(record.payment.position, note_data);
    // The paid key, then the lookahead key its index brings in.
    assert_eq!(settle(&mut st, through, &directory, &mut notes).await, 2);
    assert_eq!(
        st.get_total_balance(account),
        Zatoshis::const_from_u64(VALUE)
    );

    // A later publication still holds the paid key, but it is not looked up again.
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    let later = tip(&st);
    let directory = Directory::new(publish(
        std::slice::from_ref(&record),
        &[record.payment.cmx],
        later,
        &provider(&[]),
    ));
    let swept = run(&mut st, later, &directory, &mut notes, &NoLock, NOW).await;
    let swept = swept.unwrap();
    assert_eq!((swept.finished, swept.pending), (0, false));
    assert!(directory.requests().iter().all(|r| !r.starts_with("POST")));
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
        let mut st = ironwood_wallet();
        let account = st.test_account().unwrap().id();
        st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
        restore(&mut st, account);
        let through = tip(&st);
        let sets = if case == "quoted" {
            // The old device quoted addresses 0 and 2, and 2 only today.
            let mut sets = provider(&[receiver(&st, 0), receiver(&st, 2)]);
            sets[0].receivers = vec![receiver(&st, 2)];
            sets
        } else {
            // Provider `b` publishes only its seen set in the last case.
            let mut sets = provider_named("a", &[]);
            let b = provider_named("b", &[]).into_iter();
            sets.extend(b.skip(usize::from(case == "one recent")));
            sets
        };
        let directory = Directory::new(publish(&[], &[], through, &sets));
        let mut notes = Notes::new(BTreeMap::new());
        settle(&mut st, through, &directory, &mut notes).await;
        let mut scanning: Vec<_> = st
            .wallet()
            .get_one_time_scanning_keys()
            .unwrap()
            .iter()
            .map(|k| k.key_id().index())
            .collect();
        scanning.sort();
        assert_eq!(scanning, expected, "{case}");
    }
}

/// A seen hit counts from the attempt that observes it. When publication A's seen set
/// holds a receiver whose payment it then misstates, a later publication whose seen set
/// misses the receiver and whose lookup finds nothing does not make it issuable.
#[tokio::test]
async fn a_seen_hit_outlives_a_rejected_payment_and_a_later_miss() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let key = KeyId::new(Purpose::Receive, 0);
    let (record, note_data) = pay_restored_key(&mut st, key.index(), 0);
    // A later output, which publication A's tree replaces.
    let (later_output, _) = pay_restored_key(&mut st, 1000, 1);
    let commitments = [record.payment.cmx, later_output.payment.cmx];
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
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
    let mut notes = Notes::new(BTreeMap::from([(record.payment.position, note_data)]));
    // Publication A's witnesses are over another tree, so its payment is rejected.
    let a = Directory::new(publish(
        std::slice::from_ref(&record),
        &[record.payment.cmx, [1; 32]],
        through,
        &provider(&[record.receiver]),
    ));
    let swept = run(&mut st, through, &a, &mut notes, &NoLock, NOW)
        .await
        .unwrap();
    assert!(
        matches!(
            &swept.deferred[..],
            [(deferred, Error::Queued(PaymentApplication::Rejected))] if *deferred == key
        ),
        "{:?}",
        swept.deferred
    );
    assert!(seen(&st));

    let b = Directory::new(publish(&[], &commitments, through, &provider(&[])));
    let later = NOW + 3_600;
    let swept = run(&mut st, through, &b, &mut notes, &NoLock, later)
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
        if label == "one_time_sweep.attempt" && !labels.contains(&label) {
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
    let account = st.test_account().unwrap().id();
    let (record, note_data) = pay_restored_key(&mut st, 0, 0);
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    restore(&mut st, account);
    let through = tip(&st);
    let directory = Directory::new(publish(
        std::slice::from_ref(&record),
        &[record.payment.cmx],
        through,
        &provider(&[]),
    ));
    let mut notes = Notes::new(BTreeMap::from([(record.payment.position, note_data)]));
    let lock = FailFirstAttempt {
        fail: Arc::new(AtomicBool::new(false)),
        labels: RefCell::new(Vec::new()),
    };
    let fail = lock.fail.clone();
    // Returning true turns the commit into a rollback, which fails the write.
    st.wallet()
        .conn()
        .commit_hook(Some(move || fail.swap(false, Ordering::SeqCst)));
    let result = run(&mut st, through, &directory, &mut notes, &lock, NOW).await;
    assert!(matches!(result, Err(Error::Wallet(_))), "{result:?}");
    assert_eq!(
        *lock.labels.borrow(),
        ["one_time_sweep.due", "one_time_sweep.attempt"]
    );
    assert!(
        directory.requests().iter().all(|r| !r.starts_with("POST")),
        "{:?}",
        directory.requests()
    );
    assert!(notes.requested.is_empty());
}

/// A `through` the wallet has scanned past is not a tip to release evidence at, so a
/// run with it writes nothing.
#[tokio::test]
async fn a_stale_tip_releases_nothing() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    restore(&mut st, account);
    let through = tip(&st);
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    let directory = Directory::new(publish(&[], &[], through, &provider(&[])));
    let lock = Labels::default();
    run(&mut st, through, &directory, &mut NoNotes, &lock, NOW)
        .await
        .unwrap();
    assert!(lock.0.borrow().is_empty(), "{:?}", lock.0.borrow());
    assert!(directory.requests().is_empty());
}

/// Another handle on the wallet's file, as another writer holds.
type OtherWriter = WalletDb<rusqlite::Connection, LocalNetwork, SystemClock, TestRng>;

/// A write through another handle on the wallet's file at `through`.
type OtherWrite = fn(&mut OtherWriter, ChainPoint);

/// Runs `other` just before the first release, as another writer may while the sweep
/// holds no lock, then sets `releasing` while release holds the lock.
struct WriterBeforeRelease<F> {
    other: RefCell<Option<F>>,
    releasing: Arc<AtomicBool>,
}

impl<F: FnOnce()> WriteLock for WriterBeforeRelease<F> {
    fn write<T>(&self, label: &'static str, write: impl FnOnce() -> T) -> T {
        if label != "one_time_sweep.release" {
            return write();
        }
        if let Some(other) = self.other.borrow_mut().take() {
            other();
        }
        self.releasing.store(true, Ordering::SeqCst);
        let result = write();
        self.releasing.store(false, Ordering::SeqCst);
        result
    }
}

/// Release checks the chain point again under its lock, since another writer may move
/// the tip while the sweep's lookups run without it, and waits for the fully scanned
/// height to reach it. Each case sweeps against a publication `behind` blocks below the
/// tip, with `other` writing through a second handle just before release, and judges
/// whether release ran by its read of the retention table.
#[tokio::test]
async fn release_runs_only_at_the_fully_scanned_tip() {
    let cases: [(&str, u32, OtherWrite, bool); 5] = [
        ("an unmoved tip", 0, |_, _| (), true),
        (
            "an advanced tip",
            0,
            |other, through| {
                other.update_chain_tip(through.height + 1).unwrap();
            },
            false,
        ),
        (
            "a reorg that rewound the tip",
            0,
            |other, through| {
                other.truncate_to_height(through.height - 1).unwrap();
            },
            false,
        ),
        // The tip is back at `through`'s height, but its block is not scanned yet.
        (
            "a replaced block",
            0,
            |other, through| {
                other.truncate_to_height(through.height - 1).unwrap();
                other.update_chain_tip(through.height).unwrap();
            },
            false,
        ),
        // Finishing keys against a publication behind `through` rescans the blocks
        // after it, lowering the fully scanned height without moving the tip.
        ("a rescan the sweep queued", 1, |_, _| (), false),
    ];
    for (case, behind, other, expected) in cases {
        let mut st = ironwood_wallet_in(TestDbFactory::file_backed());
        let network = *st.network();
        let account = st.test_account().unwrap().id();
        st.generate_and_scan_empty_blocks_with_one_time_ivks(2);
        restore(&mut st, account);
        let through = tip(&st);
        let path = st.wallet().conn().path().unwrap().to_owned();
        let mut handle =
            OtherWriter::for_path(path, network, SystemClock, TestRng::seed_from_u64(0)).unwrap();
        let lock = WriterBeforeRelease {
            other: RefCell::new(Some(|| other(&mut handle, through))),
            releasing: Arc::new(AtomicBool::new(false)),
        };
        let released = Arc::new(AtomicBool::new(false));
        let (releasing, read) = (lock.releasing.clone(), released.clone());
        st.wallet()
            .conn()
            .authorizer(Some(move |ctx: AuthContext<'_>| {
                if releasing.load(Ordering::SeqCst)
                    && matches!(
                        ctx.action,
                        AuthAction::Read {
                            table_name: "ironwood_one_time_spend_retention",
                            ..
                        }
                    )
                {
                    read.store(true, Ordering::SeqCst);
                }
                Authorization::Allow
            }));
        let height = through.height - behind;
        let end = ChainPoint {
            height,
            hash: st.wallet().get_block_hash(height).unwrap().unwrap(),
        };
        // Without a recent set, every key keeps scanning from the block after `end`.
        let directory = Directory::new(publish(&[], &[], end, &provider(&[])[1..]));
        let swept = run(&mut st, through, &directory, &mut NoNotes, &lock, NOW)
            .await
            .unwrap();
        assert_eq!(swept.finished as u64, RECEIVE_GAP_LIMIT);
        st.wallet()
            .conn()
            .authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
        assert_eq!(released.load(Ordering::SeqCst), expected, "{case}");
    }
}

/// Another network's seen sets say nothing about this network's quotes, so a
/// publication committing to another genesis is refused as a sweep refuses it.
#[tokio::test]
async fn seen_sets_of_another_network_are_refused() {
    let mut st = ironwood_wallet();
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
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

/// A publication without seen sets, or with a provider that has a recent set but no
/// seen set, may omit any receiver, so issuance and sweeps both refuse it, before any
/// key finishes or spend evidence is released. Once every provider has a dated seen
/// set, the sets cover the quote times they all cover, and hold what any of them holds.
#[tokio::test]
async fn every_provider_with_sets_needs_a_seen_set() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    restore(&mut st, account);
    let through = tip(&st);
    // Provider `a` has its seen set only if `a_seen`. `b` has only a seen set, from a
    // later feed start and a later read.
    let sets = |a_seen: bool| {
        let mut sets = provider_named("a", &[receiver(&st, 0)]);
        sets.truncate(1 + usize::from(a_seen));
        let mut b = provider_named("b", &[receiver(&st, 1)]).pop().unwrap();
        b.since_unix = NOW - RESTORE_WATCH_SECS;
        b.until_unix = NOW - 30;
        sets.push(b);
        sets
    };
    let (missing, complete) = (sets(false), sets(true));
    // The first refusal backs every due key off for a minute.
    for (sets, now) in [(missing, NOW), (Vec::new(), NOW + 60)] {
        let directory = Directory::new(publish(&[], &[], through, &sets));
        let refused = fetch_seen(ORIGIN, &directory, GENESIS).await;
        assert!(matches!(refused, Err(DirectoryError::Malformed)));
        let lock = Labels::default();
        let result = run(&mut st, through, &directory, &mut NoNotes, &lock, now).await;
        assert!(
            matches!(result, Err(Error::Directory(DirectoryError::Malformed))),
            "{result:?}"
        );
        let labels = lock.0.borrow();
        assert!(
            labels
                .iter()
                .all(|l| ["one_time_sweep.due", "one_time_sweep.attempt"].contains(l)),
            "{labels:?}"
        );
        assert!(
            st.wallet()
                .db()
                .one_time_history_pending(account, through.height)
                .unwrap()
        );
    }

    let directory = Directory::new(publish(&[], &[], through, &complete));
    let seen = fetch_seen(ORIGIN, &directory, GENESIS).await.unwrap();
    assert_eq!(
        (seen.since(), seen.until()),
        (NOW - RESTORE_WATCH_SECS, NOW - 60)
    );
    let held = [0, 1, 2].map(|index| *receiver(&st, index).as_bytes());
    assert_eq!(seen.contains(&held), [true, true, false]);
}

/// Which part of a directory fails.
#[derive(Clone, Copy, Debug)]
enum Fault {
    None,
    /// Queries fail after the session was accepted.
    Queries,
    /// The witness snapshot is malformed, so no session opens.
    Witnesses,
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
        if matches!(self.fault, Fault::Queries) {
            return Err(DirectoryError::Revision);
        }
        self.directory.post(url, body, limit).await
    }
}

/// A revoked session, a session that fails to open, or a note source that cannot serve
/// the wallet's chain would fail every later key the same way, so the run stops at the
/// first paid key, and later paid keys are neither leased nor backed off.
#[tokio::test]
async fn a_run_fatal_failure_stops_the_run_before_leasing_more_keys() {
    for fault in [Fault::Queries, Fault::Witnesses, Fault::None] {
        let mut st = ironwood_wallet();
        let account = st.test_account().unwrap().id();
        // The batch's first two keys are paid, so each needs a lookup.
        let records: Vec<_> = (0..2)
            .map(|index| pay_restored_key(&mut st, index, index).0)
            .collect();
        st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
        restore(&mut st, account);
        let through = tip(&st);
        let cmxs: Vec<_> = records.iter().map(|record| record.payment.cmx).collect();
        let directory = Faulty {
            directory: Directory::new(publish(&records, &cmxs, through, &provider(&[]))),
            fault,
        };
        let swept = run(&mut st, through, &directory, &mut NoNotes, &NoLock, NOW)
            .await
            .unwrap();
        let [(key, e)] = &swept.deferred[..] else {
            panic!("{fault:?}: {:?}", swept.deferred);
        };
        let failed = match fault {
            Fault::Queries => matches!(e, Error::Directory(DirectoryError::Revision)),
            Fault::Witnesses => matches!(e, Error::Directory(_)),
            Fault::None => matches!(e, Error::NotesUnavailable(_)),
        };
        assert!(
            *key == KeyId::new(Purpose::Receive, 0) && failed,
            "{fault:?}: {e:?}"
        );
        assert_eq!(swept.finished, 0);
        assert!(swept.pending);
        let due: Vec<_> = st
            .wallet_mut()
            .db_mut()
            .prepare_one_time_sweeps(account, through, NOW, NonZeroU32::new(64).unwrap())
            .unwrap()
            .unwrap()
            .iter()
            .map(|item| item.key.index())
            .collect();
        assert!(!due.contains(&0) && due.contains(&1), "{fault:?}: {due:?}");
    }
}

/// A publication off the wallet's chain, or ending at the wallet's block but short of
/// that block's last Ironwood output, is refused before any lookup: a payment in the
/// omitted tail would be neither looked up nor rescanned. Every due key backs off, so
/// the directory is not asked again until a minute on.
#[tokio::test]
async fn a_publication_off_the_wallets_chain_is_refused_before_any_lookup() {
    for off_chain in [true, false] {
        let mut st = ironwood_wallet();
        let account = st.test_account().unwrap().id();
        let (record, note_data) = pay_restored_key(&mut st, 0, 0);
        st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
        restore(&mut st, account);
        let through = tip(&st);
        let publication = if off_chain {
            let other = ChainPoint {
                hash: BlockHash([1; 32]),
                ..through
            };
            publish(
                std::slice::from_ref(&record),
                &[record.payment.cmx],
                other,
                &provider(&[]),
            )
        } else {
            // Without the chain's one Ironwood output.
            publish(&[], &[], through, &provider(&[]))
        };
        let directory = Directory::new(publication);
        let mut notes = Notes::new(BTreeMap::from([(record.payment.position, note_data)]));
        let result = run(&mut st, through, &directory, &mut notes, &NoLock, NOW).await;
        let refused = match result {
            Err(Error::Directory(_)) => off_chain,
            Err(Error::Unavailable(_)) => !off_chain,
            _ => false,
        };
        assert!(refused, "{result:?}");
        assert_eq!(directory.requests(), ["GET /v1/receiver/init"]);
        assert!(notes.requested.is_empty());
        assert!(
            st.wallet()
                .db()
                .one_time_history_pending(account, through.height)
                .unwrap()
        );
        for (now, requests) in [(NOW, 1), (NOW + 60, 2)] {
            let _ = run(&mut st, through, &directory, &mut notes, &NoLock, now).await;
            assert_eq!(directory.requests().len(), requests);
        }
    }
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

/// Enhance notes open no session until a position needs note data, accept fresh routing
/// after a refused query, and cannot serve a wallet whose chain lacks their anchor.
#[tokio::test]
async fn enhance_notes_follow_the_wallets_chain_and_fresh_routing() {
    let mut st = ironwood_wallet();
    pay_restored_key(&mut st, 0, 0);
    let anchor = tip(&st);
    let records = st
        .wallet()
        .block_metadata(anchor.height)
        .unwrap()
        .unwrap()
        .ironwood_tree_size()
        .unwrap()
        .into();
    let network = EnhanceNetwork(*st.network());
    for status in [409, 410] {
        let enhance = RefusingEnhance::new(anchor, records, status);
        let mut notes = EnhanceNotes::new("https://enhance.test", &enhance, &network);
        let data = notes.note_data(st.wallet().db(), Vec::new()).await.unwrap();
        assert!(data.is_empty());
        assert_eq!(enhance.inits.get(), 0);
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
    // Enhance's anchor is at the wallet's tip height but on another chain.
    let other = ChainPoint {
        hash: BlockHash([7; 32]),
        ..anchor
    };
    let enhance = RefusingEnhance::new(other, records, 409);
    let mut notes = EnhanceNotes::new("https://enhance.test", &enhance, &network);
    let refused = notes.note_data(st.wallet().db(), vec![0]).await;
    assert!(
        matches!(refused, Err(Error::NotesUnavailable(_))),
        "{refused:?}"
    );
    assert_eq!(enhance.queries.get(), 0);
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
        st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
        restore(&mut st, account);
        let mut through = tip(&st);
        let mut first = record.clone();
        let commitments = [record.payment.cmx];
        match deferral {
            // A block below the tip is not scanned yet.
            AwaitingScan => {
                st.generate_empty_block();
                let (top, _) = st.generate_empty_block();
                st.scan_cached_blocks_with_one_time_ivks(top, 1);
                let block = st.wallet().block_metadata(top).unwrap().unwrap();
                through = ChainPoint {
                    height: top,
                    hash: block.block_hash(),
                };
                if corrected {
                    // Publication A misstates the payment's transaction.
                    first.payment.tx_index += 1;
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
        let mut notes = Notes::new(BTreeMap::from([(0, note_data)]));
        let a = Directory::new(publish(&[first], &commitments, through, &provider(&[])));
        let swept = run(&mut st, through, &a, &mut notes, &NoLock, NOW)
            .await
            .unwrap();
        assert!(
            matches!(
                &swept.deferred[..],
                [(k, Error::Queued(d))] if *k == key && *d == deferral
            ),
            "{deferral:?}: {:?}",
            swept.deferred
        );
        assert!(swept.pending);
        if deferral == AwaitingScan {
            st.scan_cached_blocks_with_one_time_ivks(through.height - 1, 1);
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
            publish(&[], &commitments, through, &provider(&[]))
        };
        let b = Directory::new(b);
        let swept = run(&mut st, through, &b, &mut notes, &NoLock, NOW + 60)
            .await
            .unwrap();
        assert!(
            swept.deferred.is_empty(),
            "{deferral:?}: {:?}",
            swept.deferred
        );
        settle(&mut st, through, &b, &mut notes).await;
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
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    restore(&mut st, account);
    let through = tip(&st);
    st.wallet()
        .conn()
        .execute_batch("DELETE FROM nullifier_map; DELETE FROM ironwood_nullifier_scan_blocks;")
        .unwrap();
    let mut notes = Notes::new(BTreeMap::from([(record.payment.position, note_data)]));
    let directory = Directory::new(publish(
        std::slice::from_ref(&record),
        &[record.payment.cmx],
        through,
        &provider(&[]),
    ));
    let swept = run(&mut st, through, &directory, &mut notes, &NoLock, NOW)
        .await
        .unwrap();
    assert!(
        matches!(
            &swept.deferred[..],
            [(_, Error::Queued(PaymentApplication::AwaitingSpendHistory))]
        ),
        "{:?}",
        swept.deferred
    );
    // The replay the deferral queued is still unscanned.
    let swept = run(&mut st, through, &directory, &mut notes, &NoLock, NOW + 60)
        .await
        .unwrap();
    assert!(
        matches!(
            &swept.deferred[..],
            [(_, Error::Queued(PaymentApplication::AwaitingScan))]
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

/// A seen set that holds every restored receiver moves the lookahead after each batch,
/// so a run sweeps at most one batch and leaves the new keys pending. Later runs
/// progress and find a payment far past the first batch.
#[tokio::test]
async fn each_run_sweeps_one_batch_and_later_runs_progress() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let paid = 100;
    let (record, note_data) = pay_restored_key(&mut st, paid, 0);
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    restore(&mut st, account);
    let through = tip(&st);
    // The set is finite, so an unbounded run stops past it instead of hanging.
    let seen: Vec<_> = (0..200).map(|i| receiver(&st, i)).collect();
    let directory = Directory::new(publish(
        std::slice::from_ref(&record),
        &[record.payment.cmx],
        through,
        &provider(&seen),
    ));
    let mut notes = Notes::new(BTreeMap::from([(record.payment.position, note_data)]));
    let mut runs = 0;
    loop {
        let swept = run(&mut st, through, &directory, &mut notes, &NoLock, NOW)
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
