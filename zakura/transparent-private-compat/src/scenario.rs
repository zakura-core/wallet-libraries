// Included by a module that defines `api`, naming one implementation's wallet
// adapter, fixture service and wallet crates. A wallet recovers privately from
// an in-process shard service over loopback HTTP; the databases it leaves are
// what a later build must reopen and resume.

/// The first height the publication covers, a mainnet height.
pub const H0: u64 = 3_428_143;
/// The origin every companion is bound to.
pub const ORIGIN: &str = "https://fixture.test";
const RESPONSE_LIMIT: usize = 64 << 20;

type State = api::backend::data_api::testing::TestState<
    api::sqlite::testing::BlockCache,
    api::sqlite::testing::db::TestDb,
    zcash_protocol::local_consensus::LocalNetwork,
>;

/// What [`interrupted`] leaves: both databases as SQL, and the account.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Interrupted {
    pub account: String,
    /// The scripts the publication pays, hex: A0, A1 and the last external
    /// address when the wallet was created.
    pub owned: Vec<String>,
    pub wallet_sql: String,
    pub companion_sql: String,
    /// What the passes reported, for reading the fixture.
    pub notes: Vec<String>,
}

/// What a resumed wallet holds after each step, by name.
pub type Resumed = std::collections::BTreeMap<String, dump::SnapshotDigest>;

fn config(account: &[u8], queries: u64) -> api::recovery::TransparentHistoryRecoveryConfig {
    api::recovery::TransparentHistoryRecoveryConfig {
        source: b"fixture/transparent-pir/v1".to_vec(),
        account_binding: account.to_vec(),
        origin: ORIGIN.into(),
        scripts: 10_000,
        shards: 1_024,
        events: 500_000,
        queries,
        private_bytes: 96 << 20,
    }
}

fn height(at: u64) -> zcash_protocol::consensus::BlockHeight {
    zcash_protocol::consensus::BlockHeight::from(u32::try_from(at).unwrap())
}

fn pubkey_script(address: transparent::address::TransparentAddress) -> api::filter::ScriptBytes {
    let transparent::address::TransparentAddress::PublicKeyHash(hash) = address else {
        panic!("derived addresses pay to public key hashes")
    };
    api::filter::ScriptBytes::new([&[0x76, 0xa9, 20][..], &hash, &[0x88, 0xac]].concat())
}

fn unrelated(tag: u32) -> api::filter::ScriptBytes {
    let mut bytes = vec![0x76, 0xa9, 20];
    bytes.extend_from_slice(&tag.to_le_bytes());
    bytes.extend_from_slice(&[0xee; 16]);
    bytes.extend_from_slice(&[0x88, 0xac]);
    api::filter::ScriptBytes::new(bytes)
}

fn txid(tag: u64) -> api::events::Txid {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&tag.to_le_bytes());
    bytes[31] = 0x77;
    api::events::Txid(bytes)
}

fn receive(at: u64, txid: api::events::Txid, output_index: u32, value: u64) -> api::events::TransparentEvent {
    api::events::TransparentEvent::Receive(api::events::ReceiveEvent {
        metadata: None,
        height: at as u32,
        txid,
        transaction_index: 1,
        output_index,
        value,
        coinbase: false,
    })
}

fn spend(at: u64, spending: api::events::Txid, spent: (api::events::Txid, u32)) -> api::events::TransparentEvent {
    api::events::TransparentEvent::Spend(api::events::SpendEvent {
        metadata: None,
        height: at as u32,
        spending_txid: spending,
        transaction_index: 2,
        input_index: 0,
        spent_txid: spent.0,
        spent_output_index: spent.1,
    })
}

fn noise(start: u64, end: u64, salt: u32) -> Vec<(api::filter::ScriptBytes, api::events::TransparentEvent)> {
    (0..40u32)
        .map(|n| {
            let tag = salt * 1_000 + n;
            let at = start + u64::from(n * 7) % (end - start + 1);
            (unrelated(tag), receive(at, txid(u64::from(tag) + 100_000), 0, 1))
        })
        .collect()
}

/// The addresses the publication pays, as scripts.
#[derive(Clone)]
struct Owned {
    a0: api::filter::ScriptBytes,
    a1: api::filter::ScriptBytes,
    last: api::filter::ScriptBytes,
}

/// Three sealed shards and a tail through `tail_end` at `revision`. A0's entry
/// in the second shard is published malformed, so it fails on every pass. The
/// last external address receives often enough in the third shard that its
/// older receives are pushed into a page shard, and A1's history in the tail
/// runs across the tail's page shards, ten blocks each.
fn publication(owned: &Owned, tail_end: u64, revision: u32) -> Vec<api::fixture::service::ShardSpec> {
    use api::fixture::service::ShardSpec;
    let mut s1 = noise(H0 + 200, H0 + 399, 1);
    s1.push((owned.a0.clone(), receive(H0 + 300, txid(2), 0, 50_000)));
    let mut s2 = noise(H0 + 400, H0 + 599, 2);
    for k in 0..6u64 {
        s2.push((owned.last.clone(), receive(H0 + 410 + k * 20, txid(10 + k), 1, 7_000 + k)));
    }
    let mut tail = noise(H0 + 600, tail_end, 3);
    tail.push((owned.last.clone(), spend(H0 + 620, txid(4), (txid(10), 1))));
    for (n, offset) in [1u64, 2, 3, 11, 12, 21, 31, 42].into_iter().enumerate() {
        tail.push((owned.a1.clone(), receive(H0 + 600 + offset, txid(20 + n as u64), 0, 1_000 * (n as u64 + 1))));
    }
    if tail_end >= H0 + 655 {
        tail.push((owned.a1.clone(), receive(H0 + 655, txid(5), 0, 30_000)));
    }
    let mut s0 = noise(H0, H0 + 199, 0);
    s0.push((owned.a0.clone(), receive(H0 + 50, txid(1), 0, 11_000)));
    vec![
        ShardSpec::first(H0, H0 + 199, true, s0),
        ShardSpec {
            malformed_entries: vec![owned.a0.clone()],
            ..ShardSpec::first(H0 + 200, H0 + 399, true, s1)
        },
        ShardSpec::first(H0 + 400, H0 + 599, true, s2),
        ShardSpec {
            revision,
            page_span: 10,
            ..ShardSpec::first(H0 + 600, tail_end, false, tail)
        },
    ]
}

/// A loopback HTTP server answering from the in-process shard service.
struct Server {
    runtime: tokio::runtime::Runtime,
    serving: Option<tokio::task::JoinHandle<()>>,
}

impl Server {
    fn start() -> Self {
        Self {
            runtime: tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap(),
            serving: None,
        }
    }

    /// Serves the publication in `dir`, returning its base URL.
    fn serve(&mut self, dir: &std::path::Path) -> String {
        if let Some(previous) = self.serving.take() {
            previous.abort();
        }
        let service = api::fixture::service::InProcess::serve(dir);
        let (url, serving) = self.runtime.block_on(async move {
            let app = axum::Router::new().fallback(move |request: axum::extract::Request| {
                let service = service.clone();
                async move {
                    let (parts, body) = request.into_parts();
                    let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
                    let request = axum::http::Request::from_parts(parts, body.to_vec());
                    tokio::task::spawn_blocking(move || service.answer(request))
                        .await
                        .unwrap()
                        .map(axum::body::Body::from)
                }
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let serving = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            (url, serving)
        });
        self.serving = Some(serving);
        url
    }
}

/// A wallet's exchange over loopback HTTP: one blocking request at a time.
struct Loopback {
    client: reqwest::blocking::Client,
    url: String,
}

impl api::recovery::HttpExchange for Loopback {
    fn send(
        &self,
        request: &api::recovery::HttpRequest,
    ) -> Result<api::recovery::HttpReply, api::recovery::HttpFailure> {
        let url = format!("{}{}", self.url, request.path);
        let sending = match request.method {
            api::recovery::HttpMethod::Get => self.client.get(url),
            api::recovery::HttpMethod::Post => self
                .client
                .post(url)
                .header("content-type", "application/octet-stream")
                .body(request.body.clone()),
        };
        let response = sending
            .send()
            .map_err(|_| api::recovery::HttpFailure::Unreachable)?;
        let status = response.status().as_u16();
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let (retry_after, map_sha256) = (header("retry-after"), header("x-txid-map-sha256"));
        let mut body = response
            .bytes()
            .map_err(|_| api::recovery::HttpFailure::Unreachable)?
            .to_vec();
        if (200..300).contains(&status) {
            if body.len() > request.limit {
                return Err(api::recovery::HttpFailure::TooLarge);
            }
        } else {
            body.truncate(request.error_limit);
        }
        Ok(api::recovery::HttpReply {
            status,
            retry_after,
            map_sha256,
            body,
        })
    }
}

fn exchange(url: &str) -> Loopback {
    Loopback {
        client: reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .unwrap(),
        url: url.to_owned(),
    }
}

/// The wallet's hash at `at`, or a synthetic one below its birthday.
fn block_hash<W: api::backend::data_api::WalletRead>(wallet: &W, birthday: u64, at: u64) -> api::filter::BlockHash {
    if at < birthday {
        return api::fixture::service::synthetic(at);
    }
    let hash = wallet
        .get_block_hash(height(at))
        .ok()
        .flatten()
        .expect("a scanned block");
    api::filter::BlockHash::from_internal_bytes(hash.0)
}

fn derived(
    watch: &api::backend::data_api::transparent_ledger::TransparentAddressWatchSet<api::sqlite::AccountUuid>,
    index: u32,
) -> transparent::address::TransparentAddress {
    use api::backend::data_api::transparent_ledger::WatchOrigin;
    watch
        .addresses
        .iter()
        .find(|w| {
            matches!(w.origin, WatchOrigin::Derived { scope, index: i }
                if scope == transparent::keys::TransparentKeyScope::EXTERNAL && i.index() == index)
        })
        .expect("a derived address")
        .address
}

fn last_external(
    watch: &api::backend::data_api::transparent_ledger::TransparentAddressWatchSet<api::sqlite::AccountUuid>,
) -> transparent::address::TransparentAddress {
    use api::backend::data_api::transparent_ledger::WatchOrigin;
    watch
        .addresses
        .iter()
        .filter_map(|w| match w.origin {
            WatchOrigin::Derived { scope, index } | WatchOrigin::CandidateWindow { scope, index }
                if scope == transparent::keys::TransparentKeyScope::EXTERNAL =>
            {
                Some((index.index(), w.address))
            }
            _ => None,
        })
        .max_by_key(|(index, _)| *index)
        .unwrap()
        .1
}

/// A wallet that recovered once, settled, then recovered again after its chain
/// grew and committed that batch to the wallet without the companion ever
/// acknowledging it: the state an application killed between the two leaves.
pub fn interrupted(work: &std::path::Path) -> Interrupted {
    use api::backend::data_api::{Account as _, WalletRead as _, chain::ChainState, testing::{InitialChainState, TestBuilder}};
    use api::backend::data_api::transparent_ledger::{TransparentLedgerMode::PrivateRequired, TransparentLedgerRead as _, TransparentLedgerWrite as _};

    let birthday = H0 + 250;
    let mut st: State = TestBuilder::new()
        .with_data_store_factory(api::sqlite::testing::db::TestDbFactory::file_backed())
        .with_block_cache(api::sqlite::testing::BlockCache::new())
        .with_initial_chain_state(|_, _| InitialChainState {
            chain_state: ChainState::empty(
                height(birthday - 1),
                zcash_primitives::block::BlockHash(api::fixture::service::synthetic(birthday - 1).internal_bytes().to_owned()),
            ),
            prior_sapling_roots: vec![],
            prior_orchard_roots: vec![],
        })
        .with_account_having_current_birthday()
        .build();
    let account = st.test_account().unwrap().id();
    let name = account.expose_uuid().to_string();
    let scan_to = |st: &mut State, through: u64| {
        let from = st.wallet().chain_height().unwrap().map_or(birthday, |tip| u64::from(u32::from(tip)) + 1);
        for _ in from..=through {
            st.generate_empty_block();
        }
        st.scan_cached_blocks(height(from), (through + 1 - from) as usize);
    };
    scan_to(&mut st, H0 + 649);
    {
        let db = st.wallet_mut().db_mut();
        db.apply_transparent_policy(PrivateRequired).unwrap();
        db.set_transparent_ledger_mode(PrivateRequired);
    }
    let companions = api::recovery::CompanionDir::new(work.join("companions"));
    let open = |companions: &api::recovery::CompanionDir, queries: u64| {
        companions
            .open(
                &name,
                config(account.expose_uuid().as_bytes(), queries),
                || Ok(std::collections::BTreeSet::from([name.clone()])),
                &|| false,
            )
            .unwrap()
    };
    let mut companion = open(&companions, 256);
    let watch = st.wallet().db().transparent_watch_set(account).unwrap();
    let owned = Owned {
        a0: pubkey_script(derived(&watch, 0)),
        a1: pubkey_script(derived(&watch, 1)),
        last: pubkey_script(last_external(&watch)),
    };
    let mut server = Server::start();
    let mut notes = Vec::new();

    // The first sync: recovered, applied and acknowledged.
    let dir = work.join("publication-1");
    api::fixture::service::publish(&dir, &publication(&owned, H0 + 649, 0), api::fixture::service::SEAL, |at| block_hash(st.wallet().db(), birthday, at), vec![]);
    let url = server.serve(&dir);
    let watch = st.wallet().db().transparent_watch_set(account).unwrap();
    let report = {
        let chain = api::recovery::WalletChain::new(st.wallet().db(), watch.target.unwrap());
        companion
            .pass(&watch, &chain, &exchange(&url), RESPONSE_LIMIT, &|| false)
            .unwrap()
    };
    notes.push(format!("first pass: {report:?}"));
    let batch = companion
        .take_latest::<api::sqlite::AccountUuid>()
        .expect("a ready first pass");
    let applied = companion
        .apply_and_acknowledge_gated(batch, st.wallet_mut().db_mut(), api::recovery::Trust::Trusted, &mut api::recovery::Ungated)
        .unwrap();
    notes.push(format!("first settlement: {:?}", applied.stats));

    // The chain grows and the tail is republished. Under a one-query budget the
    // second pass leaves page retrievals pending; its batch is committed to the
    // wallet, and the application stops before acknowledging.
    scan_to(&mut st, H0 + 660);
    drop(companion);
    let mut companion = open(&companions, 1);
    let dir = work.join("publication-2");
    api::fixture::service::publish(&dir, &publication(&owned, H0 + 660, 1), api::fixture::service::SEAL, |at| block_hash(st.wallet().db(), birthday, at), vec![]);
    let url = server.serve(&dir);
    // Passes that hold no batch are settled as an application would, until one
    // holds a ready batch.
    let mut passes = 0;
    let batch = loop {
        passes += 1;
        assert!(passes <= 40, "no ready pass under a one-query budget");
        let watch = st.wallet().db().transparent_watch_set(account).unwrap();
        let report = {
            let chain = api::recovery::WalletChain::new(st.wallet().db(), watch.target.unwrap());
            companion
                .pass(&watch, &chain, &exchange(&url), RESPONSE_LIMIT, &|| false)
                .unwrap()
        };
        notes.push(format!("budgeted pass {passes}: {report:?}"));
        if let Some(batch) = companion.take_latest::<api::sqlite::AccountUuid>() {
            break batch;
        }
        companion
            .settle_latest(st.wallet_mut().db_mut(), api::recovery::Trust::Trusted, &mut api::recovery::Ungated)
            .unwrap();
    };
    let applied = api::recovery::testing::apply(batch, st.wallet_mut().db_mut(), api::recovery::Trust::Trusted).unwrap();
    notes.push(format!("second commits, unacknowledged: {:?}", applied.stats));
    let companion_path = companions.companion_path(&name, ORIGIN);
    drop(companion);
    let companion_sql = dump::to_sql(&rusqlite::Connection::open(&companion_path).unwrap());
    let wallet_sql = dump::to_sql(st.wallet().conn());
    Interrupted {
        account: name,
        owned: [&owned.a0, &owned.a1, &owned.last]
            .map(|script| hex::encode(script.as_slice()))
            .to_vec(),
        wallet_sql,
        companion_sql,
        notes,
    }
}

/// Restores `from` in `work`, reopens both databases as an application starts,
/// and resumes: the next pass exports the unacknowledged batch again, which is
/// applied and acknowledged, and one more pass finds nothing new. Returns both
/// databases after each step, and what each pass reported.
pub fn resume(from: &Interrupted, work: &std::path::Path) -> (Resumed, Vec<String>) {
    use api::backend::data_api::transparent_ledger::{TransparentLedgerMode::PrivateRequired, TransparentLedgerRead as _};

    std::fs::create_dir_all(work).unwrap();
    let wallet_path = work.join("wallet.sqlite");
    dump::restore(&from.wallet_sql, &wallet_path);
    let companions = api::recovery::CompanionDir::new(work.join("companions"));
    std::fs::create_dir_all(companions.path()).unwrap();
    let companion_path = companions.companion_path(&from.account, ORIGIN);
    dump::restore(&from.companion_sql, &companion_path);
    let account_id = uuid::Uuid::parse_str(&from.account).unwrap();

    let mut snapshots = Resumed::new();
    let mut notes = Vec::new();
    let mut snap = |step: &str| {
        snapshots.insert(format!("{step}/wallet"), dump::Snapshot::of_path(&wallet_path).digest());
        snapshots.insert(format!("{step}/companion"), dump::Snapshot::of_path(&companion_path).digest());
    };
    snap("restored");

    let mut db = api::sqlite::WalletDb::for_path(
        &wallet_path,
        api::backend::data_api::testing::TestBuilder::<(), ()>::DEFAULT_NETWORK,
        api::sqlite::util::testing::FixedClock::new(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_740_441_600)),
        api::backend::data_api::testing::TestRng::seed_from_u64(0),
    )
    .unwrap();
    api::sqlite::wallet::init::init_wallet_db(&mut db, None).unwrap();
    db.set_transparent_ledger_mode(PrivateRequired);
    let account = api::sqlite::AccountUuid::from_uuid(account_id);
    let mut companion = companions
        .open(
            &from.account,
            config(account_id.as_bytes(), 256),
            || Ok(std::collections::BTreeSet::from([from.account.clone()])),
            &|| false,
        )
        .unwrap();
    snap("reopened");

    let birthday = H0 + 250;
    let script = |n: usize| api::filter::ScriptBytes::new(hex::decode(&from.owned[n]).unwrap());
    let owned = Owned {
        a0: script(0),
        a1: script(1),
        last: script(2),
    };
    let dir = work.join("publication");
    api::fixture::service::publish(&dir, &publication(&owned, H0 + 660, 1), api::fixture::service::SEAL, |at| block_hash(&db, birthday, at), vec![]);
    let mut server = Server::start();
    let url = server.serve(&dir);
    for step in ["replayed", "settled"] {
        let watch = db.transparent_watch_set(account).unwrap();
        let report = {
            let chain = api::recovery::WalletChain::new(&db, watch.target.unwrap());
            companion
                .pass(&watch, &chain, &exchange(&url), RESPONSE_LIMIT, &|| false)
                .unwrap()
        };
        notes.push(format!("{step} pass: {report:?}"));
        let settled = match companion.take_latest::<api::sqlite::AccountUuid>() {
            Some(batch) => companion
                .apply_and_acknowledge_gated(batch, &mut db, api::recovery::Trust::Trusted, &mut api::recovery::Ungated)
                .map(|applied| Some(applied.stats)),
            None => companion
                .settle_latest(&mut db, api::recovery::Trust::Trusted, &mut api::recovery::Ungated)
                .map(|applied| applied.map(|applied| applied.stats)),
        };
        notes.push(format!("{step} settlement: {:?}", settled.map_err(|failure| failure.error.to_string())));
        snap(step);
    }
    drop(companion);
    (snapshots, notes)
}
