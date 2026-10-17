//! A wallet on one device: its own SQLite database over the shared chain, synced in
//! Vizor's order, recording how it found each payment.

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    panic::AssertUnwindSafe,
    path::{Path, PathBuf},
};

use orchard::keys::FullViewingKey;
use rusqlite::{Connection, OpenFlags};
use sapling::prover::mock::{MockOutputProver, MockSpendProver};
use secrecy::SecretVec;
use tempfile::NamedTempFile;
use zakura_near_intents::{NearStatus, near_observation};
use zakura_one_time_ivk::{KeyId, Purpose};
use zakura_one_time_ivk_scenarios::Class;
use zakura_pir_receiver::discover;
use zcash_client_backend::data_api::{
    AccountBirthday, TransactionStatus, WalletCommitmentTrees, WalletRead as _, WalletWrite as _,
    chain::{error::Error as ChainError, scan_cached_blocks_with_one_time_ivks},
    enhance_pir::{EnhancePirRead as _, EnhancementMode, TransactionEnhancementWork},
    one_time_ivk::{OneTimeIvkRead as _, restore::OneTimeIvkRestoreRead as _},
    scanning::ScanPriority,
    status::{TransactionStatusMode, TransactionStatusRead as _},
    testing::TestRng,
    transparent_ledger::TransparentLedgerMode,
    wallet::ConfirmationsPolicy,
    wallet::{
        SpendingKeys, create_proposed_transactions,
        decrypt_and_store_transaction_with_one_time_ivks,
        input_selection::{GreedyInputSelector, NoteSelection, SpendPolicy},
        propose_transfer,
    },
};
use zcash_client_backend::{
    fees::{DustOutputPolicy, StandardFeeRule, standard::SingleOutputChangeStrategy},
    wallet::OvkPolicy,
};
use zcash_client_sqlite::{
    AccountUuid, WalletDb,
    error::SqliteClientError,
    util::testing::FixedClock,
    wallet::{
        init::init_wallet_db,
        one_time_ivk::swap::{
            OperationOutcome, ProviderSeen, ReceiveDeposit, ReservationPolicy,
            verify_refund_funding_proposal,
        },
    },
};
use zcash_keys::{address::Address, keys::UnifiedSpendingKey};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::ShieldedPool;
use zcash_protocol::{consensus::BlockHeight, local_consensus::LocalNetwork, value::Zatoshis};

use super::{
    chain::{Chain, GENESIS, network, receiver_of},
    directory::{APP_STOPS, Directory, Fault, ORIGIN, Options, Served},
    near::{Near, Role},
};

type Wallet = WalletDb<Connection, LocalNetwork, FixedClock, TestRng>;

/// What a wallet operation was doing when it credited a payment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Scan,
    Recheck,
}

/// A payment a wallet credited, and how.
#[derive(Clone, Copy, Debug)]
pub struct Found {
    pub class: Class,
}

/// A ZEC-to-X swap a wallet quoted: its refund key and NEAR's deposit address.
#[derive(Clone, Debug)]
pub struct RefundSwap {
    pub index: u64,
    pub fvk: FullViewingKey,
    pub deposit: String,
}

impl RefundSwap {
    /// The report's name for its key.
    pub fn label(&self) -> String {
        format!("R{}", self.index)
    }
}

/// An incoming (X to ZEC) swap a wallet quoted.
#[derive(Clone, Debug)]
pub struct IncomingSwap {
    pub index: u64,
    pub fvk: FullViewingKey,
    pub deposit: ReceiveDeposit,
}

impl IncomingSwap {
    /// The report's name for its key.
    pub fn label(&self) -> String {
        format!("I{}", self.index)
    }
}

/// One key's stored state.
#[derive(Clone, Debug)]
pub struct KeyState {
    pub purpose: u8,
    pub index: u64,
    pub active_from: Option<u32>,
    pub closed_at: Option<i64>,
    pub used: bool,
}

impl KeyState {
    /// The report's name for the key.
    pub fn label(&self) -> String {
        key_label(self.purpose, self.index)
    }

    /// Whether the wallet trial-decrypts with it.
    pub fn open(&self) -> bool {
        self.active_from.is_some() && self.closed_at.is_none()
    }
}

/// A wallet's current record of one Ironwood output it received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    /// The height its transaction is mined at, as the wallet now knows it.
    pub mined_height: Option<u32>,
    /// Its note commitment tree position.
    pub position: Option<u64>,
    /// The value received, in zatoshis.
    pub value: u64,
    /// The one-time key that received it, labelled as the report labels keys.
    pub key: Option<String>,
    /// The nullifier that spends it, as the wallet derived it.
    pub nullifier: Option<[u8; 32]>,
}

/// A one-time key's directory lookup, as the wallet stored it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LookupState {
    /// Failed attempts so far.
    pub attempts: u32,
    /// Unix time before which the lookup is not due again.
    pub next_attempt_at: i64,
    /// The publication height the lookup finished through, if it did.
    pub done_height: Option<u32>,
}

/// The report's name for the one-time key with stored purpose code `purpose` (0 for
/// refund, 1 for incoming) and `index`, such as `R0` or `I3`.
fn key_label(purpose: u8, index: u64) -> String {
    format!("{}{index}", if purpose == 0 { "R" } else { "I" })
}

/// How a device's sync went.
#[derive(Clone, Debug, Default)]
pub struct SyncReport {
    pub found_live: usize,
    pub found_by_discovery: usize,
    pub lookups: usize,
    pub open_keys: usize,
    /// Blocks scanned, rescans included.
    pub scanned_blocks: u64,
    /// Whether discovery is incomplete or has lookups or late payments left after the sync.
    pub pending: bool,
    /// Why discovery failed keys or stopped, as the library reported it.
    pub problems: Vec<String>,
    /// Every directory request the sync made, as method and path, in order.
    pub requests: Vec<String>,
}

/// What a device can reach when it syncs.
#[derive(Clone, Debug)]
pub struct Reach {
    /// Whether the receiver directory answers.
    pub directory: bool,
    /// HTTP statuses the directory answers the first requests with.
    pub directory_faults: Vec<u16>,
    /// Failures of particular directory endpoints (see [`Fault`]).
    pub endpoint_faults: Vec<Fault>,
    /// How the publication differs from a faithful index.
    pub publication: Options,
}

impl Default for Reach {
    fn default() -> Self {
        Self {
            directory: true,
            directory_faults: Vec::new(),
            endpoint_faults: Vec::new(),
            publication: Options::default(),
        }
    }
}

/// A wallet on one device.
pub struct Device {
    pub name: String,
    db: Wallet,
    path: PathBuf,
    /// The wallet file, owned by the device's first account; another account's handle
    /// shares it (see [`Self::add_account`]).
    _file: Option<NamedTempFile>,
    pub account: AccountUuid,
    /// The wallet's other accounts, whose discovery each sync runs too.
    pub extra_accounts: Vec<AccountUuid>,
    /// Whether the directory's NEAR feed and seen sets are dated by the chain's clock,
    /// as a real directory's are, rather than by this device's.
    pub feed_clock: bool,
    /// Directory requests the current sync made so far.
    requests: Vec<String>,
    pub fvk: FullViewingKey,
    usk: UnifiedSpendingKey,
    skew: i64,
    /// The device's clock, which follows the chain; a restart reopens with it.
    clock: FixedClock,
    /// Times the app restarted, which seeds each reopened database's randomness.
    restarts: u64,
    /// Receivers of the one-time keys the harness derived from this account.
    derived: RefCell<BTreeSet<[u8; 43]>>,
    found: BTreeMap<([u8; 32], u32), Found>,
    phase: Phase,
    /// Outputs a directory lookup listed as payments, seen after each discovery run.
    candidates: BTreeSet<([u8; 32], u32)>,
    pub syncs: u32,
    /// Encrypted directory lookups across every discovery run.
    pub lookups: usize,
    /// Blocks scanned across every sync and scan.
    pub scanned_blocks: u64,
    /// Reorgs the wallet rewound for, as (conflict height, height rewound to).
    pub rewinds: Vec<(u32, u32)>,
    /// Directory request and response bytes across every discovery run.
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub reach: Reach,
}

impl Device {
    /// A wallet for `seed` whose account birthday is `birthday`, on a device whose clock
    /// runs `skew` seconds ahead of the chain.
    pub fn new(
        name: &str,
        chain: &mut Chain,
        seed: [u8; 32],
        birthday: BlockHeight,
        skew: i64,
    ) -> Self {
        let file = NamedTempFile::new().expect("a temporary wallet file");
        let path = file.path().to_path_buf();
        let clock = chain.clock(skew);
        let mut db = open(&path, &clock, 0);
        init_wallet_db(&mut db, Some(SecretVec::new(seed.to_vec()))).expect("the schema migrates");
        // Records every directory candidate, which the wallet deletes once it settles.
        Connection::open(&path)
            .and_then(|conn| {
                conn.execute_batch(
                    "CREATE TABLE harness_candidates (txid BLOB, action_index INTEGER,
                         PRIMARY KEY (txid, action_index));
                     CREATE TRIGGER harness_candidate AFTER INSERT
                         ON ironwood_one_time_payment_recovery BEGIN
                         INSERT OR IGNORE INTO harness_candidates
                             VALUES (NEW.txid, NEW.action_index);
                     END;",
                )
            })
            .expect("the harness records candidates");
        let birthday = AccountBirthday::from_parts(chain.state_below(birthday), None);
        let (account, usk) = db
            .create_account(name, &SecretVec::new(seed.to_vec()), &birthday, None)
            .expect("the account is created");
        Self {
            name: name.into(),
            db,
            path,
            _file: Some(file),
            account,
            extra_accounts: Vec::new(),
            feed_clock: false,
            requests: Vec::new(),
            fvk: FullViewingKey::from(usk.orchard()),
            usk,
            skew,
            clock,
            restarts: 0,
            derived: RefCell::new(BTreeSet::new()),
            found: BTreeMap::new(),
            phase: Phase::Scan,
            candidates: BTreeSet::new(),
            syncs: 0,
            lookups: 0,
            scanned_blocks: 0,
            rewinds: Vec::new(),
            bytes_sent: 0,
            bytes_received: 0,
            reach: Reach::default(),
        }
    }

    /// Adds the seed's next account to this wallet, with its birthday at `birthday`, and
    /// returns a handle to it named `name`. The handle shares this wallet's database; this
    /// device's syncs run its discovery, so the handle need not sync.
    pub fn add_account(
        &mut self,
        name: &str,
        chain: &Chain,
        seed: [u8; 32],
        birthday: BlockHeight,
    ) -> Self {
        let clock = self.clock.clone();
        let mut db = open(&self.path, &clock, 1_000 + self.extra_accounts.len() as u64);
        let birthday = AccountBirthday::from_parts(chain.state_below(birthday), None);
        let (account, usk) = db
            .create_account(name, &SecretVec::new(seed.to_vec()), &birthday, None)
            .expect("the account is created");
        self.extra_accounts.push(account);
        Self {
            name: name.into(),
            db,
            path: self.path.clone(),
            _file: None,
            account,
            extra_accounts: Vec::new(),
            feed_clock: self.feed_clock,
            requests: Vec::new(),
            fvk: FullViewingKey::from(usk.orchard()),
            usk,
            skew: self.skew,
            clock,
            restarts: 1_000,
            derived: RefCell::new(BTreeSet::new()),
            found: BTreeMap::new(),
            phase: Phase::Scan,
            candidates: BTreeSet::new(),
            syncs: 0,
            lookups: 0,
            scanned_blocks: 0,
            rewinds: Vec::new(),
            bytes_sent: 0,
            bytes_received: 0,
            reach: Reach::default(),
        }
    }

    /// Declares this account's seed fresh, as an app does for a seed it just generated
    /// (see `mark_one_time_account_fresh`).
    pub fn mark_fresh(&mut self) {
        self.db
            .mark_one_time_account_fresh(self.account)
            .expect("the account is marked fresh");
    }

    /// A read-only connection to the wallet file, for oracles.
    pub fn conn(&self) -> Connection {
        read_only(&self.path)
    }

    /// The account's discovery status at the device's time.
    pub fn discovery(
        &self,
        chain: &Chain,
        account: AccountUuid,
    ) -> Option<zcash_client_backend::data_api::one_time_ivk::restore::DiscoveryStatus> {
        self.db
            .one_time_discovery(account, self.now(chain))
            .expect("the discovery status")
    }

    /// The time the directory's feed is read at (see [`Self::feed_clock`]).
    fn feed_now(&self, chain: &Chain) -> i64 {
        if self.feed_clock {
            chain.now()
        } else {
            self.now(chain)
        }
    }

    /// Restarts the app, as after a crash: closes the wallet database and opens it again,
    /// as Vizor does at launch. Only what the database stored survives.
    pub fn reopen(&mut self) {
        self.restarts += 1;
        let mut db = open(&self.path, &self.clock, self.restarts);
        init_wallet_db(&mut db, None).expect("the schema is current");
        self.db = db;
    }

    /// The device's Unix time.
    pub fn now(&self, chain: &Chain) -> i64 {
        chain.now() + self.skew
    }

    /// The account's one-time key for `purpose` and `index`, whose receiver joins
    /// [`Self::derived_receivers`].
    pub fn key(&self, purpose: Purpose, index: u64) -> FullViewingKey {
        let fvk = KeyId::new(purpose, index)
            .derive(&self.fvk)
            .expect("the key derives");
        self.derived.borrow_mut().insert(receiver_of(&fvk));
        fvk
    }

    /// Receivers of every one-time key the harness derived from this account, which the
    /// harness knows independently of how the wallet labels its notes.
    pub fn derived_receivers(&self) -> BTreeSet<[u8; 43]> {
        self.derived.borrow().clone()
    }

    /// Syncs as Vizor does: discovery before the scan, so its lookups become scan hints,
    /// every suggested range, closing finished keys at the verified tip, then discovery
    /// again for the late path.
    pub fn sync(&mut self, chain: &Chain, near: &Near) -> SyncReport {
        self.syncs += 1;
        let mut report = SyncReport::default();
        self.requests.clear();
        self.db
            .update_chain_tip(chain.tip())
            .expect("the tip updates");
        let (before, mut problems) = self.discover(chain, near);
        report.scanned_blocks = self.scan(chain);
        let (after, late) = self.discover(chain, near);
        problems.extend(late);
        report.lookups = before + after;
        report.problems = problems;
        let (live, discovered) = self.tag();
        report.found_live = live;
        report.found_by_discovery = discovered;
        report.open_keys = self.keys().iter().filter(|k| k.open()).count();
        report.pending = self.history_pending();
        report.requests = std::mem::take(&mut self.requests);
        report
    }

    /// Whether the account's discovery is incomplete or has lookups or late payments left.
    pub fn history_pending(&self) -> bool {
        let status = self
            .db
            .one_time_discovery(self.account, i64::MAX)
            .expect("the discovery status");
        status.is_some_and(|s| !s.complete || !s.lookups.is_empty() || !s.witnesses.is_empty())
    }

    /// The scanning half of [`Self::sync`]. Returns the blocks it scanned.
    pub fn scan(&mut self, chain: &Chain) -> u64 {
        let mut scanned = 0u64;
        let account = self.account;
        let tip = chain.tip();
        self.db.update_chain_tip(tip).expect("the tip updates");
        loop {
            let next = self
                .db
                .suggest_scan_ranges()
                .expect("scan ranges")
                .into_iter()
                .find(|r| r.priority() > ScanPriority::Scanned);
            let Some(range) = next else {
                self.enhance(chain);
                let more = self
                    .db
                    .suggest_scan_ranges()
                    .expect("scan ranges")
                    .iter()
                    .any(|r| r.priority() > ScanPriority::Scanned);
                if more {
                    continue;
                }
                break;
            };
            let start = range.block_range().start;
            let len = u32::from(range.block_range().end) - u32::from(start);
            let batch = len.min(1_000);
            let scan = scan_cached_blocks_with_one_time_ivks(
                &network(),
                chain.block_source(),
                &mut self.db,
                start,
                &chain.state_below(start),
                batch as usize,
            );
            // A reorg: a block that does not chain to the scanned one, or, when a rescan
            // reaches a replaced block whose parent survived, a stored block with another
            // hash. Vizor treats both as a continuity break at that height.
            let conflict = match scan {
                Ok(_) => {
                    scanned += u64::from(batch);
                    None
                }
                Err(ChainError::Scan(e)) if e.is_continuity_error() => Some(e.at_height()),
                Err(ChainError::Wallet(SqliteClientError::BlockConflict(at))) => Some(at),
                Err(e) => panic!("blocks scan: {e:?}"),
            };
            if let Some(at) = conflict {
                // Rewind ten blocks below the conflict and scan again, as wallets do, but
                // not below the wallet's history: rewind as far as it allows. Near the
                // birthday the reported safe height itself can be refused, so step up.
                let mut target = at.saturating_sub(10);
                let to = loop {
                    match self.db.truncate_to_height(target) {
                        Ok(to) => break to,
                        Err(SqliteClientError::RequestedRewindInvalid {
                            safe_rewind_height: Some(safe),
                            ..
                        }) if target < at => {
                            target = if safe > target { safe } else { target + 1 };
                        }
                        Err(error) => panic!("the wallet rewinds: {error:?}"),
                    }
                };
                self.rewinds.push((u32::from(at), u32::from(to)));
                self.db.update_chain_tip(tip).expect("the tip updates");
            }
        }
        self.db
            .close_finished_one_time_keys(account, self.now(chain), tip)
            .expect("finished keys close");
        self.scanned_blocks += scanned;
        scanned
    }

    /// Serves the wallet's status and payload requests from the chain, as lightwalletd's
    /// GetTransaction would (Vizor routes the same obligations to Status and Enhance PIR
    /// under Private queries), until none it can serve remains.
    fn enhance(&mut self, chain: &Chain) {
        let status_work = self.db.transaction_status_work().expect("status work");
        for item in status_work {
            let txid = item.txid();
            self.db
                .set_transaction_status(txid, chain.status(&txid))
                .expect("the status records");
        }
        for _ in 0..4 {
            let work = self
                .db
                .transaction_enhancement_work()
                .expect("enhancement work");
            let mut served = 0;
            for item in work {
                let TransactionEnhancementWork::Public(request) = item else {
                    continue;
                };
                let Some((tx, height)) = chain.transaction(&request.txid()) else {
                    // GetTransaction's NotFound for a transaction a reorg removed. A fake
                    // output still on the chain has no raw form to serve, so it waits.
                    if let TransactionStatus::TxidNotRecognized = chain.status(&request.txid()) {
                        self.db
                            .set_transaction_status(
                                request.txid(),
                                TransactionStatus::TxidNotRecognized,
                            )
                            .expect("the status records");
                    }
                    continue;
                };
                decrypt_and_store_transaction_with_one_time_ivks(
                    &network(),
                    &mut self.db,
                    &tx,
                    Some(height),
                )
                .expect("the transaction decrypts and stores");
                served += 1;
            }
            if served == 0 {
                break;
            }
        }
    }

    /// Runs discovery once against a fresh publication, and returns the lookups made and why
    /// any key failed or the run stopped. A recheck's first run starts a new pass. An
    /// injected fault that stops the app ends discovery there, and the app restarts (see
    /// [`Self::reopen`]).
    pub fn discover(&mut self, chain: &Chain, near: &Near) -> (usize, Vec<String>) {
        let accounts: Vec<AccountUuid> = std::iter::once(self.account)
            .chain(self.extra_accounts.iter().copied())
            .collect();
        let (mut lookups, mut problems) = (0, Vec::new());
        for account in accounts {
            let (n, more, stopped) = self.discover_account(chain, near, account);
            lookups += n;
            problems.extend(more);
            if stopped {
                break;
            }
        }
        (lookups, problems)
    }

    /// Runs discovery once for `account` (see [`Self::discover`]), returning the lookups
    /// made, problems, and whether the app stopped.
    fn discover_account(
        &mut self,
        chain: &Chain,
        near: &Near,
        account: AccountUuid,
    ) -> (usize, Vec<String>, bool) {
        let now = self.now(chain);
        let feed_now = self.feed_now(chain);
        let reach = self.reach.clone();
        // Injected failures hit one discovery run only.
        self.reach.directory_faults.clear();
        self.reach.endpoint_faults.clear();
        let directory = Served::new(reach.directory, move || {
            let directory = Directory::publish(chain, near, feed_now, &reach.publication);
            directory.fail_next(&reach.directory_faults);
            directory.fail_at(&reach.endpoint_faults);
            directory
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let mut problems = Vec::new();
        let mut stopped = false;
        let run = std::panic::catch_unwind(AssertUnwindSafe(|| {
            runtime.block_on(discover(
                &mut self.db,
                &network(),
                account,
                GENESIS,
                ORIGIN,
                &directory,
                &NoLock,
                now,
            ))
        }));
        match run {
            Ok(Ok(found)) => {
                for (key, error) in &found.failed {
                    problems.push(format!(
                        "failed {key:?}: {error} ({})",
                        checkpoints(&self.path)
                    ));
                }
            }
            Ok(Err(error)) => problems.push(format!("discovery stopped: {error}")),
            Err(payload) if stops_the_app(payload.as_ref()) => {
                problems.push(format!("{APP_STOPS}; it restarts"));
                stopped = true;
            }
            Err(payload) => std::panic::resume_unwind(payload),
        }
        let lookups = directory.published().map_or(0, Directory::lookups);
        self.lookups += lookups;
        if let Some(published) = directory.published() {
            let (sent, received) = published.bytes();
            self.bytes_sent += sent;
            self.bytes_received += received;
            self.requests.extend(published.requests());
        }
        drop(directory);
        self.candidates.extend(candidates(&self.path));
        if stopped {
            self.reopen();
        }
        (lookups, problems, stopped)
    }

    /// "Check swap history": ends the account's discovery pass, so the next starts a new
    /// one against a newer publication, then syncs, crediting what it finds to the recheck.
    pub fn check_swap_history(&mut self, chain: &Chain, near: &Near) -> SyncReport {
        self.db
            .recheck_one_time_key_history(self.account)
            .expect("the recheck ends the pass");
        self.phase = Phase::Recheck;
        let report = self.sync(chain, near);
        self.phase = Phase::Scan;
        report
    }

    /// Starts "Check swap history" without syncing: ends the account's discovery pass, so
    /// the next sync starts a new one.
    pub fn begin_recheck(&mut self) {
        self.db
            .recheck_one_time_key_history(self.account)
            .expect("the recheck ends the pass");
    }

    /// Continues a "Check swap history" begun by [`Self::check_swap_history`]: one more
    /// sync whose finds count as the recheck's.
    pub fn continue_recheck(&mut self, chain: &Chain, near: &Near) -> SyncReport {
        self.phase = Phase::Recheck;
        let report = self.sync(chain, near);
        self.phase = Phase::Scan;
        report
    }

    /// Tags payments credited since the last tag: during a recheck as found after it,
    /// otherwise as found through discovery if a directory lookup listed it, whether the
    /// scan then found it from a hint or the late path admitted it, or as found live.
    /// Returns how many were found live and how many otherwise.
    fn tag(&mut self) -> (usize, usize) {
        let discovered = &self.candidates;
        let (mut live, mut other) = (0, 0);
        for (id, _) in credited(&self.path) {
            let class = if self.phase == Phase::Recheck {
                Class::FoundAfterRecheck
            } else if discovered.contains(&id) {
                Class::FoundByDiscovery
            } else {
                Class::FoundLive
            };
            self.found.entry(id).or_insert_with(|| {
                if class == Class::FoundLive {
                    live += 1;
                } else {
                    other += 1;
                }
                Found { class }
            });
        }
        (live, other)
    }

    /// How this wallet found the output `id`, if it did.
    pub fn found(&self, id: ([u8; 32], u32)) -> Option<Found> {
        self.found.get(&id).copied()
    }

    /// Reserves an incoming address against NEAR's current seen set, as Vizor does
    /// before a quote: the draft, or the next address issuance allows.
    pub fn prepare_incoming(
        &mut self,
        chain: &Chain,
        near: &Near,
    ) -> Result<u64, ReservationPolicy> {
        let now = self.now(chain);
        let feed_now = self.feed_now(chain);
        let contains =
            |receivers: &[[u8; 43]]| receivers.iter().map(|r| near.seen(r, feed_now)).collect();
        let seen = ProviderSeen {
            since: near.feed_started,
            until: near.read_until(feed_now),
            contains: &contains,
        };
        self.db
            .prepare_receive_reservation(self.account, now, chain.tip(), Some(&seen))
            .expect("reservation")
            .map(|key| key.key_id().index())
    }

    /// Saves a quote request for the reservation at `index` just before it leaves the
    /// device, returning its identity.
    pub fn begin_incoming(
        &mut self,
        chain: &Chain,
        index: u64,
        deadline_in: i64,
    ) -> Result<String, ReservationPolicy> {
        let now = self.now(chain);
        self.db
            .begin_receive_operation(self.account, index, now + deadline_in, now)
            .expect("the request is saved")
    }

    /// Records how a quote request ended.
    pub fn finish_incoming(&mut self, request: &str, outcome: &OperationOutcome) {
        self.db
            .finish_receive_operation(self.account, request, outcome)
            .expect("the outcome records");
    }

    /// Starts the accepted quote `request` at the device's own clock, returning the
    /// deposit instructions the store kept for it.
    pub fn start_incoming(
        &mut self,
        chain: &Chain,
        request: &str,
    ) -> Result<ReceiveDeposit, ReservationPolicy> {
        let now = self.now(chain);
        self.db
            .start_receive_operation(self.account, request, now)
            .expect("the operation starts")
    }

    /// The incoming index and receiver of the key the quote `request` was begun on, as
    /// the wallet stored them.
    pub fn request_receiver(&self, request: &str) -> Option<(u64, [u8; 43])> {
        let conn = read_only(&self.path);
        conn.query_row(
            "SELECT k.key_index, k.receiver FROM ironwood_one_time_operations o
             JOIN ironwood_one_time_keys k ON k.id = o.one_time_key_id
             WHERE o.request = ?1 AND k.purpose = 1",
            [request],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .ok()
        .map(|(index, receiver)| {
            (
                u64::from_be_bytes(index.try_into().expect("8-byte index")),
                receiver.try_into().expect("43-byte receiver"),
            )
        })
    }

    /// The wallet's current record of the Ironwood output `id`, if it holds it.
    pub fn receipt(&self, id: ([u8; 32], u32)) -> Option<Receipt> {
        let conn = read_only(&self.path);
        conn.query_row(
            "SELECT t.mined_height, n.commitment_tree_position, n.value, k.purpose, k.key_index,
                    n.nf
             FROM ironwood_received_notes n JOIN transactions t ON t.id_tx = n.transaction_id
             LEFT JOIN ironwood_one_time_keys k ON k.id = n.one_time_key_id
             WHERE t.txid = ?1 AND n.action_index = ?2",
            rusqlite::params![id.0.to_vec(), id.1],
            |row| {
                let key = match (
                    row.get::<_, Option<u8>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                ) {
                    (Some(purpose), Some(index)) => Some(key_label(
                        purpose,
                        u64::from_be_bytes(index.try_into().expect("8-byte index")),
                    )),
                    _ => None,
                };
                let nullifier = row.get::<_, Option<Vec<u8>>>(5)?;
                Ok(Receipt {
                    mined_height: row.get(0)?,
                    position: row.get(1)?,
                    value: row.get(2)?,
                    key,
                    nullifier: nullifier.map(|nf| nf.try_into().expect("32-byte nullifier")),
                })
            },
        )
        .ok()
    }

    /// The directory lookup of the one-time key `purpose`/`index`, if it has one.
    pub fn lookup_state(&self, purpose: Purpose, index: u64) -> Option<LookupState> {
        let conn = read_only(&self.path);
        // The stored purpose code, as in `key_label`.
        let code = u8::from(purpose == Purpose::Receive);
        conn.query_row(
            "SELECT s.attempts, s.next_attempt_at, s.done_height FROM ironwood_one_time_lookups s
             JOIN ironwood_one_time_keys k ON k.id = s.one_time_key_id
             WHERE k.purpose = ?1 AND k.key_index = ?2",
            rusqlite::params![code, index.to_be_bytes()],
            |row| {
                Ok(LookupState {
                    attempts: row.get(0)?,
                    next_attempt_at: row.get(1)?,
                    done_height: row.get(2)?,
                })
            },
        )
        .ok()
    }

    /// Notes the wallet holds from incoming key `index`, spent or not.
    pub fn incoming_receipts(&self, index: u64) -> usize {
        let conn = read_only(&self.path);
        conn.query_row(
            "SELECT COUNT(*) FROM ironwood_received_notes n
             JOIN ironwood_one_time_keys k ON k.id = n.one_time_key_id
             WHERE k.purpose = 1 AND k.key_index = ?1",
            [index.to_be_bytes()],
            |row| row.get(0),
        )
        .expect("a receipt count")
    }

    /// Quotes an X-to-ZEC swap: reserves an incoming address, saves the request before
    /// it leaves, records NEAR's acceptance and starts it.
    pub fn quote_incoming(
        &mut self,
        chain: &Chain,
        near: &mut Near,
        deadline_in: i64,
    ) -> Result<IncomingSwap, ReservationPolicy> {
        let index = self.prepare_incoming(chain, near)?;
        let request = self.begin_incoming(chain, index, deadline_in)?;
        let fvk = self.key(Purpose::Receive, index);
        near.give(receiver_of(&fvk), chain.now(), Role::Payout);
        // NEAR sets the accepted deadline by its own clock; the store keeps the earlier
        // of it and the one the device requested.
        let deposit = ReceiveDeposit {
            address: near.deposit_address(),
            memo: None,
            deadline: chain.now() + deadline_in,
        };
        self.finish_incoming(&request, &OperationOutcome::Accepted(deposit.clone()));
        self.start_incoming(chain, &request)?;
        Ok(IncomingSwap {
            index,
            fvk,
            deposit,
        })
    }

    /// Quotes a ZEC-to-X swap: reserves the next refund key and binds NEAR's deposit
    /// address to it, as Vizor does before showing the quote.
    pub fn quote_refund(
        &mut self,
        chain: &Chain,
        near: &mut Near,
        deadline_in: i64,
    ) -> Result<RefundSwap, ReservationPolicy> {
        let now = self.now(chain);
        let feed_now = self.feed_now(chain);
        let key = {
            let seen_near = &*near;
            let contains = |receivers: &[[u8; 43]]| {
                receivers
                    .iter()
                    .map(|r| seen_near.seen(r, feed_now))
                    .collect()
            };
            let seen = ProviderSeen {
                since: near.feed_started,
                until: near.read_until(feed_now),
                contains: &contains,
            };
            self.db
                .reserve_refund_key(self.account, chain.tip(), Some(&seen))
                .expect("refund reservation")?
        };
        let index = key.key_id().index();
        let deposit = near.zec_deposit_address();
        let deadline = now + deadline_in;
        self.db
            .record_refund_operation(self.account, index, &deposit, deadline, now)
            .expect("the refund operation records");
        let fvk = self.key(Purpose::Refund, index);
        near.give(receiver_of(&fvk), self.feed_now(chain), Role::Refund);
        Ok(RefundSwap {
            index,
            fvk,
            deposit,
        })
    }

    /// Builds and signs the transaction paying `amount` to the swap's deposit address from
    /// Ironwood notes, with the refund memo on its Ironwood change, checked as Vizor checks
    /// it. The wallet stores it as sent; the caller mines it.
    pub fn fund_refund(&mut self, swap: &RefundSwap, amount: u64) -> Transaction {
        let memo = self
            .db
            .refund_funding_memo(self.account, swap.index, &swap.deposit)
            .expect("the refund memo");
        let to = Address::decode(&network(), &swap.deposit)
            .expect("the deposit address decodes")
            .to_zcash_address(&network());
        let payment = zip321::Payment::new(
            to,
            Some(Zatoshis::const_from_u64(amount)),
            None,
            None,
            None,
            vec![],
        )
        .expect("a payment");
        let request = zip321::TransactionRequest::new(vec![payment]).expect("a request");
        let strategy = SingleOutputChangeStrategy::<Wallet>::new(
            StandardFeeRule::Zip317,
            Some(memo.clone()),
            ShieldedPool::Ironwood,
            DustOutputPolicy::default(),
        );
        let policy = SpendPolicy::shielded_pools([ShieldedPool::Ironwood])
            .with_note_selection(NoteSelection::PreferConsolidation);
        let proposal = propose_transfer::<_, _, _, _, <Wallet as WalletCommitmentTrees>::Error>(
            &mut self.db,
            &network(),
            self.account,
            &GreedyInputSelector::new(),
            &strategy,
            request,
            ConfirmationsPolicy::MIN,
            &policy,
            None,
            None,
        )
        .expect("the funding proposal");
        verify_refund_funding_proposal(&proposal, &memo, &swap.deposit)
            .expect("the funding proposal carries the refund memo");
        let txids = create_proposed_transactions::<
            _,
            _,
            std::convert::Infallible,
            _,
            std::convert::Infallible,
            _,
        >(
            &mut self.db,
            &network(),
            &MockSpendProver,
            &MockOutputProver,
            &SpendingKeys::from_unified_spending_key(self.usk.clone()),
            OvkPolicy::Sender,
            &proposal,
            None,
        )
        .expect("the funding transaction builds");
        self.db
            .get_transaction(*txids.first())
            .expect("the stored transaction")
            .expect("the wallet stored its transaction")
    }

    /// Builds and signs a transaction paying `value` to `to` from this wallet's Ironwood
    /// notes, with `ovk` (the zero OVK for NEAR's payouts). The wallet stores it as sent.
    pub fn send_to(&mut self, to: orchard::Address, value: u64, ovk: OvkPolicy) -> Transaction {
        let to = Address::Unified(
            zcash_keys::address::UnifiedAddress::from_receivers(Some(to), None, None)
                .expect("a unified address"),
        )
        .to_zcash_address(&network());
        let payment = zip321::Payment::new(
            to,
            Some(Zatoshis::const_from_u64(value)),
            None,
            None,
            None,
            vec![],
        )
        .expect("a payment");
        let request = zip321::TransactionRequest::new(vec![payment]).expect("a request");
        let strategy = SingleOutputChangeStrategy::<Wallet>::new(
            StandardFeeRule::Zip317,
            None,
            ShieldedPool::Ironwood,
            DustOutputPolicy::default(),
        );
        let policy = SpendPolicy::shielded_pools([ShieldedPool::Ironwood]);
        let proposal = propose_transfer::<_, _, _, _, <Wallet as WalletCommitmentTrees>::Error>(
            &mut self.db,
            &network(),
            self.account,
            &GreedyInputSelector::new(),
            &strategy,
            request,
            ConfirmationsPolicy::MIN,
            &policy,
            None,
            None,
        )
        .expect("the payment proposal");
        let txids = create_proposed_transactions::<
            _,
            _,
            std::convert::Infallible,
            _,
            std::convert::Infallible,
            _,
        >(
            &mut self.db,
            &network(),
            &MockSpendProver,
            &MockOutputProver,
            &SpendingKeys::from_unified_spending_key(self.usk.clone()),
            ovk,
            &proposal,
            None,
        )
        .expect("the payment builds");
        self.db
            .get_transaction(*txids.first())
            .expect("the stored transaction")
            .expect("the wallet stored its transaction")
    }

    /// Records a NEAR status for a refund swap, normalized by `zakura-near-intents`.
    pub fn observe_refund(
        &mut self,
        chain: &Chain,
        swap: &RefundSwap,
        status: &str,
        refunded: Option<u64>,
    ) -> bool {
        let observation = near_observation(
            Purpose::Refund,
            &NearStatus {
                status,
                swap_type: Some("EXACT_INPUT"),
                refunded_amount: refunded.map(Zatoshis::const_from_u64),
                amount_out: None,
            },
        );
        self.db
            .record_operation_status(
                self.account,
                &swap.deposit,
                None,
                observation,
                self.now(chain),
            )
            .expect("the status records")
    }

    /// Records a NEAR status for an incoming swap, normalized by `zakura-near-intents`
    /// as Vizor does. Returns whether it matched an operation.
    pub fn observe_incoming(
        &mut self,
        chain: &Chain,
        swap: &IncomingSwap,
        status: &str,
        amount_out: Option<u64>,
    ) -> bool {
        let observation = near_observation(
            Purpose::Receive,
            &NearStatus {
                status,
                swap_type: Some("EXACT_INPUT"),
                refunded_amount: None,
                amount_out: amount_out.map(Zatoshis::const_from_u64),
            },
        );
        self.db
            .record_operation_status(
                self.account,
                &swap.deposit.address,
                None,
                observation,
                self.now(chain),
            )
            .expect("the status records")
    }

    /// Stores a transaction seen in the mempool, as Vizor's mempool watcher does for one
    /// that pays the wallet, and credits what it finds to live scanning.
    pub fn receive_mempool(&mut self, tx: &Transaction) -> usize {
        decrypt_and_store_transaction_with_one_time_ivks(&network(), &mut self.db, tx, None)
            .expect("the mempool transaction stores");
        let (live, discovered) = self.tag();
        live + discovered
    }

    /// Sends `value` to `to` as an ordinary payment, selecting notes as Vizor does for
    /// ordinary sends (consolidating into spare input slots), and returns the transaction,
    /// or why the wallet could not build it.
    pub fn send_ordinary(
        &mut self,
        to: orchard::Address,
        value: u64,
    ) -> Result<Transaction, String> {
        let to = Address::Unified(
            zcash_keys::address::UnifiedAddress::from_receivers(Some(to), None, None)
                .expect("a unified address"),
        )
        .to_zcash_address(&network());
        let payment = zip321::Payment::new(
            to,
            Some(Zatoshis::const_from_u64(value)),
            None,
            None,
            None,
            vec![],
        )
        .expect("a payment");
        let request = zip321::TransactionRequest::new(vec![payment]).expect("a request");
        let strategy = SingleOutputChangeStrategy::<Wallet>::new(
            StandardFeeRule::Zip317,
            None,
            ShieldedPool::Ironwood,
            DustOutputPolicy::default(),
        );
        let policy = SpendPolicy::shielded_pools([ShieldedPool::Ironwood])
            .with_note_selection(NoteSelection::PreferConsolidation);
        let proposal = propose_transfer::<_, _, _, _, <Wallet as WalletCommitmentTrees>::Error>(
            &mut self.db,
            &network(),
            self.account,
            &GreedyInputSelector::new(),
            &strategy,
            request,
            ConfirmationsPolicy::MIN,
            &policy,
            None,
            None,
        )
        .map_err(|e| format!("no proposal: {e}"))?;
        let txids = create_proposed_transactions::<
            _,
            _,
            std::convert::Infallible,
            _,
            std::convert::Infallible,
            _,
        >(
            &mut self.db,
            &network(),
            &MockSpendProver,
            &MockOutputProver,
            &SpendingKeys::from_unified_spending_key(self.usk.clone()),
            OvkPolicy::Sender,
            &proposal,
            None,
        )
        .map_err(|e| format!("the transaction does not build: {e}"))?;
        Ok(self
            .db
            .get_transaction(*txids.first())
            .expect("the stored transaction")
            .expect("the wallet stored its transaction"))
    }

    /// Sends everything the wallet can spend now to `to`, less the fee, so the change
    /// output carries no value, and returns the transaction, or why it could not.
    pub fn send_max(&mut self, to: orchard::Address) -> Result<Transaction, String> {
        let to = Address::Unified(
            zcash_keys::address::UnifiedAddress::from_receivers(Some(to), None, None)
                .expect("a unified address"),
        )
        .to_zcash_address(&network());
        let proposal = zcash_client_backend::data_api::wallet::propose_send_max_transfer::<
            _,
            _,
            _,
            <Wallet as WalletCommitmentTrees>::Error,
        >(
            &mut self.db,
            &network(),
            self.account,
            &[ShieldedPool::Ironwood],
            &StandardFeeRule::Zip317,
            to,
            None,
            zcash_client_backend::data_api::MaxSpendMode::MaxSpendable,
            ConfirmationsPolicy::MIN,
            &zcash_client_backend::data_api::wallet::input_selection::LockedInputPolicy::Exclude,
            None,
        )
        .map_err(|e| format!("no proposal: {e}"))?;
        let txids = create_proposed_transactions::<
            _,
            _,
            std::convert::Infallible,
            _,
            std::convert::Infallible,
            _,
        >(
            &mut self.db,
            &network(),
            &MockSpendProver,
            &MockOutputProver,
            &SpendingKeys::from_unified_spending_key(self.usk.clone()),
            OvkPolicy::Sender,
            &proposal,
            None,
        )
        .map_err(|e| format!("the transaction does not build: {e}"))?;
        Ok(self
            .db
            .get_transaction(*txids.first())
            .expect("the stored transaction")
            .expect("the wallet stored its transaction"))
    }

    /// Unspent value the wallet holds in notes one-time keys received, in zatoshis: notes
    /// from mined transactions that no mined or unexpired transaction spends. A note from
    /// a transaction a reorg removed for good is not counted.
    pub fn unspent_one_time_value(&self) -> u64 {
        let conn = read_only(&self.path);
        conn.query_row(
            "SELECT COALESCE(SUM(n.value), 0) FROM ironwood_received_notes n
             JOIN transactions r ON r.id_tx = n.transaction_id
             WHERE n.one_time_key_id IS NOT NULL AND r.mined_height IS NOT NULL
               AND NOT EXISTS (SELECT 1 FROM ironwood_received_note_spends s
                               JOIN transactions t ON t.id_tx = s.transaction_id
                               WHERE s.ironwood_received_note_id = n.id
                                 AND (t.mined_height IS NOT NULL
                                      OR t.expiry_height = 0
                                      OR t.expiry_height > (SELECT MAX(height) FROM blocks)))",
            [],
            |r| r.get::<_, i64>(0),
        )
        .map(|v| u64::try_from(v).unwrap_or(0))
        .expect("one-time value")
    }

    /// Total balance, unconfirmed notes included, in zatoshis.
    pub fn balance(&self) -> u64 {
        self.db
            .get_wallet_summary(ConfirmationsPolicy::MIN)
            .expect("a summary")
            .map_or(0, |summary| {
                summary
                    .account_balances()
                    .get(&self.account)
                    .map_or(0, |b| b.total().into_u64())
            })
    }

    /// The balance the wallet can spend now, in zatoshis.
    pub fn spendable_balance(&self) -> u64 {
        self.db
            .get_wallet_summary(ConfirmationsPolicy::MIN)
            .expect("a summary")
            .map_or(0, |summary| {
                summary
                    .account_balances()
                    .get(&self.account)
                    .map_or(0, |b| b.spendable_value().into_u64())
            })
    }

    /// Every one-time key the wallet holds.
    pub fn keys(&self) -> Vec<KeyState> {
        let conn = read_only(&self.path);
        let mut stmt = conn
            .prepare(
                "SELECT purpose, key_index, active_from, closed_at, used
                 FROM ironwood_one_time_keys ORDER BY purpose, key_index",
            )
            .expect("a key query");
        stmt.query_map([], |row| {
            let index: Vec<u8> = row.get(1)?;
            Ok(KeyState {
                purpose: row.get(0)?,
                index: u64::from_be_bytes(index.try_into().expect("8-byte index")),
                active_from: row.get(2)?,
                closed_at: row.get(3)?,
                used: row.get(4)?,
            })
        })
        .expect("keys")
        .collect::<Result<_, _>>()
        .expect("keys decode")
    }

    /// Labels of the keys the wallet trial-decrypts with now.
    pub fn scanning(&self) -> Vec<String> {
        self.db
            .get_one_time_scanning_keys()
            .expect("scanning keys")
            .iter()
            .map(|k| {
                let id = k.key_id();
                let prefix = if id.purpose() == Purpose::Refund {
                    "R"
                } else {
                    "I"
                };
                format!("{prefix}{}", id.index())
            })
            .collect()
    }
}

impl Device {
    /// The wallet's stored view of a transaction, for diagnostics: mined height, expiry
    /// height, and whether a status request for it is queued.
    pub fn tx_view(&self, txid: [u8; 32]) -> String {
        let conn = read_only(&self.path);
        let row: Option<(Option<u32>, Option<u32>)> = conn
            .query_row(
                "SELECT mined_height, expiry_height FROM transactions WHERE txid = ?1",
                [txid.to_vec()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        let queued = self
            .db
            .transaction_status_work()
            .map(|work| work.iter().any(|w| *w.txid().as_ref() == txid))
            .unwrap_or(false);
        format!("stored {row:?} (mined_height, expiry_height), status queued {queued}")
    }
}

/// The outputs directory lookups listed as payments (see `harness_candidates`).
fn candidates(path: &Path) -> BTreeSet<([u8; 32], u32)> {
    let conn = read_only(path);
    let mut stmt = conn
        .prepare("SELECT txid, action_index FROM harness_candidates")
        .expect("a candidate query");
    stmt.query_map([], |row| {
        let txid: Vec<u8> = row.get(0)?;
        Ok((txid.try_into().expect("32-byte txid"), row.get(1)?))
    })
    .expect("candidates")
    .collect::<Result<_, _>>()
    .expect("candidates decode")
}

/// Every Ironwood output the wallet credited, with its value.
fn credited(path: &Path) -> Vec<(([u8; 32], u32), u64)> {
    let conn = read_only(path);
    let mut stmt = conn
        .prepare(
            "SELECT t.txid, n.action_index, n.value
             FROM ironwood_received_notes n JOIN transactions t ON t.id_tx = n.transaction_id",
        )
        .expect("a note query");
    stmt.query_map([], |row| {
        let txid: Vec<u8> = row.get(0)?;
        Ok((
            (txid.try_into().expect("32-byte txid"), row.get(1)?),
            row.get(2)?,
        ))
    })
    .expect("notes")
    .collect::<Result<_, _>>()
    .expect("notes decode")
}

/// The wallet's Ironwood tree checkpoints, as a range and count, for diagnostics.
fn checkpoints(path: &Path) -> String {
    let conn = read_only(path);
    conn.query_row(
        "SELECT MIN(checkpoint_id), MAX(checkpoint_id), COUNT(*) FROM ironwood_tree_checkpoints",
        [],
        |r| {
            Ok(format!(
                "Ironwood checkpoints {:?}..={:?} ({})",
                r.get::<_, Option<u32>>(0)?,
                r.get::<_, Option<u32>>(1)?,
                r.get::<_, u32>(2)?
            ))
        },
    )
    .unwrap_or_else(|e| format!("checkpoints unreadable: {e}"))
}

/// Opens the wallet file at `path` with randomness seeded from `seed`, serving payloads
/// over the public path, since the simulator serves raw transactions.
fn open(path: &Path, clock: &FixedClock, seed: u64) -> Wallet {
    let mut db = WalletDb::for_path(
        path,
        network(),
        clock.clone(),
        TestRng::seed_from_u64(7 + seed),
    )
    .expect("the wallet opens");
    db.set_enhancement_mode(EnhancementMode::Standard);
    db.set_transparent_ledger_mode(TransparentLedgerMode::Public);
    db.set_status_mode(TransactionStatusMode::Public);
    db
}

/// A read-only connection to a wallet file.
fn read_only(path: &Path) -> Connection {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("the wallet file opens")
}

/// Whether a panic's `payload` is an injected fault stopping the app (see [`APP_STOPS`]).
fn stops_the_app(payload: &(dyn std::any::Any + Send)) -> bool {
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied());
    message == Some(APP_STOPS)
}

/// Discovery's write lock. Nothing else writes to a scenario's wallet concurrently.
struct NoLock;

impl zakura_pir_receiver::WriteLock for NoLock {
    fn write<T>(&self, _: &'static str, write: impl FnOnce() -> T) -> T {
        write()
    }
}
