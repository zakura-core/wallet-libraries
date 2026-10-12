//! A wallet on one device: its own SQLite database over the shared chain, synced in
//! Vizor's order, recording how it found each payment.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use orchard::keys::FullViewingKey;
use rusqlite::{Connection, OpenFlags};
use secrecy::SecretVec;
use tempfile::NamedTempFile;
use zakura_near_intents::{NearStatus, near_observation};
use zakura_one_time_ivk::{KeyId, Purpose};
use zakura_one_time_ivk_scenarios::Class;
use zakura_pir_receiver::{Swept, sweep};
use zcash_client_backend::data_api::{
    AccountBirthday, WalletRead as _, WalletWrite as _,
    chain::scan_cached_blocks_with_one_time_ivks,
    one_time_ivk::{
        OneTimeIvkRead as _,
        restore::{OneTimeIvkRestoreRead as _, OneTimeIvkRestoreWrite as _},
    },
    scanning::ScanPriority,
    testing::TestRng,
    transparent_ledger::ChainPoint,
    wallet::ConfirmationsPolicy,
};
use zcash_client_sqlite::{
    AccountUuid, WalletDb,
    error::SqliteClientError,
    util::testing::FixedClock,
    wallet::{
        init::init_wallet_db,
        one_time_ivk::swap::{OperationOutcome, ProviderSeen, ReceiveDeposit, ReservationPolicy},
    },
};
use zcash_protocol::{consensus::BlockHeight, local_consensus::LocalNetwork, value::Zatoshis};

use super::{
    chain::{Chain, GENESIS, network, receiver_of},
    directory::{Directory, ORIGIN, Options, Served},
    near::{Near, Role},
};

type Wallet = WalletDb<Connection, LocalNetwork, FixedClock, TestRng>;

/// What a wallet operation was doing when it credited a payment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Scan,
    Sweep,
    Recheck,
}

/// A payment a wallet credited, and how.
#[derive(Clone, Copy, Debug)]
pub struct Found {
    pub class: Class,
    /// The wallet's sync count when it was found.
    pub sync: u32,
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
        format!("{}{}", if self.purpose == 0 { "R" } else { "I" }, self.index)
    }

    /// Whether the wallet trial-decrypts with it.
    pub fn open(&self) -> bool {
        self.active_from.is_some() && self.closed_at.is_none()
    }
}

/// How a device's sync went.
#[derive(Clone, Debug, Default)]
pub struct SyncReport {
    pub found_live: usize,
    pub found_by_sweep: usize,
    pub lookups: usize,
    pub sweeps_finished: usize,
    pub open_keys: usize,
    /// Blocks scanned, rescans and spend-history replays included.
    pub scanned_blocks: u64,
    /// Whether restore sweeps or queued payments remain after the sync.
    pub pending: bool,
    /// Why sweeps deferred keys or stopped, as the library reported it.
    pub problems: Vec<String>,
}

/// What a device can reach when it syncs.
#[derive(Clone, Debug)]
pub struct Reach {
    /// Whether the receiver directory answers.
    pub directory: bool,
    /// HTTP statuses the directory answers the first requests with.
    pub directory_faults: Vec<u16>,
    /// How the publication differs from a faithful index.
    pub publication: Options,
}

impl Default for Reach {
    fn default() -> Self {
        Self {
            directory: true,
            directory_faults: Vec::new(),
            publication: Options::default(),
        }
    }
}

/// A wallet on one device.
pub struct Device {
    pub name: String,
    db: Wallet,
    path: PathBuf,
    _file: NamedTempFile,
    pub account: AccountUuid,
    pub fvk: FullViewingKey,
    skew: i64,
    found: BTreeMap<([u8; 32], u32), Found>,
    phase: Phase,
    pub syncs: u32,
    /// Encrypted directory lookups across every sweep.
    pub lookups: usize,
    /// Sweep runs across every sync.
    pub sweep_runs: usize,
    /// Blocks scanned across every sync.
    pub scanned_blocks: u64,
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
        let mut db = WalletDb::for_path(&path, network(), chain.clock(skew), TestRng::seed_from_u64(7))
            .expect("the wallet opens");
        init_wallet_db(&mut db, Some(SecretVec::new(seed.to_vec()))).expect("the schema migrates");
        let birthday = AccountBirthday::from_parts(chain.state_below(birthday), None);
        let (account, usk) = db
            .create_account(name, &SecretVec::new(seed.to_vec()), &birthday, None)
            .expect("the account is created");
        Self {
            name: name.into(),
            db,
            path,
            _file: file,
            account,
            fvk: FullViewingKey::from(usk.orchard()),
            skew,
            found: BTreeMap::new(),
            phase: Phase::Scan,
            syncs: 0,
            lookups: 0,
            sweep_runs: 0,
            scanned_blocks: 0,
            reach: Reach::default(),
        }
    }

    /// The device's Unix time.
    pub fn now(&self, chain: &Chain) -> i64 {
        chain.now() + self.skew
    }

    /// The account's one-time key for `purpose` and `index`.
    pub fn key(&self, purpose: Purpose, index: u64) -> FullViewingKey {
        KeyId::new(purpose, index)
            .derive(&self.fvk)
            .expect("the key derives")
    }

    /// Syncs as Vizor does: recovery maintenance at the start, every suggested range,
    /// maintenance again at the tip (looping while it queues a rescan), closing finished
    /// keys at the verified tip, then the restore sweeps.
    pub fn sync(&mut self, chain: &Chain, near: &Near) -> SyncReport {
        self.syncs += 1;
        let mut report = SyncReport::default();
        let scan_phase = if self.phase == Phase::Recheck {
            Phase::Recheck
        } else {
            Phase::Scan
        };
        report.scanned_blocks = self.scan(chain);
        report.found_live = self.tag(scan_phase);
        let sweep_phase = if self.phase == Phase::Recheck {
            Phase::Recheck
        } else {
            Phase::Sweep
        };
        let (finished, lookups, problems) = self.sweep(chain, near);
        report.sweeps_finished = finished;
        report.lookups = lookups;
        report.problems = problems;
        report.found_by_sweep = self.tag(sweep_phase);
        report.open_keys = self.keys().iter().filter(|k| k.open()).count();
        report.pending = self.history_pending();
        self.scanned_blocks += report.scanned_blocks;
        report
    }

    /// Whether the account still has restore sweeps or queued payments.
    pub fn history_pending(&self) -> bool {
        let Some(through) = self.through() else {
            return false;
        };
        self.db
            .one_time_history_pending(self.account, through.height)
            .expect("pending history")
    }

    /// The scanning half of [`Self::sync`]. Returns the blocks it scanned.
    pub fn scan(&mut self, chain: &Chain) -> u64 {
        let mut scanned = 0u64;
        let account = self.account;
        self.db
            .maintain_one_time_ivks(account)
            .expect("maintenance at the sync start");
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
                self.db
                    .maintain_one_time_ivks(account)
                    .expect("maintenance at the tip");
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
            scan_cached_blocks_with_one_time_ivks(
                &network(),
                chain.block_source(),
                &mut self.db,
                start,
                &chain.state_below(start),
                batch as usize,
            )
            .expect("blocks scan");
            scanned += u64::from(batch);
        }
        self.db
            .close_finished_one_time_keys(account, self.now(chain), tip)
            .expect("finished keys close");
        scanned
    }

    /// Runs restore sweeps against a fresh publication until none is pending, at most
    /// 20 runs, and returns the keys finished, the lookups made, and why any key was
    /// deferred or a run stopped.
    pub fn sweep(&mut self, chain: &Chain, near: &Near) -> (usize, usize, Vec<String>) {
        let now = self.now(chain);
        let reach = self.reach.clone();
        let directory = Served::new(reach.directory, move || {
            let directory = Directory::publish(chain, near, now, &reach.publication);
            directory.fail_next(&reach.directory_faults);
            directory
        });
        let Some(through) = self.through() else {
            return (0, 0, Vec::new());
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let mut finished = 0;
        let mut problems = Vec::new();
        for _ in 0..20 {
            self.sweep_runs += 1;
            let swept: Result<Swept<SqliteClientError>, _> = runtime.block_on(sweep(
                &mut self.db,
                &network(),
                self.account,
                through.clone(),
                GENESIS,
                ORIGIN,
                &directory,
                &NoLock,
                now,
            ));
            match swept {
                Ok(swept) => {
                    finished += swept.finished;
                    for (key, error) in &swept.deferred {
                        problems.push(format!(
                            "deferred {key:?}: {error} (through {}, {})",
                            u32::from(through.height),
                            checkpoints(&self.path)
                        ));
                    }
                    if !swept.pending || !swept.deferred.is_empty() {
                        break;
                    }
                }
                Err(error) => {
                    problems.push(format!("sweep stopped: {error}"));
                    break;
                }
            }
        }
        let lookups = directory.published().map_or(0, Directory::lookups);
        self.lookups += lookups;
        (finished, lookups, problems)
    }

    /// "Check swap history": queues a sweep of every closed key, then syncs, crediting
    /// what it finds to the recheck. A late find can queue a spend-history replay and a
    /// finished sweep a rescan, which later syncs run, so this keeps syncing (the caller
    /// mines a block between syncs) while history is pending, at most `rounds` syncs.
    pub fn check_swap_history(&mut self, chain: &Chain, near: &Near) -> (usize, SyncReport) {
        let queued = self
            .db
            .recheck_one_time_key_history(self.account)
            .expect("the recheck queues");
        self.phase = Phase::Recheck;
        let report = self.sync(chain, near);
        self.phase = Phase::Scan;
        (queued, report)
    }

    /// Continues a "Check swap history" begun by [`Self::check_swap_history`]: one more
    /// sync whose finds count as the recheck's.
    pub fn continue_recheck(&mut self, chain: &Chain, near: &Near) -> SyncReport {
        self.phase = Phase::Recheck;
        let report = self.sync(chain, near);
        self.phase = Phase::Scan;
        report
    }

    /// The fully scanned tip, if the wallet has scanned anything.
    fn through(&self) -> Option<ChainPoint> {
        let block = self.db.block_fully_scanned().expect("a scanned tip")?;
        Some(ChainPoint {
            height: block.block_height(),
            hash: block.block_hash(),
        })
    }

    /// Tags payments credited since the last tag with `phase`, returning how many.
    fn tag(&mut self, phase: Phase) -> usize {
        let class = match phase {
            Phase::Scan => Class::FoundLive,
            Phase::Sweep => Class::FoundBySweep,
            Phase::Recheck => Class::FoundAfterRecheck,
        };
        let mut new = 0;
        for (id, _) in credited(&self.path) {
            self.found.entry(id).or_insert_with(|| {
                new += 1;
                Found {
                    class,
                    sync: self.syncs,
                }
            });
        }
        new
    }

    /// How this wallet found the output `id`, if it did.
    pub fn found(&self, id: ([u8; 32], u32)) -> Option<Found> {
        self.found.get(&id).copied()
    }

    /// Quotes an X-to-ZEC swap: reserves an incoming address against NEAR's current seen
    /// set, saves the request before it leaves, records NEAR's acceptance and starts it.
    pub fn quote_incoming(
        &mut self,
        chain: &Chain,
        near: &mut Near,
        deadline_in: i64,
    ) -> Result<IncomingSwap, ReservationPolicy> {
        let now = self.now(chain);
        let tip = chain.tip();
        let key = {
            let seen_near = &*near;
            let contains = |receivers: &[[u8; 43]]| {
                receivers.iter().map(|r| seen_near.seen(r, now)).collect()
            };
            let seen = ProviderSeen {
                since: near.feed_started,
                until: near.read_until(now),
                contains: &contains,
            };
            self.db
                .prepare_receive_reservation(self.account, now, tip, Some(&seen))
                .expect("reservation")?
        };
        let index = key.key_id().index();
        let deadline = now + deadline_in;
        let request = self
            .db
            .begin_receive_operation(self.account, index, deadline, now)
            .expect("the request is saved")?;
        let fvk = self.key(Purpose::Receive, index);
        near.give(receiver_of(&fvk), now, Role::Payout);
        let deposit = ReceiveDeposit {
            address: near.deposit_address(),
            memo: None,
            deadline,
        };
        self.db
            .finish_receive_operation(
                self.account,
                &request,
                &OperationOutcome::Accepted(deposit.clone()),
            )
            .expect("the outcome records");
        self.db
            .start_receive_operation(self.account, &request)
            .expect("the operation starts")?;
        Ok(IncomingSwap {
            index,
            fvk,
            deposit,
        })
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

    /// Every one-time key the wallet holds.
    pub fn keys(&self) -> Vec<KeyState> {
        let conn = read_only(&self.path);
        let mut stmt = conn
            .prepare(
                "SELECT purpose, key_index, active_from, closed_at, used
                 FROM ironwood_receiving_keys ORDER BY purpose, key_index",
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
                let prefix = if id.purpose() == Purpose::Refund { "R" } else { "I" };
                format!("{prefix}{}", id.index())
            })
            .collect()
    }
}

/// The Ironwood outputs a wallet holds, as (txid, action index) and value.
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

/// A read-only connection to a wallet file.
fn read_only(path: &Path) -> Connection {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).expect("the wallet file opens")
}

/// The sweep's write lock. Nothing else writes to a scenario's wallet concurrently.
struct NoLock;

impl zakura_pir_receiver::WriteLock for NoLock {
    fn write<T>(&self, _: &'static str, write: impl FnOnce() -> T) -> T {
        write()
    }
}
