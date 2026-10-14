//! Seeded, randomized scenarios. Each seed composes the harness's operations into one
//! plausible world: incoming and refund swaps on one or two devices of a seed, NEAR's
//! zero-OVK payouts and refunds at times around their deadlines, NEAR statuses in
//! plausible orders (stale and same-second ones included), offline periods, seed
//! restores, directory outages, a device clock that drifts, a reorg, Check swap history,
//! and the spend check.
//!
//! The suite's oracles judge it: each payment's class against what the documented
//! contract predicts, final balances, receipt heights and key attribution, address
//! reuse, and the spend check. The predicted classes come from [`Model`], a statement of
//! the documented lifecycle written from the library's documentation
//! (`close_finished_one_time_keys`, `record_operation_status`, `ProviderSeen`, the restore
//! sweep with its paid filter, `recheck_one_time_key_history`, and rewinds), evaluated
//! at every sync of every wallet. A disagreement is either a model bug or a library one;
//! checks named `model: ...` flag the model's own gaps.
//!
//! Seeds come from `ONE_TIME_IVK_FUZZ_SEEDS`, as `start..end` or one seed, so a failing
//! seed reruns exactly: `ONE_TIME_IVK_FUZZ_SEEDS=17 ... Z-fuzz-000017`.
//! `ONE_TIME_IVK_FUZZ_PROFILE` biases the worlds: `reorg` always reorgs, `devices` always
//! has a second device and a restore. Its name joins the scenario ID.
//!
//! Left out, because the harness or an oracle cannot express them faithfully: device
//! clock skew on a wallet that quotes alongside another device or sweeps another device's
//! keys (the harness dates NEAR's feed by each device's clock, where the real directory
//! dates it by its own); payouts reorged out for good (fake outputs have no transaction
//! to expire); statuses requested before an earlier response arrived (the harness
//! records statuses at the device's current time); app restarts during a sweep and
//! failures of one directory endpoint mid-lookup (the model covers only failures of a
//! whole sweep run); refund swaps on the second device (both devices would spend the
//! seed's shared notes); payers other than NEAR's zero OVK, and payouts seen in the
//! mempool; and the balance of a restore with a later birthday, which does not see the
//! funds and spends below it (its payments are still judged).

use std::collections::BTreeMap;

use orchard::keys::{FullViewingKey, SpendingKey};
use zakura_near_intents::{NearStatus, near_observation};
use zakura_one_time_ivk::{
    Purpose,
    swap::{COMPLETION_LIMIT_SECS, OperationStatus, RESTORE_WATCH_SECS, ReceiptExpectation},
};
use zakura_one_time_ivk_scenarios::{Class, zec};
use zcash_client_sqlite::wallet::one_time_ivk::swap::{RECEIVE_GAP_LIMIT, RECEIVE_RECLAIM_SECONDS};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::{consensus::BlockHeight, value::Zatoshis};

use super::{FUZZ, Scenario, Schedule, span};
use crate::harness::{
    Ctx, Dev,
    chain::{BLOCK_SECS, DAY, HOUR, MINUTE, Mined, Payer, ZEC, block_time},
    device::{IncomingSwap, RefundSwap, SyncReport},
};

const SEED: [u8; 32] = [0x7a; 32];
/// Seeds a run without `ONE_TIME_IVK_FUZZ_SEEDS` generates.
const DEFAULT_SEEDS: u64 = 2;
/// Ironwood funds wallet A holds for funding ZEC-to-X swaps.
const FUNDS: u64 = 5 * ZEC;
/// Confirmations a receipt needs before its key closes (the default untrusted policy).
const CONFIRMATIONS: u32 = 10;
/// How recent a status must be to reclaim a started reservation (`reservations.rs`).
const STATUS_FRESH_SECONDS: i64 = 120;
/// How old a recent set's last read may be and still rule a receiver out (the receiver
/// sweep's `RECENT_SET_MAX_AGE_SECS`).
const RECENT_SET_MAX_AGE_SECS: i64 = 15 * 60;
/// Due sweeps one run prepares (the receiver sweep's `BATCH`).
const SWEEP_BATCH: usize = 64;
/// Blocks past its first observation a transaction of unknown expiry stays pending.
const EXPIRY_DELTA: u32 = 40;
/// ZIP 317 fee of a refund funding with one Ironwood input, its change and the
/// transparent deposit.
const FUNDING_FEE: u64 = 15_000;

const A: usize = 0;
const A2: usize = 1;
const B1: usize = 2;
const B2: usize = 3;
const NAMES: [&str; 4] = ["A", "A2", "B1", "B2"];

pub fn all() -> Vec<Scenario> {
    let (start, end) = seeds();
    let mut scenarios = findings();
    scenarios.extend((start..end).map(scenario));
    scenarios
}

/// Minimal reproductions of what the randomized worlds found. Each fails until its issue
/// is fixed (the refund one is #198), so they run only with `ONE_TIME_IVK_FUZZ_FINDINGS=1`.
fn findings() -> Vec<Scenario> {
    if std::env::var_os("ONE_TIME_IVK_FUZZ_FINDINGS").is_none() {
        return Vec::new();
    }
    vec![refund_after_a_later_birthday()]
}

/// A funds a ZEC-to-X swap, then its device is lost. The seed is restored on B with a
/// birthday a few blocks after the funding, as a user who enters the day they restore
/// would. NEAR refunds the deposit after B's birthday. Control: an incoming payout to a
/// key quoted before the birthday and paid after it.
fn refund_after_a_later_birthday() -> Scenario {
    Scenario {
        id: "Z-finding-refund-funded-before-restore-birthday".into(),
        group: FUZZ,
        title: "A refund paid after the restore's birthday to a key funded before it".into(),
        summary: "A restore recovers refund keys only from funding memos it scans, and it scans \
            from its birthday. When the birthday falls after the funding but before NEAR's \
            refund, the refund is a note after the birthday that the restored wallet should \
            track. Checks whether it is found, and whether Check swap history finds it."
            .into(),
        params: vec![("birthday".into(), "5 blocks after the funding".into())],
        slow: false,
        run: Box::new(|ctx| {
            ctx.mine(20);
            let birthday = ctx.chain.tip() + 1;
            ctx.mine(5);
            let a = ctx.device("A", SEED, birthday);
            let fvk = ctx.get(a).fvk.clone();
            ctx.pay(
                "A's Ironwood funds",
                "A's address",
                &fvk,
                3 * ZEC,
                Payer::Wallet,
            );
            ctx.mine(10);
            ctx.sync(a);
            let swap = ctx.quote_refund(a, HOUR).expect("a refund key");
            let incoming = ctx.quote_incoming(a, HOUR).expect("an incoming quote");
            let (funded_at, _) = ctx.fund_refund(a, &swap, ZEC);
            ctx.mine(5);
            ctx.sync(a);
            ctx.observe_refund(a, &swap, "PROCESSING", None);
            ctx.log("A", "the device is lost");
            ctx.mine(4);
            let b = ctx.device("B", SEED, funded_at + 5);
            ctx.sync(b);
            ctx.sync(b);
            ctx.wait(30 * MINUTE);
            let refund = ctx.pay(
                "refund",
                &swap.label(),
                &swap.fvk,
                ZEC - 10_000,
                Payer::Near,
            );
            let payout = ctx.pay(
                "payout",
                &incoming.label(),
                &incoming.fvk,
                ZEC / 2,
                Payer::Near,
            );
            ctx.mine(1);
            ctx.sync(b);
            ctx.wait(DAY);
            ctx.sync(b);
            ctx.sync(b);
            let found = ctx.get(b).found(refund.id()).is_some();
            ctx.check_swap_history(b);
            let after = ctx.get(b).found(refund.id()).is_some();
            let keys: Vec<String> = ctx.get(b).keys().iter().map(|k| k.label()).collect();
            ctx.check(
                format!(
                    "B holds the refund to {} after Check swap history",
                    swap.label()
                ),
                after,
                format!("found before the recheck: {found}; B's keys {keys:?}"),
            );
            ctx.expect(
                b,
                "refund",
                &swap.label(),
                &refund,
                Class::FoundAutomatically,
                "The refund is a note after B's birthday. A restore recovers refund keys from funding memos; no documented rule leaves a note after the birthday unfound.",
            );
            ctx.expect(
                b,
                "payout",
                &incoming.label(),
                &payout,
                Class::FoundAutomatically,
                "A restore sweeps the incoming lookahead through the receiver directory.",
            );
        }),
    }
}

/// The seeds `ONE_TIME_IVK_FUZZ_SEEDS` names, as `start..end` or one seed.
fn seeds() -> (u64, u64) {
    let Ok(spec) = std::env::var("ONE_TIME_IVK_FUZZ_SEEDS") else {
        return (0, DEFAULT_SEEDS);
    };
    let parse = |s: &str| {
        s.trim()
            .parse::<u64>()
            .expect("ONE_TIME_IVK_FUZZ_SEEDS holds seeds")
    };
    match spec.split_once("..") {
        Some((a, b)) => (parse(a), parse(b)),
        None => {
            let seed = parse(&spec);
            (seed, seed + 1)
        }
    }
}

/// How `ONE_TIME_IVK_FUZZ_PROFILE` biases the generated worlds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile {
    Default,
    /// Every world reorgs, most aimed past a payout's tenth confirmation.
    Reorg,
    /// Every world has a second device and a restore, and devices quote together.
    Devices,
}

/// The profile `ONE_TIME_IVK_FUZZ_PROFILE` names.
fn profile() -> Profile {
    match std::env::var("ONE_TIME_IVK_FUZZ_PROFILE").as_deref() {
        Ok("reorg") => Profile::Reorg,
        Ok("devices") => Profile::Devices,
        Ok("") | Err(_) => Profile::Default,
        Ok(other) => panic!("unknown ONE_TIME_IVK_FUZZ_PROFILE {other}"),
    }
}

/// The scenario seed `seed` generates.
fn scenario(seed: u64) -> Scenario {
    let profile = profile();
    let plan = Plan::generate(seed, profile);
    let name = match profile {
        Profile::Default => String::new(),
        Profile::Reorg => "reorg-".into(),
        Profile::Devices => "devices-".into(),
    };
    Scenario {
        id: format!("Z-fuzz-{name}{seed:06}"),
        group: FUZZ,
        title: format!("Randomized world, seed {seed}"),
        summary: plan.notes.join("; "),
        params: plan.params(),
        slow: plan.end > 3 * DAY,
        run: Box::new(move |ctx| Exec::run(&plan, ctx)),
    }
}

/// A deterministic 64-bit generator (SplitMix64) seeded from the scenario seed, so a
/// seed always builds the same plan.
struct Rng(u64);

impl Rng {
    /// The generator for `seed`.
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xD1B5_4A32_D192_ED03)
    }

    /// The next 64 random bits.
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A uniform value in `lo..hi`, or `lo` when the range is empty.
    fn range(&mut self, lo: i64, hi: i64) -> i64 {
        if hi <= lo {
            lo
        } else {
            lo + (self.next() % (hi - lo) as u64) as i64
        }
    }

    /// True with probability `percent` in 100.
    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }

    /// One of `items`, uniformly.
    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[(self.next() % items.len() as u64) as usize]
    }

    /// One of `items`, drawn with the paired weights.
    fn weighted<T: Copy>(&mut self, items: &[(T, u64)]) -> T {
        let total: u64 = items.iter().map(|(_, w)| w).sum();
        let mut roll = self.next() % total;
        for (item, weight) in items {
            if roll < *weight {
                return *item;
            }
            roll -= weight;
        }
        items[items.len() - 1].0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Incoming,
    Refund,
}

/// How a ZEC-to-X swap's deposit is funded.
#[derive(Clone, Copy, Debug)]
enum Deposit {
    Amount(u64),
    /// Everything wallet A holds less the fee, so the refund memo rides on zero-value
    /// change.
    ZeroChange,
}

/// One planned swap.
#[derive(Clone, Debug)]
struct SwapPlan {
    kind: Kind,
    slot: usize,
    deadline_in: i64,
    deposit: Option<Deposit>,
}

/// One planned action, at a time relative to the scenario start.
#[derive(Clone, Debug)]
enum Step {
    Sync(usize),
    /// A seed restore on a new device, its directory possibly down for a while or
    /// answering errors at its first sync.
    Restore {
        slot: usize,
        down: bool,
        fault: Option<u16>,
        /// The restore's birthday, as a percentage of the way from A's birthday to the
        /// tip, for a user who enters a later date; `None` restores from A's birthday.
        late_birthday: Option<u32>,
    },
    Quote(usize),
    Fund(usize),
    Status {
        swap: usize,
        status: &'static str,
        amount: Option<u64>,
    },
    /// One NEAR transaction paying each (swap, value).
    Pay(Vec<(usize, u64)>),
    Directory {
        slot: usize,
        up: bool,
    },
    /// The directory answers the wallet's next requests with this HTTP status, for its
    /// next sync.
    Fault {
        slot: usize,
        status: u16,
    },
    Reorg {
        depth: u32,
        tail: u32,
    },
    Recheck(usize),
    /// The app restarts and reopens its wallet database.
    Restart(usize),
}

/// A generated world.
#[derive(Clone, Debug)]
struct Plan {
    seed: u64,
    skew: i64,
    a2: bool,
    restores: usize,
    read_lag: i64,
    funds: bool,
    /// NEAR pays with signed transactions, which a reorg can return to the chain.
    real_payouts: bool,
    swaps: Vec<SwapPlan>,
    steps: Vec<(i64, Step)>,
    end: i64,
    final_rechecks: Vec<usize>,
    spend: bool,
    notes: Vec<String>,
}

impl Plan {
    /// The world seed `seed` generates.
    fn generate(seed: u64, profile: Profile) -> Self {
        let mut r = Rng::new(seed);
        let horizon = r.weighted(&[
            (6 * HOUR, 30),
            (2 * DAY, 35),
            (8 * DAY, 20),
            (35 * DAY, 10),
            (45 * DAY, 5),
        ]);
        let skew = if r.chance(20) {
            r.pick(&[5 * MINUTE, 2 * HOUR, 5 * DAY, -2 * HOUR, -2 * DAY])
        } else {
            0
        };
        let a2 = skew == 0 && (profile == Profile::Devices || r.chance(30));
        let read_lag = r.weighted(&[(MINUTE, 85), (30 * MINUTE, 10), (6 * HOUR, 5)]);
        let restores = if profile == Profile::Devices {
            r.weighted(&[(1usize, 60), (2, 40)])
        } else {
            r.weighted(&[(0usize, 35), (1, 50), (2, 15)])
        };
        let reorg = profile == Profile::Reorg || r.chance(15);
        let together = if profile == Profile::Devices { 60 } else { 20 };
        let restore_quotes = if profile == Profile::Devices { 60 } else { 30 };
        let count = r.weighted(&[(1usize, 15), (2, 30), (3, 30), (4, 25)]);
        let zero_change = r.chance(8);
        let mut s = Schedule::new();
        let mut swaps = Vec::new();
        let mut notes = vec![format!("horizon {}", span(horizon))];
        if skew != 0 {
            notes.push(format!(
                "A's clock {}{}",
                if skew > 0 { "+" } else { "-" },
                span(skew.abs())
            ));
        }
        if read_lag != MINUTE {
            notes.push(format!("NEAR feed {} behind", span(read_lag)));
        }
        // (time, outputs, joinable)
        let mut payouts: Vec<(i64, Vec<(usize, u64)>, bool)> = Vec::new();
        let mut quote_times = Vec::new();
        for i in 0..count {
            let refund = if zero_change { i == 0 } else { r.chance(30) };
            let quote_at = if zero_change && i == 0 {
                10 * MINUTE
            } else if zero_change {
                r.range(30 * MINUTE, horizon * 6 / 10)
            } else if i == 0 {
                r.range(10 * MINUTE, 2 * HOUR)
            } else {
                r.range(10 * MINUTE, horizon * 6 / 10)
            };
            let id = swaps.len();
            quote_times.push(quote_at);
            if refund {
                let deadline_in = r.pick(&[20 * MINUTE, HOUR, 3 * HOUR]);
                let deposit = if zero_change {
                    Some(Deposit::ZeroChange)
                } else if r.chance(90) {
                    Some(Deposit::Amount(r.pick(&[ZEC / 5, ZEC / 2, ZEC])))
                } else {
                    None
                };
                swaps.push(SwapPlan {
                    kind: Kind::Refund,
                    slot: A,
                    deadline_in,
                    deposit,
                });
                let note = plan_refund(&mut r, &mut s, &mut payouts, id, quote_at, deposit);
                notes.push(format!(
                    "R-swap {id} on A at +{}: {note}",
                    span_of(quote_at)
                ));
            } else {
                let slot = if a2 && r.chance(40) { A2 } else { A };
                let deadline_in = r.pick(&[20 * MINUTE, HOUR, 3 * HOUR, DAY]);
                swaps.push(SwapPlan {
                    kind: Kind::Incoming,
                    slot,
                    deadline_in,
                    deposit: None,
                });
                let note = plan_incoming(&mut r, &mut s, &mut payouts, id, quote_at, deadline_in);
                notes.push(format!(
                    "I-swap {id} on {} at +{}, deadline {}: {note}",
                    NAMES[slot],
                    span_of(quote_at),
                    span(deadline_in)
                ));
            }
        }
        // A2 quotes in the same second as one of A's incoming quotes, inside NEAR's
        // feed lag, so both can give NEAR one address.
        if a2 && r.chance(together) {
            let first = swaps
                .iter()
                .position(|sp| sp.kind == Kind::Incoming && sp.slot == A);
            let quoted = first.map(|i| quote_times[i]);
            if let Some(quote_at) = quoted {
                let id = swaps.len();
                let deadline_in = r.pick(&[20 * MINUTE, HOUR, 3 * HOUR, DAY]);
                swaps.push(SwapPlan {
                    kind: Kind::Incoming,
                    slot: A2,
                    deadline_in,
                    deposit: None,
                });
                let note = plan_incoming(&mut r, &mut s, &mut payouts, id, quote_at, deadline_in);
                notes.push(format!(
                    "I-swap {id} on A2 in the same second as A's, deadline {}: {note}",
                    span(deadline_in)
                ));
            }
        }
        // Seed restores, sometimes a block or two after a payout.
        let mut restore_at = Vec::new();
        for k in 0..restores {
            let slot = B1 + k;
            let at = if !payouts.is_empty() && r.chance(20) {
                let i = r.range(0, payouts.len() as i64) as usize;
                payouts[i].0 + r.pick(&[BLOCK_SECS, 2 * BLOCK_SECS, 3 * BLOCK_SECS])
            } else {
                r.range(20 * MINUTE, horizon)
            };
            let (down, fault) = if r.chance(25) {
                if r.chance(50) {
                    (true, None)
                } else {
                    (false, Some(r.pick(&[503u16, 429, 410])))
                }
            } else {
                (false, None)
            };
            let late_birthday = r.chance(15).then(|| r.range(10, 95) as u32);
            s.at(
                at,
                Step::Restore {
                    slot,
                    down,
                    fault,
                    late_birthday,
                },
            );
            if let Some(pct) = late_birthday {
                notes.push(format!(
                    "{} restores with a birthday {pct}% of the way from A's to the tip",
                    NAMES[slot]
                ));
            }
            if down {
                let len = r.range(10 * MINUTE, 6 * HOUR);
                s.at(at + len, Step::Directory { slot, up: true });
                notes.push(format!(
                    "{} restores at +{}, directory down for {}",
                    NAMES[slot],
                    span_of(at),
                    span_of(len)
                ));
            } else if let Some(status) = fault {
                notes.push(format!(
                    "{} restores at +{}, directory answers {status} at first",
                    NAMES[slot],
                    span_of(at)
                ));
            } else {
                notes.push(format!("{} restores at +{}", NAMES[slot], span_of(at)));
            }
            restore_at.push((slot, at));
        }
        // A restored device sometimes quotes an incoming swap of its own.
        if skew == 0 && !restore_at.is_empty() && r.chance(restore_quotes) {
            let (slot, at) = restore_at[0];
            let quote_at = at + r.range(30 * MINUTE, 3 * HOUR);
            let id = swaps.len();
            swaps.push(SwapPlan {
                kind: Kind::Incoming,
                slot,
                deadline_in: HOUR,
                deposit: None,
            });
            let v = r.pick(&[ZEC / 4, ZEC]);
            s.at(
                quote_at + 10 * MINUTE,
                Step::Status {
                    swap: id,
                    status: "KNOWN_DEPOSIT_TX",
                    amount: None,
                },
            );
            payouts.push((quote_at + 20 * MINUTE, vec![(id, v)], true));
            s.at(
                quote_at + 21 * MINUTE,
                Step::Status {
                    swap: id,
                    status: "SUCCESS",
                    amount: Some(v),
                },
            );
            s.at(quote_at, Step::Quote(id));
            notes.push(format!(
                "I-swap {id} on {} at +{}: paid {} 20m later",
                NAMES[slot],
                span_of(quote_at),
                zec(v)
            ));
        }
        // NEAR sometimes batches two swaps' payouts into one transaction.
        if !reorg && r.chance(15) {
            let joinable: Vec<usize> = (0..payouts.len())
                .filter(|&i| payouts[i].2 && payouts[i].1.len() == 1)
                .collect();
            if joinable.len() >= 2 {
                let (i, j) = (joinable[0], joinable[1]);
                let (ti, tj) = (payouts[i].0, payouts[j].0);
                let other = payouts[j].1[0];
                if payouts[i].1[0].0 != other.0 {
                    payouts[i].0 = ti.max(tj);
                    payouts[i].1.push(other);
                    payouts.remove(j);
                    notes.push(format!(
                        "NEAR pays swaps {} and {} in one transaction",
                        payouts[i].1[0].0, other.0
                    ));
                }
            }
        }
        // A reorg aimed just past a payout's tenth confirmation, after the paid wallet
        // synced, so it can un-mine a receipt whose key just closed.
        let aim = if profile == Profile::Reorg { 80 } else { 60 };
        let aimed = (reorg && !payouts.is_empty() && r.chance(aim)).then(|| {
            let i = r.range(0, payouts.len() as i64) as usize;
            let (at, outs, _) = &payouts[i];
            let paid = swaps[outs[0].0].slot;
            let k = r.range(11, 19);
            let depth = (k + r.range(-2, 4)).max(2) as u32;
            s.at(at + 11 * BLOCK_SECS + 30, Step::Sync(paid));
            (at + k * BLOCK_SECS, depth)
        });
        let mut last = horizon;
        for (at, outs, _) in payouts {
            last = last.max(at);
            if reorg && outs.len() > 1 {
                // Signed payouts carry one output each.
                for (k, out) in outs.into_iter().enumerate() {
                    s.at(at + k as i64 * BLOCK_SECS, Step::Pay(vec![out]));
                }
            } else {
                s.at(at, Step::Pay(outs));
            }
        }
        let end = last + 2 * HOUR;
        // Syncs, with offline periods.
        sync_steps(&mut r, &mut s, A, 0, end, horizon, &mut notes);
        if a2 {
            sync_steps(&mut r, &mut s, A2, 0, end, horizon, &mut notes);
        }
        for &(slot, at) in &restore_at {
            sync_steps(
                &mut r,
                &mut s,
                slot,
                at + 10 * MINUTE,
                end,
                horizon,
                &mut notes,
            );
        }
        if r.chance(10) {
            let at = r.range(HOUR, horizon);
            let status = r.pick(&[503u16, 429, 410]);
            s.at(at, Step::Fault { slot: A, status });
            notes.push(format!(
                "A's directory answers {status} at +{}",
                span_of(at)
            ));
        }
        if r.chance(10) {
            let at = r.range(HOUR, horizon);
            let len = r.range(10 * MINUTE, 6 * HOUR);
            s.at(at, Step::Directory { slot: A, up: false });
            s.at(at + len, Step::Directory { slot: A, up: true });
            notes.push(format!(
                "A's directory down at +{} for {}",
                span_of(at),
                span_of(len)
            ));
        }
        if reorg {
            let (at, depth) = aimed.unwrap_or_else(|| {
                (
                    r.range(horizon * 15 / 100, horizon * 85 / 100).max(HOUR),
                    r.pick(&[2u32, 4, 7, 9, 10, 11, 12, 14, 18, 25]),
                )
            });
            let tail = r.range(0, 6) as u32;
            s.at(at, Step::Reorg { depth, tail });
            notes.push(format!(
                "{depth}-block reorg at +{}{}",
                span_of(at),
                if aimed.is_some() {
                    ", aimed past a payout's tenth confirmation"
                } else {
                    ""
                }
            ));
        }
        if r.chance(10) {
            let at = r.range(HOUR, horizon);
            s.at(at, Step::Restart(A));
            notes.push(format!("A's app restarts at +{}", span_of(at)));
        }
        if r.chance(10) {
            let at = r.range(horizon / 2, horizon);
            let slot = restore_at
                .iter()
                .find(|(_, t)| *t < at)
                .filter(|_| r.chance(40))
                .map_or(A, |(slot, _)| *slot);
            s.at(at, Step::Recheck(slot));
            notes.push(format!(
                "{} runs Check swap history at +{}",
                NAMES[slot],
                span_of(at)
            ));
        }
        let mut final_rechecks = Vec::new();
        for (slot, p) in [(A, 40), (A2, 30), (B1, 30), (B2, 30)] {
            let exists = match slot {
                A => true,
                A2 => a2,
                _ => restore_at.iter().any(|(s, _)| *s == slot),
            };
            if exists && r.chance(p) {
                final_rechecks.push(slot);
            }
        }
        if !final_rechecks.is_empty() {
            let names: Vec<_> = final_rechecks.iter().map(|s| NAMES[*s]).collect();
            notes.push(format!(
                "at the end {} run Check swap history",
                names.join(", ")
            ));
        }
        let spend = r.chance(40);
        let funds = swaps.iter().any(|s| s.kind == Kind::Refund);
        Self {
            seed,
            skew,
            a2,
            restores,
            read_lag,
            funds,
            real_payouts: reorg,
            swaps,
            steps: s.into_steps(),
            end,
            final_rechecks,
            spend,
            notes,
        }
    }

    /// The report's parameters.
    fn params(&self) -> Vec<(String, String)> {
        vec![
            ("seed".into(), self.seed.to_string()),
            ("swaps".into(), self.swaps.len().to_string()),
            ("second device".into(), self.a2.to_string()),
            ("restores".into(), self.restores.to_string()),
            ("A clock skew".into(), format!("{} s", self.skew)),
            ("feed read lag".into(), span(self.read_lag)),
            ("reorg".into(), self.real_payouts.to_string()),
            ("ends after".into(), span_of(self.end)),
        ]
    }
}

/// `secs` as the report names gaps, for any number of seconds.
fn span_of(secs: i64) -> String {
    if secs >= DAY {
        format!("{:.1}d", secs as f64 / DAY as f64)
    } else if secs >= HOUR {
        format!("{:.1}h", secs as f64 / HOUR as f64)
    } else {
        format!("{}m", secs / MINUTE)
    }
}

/// Plans an incoming swap quoted at `quote_at`: NEAR's payouts and statuses.
fn plan_incoming(
    r: &mut Rng,
    s: &mut Schedule<Step>,
    payouts: &mut Vec<(i64, Vec<(usize, u64)>, bool)>,
    id: usize,
    quote_at: i64,
    deadline_in: i64,
) -> String {
    s.at(quote_at, Step::Quote(id));
    let deadline = quote_at + deadline_in;
    let status = |s: &mut Schedule<Step>, at: i64, status: &'static str, amount: Option<u64>| {
        s.at(
            at,
            Step::Status {
                swap: id,
                status,
                amount,
            },
        )
    };
    if r.chance(25) {
        // Unpaid: the user never deposits, or NEAR refunds the deposit on its chain.
        let mode = r.weighted(&[(0, 40), (1, 30), (2, 10), (3, 20)]);
        match mode {
            0 => {
                status(s, quote_at + MINUTE, "PENDING_DEPOSIT", None);
                status(
                    s,
                    deadline + RECEIVE_RECLAIM_SECONDS + r.range(MINUTE, HOUR),
                    "PENDING_DEPOSIT",
                    None,
                );
                return "never deposited, PENDING_DEPOSIT polled past the deadline".into();
            }
            1 | 2 => {
                let end = if mode == 1 { "REFUNDED" } else { "FAILED" };
                status(s, quote_at + 5 * MINUTE, "KNOWN_DEPOSIT_TX", None);
                status(s, quote_at + 7 * MINUTE, "PROCESSING", None);
                status(s, deadline + r.pick(&[10 * MINUTE, 3 * HOUR]), end, None);
                if r.chance(70) {
                    status(
                        s,
                        deadline + RECEIVE_RECLAIM_SECONDS + r.range(MINUTE, HOUR),
                        end,
                        None,
                    );
                }
                return format!("unpaid, {end}");
            }
            _ => return "never deposited, NEAR silent".into(),
        }
    }
    let deposit_at = quote_at + r.range(MINUTE, (deadline_in * 9 / 10).max(2 * MINUTE));
    let timing = r.weighted(&[(0, 75), (1, 15), (2, 10)]);
    let p1 = match timing {
        0 => deposit_at + r.pick(&[2 * MINUTE, 10 * MINUTE, 40 * MINUTE, 2 * HOUR]),
        1 => deadline + r.pick(&[DAY, 7 * DAY]),
        _ => deadline + r.pick(&[29 * DAY, 31 * DAY, 40 * DAY]),
    };
    let v1 = r.pick(&[ZEC / 2, ZEC, 5 * ZEC / 4]);
    let mut note = format!(
        "paid {} at deadline{:+}",
        zec(v1),
        span_of_signed(p1 - deadline)
    );
    let mut total = v1;
    let second = r.chance(30);
    if second {
        let v2 = r.pick(&[ZEC / 10, ZEC / 2]);
        total += v2;
        let gap = r.weighted(&[
            (0, 25),
            (BLOCK_SECS, 10),
            (10 * MINUTE, 15),
            (HOUR, 15),
            (DAY, 15),
            (7 * DAY, 10),
            (21 * DAY, 10),
        ]);
        if gap == 0 {
            payouts.push((p1, vec![(id, v1), (id, v2)], false));
            note.push_str(&format!(", and {} in the same transaction", zec(v2)));
        } else {
            payouts.push((p1, vec![(id, v1)], timing == 0));
            payouts.push((p1 + gap, vec![(id, v2)], false));
            note.push_str(&format!(", and {} {} later", zec(v2), span(gap)));
        }
    } else {
        payouts.push((p1, vec![(id, v1)], timing == 0));
    }
    let mode = r.weighted(&[(0, 60), (1, 20), (2, 20)]);
    if mode != 1 {
        if r.chance(50) {
            status(s, quote_at + MINUTE, "PENDING_DEPOSIT", None);
        }
        if r.chance(10) {
            status(s, deposit_at + 30, "INCOMPLETE_DEPOSIT", None);
        }
        status(s, deposit_at + MINUTE, "KNOWN_DEPOSIT_TX", None);
        status(s, deposit_at + 3 * MINUTE, "PROCESSING", None);
    }
    match mode {
        0 => {
            let at =
                (p1 + r.pick(&[-MINUTE, MINUTE, 30 * MINUTE, DAY])).max(deposit_at + 4 * MINUTE);
            let amount = if second {
                r.weighted(&[(Some(total), 50), (None, 25), (Some(v1), 25)])
            } else {
                r.weighted(&[(Some(total), 50), (None, 30), (Some(0), 20)])
            };
            status(s, at, "SUCCESS", amount);
            note.push_str(&format!(
                "; SUCCESS at payout{:+} amountOut {}",
                span_of_signed(at - p1),
                amount.map_or("missing".to_string(), zec)
            ));
            if r.chance(15) {
                status(s, at, "PROCESSING", None);
                note.push_str(", a stale PROCESSING in the same second");
            } else if r.chance(12) {
                status(s, at + 5 * MINUTE, "PROCESSING", None);
                status(s, at + 15 * MINUTE, "SUCCESS", amount);
                note.push_str(", a stale PROCESSING 5m later, SUCCESS again");
            }
        }
        1 => note.push_str("; NEAR silent"),
        _ => note.push_str("; statuses stop at PROCESSING"),
    }
    note
}

/// `secs` with its sign.
fn span_of_signed(secs: i64) -> String {
    if secs < 0 {
        format!("-{}", span_of(-secs))
    } else {
        format!("+{}", span_of(secs))
    }
}

/// Plans a ZEC-to-X swap on A quoted at `quote_at`: its funding, NEAR's refunds and
/// statuses.
fn plan_refund(
    r: &mut Rng,
    s: &mut Schedule<Step>,
    payouts: &mut Vec<(i64, Vec<(usize, u64)>, bool)>,
    id: usize,
    quote_at: i64,
    deposit: Option<Deposit>,
) -> String {
    s.at(quote_at, Step::Quote(id));
    let status = |s: &mut Schedule<Step>, at: i64, status: &'static str, amount: Option<u64>| {
        s.at(
            at,
            Step::Status {
                swap: id,
                status,
                amount,
            },
        )
    };
    let Some(deposit) = deposit else {
        if r.chance(50) {
            status(s, quote_at + MINUTE, "PENDING_DEPOSIT", None);
        }
        return "never funded".into();
    };
    let fund_at = quote_at + r.pick(&[MINUTE, 5 * MINUTE]);
    s.at(fund_at, Step::Fund(id));
    let dep = match deposit {
        Deposit::Amount(v) => v,
        Deposit::ZeroChange => FUNDS - FUNDING_FEE,
    };
    let mut note = match deposit {
        Deposit::Amount(v) => format!("funds {}", zec(v)),
        Deposit::ZeroChange => "funds everything, zero-value change".into(),
    };
    if r.chance(80) {
        status(s, fund_at + 5 * MINUTE, "PROCESSING", None);
    }
    match r.weighted(&[(0, 45), (1, 20), (2, 35)]) {
        0 => {
            let delay = r.weighted(&[
                (30 * MINUTE, 20),
                (2 * HOUR, 20),
                (DAY, 20),
                (7 * DAY, 15),
                (25 * DAY, 10),
                (31 * DAY, 8),
                (40 * DAY, 7),
            ]);
            let refund_at = fund_at + delay;
            let v = if r.chance(75) { dep - 10_000 } else { dep / 2 };
            payouts.push((refund_at, vec![(id, v)], false));
            note.push_str(&format!(
                "; refunded {} {} after funding",
                zec(v),
                span(delay)
            ));
            let at = refund_at + r.pick(&[-MINUTE, MINUTE, HOUR]);
            match r.weighted(&[(0, 60), (1, 15), (2, 10), (3, 15)]) {
                0 => status(s, at, "REFUNDED", Some(v)),
                1 => status(s, at, "FAILED", Some(v)),
                2 => status(s, at, "REFUNDED", None),
                _ => note.push_str(", NEAR silent"),
            }
            if r.chance(15) {
                let v2 = ZEC / 20;
                let gap = r.pick(&[BLOCK_SECS, HOUR, 7 * DAY]);
                payouts.push((refund_at + gap, vec![(id, v2)], false));
                note.push_str(&format!(", refunded {} again {} later", zec(v2), span(gap)));
            }
        }
        1 => {
            let v = dep / 4;
            let at = fund_at + r.pick(&[HOUR, DAY]);
            payouts.push((at, vec![(id, v)], false));
            status(s, at + r.pick(&[-MINUTE, MINUTE]), "SUCCESS", Some(v));
            note.push_str(&format!("; SUCCESS with an excess refund of {}", zec(v)));
        }
        _ => {
            let at = fund_at + r.pick(&[30 * MINUTE, 2 * HOUR]);
            if r.chance(60) {
                status(s, at, "SUCCESS", Some(0));
                note.push_str("; SUCCESS, refundedAmount 0");
            } else {
                status(s, at, "SUCCESS", None);
                note.push_str("; SUCCESS without refundedAmount");
            }
        }
    }
    note
}

/// Schedules `slot`'s periodic syncs from `from` to `to`, maybe with one offline period.
fn sync_steps(
    r: &mut Rng,
    s: &mut Schedule<Step>,
    slot: usize,
    from: i64,
    to: i64,
    horizon: i64,
    notes: &mut Vec<String>,
) {
    // Every sync with closed keys publishes a directory for their paid filter, which
    // dominates a scenario's cost, so a wallet syncs at most about 30 times.
    let every = r
        .pick(&[30 * MINUTE, 2 * HOUR, 6 * HOUR, 12 * HOUR])
        .max(horizon / 30)
        .max((to - from) / 30);
    let offline = r.chance(40).then(|| {
        let start = r.range(from, to.max(from + 1));
        (
            start,
            start + r.range(HOUR, ((to - from) / 3).max(2 * HOUR)),
        )
    });
    let mut text = format!("{} syncs every {}", NAMES[slot], span_of(every));
    if let Some((a, b)) = offline {
        text.push_str(&format!(", offline +{}..+{}", span_of(a), span_of(b)));
    }
    notes.push(text);
    let mut t = from;
    while t <= to {
        if !offline.is_some_and(|(a, b)| a <= t && t < b) {
            s.at(t, Step::Sync(slot));
        }
        t += every;
    }
}

/// A one-time key, as the report names keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct KeyRef {
    refund: bool,
    index: u64,
}

impl KeyRef {
    /// `R3` or `I0`.
    fn label(self) -> String {
        format!("{}{}", if self.refund { "R" } else { "I" }, self.index)
    }
}

/// How a wallet credited a payment, in the model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Found {
    Live,
    Sweep,
    Recheck,
}

/// A wallet's record of a receipt's block, in the model.
#[derive(Clone, Copy, Debug)]
enum Known {
    Mined(u32),
    /// A rewind un-mined it; it was first seen at this height.
    Unmined(u32),
}

/// A provider operation on a key, in the model.
#[derive(Clone, Debug)]
struct Op {
    swap: usize,
    deadline: i64,
    observed_at: i64,
    /// 0 active, 1 final without receipt, 2 final with receipt, 3 inconclusive, 4
    /// awaiting deposit (`swap::lifecycle::record`).
    expectation: u8,
    value: Option<u64>,
    funded: bool,
    started: bool,
}

/// A key's restore sweep, in the model.
#[derive(Clone, Debug)]
struct Sweep {
    done: Option<u32>,
    attempts: u32,
    next_at: i64,
}

/// One wallet's record of one key, in the model.
#[derive(Clone, Debug)]
struct MKey {
    id: u64,
    registered_at: i64,
    scan_from: u32,
    active_from: Option<u32>,
    closed: bool,
    sweep: Option<Sweep>,
    reserved_at: Option<i64>,
    released: bool,
    seen: bool,
    advances: bool,
    used: bool,
    /// A sweep found a payment before the account's birthday, which it does not track.
    paid_before_birthday: bool,
    ops: Vec<Op>,
}

impl MKey {
    /// Whether the wallet trial-decrypts with it.
    fn open(&self) -> bool {
        self.active_from.is_some() && !self.closed
    }

    /// Swept, never reserved and without operations (`RESTORED`).
    fn restored(&self) -> bool {
        self.sweep.is_some() && self.reserved_at.is_none() && self.ops.is_empty()
    }
}

/// How a key is registered (`Discovery`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Discovery {
    Scan,
    Sweep,
    Funding,
}

/// One wallet in the model.
struct MDev {
    name: String,
    skew: i64,
    birthday: u32,
    scanned: Option<u32>,
    keys: BTreeMap<KeyRef, MKey>,
    next_id: u64,
    found: BTreeMap<usize, (Found, String)>,
    known: BTreeMap<usize, Known>,
    rescans: Vec<(u32, u32)>,
    directory: bool,
    fault: bool,
}

/// A NEAR payment to a one-time key, in the model.
struct MPay {
    label: String,
    key: KeyRef,
    swap: usize,
    mined: Mined,
    alive: bool,
    tx: Option<Transaction>,
    fvk: FullViewingKey,
    spent_by_funding: bool,
}

/// A refund funding transaction, in the model.
struct MFunding {
    key: KeyRef,
    height: u32,
    alive: bool,
    tx: Transaction,
    /// Deposit plus fee.
    cost: u64,
}

/// NEAR was given `key` at `at`, as the harness records it, by the wallet in `slot`.
struct Given {
    key: KeyRef,
    at: i64,
    slot: usize,
}

/// The documented lifecycle of one-time keys, evaluated alongside the scenario.
struct Model {
    devs: Vec<Option<MDev>>,
    pays: Vec<MPay>,
    fundings: Vec<MFunding>,
    given: Vec<Given>,
    read_lag: i64,
    feed_started: i64,
}

impl Model {
    /// The wallet in `slot`.
    fn dev(&mut self, slot: usize) -> &mut MDev {
        self.devs[slot].as_mut().expect("the device exists")
    }

    /// The birthday height of the wallet in `slot`.
    fn dev_birthday(&self, slot: usize) -> u32 {
        self.devs[slot]
            .as_ref()
            .expect("the device exists")
            .birthday
    }

    /// Whether NEAR's seen set read until `until` holds `key`.
    fn seen_at(&self, key: KeyRef, until: i64) -> bool {
        self.given
            .iter()
            .any(|g| g.key == key && g.at >= self.feed_started && g.at <= until)
    }

    /// Whether NEAR's recent set read until `until` holds `key`.
    fn recent_at(&self, key: KeyRef, until: i64) -> bool {
        self.given
            .iter()
            .any(|g| g.key == key && g.at <= until && g.at > until - RESTORE_WATCH_SECS)
    }

    /// Registers `key` on `slot`, or widens its registration (`register`).
    fn register(
        &mut self,
        slot: usize,
        key: KeyRef,
        scan_from: u32,
        advances: bool,
        discovery: Discovery,
        now: i64,
    ) {
        let dev = self.dev(slot);
        let id = dev.next_id;
        let entry = dev.keys.entry(key).or_insert_with(|| MKey {
            id,
            registered_at: now,
            scan_from,
            active_from: None,
            closed: false,
            sweep: None,
            reserved_at: None,
            released: false,
            seen: false,
            advances: false,
            used: false,
            paid_before_birthday: false,
            ops: Vec::new(),
        });
        if entry.id == id {
            dev.next_id += 1;
        }
        entry.scan_from = entry.scan_from.min(scan_from);
        entry.advances |= advances;
        match discovery {
            Discovery::Scan => {
                self.activate(slot, key, scan_from);
            }
            Discovery::Sweep => {
                let stored = entry.scan_from;
                if entry.active_from.is_none_or(|a| a > stored) && entry.sweep.is_none() {
                    entry.sweep = Some(Sweep {
                        done: None,
                        attempts: 0,
                        next_at: 0,
                    });
                }
            }
            Discovery::Funding => {}
        }
    }

    /// Starts or extends trial decryption of `key` from `from` (`activate`).
    fn activate(&mut self, slot: usize, key: KeyRef, from: u32) -> bool {
        let dev = self.dev(slot);
        let scanned_end = dev.scanned.map_or(from, |s| s + 1);
        let k = dev.keys.get_mut(&key).expect("registered");
        let pending = k.sweep.as_ref().is_some_and(|s| s.done.is_none());
        if k.active_from.is_none() && pending {
            return false;
        }
        let rescan_end = match k.active_from {
            Some(start) if !k.closed && start <= from => return true,
            Some(start) if !k.closed => start.min(scanned_end),
            _ => scanned_end,
        };
        k.active_from = Some(from);
        k.closed = false;
        if from < rescan_end {
            dev.rescans.push((from, rescan_end));
        }
        true
    }

    /// Recovers funding memos and keeps the incoming lookahead (`maintain`).
    fn maintain(&mut self, slot: usize, now: i64) {
        if self.dev(slot).scanned.is_none() {
            return;
        }
        self.recover_memos(slot, now);
        self.lookahead(slot, now);
    }

    /// Registers the refund key of each funding memo the wallet scanned, unless a key
    /// covers it (`recover_refund_memos`).
    fn recover_memos(&mut self, slot: usize, now: i64) {
        let scanned = self.dev(slot).scanned.unwrap_or(0);
        let memos: Vec<(KeyRef, u32)> = self
            .fundings
            .iter()
            .filter(|f| f.alive && f.height <= scanned && f.height >= self.dev_birthday(slot))
            .map(|f| (f.key, f.height))
            .collect();
        for (key, height) in memos {
            let covered = self.dev(slot).keys.get(&key).is_some_and(|k| {
                k.scan_from <= height
                    && (k.active_from.is_some_and(|a| a <= height) || k.sweep.is_some())
            });
            if !covered {
                self.register(slot, key, height, true, Discovery::Sweep, now);
            }
        }
    }

    /// Keeps the incoming lookahead above a restored top (`maintain_receive_lookahead`).
    fn lookahead(&mut self, slot: usize, now: i64) {
        let dev = self.dev(slot);
        let start = dev.birthday;
        let top = dev
            .keys
            .iter()
            .filter(|(k, v)| !k.refund && v.advances)
            .max_by_key(|(k, _)| k.index)
            .map(|(k, v)| (k.index, v.restored()));
        let first = match top {
            Some((_, false)) => return,
            Some((index, true)) => index + 1,
            None => 0,
        };
        for index in first..first + RECEIVE_GAP_LIMIT {
            let key = KeyRef {
                refund: false,
                index,
            };
            let exists = self
                .dev(slot)
                .keys
                .get(&key)
                .is_some_and(|k| k.scan_from <= start);
            if !exists {
                self.register(slot, key, start, false, Discovery::Sweep, now);
            }
        }
    }

    /// The found receipts of `key` on `slot`, with values and blocks.
    fn receipts(&self, slot: usize, key: KeyRef) -> Vec<(u64, Known)> {
        let dev = self.devs[slot].as_ref().expect("the device exists");
        self.pays
            .iter()
            .enumerate()
            .filter(|(i, p)| p.key == key && dev.found.contains_key(i))
            .map(|(i, p)| (p.mined.value, dev.known[&i]))
            .collect()
    }

    /// Releases settled paid reservations and reclaims abandoned unpaid ones (`reap`).
    fn reap(&mut self, slot: usize, now: i64) {
        let dev = self.dev(slot);
        let latest = dev
            .scanned
            .map_or(now, |h| block_time(BlockHeight::from(h)));
        let deadline_now = now.min(latest);
        let reclaim = RECEIVE_RECLAIM_SECONDS;
        for (key, k) in dev.keys.iter_mut() {
            if key.refund || k.reserved_at.is_none() || k.released || !k.used {
                continue;
            }
            let ok = k.ops.iter().all(|o| {
                o.observed_at <= now
                    && (matches!(o.expectation, 1..=3)
                        || (o.expectation == 4
                            && !o.funded
                            && o.deadline <= deadline_now - reclaim
                            && o.observed_at >= now - STATUS_FRESH_SECONDS))
            });
            if ok {
                release(k, now);
            }
        }
        for (key, k) in dev.keys.iter_mut() {
            if key.refund || k.released {
                continue;
            }
            let Some(reserved_at) = k.reserved_at else {
                continue;
            };
            let started = k.ops.iter().any(|o| o.started);
            let reusable = reserved_at <= now - reclaim
                && !k.used
                && k.ops.iter().all(|o| {
                    o.deadline <= deadline_now - reclaim
                        && (!started
                            || (o.observed_at >= now - STATUS_FRESH_SECONDS
                                && o.observed_at <= now
                                && (o.expectation == 1
                                    || (matches!(o.expectation, 3 | 4) && !o.funded))))
                });
            if reusable && k.open() {
                release(k, now);
                k.closed = true;
            }
        }
    }

    /// Closes `slot`'s finished keys at `tip` (`close_finished_one_time_keys`).
    fn close(&mut self, slot: usize, now_raw: i64, tip: u32) {
        if self.dev(slot).scanned != Some(tip) {
            return;
        }
        self.reap(slot, now_raw);
        let now = now_raw.min(block_time(BlockHeight::from(tip)));
        let confirmed_below = (tip + 1).saturating_sub(CONFIRMATIONS);
        let keys: Vec<KeyRef> = self.dev(slot).keys.keys().copied().collect();
        for key in keys {
            let receipts = self.receipts(slot, key);
            let k = &self.dev(slot).keys[&key];
            if !k.open() {
                continue;
            }
            let reserved = !key.refund && k.reserved_at.is_some() && !k.released;
            let pending = receipts.iter().any(|(_, known)| match known {
                Known::Mined(h) => *h > confirmed_below,
                Known::Unmined(h) => h + EXPIRY_DELTA >= tip + 1,
            });
            let swept_at = k
                .sweep
                .as_ref()
                .and_then(|s| s.done)
                .map(|h| block_time(BlockHeight::from(h)));
            let limit = if k.restored() {
                k.registered_at.max(swept_at.unwrap_or(k.registered_at)) + RESTORE_WATCH_SECS
            } else {
                k.ops
                    .iter()
                    .map(|o| o.deadline)
                    .max()
                    .unwrap_or(k.registered_at)
                    + COMPLETION_LIMIT_SECS
            };
            let received: u64 = receipts
                .iter()
                .filter(|(_, known)| matches!(known, Known::Mined(h) if *h <= confirmed_below))
                .map(|(v, _)| v)
                .sum();
            let expected: u64 = k
                .ops
                .iter()
                .filter(|o| o.expectation == 2)
                .map(|o| o.value.unwrap_or(1))
                .sum();
            let settled = !k.ops.is_empty()
                && k.ops.iter().all(|o| !matches!(o.expectation, 0 | 3 | 4))
                && received >= expected;
            let started = k.ops.iter().any(|o| o.started);
            let finished = if reserved {
                started && now >= limit
            } else {
                settled || now >= limit
            };
            if finished && !pending {
                self.dev(slot).keys.get_mut(&key).expect("a key").closed = true;
            }
        }
    }

    /// Credits payment `pay` to `slot`, as `how` found it.
    fn credit(&mut self, slot: usize, pay: usize, how: Found, why: String) {
        let height = u32::from(self.pays[pay].mined.height);
        let key = self.pays[pay].key;
        let dev = self.dev(slot);
        dev.found.entry(pay).or_insert((how, why));
        dev.known.insert(pay, Known::Mined(height));
        let k = dev.keys.get_mut(&key).expect("a key");
        k.used = true;
        k.advances = true;
    }

    /// One sync of `slot` at `tip`: maintenance, the rewinds it ran, scanning, closing
    /// and its restore sweep.
    fn sync(&mut self, slot: usize, tip: u32, rewinds: &[(u32, u32)], recheck: bool) {
        let now = block_time(BlockHeight::from(tip)) + self.dev(slot).skew;
        self.maintain(slot, now);
        for &(_, to) in rewinds {
            self.truncate(slot, to);
        }
        let dev = self.dev(slot);
        let from = dev.scanned.map_or(dev.birthday, |s| s + 1);
        let rescans = std::mem::take(&mut dev.rescans);
        let how = if recheck { Found::Recheck } else { Found::Live };
        for pay in 0..self.pays.len() {
            let p = &self.pays[pay];
            if !p.alive {
                continue;
            }
            let h = u32::from(p.mined.height);
            let scanned =
                (from..=tip).contains(&h) || rescans.iter().any(|(a, b)| *a <= h && h < *b);
            if !scanned {
                continue;
            }
            let key = p.key;
            let open = self.devs[slot]
                .as_ref()
                .and_then(|d| d.keys.get(&key))
                .is_some_and(|k| k.open() && k.active_from.is_some_and(|a| a <= h));
            if open {
                let name = self.dev(slot).name.clone();
                self.credit(
                    slot,
                    pay,
                    how,
                    format!("{} was open when {name} scanned block {h}", key.label()),
                );
            }
        }
        self.dev(slot).scanned = Some(tip);
        self.maintain(slot, now);
        self.close(slot, now, tip);
        let dev = self.dev(slot);
        let (up, fault) = (dev.directory, dev.fault);
        dev.fault = false;
        if up && !fault {
            self.sweep(slot, tip, now, recheck);
        }
    }

    /// A rewind of `slot` to `to` (`one_time_ivk::truncate_to_height`, then un-mining).
    fn truncate(&mut self, slot: usize, to: u32) {
        let confirmed_below = (to + 1).saturating_sub(CONFIRMATIONS);
        let keys: Vec<KeyRef> = self.dev(slot).keys.keys().copied().collect();
        for key in keys {
            let receipts = self.receipts(slot, key);
            let k = self.dev(slot).keys.get_mut(&key).expect("a key");
            let unconfirmed = receipts
                .iter()
                .any(|(_, known)| matches!(known, Known::Mined(h) if *h > confirmed_below));
            if k.closed && k.active_from.is_some() && unconfirmed {
                k.closed = false;
            }
            if let Some(s) = k.sweep.as_mut() {
                if s.done.is_some_and(|d| d > to) {
                    s.done = None;
                    s.next_at = 0;
                }
            }
        }
        let dev = self.dev(slot);
        for known in dev.known.values_mut() {
            if let Known::Mined(h) = *known {
                if h > to {
                    *known = Known::Unmined(h);
                }
            }
        }
        dev.scanned = dev.scanned.map(|s| s.min(to));
        for range in dev.rescans.iter_mut() {
            range.1 = range.1.min(to + 1);
        }
    }

    /// The restore sweep run of one sync at `tip` (`zakura_pir_receiver::sweep`).
    fn sweep(&mut self, slot: usize, tip: u32, now: i64, recheck: bool) {
        let end = tip - 2;
        let until = now - self.read_lag;
        let complete = (now - RECENT_SET_MAX_AGE_SECS..=now + 60).contains(&until);
        let how = if recheck {
            Found::Recheck
        } else {
            Found::Sweep
        };
        let dev = self.dev(slot);
        let mut work: Vec<(i64, u64, KeyRef)> = dev
            .keys
            .iter()
            .filter_map(|(key, k)| {
                let s = k.sweep.as_ref()?;
                (s.done.is_none() && s.next_at <= now && k.scan_from <= tip)
                    .then_some((s.next_at, k.id, *key))
            })
            .collect();
        work.sort();
        work.truncate(SWEEP_BATCH);
        for &(_, _, key) in &work {
            let seen = self.seen_at(key, until);
            let recent = !complete || self.recent_at(key, until);
            let paid: Vec<usize> = (0..self.pays.len())
                .filter(|&i| {
                    let p = &self.pays[i];
                    p.alive && p.key == key && u32::from(p.mined.height) <= end
                })
                .collect();
            let k = self.dev(slot).keys.get_mut(&key).expect("a key");
            if seen {
                k.seen = true;
                k.advances = true;
            }
            let s = k.sweep.as_mut().expect("a sweep");
            let delay = (60i64 << s.attempts.min(10)).min(43_200);
            s.attempts = (s.attempts + 1).min(30);
            s.next_at = now + delay;
            let name = self.dev(slot).name.clone();
            let birthday = self.dev_birthday(slot);
            for pay in paid {
                let height = u32::from(self.pays[pay].mined.height);
                if height < birthday {
                    // Marked paid, never credited (`apply_payment`).
                    let k = self.dev(slot).keys.get_mut(&key).expect("a key");
                    k.paid_before_birthday = true;
                    k.used = true;
                    k.advances = true;
                    continue;
                }
                self.credit(
                    slot,
                    pay,
                    how,
                    format!(
                        "{name}'s sweep of {} looked it up at a publication through {end}",
                        key.label()
                    ),
                );
                self.dev(slot).known.insert(pay, Known::Mined(height));
            }
            let k = self.dev(slot).keys.get_mut(&key).expect("a key");
            k.sweep.as_mut().expect("a sweep").done = Some(end);
            let refund_owed = key.refund
                && k.active_from.is_none()
                && !k.closed
                && k.ops.iter().any(|o| matches!(o.expectation, 2 | 3));
            if recent || k.open() || refund_owed {
                self.activate(slot, key, end + 1);
            } else {
                k.closed = true;
            }
        }
        if !work.is_empty() {
            self.lookahead(slot, now);
        }
        // Closed keys without a known payment, against this publication's paid filter.
        let dev = self.devs[slot].as_ref().expect("the device exists");
        let checks: Vec<KeyRef> = dev
            .keys
            .iter()
            .filter(|(key, k)| {
                k.closed
                    && !k.paid_before_birthday
                    && !self
                        .receipts(slot, **key)
                        .iter()
                        .any(|(_, known)| matches!(known, Known::Mined(_)))
                    && k.sweep
                        .as_ref()
                        .is_none_or(|s| s.done.is_some_and(|d| d < end))
            })
            .map(|(key, _)| *key)
            .collect();
        for key in checks {
            let paid = self
                .pays
                .iter()
                .any(|p| p.alive && p.key == key && u32::from(p.mined.height) <= end);
            let k = self.dev(slot).keys.get_mut(&key).expect("a key");
            if paid {
                requeue(k);
            } else {
                match k.sweep.as_mut() {
                    Some(s) => s.done = Some(end),
                    None => {
                        k.sweep = Some(Sweep {
                            done: Some(end),
                            attempts: 0,
                            next_at: 0,
                        })
                    }
                }
            }
        }
    }

    /// The side effects of one `prepare_receive_reservation` call on `slot` at `now`:
    /// recording the seen set, the lookahead and reaping.
    fn prepare(&mut self, slot: usize, now: i64) {
        let until = now - self.read_lag;
        let unseen: Vec<KeyRef> = self
            .dev(slot)
            .keys
            .iter()
            .filter(|(key, k)| !key.refund && !k.seen)
            .map(|(key, _)| *key)
            .collect();
        for key in unseen {
            if self.seen_at(key, until) {
                let k = self.dev(slot).keys.get_mut(&key).expect("a key");
                k.seen = true;
                k.advances = true;
            }
        }
        self.lookahead(slot, now);
        self.reap(slot, now);
    }

    /// Records the incoming reservation `slot` issued at `index` for `swap`.
    fn issue_incoming(
        &mut self,
        slot: usize,
        swap: usize,
        index: u64,
        deadline_in: i64,
        chain_now: i64,
    ) {
        let now = chain_now + self.dev(slot).skew;
        let until = now - self.read_lag;
        let start = self.dev(slot).birthday;
        for i in 0..index {
            let key = KeyRef {
                refund: false,
                index: i,
            };
            if !self.dev(slot).keys.contains_key(&key) && self.seen_at(key, until) {
                self.register(slot, key, start, false, Discovery::Sweep, now);
                let k = self.dev(slot).keys.get_mut(&key).expect("a key");
                k.seen = true;
                k.advances = true;
            }
        }
        let key = KeyRef {
            refund: false,
            index,
        };
        let from = self.dev(slot).scanned.map_or(start, |s| s + 1);
        self.register(slot, key, from, true, Discovery::Scan, now);
        let k = self.dev(slot).keys.get_mut(&key).expect("a key");
        k.reserved_at = Some(now);
        k.released = false;
        k.ops.push(Op {
            swap,
            deadline: (now + deadline_in).min(chain_now + deadline_in),
            observed_at: now,
            expectation: 0,
            value: None,
            funded: false,
            started: true,
        });
        self.given.push(Given {
            key,
            at: chain_now,
            slot,
        });
    }

    /// Records the refund key `slot` reserved at `index` for `swap`.
    fn issue_refund(&mut self, slot: usize, swap: usize, index: u64, deadline_in: i64, now: i64) {
        self.recover_memos(slot, now);
        let until = now - self.read_lag;
        let start = self.dev(slot).birthday;
        let allocated = self
            .dev(slot)
            .keys
            .iter()
            .filter(|(k, v)| k.refund && v.advances)
            .map(|(k, _)| k.index + 1)
            .max()
            .unwrap_or(0);
        for i in allocated..index {
            let key = KeyRef {
                refund: true,
                index: i,
            };
            if !self.dev(slot).keys.contains_key(&key) && self.seen_at(key, until) {
                self.register(slot, key, start, false, Discovery::Sweep, now);
                let k = self.dev(slot).keys.get_mut(&key).expect("a key");
                k.seen = true;
                k.advances = true;
            }
        }
        let key = KeyRef {
            refund: true,
            index,
        };
        let from = self.dev(slot).scanned.map_or(start, |s| s + 1);
        self.register(slot, key, from, true, Discovery::Funding, now);
        self.dev(slot)
            .keys
            .get_mut(&key)
            .expect("a key")
            .ops
            .push(Op {
                swap,
                deadline: now + deadline_in,
                observed_at: 0,
                expectation: 1,
                value: None,
                funded: false,
                started: false,
            });
        self.given.push(Given { key, at: now, slot });
    }

    /// Records a NEAR status for `swap` on `slot` (`record_operation_status`).
    fn status(
        &mut self,
        slot: usize,
        swap: usize,
        key: KeyRef,
        observed: (u8, Option<u64>, bool, bool),
        now: i64,
    ) {
        let (expectation, value, funded, refund_owed) = observed;
        let Some(k) = self.dev(slot).keys.get_mut(&key) else {
            return;
        };
        let reserved = k.reserved_at.is_some() && !k.released;
        let used = k.used;
        let Some(op) = k.ops.iter_mut().find(|o| o.swap == swap) else {
            return;
        };
        if !(key.refund || reserved || (used && (op.funded || funded))) {
            return;
        }
        op.funded |= funded;
        let current = op.observed_at < now
            || (op.observed_at == now
                && !((op.expectation == 2
                    && (expectation != 2 || value.unwrap_or(1) < op.value.unwrap_or(1)))
                    || (op.expectation == 3 && expectation == 1)));
        if current {
            op.observed_at = now;
            op.expectation = expectation;
            op.value = value;
        }
        let k = &self.dev(slot).keys[&key];
        if current && key.refund && k.active_from.is_none() && !k.closed && refund_owed {
            let from = k.scan_from;
            self.activate(slot, key, from);
        }
        self.reap(slot, now);
    }

    /// Queues a sweep of every closed key on `slot` (`recheck_one_time_key_history`).
    fn recheck(&mut self, slot: usize) {
        for k in self.dev(slot).keys.values_mut() {
            if k.closed {
                requeue(k);
            }
        }
    }
}

/// Releases key `k`'s reservation at `now` (`release`).
fn release(k: &mut MKey, now: i64) {
    k.released = true;
    for o in k.ops.iter_mut() {
        if matches!(o.expectation, 0 | 4) {
            o.expectation = 1;
            o.value = None;
            o.observed_at = o.observed_at.max(now);
        }
    }
}

/// Queues a new sweep of `k` unless one is pending (`requeue`).
fn requeue(k: &mut MKey) {
    match k.sweep.as_mut() {
        None => {
            k.sweep = Some(Sweep {
                done: None,
                attempts: 0,
                next_at: 0,
            })
        }
        Some(s) if s.done.is_some() => {
            *s = Sweep {
                done: None,
                attempts: 0,
                next_at: 0,
            }
        }
        Some(_) => {}
    }
}

/// A swap as it ran.
#[derive(Default)]
struct SwapRt {
    key: Option<KeyRef>,
    fvk: Option<FullViewingKey>,
    incoming: Option<IncomingSwap>,
    refund: Option<RefundSwap>,
    funded: bool,
    payouts: u32,
}

/// Runs a plan against the harness and the model.
struct Exec<'p> {
    plan: &'p Plan,
    slots: [Option<Dev>; 4],
    swaps: Vec<SwapRt>,
    m: Model,
    birthday: BlockHeight,
    floor: BlockHeight,
    funds: u64,
}

impl<'p> Exec<'p> {
    /// Runs `plan` in `ctx`, then registers what the model expects.
    fn run(plan: &'p Plan, ctx: &mut Ctx) {
        ctx.near.read_lag = plan.read_lag;
        ctx.log("plan", plan.notes.join("; "));
        ctx.mine(20);
        let birthday = ctx.chain.tip() + 1;
        ctx.mine(5);
        let mut ex = Exec {
            plan,
            slots: [None; 4],
            swaps: (0..plan.swaps.len()).map(|_| SwapRt::default()).collect(),
            m: Model {
                devs: (0..4).map(|_| None).collect(),
                pays: Vec::new(),
                fundings: Vec::new(),
                given: Vec::new(),
                read_lag: plan.read_lag,
                feed_started: ctx.near.feed_started,
            },
            birthday,
            floor: birthday,
            funds: 0,
        };
        ex.create(ctx, A, plan.skew);
        if plan.a2 {
            ex.create(ctx, A2, 0);
        }
        if plan.funds {
            let dev = ex.slots[A].expect("A");
            let fvk = ctx.get(dev).fvk.clone();
            ctx.pay(
                "A's Ironwood funds",
                "A's address",
                &fvk,
                FUNDS,
                Payer::Wallet,
            );
            ex.funds = FUNDS;
        }
        if plan.real_payouts {
            // NEAR's wallet, and its first payout, sit below any reorg.
            let stranger =
                FullViewingKey::from(&SpendingKey::from_bytes([0xf6; 32]).expect("a key"));
            ctx.pay_tx(
                "NEAR wallet warm-up",
                "a stranger",
                &stranger,
                10_000,
                Payer::Near,
            );
        }
        ctx.mine(10);
        ex.floor = ctx.chain.tip();
        ex.sync(ctx, A);
        if plan.a2 {
            ex.sync(ctx, A2);
        }
        let t0 = ctx.chain.now();
        for (at, step) in &plan.steps {
            ex.step(ctx, t0 + at, step.clone());
        }
        ctx.chain.mine_until(t0 + plan.end);
        ex.finish(ctx);
    }

    /// Creates the wallet in `slot`.
    fn create(&mut self, ctx: &mut Ctx, slot: usize, skew: i64) {
        self.create_at(ctx, slot, skew, self.birthday);
    }

    /// Creates the wallet in `slot` with its birthday at `birthday`.
    fn create_at(&mut self, ctx: &mut Ctx, slot: usize, skew: i64, birthday: BlockHeight) {
        let dev = ctx.device_with_skew(NAMES[slot], SEED, birthday, skew);
        self.slots[slot] = Some(dev);
        self.m.devs[slot] = Some(MDev {
            name: NAMES[slot].into(),
            skew,
            birthday: u32::from(birthday),
            scanned: None,
            keys: BTreeMap::new(),
            next_id: 0,
            found: BTreeMap::new(),
            known: BTreeMap::new(),
            rescans: Vec::new(),
            directory: true,
            fault: false,
        });
    }

    /// Syncs `slot` and the model with it.
    fn sync(&mut self, ctx: &mut Ctx, slot: usize) -> SyncReport {
        let dev = self.slots[slot].expect("the device exists");
        let before = ctx.get(dev).rewinds.len();
        let report = ctx.sync(dev);
        let rewinds = ctx.get(dev).rewinds[before..].to_vec();
        self.m
            .sync(slot, u32::from(ctx.chain.tip()), &rewinds, false);
        report
    }

    /// Runs one planned step at `at`.
    fn step(&mut self, ctx: &mut Ctx, at: i64, step: Step) {
        match step {
            Step::Pay(_) => ctx.chain.mine_until_next_at(at),
            _ => ctx.chain.mine_until(at),
        }
        match step {
            Step::Sync(slot) => {
                if self.slots[slot].is_some() {
                    self.sync(ctx, slot);
                }
            }
            Step::Restore {
                slot,
                down,
                fault,
                late_birthday,
            } => {
                let birthday = late_birthday.map(|pct| {
                    let (from, tip) = (u32::from(self.birthday), u32::from(ctx.chain.tip()));
                    BlockHeight::from(from + (tip - from) * pct / 100)
                });
                self.create_at(ctx, slot, 0, birthday.unwrap_or(self.birthday));
                let dev = self.slots[slot].expect("just created");
                if down {
                    ctx.dev(dev).reach.directory = false;
                    self.m.dev(slot).directory = false;
                    ctx.log("directory", format!("unreachable for {}", NAMES[slot]));
                }
                if let Some(status) = fault {
                    ctx.dev(dev).reach.directory_faults = vec![status; 3];
                    self.m.dev(slot).fault = true;
                    ctx.log(
                        "directory",
                        format!(
                            "answers {}'s next 3 requests with HTTP {status}",
                            NAMES[slot]
                        ),
                    );
                }
                self.sync(ctx, slot);
            }
            Step::Quote(swap) => self.quote(ctx, swap),
            Step::Fund(swap) => self.fund(ctx, swap),
            Step::Status {
                swap,
                status,
                amount,
            } => self.status(ctx, swap, status, amount),
            Step::Pay(outs) => self.pay(ctx, &outs),
            Step::Directory { slot, up } => {
                if let Some(dev) = self.slots[slot] {
                    ctx.dev(dev).reach.directory = up;
                    self.m.dev(slot).directory = up;
                    ctx.log(
                        "directory",
                        format!(
                            "{} for {}",
                            if up { "reachable" } else { "unreachable" },
                            NAMES[slot]
                        ),
                    );
                }
            }
            Step::Fault { slot, status } => {
                if let Some(dev) = self.slots[slot] {
                    ctx.dev(dev).reach.directory_faults = vec![status; 3];
                    self.m.dev(slot).fault = true;
                    ctx.log(
                        "directory",
                        format!(
                            "answers {}'s next 3 requests with HTTP {status}",
                            NAMES[slot]
                        ),
                    );
                }
            }
            Step::Reorg { depth, tail } => self.reorg(ctx, depth, tail),
            Step::Recheck(slot) => {
                if self.slots[slot].is_some() {
                    self.recheck(ctx, slot);
                }
            }
            Step::Restart(slot) => {
                if let Some(dev) = self.slots[slot] {
                    ctx.restart(dev);
                }
            }
        }
    }

    /// Quotes planned swap `swap` on its device, after syncing it as the app does.
    fn quote(&mut self, ctx: &mut Ctx, swap: usize) {
        let plans: &'p Plan = self.plan;
        let plan = &plans.swaps[swap];
        let slot = plan.slot;
        let Some(dev) = self.slots[slot] else {
            return;
        };
        self.sync(ctx, slot);
        let tip = u32::from(ctx.chain.tip());
        let now = ctx.chain.now() + self.m.dev(slot).skew;
        match plan.kind {
            Kind::Incoming => {
                let syncs = ctx.get(dev).syncs;
                let quoted = ctx.quote_incoming(dev, plan.deadline_in);
                // The harness answers Gap and Coverage by syncing and asking again.
                for _ in 0..ctx.get(dev).syncs - syncs {
                    self.m.prepare(slot, now);
                    self.m.sync(slot, tip, &[], false);
                }
                self.m.prepare(slot, now);
                let Ok(quoted) = quoted else {
                    return;
                };
                let key = KeyRef {
                    refund: false,
                    index: quoted.index,
                };
                self.check_reuse(ctx, slot, key, now);
                self.m
                    .issue_incoming(slot, swap, quoted.index, plan.deadline_in, ctx.chain.now());
                let rt = &mut self.swaps[swap];
                rt.key = Some(key);
                rt.fvk = Some(quoted.fvk.clone());
                rt.incoming = Some(quoted);
            }
            Kind::Refund => {
                let Ok(quoted) = ctx.quote_refund(dev, plan.deadline_in) else {
                    return;
                };
                let key = KeyRef {
                    refund: true,
                    index: quoted.index,
                };
                self.check_reuse(ctx, slot, key, now);
                self.m
                    .issue_refund(slot, swap, quoted.index, plan.deadline_in, now);
                let rt = &mut self.swaps[swap];
                rt.key = Some(key);
                rt.fvk = Some(quoted.fvk.clone());
                rt.refund = Some(quoted);
            }
        }
    }

    /// The address-reuse rules (`ProviderSeen`): a wallet never issues an address it
    /// gave NEAR, nor one NEAR's seen set holds, nor a refund key whose funding memo it
    /// scanned. Another device's quote inside the feed's read lag is a documented gap.
    fn check_reuse(&mut self, ctx: &mut Ctx, slot: usize, key: KeyRef, now: i64) {
        let until = now - self.m.read_lag;
        let name = NAMES[slot];
        let scanned = self.m.dev(slot).scanned.unwrap_or(0);
        let memo = self
            .m
            .fundings
            .iter()
            .any(|f| f.alive && f.key == key && f.height <= scanned);
        let mut violations = Vec::new();
        let mut gaps = Vec::new();
        for g in self.m.given.iter().filter(|g| g.key == key) {
            if g.slot == slot {
                violations.push(format!(
                    "{name} gave NEAR {} itself at {}",
                    key.label(),
                    g.at
                ));
            } else if g.at >= self.m.feed_started && g.at <= until {
                violations.push(format!(
                    "{} gave NEAR {} at {}, which the seen set read until {until} holds",
                    NAMES[g.slot],
                    key.label(),
                    g.at
                ));
            } else {
                gaps.push(format!(
                    "{} gave NEAR {} at {}, after the seen set's read until {until}",
                    NAMES[g.slot],
                    key.label(),
                    g.at
                ));
            }
        }
        if memo {
            violations.push(format!("{name} scanned {}'s funding memo", key.label()));
        }
        let paid = self.m.dev(slot).keys.get(&key).is_some_and(|k| k.used);
        if paid {
            violations.push(format!("{name} holds a payment to {}", key.label()));
        }
        if !violations.is_empty() {
            ctx.check(
                format!("{name} never reissues {}", key.label()),
                false,
                violations.join("; "),
            );
        } else if !gaps.is_empty() {
            ctx.documented_gap(
                format!("{name} reissues {} inside the feed's read lag", key.label()),
                true,
                format!(
                    "{}; ProviderSeen: one quoted within the feed's read lag can still be issued again",
                    gaps.join("; ")
                ),
            );
        }
    }

    /// Funds planned ZEC-to-X swap `swap` from A.
    fn fund(&mut self, ctx: &mut Ctx, swap: usize) {
        let plans: &'p Plan = self.plan;
        let plan = &plans.swaps[swap];
        let (Some(deposit), Some(quoted)) = (plan.deposit, self.swaps[swap].refund.clone()) else {
            return;
        };
        let dev = self.slots[plan.slot].expect("A");
        // A rescan a sweep queued, such as a spend-history replay, holds notes back until
        // the next sync finishes it, so the app syncs until the deposit is spendable.
        let ready = |ctx: &Ctx| {
            let (spendable, total) = (ctx.get(dev).spendable_balance(), ctx.get(dev).balance());
            match deposit {
                Deposit::Amount(v) => spendable >= v + 4 * FUNDING_FEE,
                Deposit::ZeroChange => spendable == total && total > FUNDING_FEE,
            }
        };
        for attempt in 0..6 {
            if ready(ctx) {
                break;
            }
            let held = ctx.get(dev).balance() - ctx.get(dev).spendable_balance();
            ctx.log(
                NAMES[plan.slot],
                format!(
                    "cannot fund yet: {} of its balance is not spendable; syncs",
                    zec(held)
                ),
            );
            if attempt > 0 {
                ctx.mine(1);
            }
            self.sync(ctx, plan.slot);
        }
        if !ready(ctx) {
            ctx.log(
                NAMES[plan.slot],
                "gives up funding: not enough is spendable",
            );
            return;
        }
        let amount = match deposit {
            Deposit::Amount(v) => v,
            Deposit::ZeroChange => ctx.get(dev).spendable_balance() - FUNDING_FEE,
        };
        let (height, tx) = ctx.fund_refund(dev, &quoted, amount);
        let fee = tx
            .fee_paid(|_| Ok::<_, zcash_protocol::value::BalanceError>(None))
            .ok()
            .flatten()
            .map_or(0, |f| f.into_u64());
        ctx.log("A", format!("the funding pays a fee of {}", zec(fee)));
        let spent: Vec<[u8; 32]> = tx
            .ironwood_bundle()
            .map(|b| {
                b.actions()
                    .iter()
                    .map(|a| a.nullifier().to_bytes())
                    .collect()
            })
            .unwrap_or_default();
        for p in self.m.pays.iter_mut() {
            let nf = ctx.get(dev).receipt(p.mined.id()).and_then(|r| r.nullifier);
            if nf.is_some_and(|nf| spent.contains(&nf)) {
                p.spent_by_funding = true;
            }
        }
        let key = self.swaps[swap].key.expect("quoted");
        let from = self.m.dev(plan.slot).scanned.unwrap_or(0) + 1;
        self.m.activate(plan.slot, key, from);
        if let Some(op) = self
            .m
            .dev(plan.slot)
            .keys
            .get_mut(&key)
            .and_then(|k| k.ops.iter_mut().find(|o| o.swap == swap))
        {
            // The wallet's own funding records Active at time 0 over the quote's record.
            if op.observed_at == 0 {
                op.expectation = 0;
                op.value = None;
            }
        }
        self.m.fundings.push(MFunding {
            key,
            height: u32::from(height),
            alive: true,
            tx,
            cost: amount + fee,
        });
        self.swaps[swap].funded = true;
    }

    /// Records a NEAR status for planned swap `swap` on its device.
    fn status(&mut self, ctx: &mut Ctx, swap: usize, status: &'static str, amount: Option<u64>) {
        let plans: &'p Plan = self.plan;
        let plan = &plans.swaps[swap];
        let Some(key) = self.swaps[swap].key else {
            return;
        };
        if key.refund && plan.deposit.is_some() && !self.swaps[swap].funded {
            // The wallet gave up funding it, so NEAR saw no deposit.
            return;
        }
        let dev = self.slots[plan.slot].expect("quoted on it");
        let purpose = if key.refund {
            Purpose::Refund
        } else {
            Purpose::Receive
        };
        let zats = amount.map(Zatoshis::const_from_u64);
        let observation = near_observation(
            purpose,
            &NearStatus {
                status,
                swap_type: Some("EXACT_INPUT"),
                refunded_amount: if key.refund { zats } else { None },
                amount_out: if key.refund { None } else { zats },
            },
        );
        let (expectation, value, owed) = match observation.status {
            OperationStatus::Active => (0, None, false),
            OperationStatus::Terminal(ReceiptExpectation::None) => (1, None, false),
            OperationStatus::Terminal(ReceiptExpectation::Positive(v)) => {
                (2, v.map(u64::from), true)
            }
            OperationStatus::Terminal(ReceiptExpectation::Unknown) => (3, None, true),
            OperationStatus::AwaitingDeposit => (4, None, false),
        };
        if key.refund {
            let quoted = self.swaps[swap].refund.clone().expect("a refund swap");
            ctx.observe_refund(dev, &quoted, status, amount);
        } else {
            let quoted = self.swaps[swap].incoming.clone().expect("an incoming swap");
            ctx.observe_incoming(dev, &quoted, status, amount);
        }
        let now = ctx.chain.now() + self.m.dev(plan.slot).skew;
        self.m.status(
            plan.slot,
            swap,
            key,
            (expectation, value, observation.funded, owed),
            now,
        );
    }

    /// NEAR pays each (swap, value) of `outs` in one transaction.
    fn pay(&mut self, ctx: &mut Ctx, outs: &[(usize, u64)]) {
        let outs: Vec<(usize, u64)> = outs
            .iter()
            .copied()
            .filter(|(swap, _)| {
                let rt = &self.swaps[*swap];
                rt.key.is_some() && (rt.refund.is_none() || rt.funded)
            })
            .collect();
        if outs.is_empty() {
            return;
        }
        let mut labels = Vec::new();
        for (swap, _) in &outs {
            let rt = &mut self.swaps[*swap];
            rt.payouts += 1;
            let key = rt.key.expect("quoted");
            let what = if key.refund { "refund" } else { "payout" };
            labels.push(format!("{what} {} to {}", rt.payouts, key.label()));
        }
        let mined: Vec<(Mined, Option<Transaction>)> = if self.plan.real_payouts {
            outs.iter()
                .zip(&labels)
                .map(|((swap, v), label)| {
                    let rt = &self.swaps[*swap];
                    let key = rt.key.expect("quoted").label();
                    let (m, tx) = ctx.pay_tx(
                        label,
                        &key,
                        rt.fvk.as_ref().expect("a key"),
                        *v,
                        Payer::Near,
                    );
                    (m, Some(tx))
                })
                .collect()
        } else {
            let keys: Vec<String> = outs
                .iter()
                .map(|(swap, _)| self.swaps[*swap].key.expect("quoted").label())
                .collect();
            let outputs: Vec<(&str, &FullViewingKey, u64)> = outs
                .iter()
                .zip(&keys)
                .map(|((swap, v), key)| {
                    (
                        key.as_str(),
                        self.swaps[*swap].fvk.as_ref().expect("a key"),
                        *v,
                    )
                })
                .collect();
            ctx.pay_many(&labels.join(" and "), &outputs, Payer::Near)
                .into_iter()
                .map(|m| (m, None))
                .collect()
        };
        for (((swap, _), label), (m, tx)) in outs.iter().zip(labels).zip(mined) {
            let rt = &self.swaps[*swap];
            self.m.pays.push(MPay {
                label,
                key: rt.key.expect("quoted"),
                swap: *swap,
                mined: m,
                alive: true,
                tx,
                fvk: rt.fvk.clone().expect("a key"),
                spent_by_funding: false,
            });
        }
    }

    /// A reorg `depth` blocks deep. NEAR's payouts and A's fundings it removes are mined
    /// again on the new branch, which outgrows the old one by `tail` blocks before anyone
    /// syncs.
    fn reorg(&mut self, ctx: &mut Ctx, depth: u32, tail: u32) {
        let tip = ctx.chain.tip();
        let to = (tip - depth).max(self.floor);
        if to >= tip {
            return;
        }
        let to_h = u32::from(to);
        ctx.reorg(to);
        let mut again: Vec<(u32, bool, usize)> = Vec::new();
        for (i, p) in self.m.pays.iter_mut().enumerate() {
            if p.alive && u32::from(p.mined.height) > to_h {
                p.alive = false;
                again.push((u32::from(p.mined.height), false, i));
            }
        }
        for (i, f) in self.m.fundings.iter_mut().enumerate() {
            if f.alive && f.height > to_h {
                f.alive = false;
                again.push((f.height, true, i));
            }
        }
        again.sort();
        for (old, funding, i) in again {
            while u32::from(ctx.chain.tip()) + 1 < old {
                ctx.mine(1);
            }
            if funding {
                let tx = &self.m.fundings[i].tx;
                let height = ctx.chain.mine_tx(tx);
                ctx.log(
                    "chain",
                    format!("A's funding is mined again at {}", u32::from(height)),
                );
                let f = &mut self.m.fundings[i];
                f.height = u32::from(height);
                f.alive = true;
            } else {
                let p = &self.m.pays[i];
                let tx = p.tx.clone().expect("a signed payout");
                let (label, fvk, value) = (p.label.clone(), p.fvk.clone(), p.mined.value);
                let mined = ctx.remine(&label, &tx, &fvk, value, Payer::Near);
                let p = &mut self.m.pays[i];
                p.mined = mined;
                p.alive = true;
            }
        }
        while ctx.chain.tip() <= tip {
            ctx.mine(1);
        }
        ctx.mine(tail);
    }

    /// Check swap history on `slot`, after a sync so its syncs scan nothing new.
    fn recheck(&mut self, ctx: &mut Ctx, slot: usize) {
        self.sync(ctx, slot);
        let dev = self.slots[slot].expect("the device exists");
        let syncs = ctx.get(dev).syncs;
        let tip = u32::from(ctx.chain.tip());
        ctx.check_swap_history(dev);
        self.m.recheck(slot);
        let rounds = ctx.get(dev).syncs - syncs;
        for i in 0..rounds {
            self.m.sync(slot, tip + i, &[], true);
        }
    }

    /// Lets every wallet settle as the suite does, in the model too, runs the final
    /// rechecks, then registers expectations, balances, receipts and the spend check.
    fn finish(&mut self, ctx: &mut Ctx) {
        ctx.mine(3);
        for slot in 0..4 {
            if self.slots[slot].is_none() {
                continue;
            }
            for _ in 0..40 {
                let report = self.sync(ctx, slot);
                let quiet =
                    !report.pending && report.problems.is_empty() && report.scanned_blocks <= 1;
                if quiet {
                    break;
                }
                ctx.mine(1);
            }
        }
        let plan: &'p Plan = self.plan;
        for &slot in &plan.final_rechecks {
            if self.slots[slot].is_some() {
                self.recheck(ctx, slot);
            }
        }
        let mut all_found: Vec<usize> = Vec::new();
        for slot in 0..4 {
            let Some(dev) = self.slots[slot] else {
                continue;
            };
            let mut found_all = true;
            let mut balance = self.funds as i64
                - self
                    .m
                    .fundings
                    .iter()
                    .filter(|f| f.alive)
                    .map(|f| f.cost as i64)
                    .sum::<i64>();
            for pay in 0..self.m.pays.len() {
                let p = &self.m.pays[pay];
                if !p.alive {
                    continue;
                }
                let originator = self.plan.swaps[p.swap].slot == slot;
                let (class, why) = self.expected(slot, pay, originator);
                if class.found() || p.spent_by_funding {
                    balance += p.mined.value as i64;
                }
                found_all &= class.found();
                let (label, key, mined) = (p.label.clone(), p.key.label(), p.mined.clone());
                if why.starts_with("model:") {
                    ctx.check(format!("{why} ({} for {label})", NAMES[slot]), false, "");
                }
                ctx.expect(dev, &label, &key, &mined, class, why);
                if ctx.get(dev).found(mined.id()).is_some() {
                    ctx.check_receipt(dev, &label, &mined);
                    let receipt = ctx.get(dev).receipt(mined.id());
                    let ok = receipt.as_ref().is_some_and(|r| {
                        r.key.as_deref() == Some(key.as_str()) && r.value == mined.value
                    });
                    ctx.check(
                        format!(
                            "{} credits {label} to {key}, {}",
                            NAMES[slot],
                            zec(mined.value)
                        ),
                        ok,
                        format!("{receipt:?}"),
                    );
                }
            }
            // A later birthday hides the funds and spends below it, so the balance it
            // should hold is not this sum; its classes are still judged.
            let late = self.m.dev_birthday(slot) != u32::from(self.birthday);
            if !late {
                ctx.check_balance(dev, u64::try_from(balance.max(0)).expect("non-negative"));
            }
            // As F4 checks after a rewind: a swept key scans or is closed.
            let limbo: Vec<String> = ctx
                .get(dev)
                .keys()
                .into_iter()
                .filter(|k| k.active_from.is_none() && k.closed_at.is_none())
                .filter(|k| {
                    let purpose = if k.purpose == 0 {
                        Purpose::Refund
                    } else {
                        Purpose::Receive
                    };
                    ctx.get(dev)
                        .sweep_state(purpose, k.index)
                        .is_some_and(|s| s.done_height.is_some())
                })
                .map(|k| k.label())
                .collect();
            ctx.check(
                format!("every key {} swept scans or is closed", NAMES[slot]),
                limbo.is_empty(),
                format!("neither scanning nor closed after a finished sweep: {limbo:?}"),
            );
            if found_all && !late {
                all_found.push(slot);
            }
        }
        let paid = self.m.pays.iter().any(|p| p.alive);
        if self.plan.spend && paid {
            if let Some(&slot) = all_found.first() {
                ctx.spend_one_time_notes(self.slots[slot].expect("exists"));
            }
        }
    }

    /// What the model expects `slot` to make of payment `pay`, and why.
    fn expected(&self, slot: usize, pay: usize, originator: bool) -> (Class, String) {
        let dev = self.m.devs[slot].as_ref().expect("the device exists");
        if let Some((how, why)) = dev.found.get(&pay) {
            let class = match (how, originator) {
                (Found::Live, true) => Class::FoundLive,
                (Found::Sweep, true) => Class::FoundBySweep,
                (Found::Live | Found::Sweep, false) => Class::FoundAutomatically,
                (Found::Recheck, _) => Class::FoundAfterRecheck,
            };
            let why = match how {
                Found::Live => format!("{why} (an open key scans until it closes)"),
                Found::Sweep => format!(
                    "{why} (a restored or closed key is swept through the receiver directory, which lists NEAR's zero-OVK payments)"
                ),
                Found::Recheck => format!("{why}, during Check swap history"),
            };
            return (class, why);
        }
        let p = &self.m.pays[pay];
        if u32::from(p.mined.height) < dev.birthday {
            return (
                Class::MissedDocumented,
                format!(
                    "it predates {}'s birthday {}; like any note before the birthday it is not tracked",
                    dev.name, dev.birthday
                ),
            );
        }
        match dev.keys.get(&p.key) {
            None if p.key.refund => (
                Class::FoundAutomatically,
                format!(
                    "{} never recovered {} (its funding predates the birthday {}), but this refund came after the birthday, and no documented rule leaves a note after the birthday unfound",
                    dev.name,
                    p.key.label(),
                    dev.birthday
                ),
            ),
            None if !p.key.refund => (
                Class::MissedDocumented,
                format!(
                    "{} never registered {}: an incoming index beyond the restored lookahead is never swept",
                    dev.name,
                    p.key.label()
                ),
            ),
            Some(k)
                if k.closed
                    && (k.paid_before_birthday
                        || self
                            .m
                            .receipts(slot, p.key)
                            .iter()
                            .any(|(_, known)| matches!(known, Known::Mined(_)))) =>
            {
                (
                    Class::MissedDocumented,
                    format!(
                        "{} had closed {} after a known payment{}: a later payment to a closed key that was already paid is found only by Check swap history",
                        dev.name,
                        p.key.label(),
                        if k.paid_before_birthday {
                            " (one before its birthday, which marks the key paid)"
                        } else {
                            ""
                        }
                    ),
                )
            }
            k => (
                Class::MissedDocumented,
                format!(
                    "model: no documented reason for {} to miss it (key {:?})",
                    dev.name,
                    k.map(|k| (k.active_from, k.closed, k.sweep.clone()))
                ),
            ),
        }
    }
}
