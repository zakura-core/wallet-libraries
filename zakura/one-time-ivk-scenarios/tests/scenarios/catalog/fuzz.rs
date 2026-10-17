//! Seeded randomized worlds. Each seed generates one history of a seed's swaps and
//! devices and runs it against the harness: blocks, incoming and refund quotes (paid,
//! abandoned, paid late), NEAR's payouts and refunds and statuses, spends of one-time
//! notes, restores with various birthdays, a second install and a second account,
//! directory outages, failing requests, app restarts in the middle of discovery, lagging,
//! stale and bad publications, reorgs (with payouts mined again at once or paid again
//! later), Check swap history, app restarts and a fast or slow device clock.
//!
//! After every sync an oracle checks the wallet against the chain: it never shows a note
//! the chain spent as unspent, never holds a note the chain does not have, never credits
//! one twice, and its balance never exceeds what the chain still holds for its keys. Each
//! quote is checked for address reuse. Each completed discovery pass must hold every
//! payment its publication lists for the keys its search reaches. At the end the world
//! stabilizes (the directory answers, nothing is injected) and every wallet's discovery
//! must complete within a day of chain time, then go quiet: no directory request per sync.
//! The payments the documented contract promises (see [`Exec::promise`]) must be credited;
//! the others are reported, not judged. Directory requests per sync are bounded, and a run
//! of syncs that keep downloading filters, witnesses or lookups while nothing changes
//! fails.
//!
//! Seeds come from `ONE_TIME_IVK_FUZZ_SEEDS` (`start..end` or one seed; three by
//! default). A failure prints the seed, how to replay it, and the last steps.
//! `ONE_TIME_IVK_FUZZ_SKIP` drops plan steps by number, to minimize a failing seed, and
//! `ONE_TIME_IVK_FUZZ_TRACE` streams the trace as a replay runs.
//! Regression scenarios for what the worlds found run with `ONE_TIME_IVK_FUZZ_FINDINGS=1`.
//!
//! Left out: payers other than NEAR's zero OVK, mempool payouts, refund quotes on a
//! second install or restored device (they would spend the same notes as the original),
//! payouts reorged out for good, a directory that omits payments (E7 covers it), and a
//! refund key's watch after a restore (judged only through discovery and Check swap
//! history).

use std::{
    collections::{BTreeMap, BTreeSet},
    panic::AssertUnwindSafe,
    sync::Arc,
};

use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use zakura_one_time_ivk::swap::{COMPLETION_LIMIT_SECS, RESTORE_WATCH_SECS};
use zakura_one_time_ivk_scenarios::{Class, PaymentResult, zec};
use zcash_client_sqlite::wallet::one_time_ivk::swap::RECEIVE_RECLAIM_SECONDS;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BlockHeight;

use super::{FUZZ, Scenario, Schedule};
use crate::harness::{
    Ctx, Dev,
    chain::{BLOCK_SECS, DAY, HOUR, MINUTE, Mined, Payer, ZEC, block_time, day_of},
    device::{IncomingSwap, RefundSwap, SyncReport},
    directory::{Bad, Fault, Frozen},
};

/// The seed every world's wallets share.
const SEED: [u8; 32] = [0x7a; 32];
/// Seeds a run without `ONE_TIME_IVK_FUZZ_SEEDS` generates.
const DEFAULT_SEEDS: u64 = 3;
/// Ironwood funds each funded account starts with.
const FUNDS: u64 = 5 * ZEC;
/// Fee margin the app keeps when funding a deposit.
const FUNDING_FEE: u64 = 15_000;
/// Keys discovery always checks (`zakura_pir_receiver::FIRST_WINDOW`).
const FIRST_WINDOW: u64 = zakura_pir_receiver::FIRST_WINDOW;
/// Unused keys after which discovery's search stops (`zakura_pir_receiver::GAP`).
const GAP: u64 = zakura_pir_receiver::GAP;
/// How old a recent set's read may be and still rule a receiver out (the receiver
/// client's `RECENT_SET_MAX_AGE_SECS`).
const RECENT_SET_MAX_AGE_SECS: i64 = 15 * 60;
/// Margin the oracle keeps around a documented time limit before judging a payment.
const MARGIN: i64 = 2 * HOUR;
/// Consecutive stable syncs that may download the same directory material.
const STREAK: u32 = 12;

const A: usize = 0;
const A2: usize = 1;
const B1: usize = 2;
const B2: usize = 3;
const NAMES: [&str; 4] = ["A", "A2", "B1", "B2"];

/// One wallet account: a device slot and the seed's account number on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct W {
    slot: usize,
    acct: u8,
}

impl W {
    /// `A`, or `A#1` for the second account.
    fn name(self) -> String {
        if self.acct == 0 {
            NAMES[self.slot].into()
        } else {
            format!("{}#{}", NAMES[self.slot], self.acct)
        }
    }
}

pub fn all() -> Vec<Scenario> {
    let (start, end) = seeds();
    let mut scenarios = findings();
    scenarios.extend((start..end).map(scenario));
    scenarios
}

/// Minimal reproductions of what the randomized worlds found, which fail until fixed, so
/// they run only with `ONE_TIME_IVK_FUZZ_FINDINGS=1`.
fn findings() -> Vec<Scenario> {
    if std::env::var_os("ONE_TIME_IVK_FUZZ_FINDINGS").is_none() {
        return Vec::new();
    }
    vec![
        memo_after_pass(false),
        memo_after_pass(true),
        seen_after_pass(),
    ]
}

/// The incoming side of [`memo_after_pass`]: A quotes and NEAR pays after A2 finished its
/// pass. A2's next quote finds A's address in NEAR's seen set and registers it for a lookup
/// (`prepare_receive_reservation`), again with the old pass publication as the cutoff, so
/// the lookup cannot list the payout.
fn seen_after_pass() -> Scenario {
    Scenario {
        id: "Z-finding-seen-key-after-pass".into(),
        group: FUZZ,
        title: "A second install registers the other install's seen address after its pass".into(),
        summary: "An incoming key issuance registers from the seen set is looked up only through \
            the account's current pass publication, which predates the payout."
            .into(),
        params: vec![],
        slow: false,
        run: Box::new(|ctx| {
            ctx.mine(20);
            let birthday = ctx.chain.tip() + 1;
            ctx.mine(5);
            let a = ctx.device("A", SEED, birthday);
            let a2 = ctx.device("A2", SEED, birthday);
            ctx.mine(10);
            for dev in [a, a, a2, a2] {
                ctx.sync(dev);
            }
            ctx.wait(HOUR);
            ctx.sync(a);
            let swap = ctx.quote_incoming(a, HOUR).expect("an incoming quote");
            ctx.wait(20 * MINUTE);
            let payout = ctx.pay("payout", &swap.label(), &swap.fvk, ZEC, Payer::Near);
            ctx.mine(1);
            ctx.observe_incoming(a, &swap, "SUCCESS", Some(ZEC));
            ctx.sync(a);
            ctx.wait(HOUR);
            ctx.sync(a2);
            let other = ctx.quote_incoming(a2, HOUR).expect("A2's quote");
            ctx.check(
                "A2 skips A's address",
                other.index != swap.index,
                format!("A2 issued {}", other.label()),
            );
            for _ in 0..3 {
                ctx.mine(1);
                ctx.sync(a2);
            }
            let lookup = ctx
                .get(a2)
                .lookup_state(zakura_one_time_ivk::Purpose::Receive, swap.index);
            ctx.check(
                format!(
                    "A2's lookup of {} reads past the payout at {}",
                    swap.label(),
                    u32::from(payout.height)
                ),
                lookup.is_some_and(|l| l.done_height.is_none_or(|h| h >= u32::from(payout.height))),
                format!("lookup {lookup:?}"),
            );
            ctx.expect(
                a,
                "payout",
                &swap.label(),
                &payout,
                Class::FoundLive,
                "A quoted I0 and scans it.",
            );
            ctx.expect(
                a2,
                "payout",
                &swap.label(),
                &payout,
                Class::FoundAutomatically,
                "Issuance registers the seen address for a lookup, and discovery looks up a key registered after it finished in its next run.",
            );
        }),
    }
}

/// Seed 300: A funds a ZEC-to-X swap after A2, a second install of the seed, finished its
/// discovery pass. A2 scans the funding memo, which registers the refund key for a lookup
/// (`recover_refund_memos`), but the lookup's cutoff is A2's old pass publication, below
/// the memo, so it cannot find the refund, and the key closes as looked up. `early`: A2
/// scans the memo before NEAR refunds.
fn memo_after_pass(early: bool) -> Scenario {
    let when = if early { "before" } else { "after" };
    Scenario {
        id: format!("Z-finding-memo-after-pass-scanned-{when}-refund"),
        group: FUZZ,
        title: format!(
            "A second install scans a funding memo after its discovery pass, {when} the refund"
        ),
        summary: "A refund key recovered from a funding memo is looked up only through the \
            account's current pass publication, which predates the memo, so the refund is never \
            found without Check swap history."
            .into(),
        params: vec![("A2 scans the memo".into(), format!("{when} the refund"))],
        slow: false,
        run: Box::new(move |ctx| {
            ctx.mine(20);
            let birthday = ctx.chain.tip() + 1;
            ctx.mine(5);
            let a = ctx.device("A", SEED, birthday);
            let a2 = ctx.device("A2", SEED, birthday);
            let fvk = ctx.get(a).fvk.clone();
            ctx.pay("A's funds", "A's address", &fvk, FUNDS, Payer::Wallet);
            ctx.mine(10);
            for dev in [a, a, a2, a2] {
                ctx.sync(dev);
            }
            ctx.wait(HOUR);
            ctx.sync(a);
            let swap = ctx.quote_refund(a, HOUR).expect("a refund key");
            let (funded, _) = ctx.fund_refund(a, &swap, ZEC / 2);
            ctx.mine(5);
            ctx.sync(a);
            if early {
                ctx.sync(a2);
                ctx.mine(1);
                ctx.sync(a2);
            }
            ctx.wait(30 * MINUTE);
            let value = ZEC / 2 - 10_000;
            let refund = ctx.pay("refund", &swap.label(), &swap.fvk, value, Payer::Near);
            ctx.mine(1);
            ctx.observe_refund(a, &swap, "REFUNDED", Some(value));
            ctx.sync(a);
            ctx.wait(HOUR);
            for _ in 0..3 {
                ctx.sync(a2);
                ctx.mine(1);
            }
            let lookup = ctx
                .get(a2)
                .lookup_state(zakura_one_time_ivk::Purpose::Refund, swap.index);
            let keys: Vec<String> = ctx
                .get(a2)
                .keys()
                .iter()
                .map(|k| format!("{} {:?}/{:?}", k.label(), k.active_from, k.closed_at))
                .collect();
            ctx.check(
                format!(
                    "A2's lookup of {} reads past the funding at {}",
                    swap.label(),
                    u32::from(funded)
                ),
                lookup.is_some_and(|l| l.done_height.is_none_or(|h| h >= u32::from(funded))),
                format!("lookup {lookup:?}; A2's keys {keys:?}"),
            );
            ctx.expect(
                a,
                "refund",
                &swap.label(),
                &refund,
                Class::FoundLive,
                "A funded R0 and scans it.",
            );
            ctx.expect(
                a2,
                "refund",
                &swap.label(),
                &refund,
                Class::FoundAutomatically,
                "A2 recovers R0 from A's funding memo, and discovery looks up a key registered after it finished in its next run.",
            );
            ctx.check_same_balance(a, a2);
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

/// Plan steps `ONE_TIME_IVK_FUZZ_SKIP` drops, by number.
fn skipped() -> BTreeSet<usize> {
    std::env::var("ONE_TIME_IVK_FUZZ_SKIP")
        .map(|spec| {
            spec.split(',')
                .filter(|s| !s.trim().is_empty())
                .map(|s| {
                    s.trim()
                        .parse()
                        .expect("ONE_TIME_IVK_FUZZ_SKIP holds step numbers")
                })
                .collect()
        })
        .unwrap_or_default()
}

/// How `ONE_TIME_IVK_FUZZ_PROFILE` biases the worlds. Its name joins the scenario ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile {
    Default,
    /// Restores after spends, with the directory down or the app stopping at first, so
    /// discovery finds payments behind the scan (the late path and the spend journal).
    Late,
    /// Every world reorgs.
    Reorg,
}

impl Profile {
    /// The profile `ONE_TIME_IVK_FUZZ_PROFILE` names.
    fn from_env() -> Self {
        match std::env::var("ONE_TIME_IVK_FUZZ_PROFILE").as_deref() {
            Ok("late") => Self::Late,
            Ok("reorg") => Self::Reorg,
            Ok("") | Err(_) => Self::Default,
            Ok(other) => panic!("unknown ONE_TIME_IVK_FUZZ_PROFILE {other}"),
        }
    }
}

/// The scenario seed `seed` generates.
fn scenario(seed: u64) -> Scenario {
    let profile = Profile::from_env();
    let plan = Plan::generate(seed, profile);
    let name = match profile {
        Profile::Default => String::new(),
        Profile::Late => "late-".into(),
        Profile::Reorg => "reorg-".into(),
    };
    Scenario {
        id: format!("Z-fuzz-{name}{seed:06}"),
        group: FUZZ,
        title: format!("Randomized world, seed {seed}"),
        summary: plan.notes.join("; "),
        params: plan.params(),
        slow: plan.horizon > 8 * DAY,
        run: Box::new(move |ctx| run(&plan, ctx)),
    }
}

/// Runs `plan` in `ctx`, printing the seed, how to replay it and the last steps when an
/// oracle fails or the world panics.
fn run(plan: &Plan, ctx: &mut Ctx) {
    let skip = skipped();
    let mut ex = Exec::new(plan);
    let ran = std::panic::catch_unwind(AssertUnwindSafe(|| ex.run(ctx, &skip)));
    let failed = !ex.violations.is_empty() || ran.is_err();
    if failed {
        let mut text = format!(
            "\nZ-fuzz seed {} failed. Replay: ONE_TIME_IVK_FUZZ_SEEDS={} python3 scripts/dev.py \
             --config one-time-ivk-scenarios test Z-fuzz-{:06}\n",
            plan.seed, plan.seed, plan.seed
        );
        for v in ex.violations.iter().take(6) {
            text.push_str(&format!("  violation: {v}\n"));
        }
        if ran.is_err() {
            text.push_str("  the world panicked\n");
        }
        let from = ex.trace.len().saturating_sub(40);
        for line in &ex.trace[from..] {
            text.push_str(&format!("  | {line}\n"));
        }
        eprint!("{text}");
    }
    if let Err(payload) = ran {
        std::panic::resume_unwind(payload);
    }
}

/// A deterministic 64-bit generator (SplitMix64) seeded from the scenario seed.
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

/// One planned swap.
#[derive(Clone, Copy, Debug)]
struct SwapPlan {
    kind: Kind,
    wallet: W,
    deadline_in: i64,
}

/// How a spend of one-time notes pays a stranger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpendMode {
    /// A small payment, with change.
    Change,
    /// Everything spendable less the fee, so the change carries no value.
    Exact,
    /// The wallet's send-max proposal.
    Max,
}

/// A directory fault for one slot's next discovery run.
#[derive(Clone, Copy, Debug)]
enum FaultKind {
    /// The first three requests get this HTTP status.
    Http(u16),
    /// The app stops during the request after this many answered ones, and restarts.
    StopAfter(usize),
}

/// How the directory's publication goes wrong for a while, for every device.
#[derive(Clone, Copy, Debug)]
enum PubKind {
    /// It trails the tip by this many blocks.
    Lag(u32),
    /// Its manifest misstates its last block.
    Bad(Bad),
    /// The indexer stalls: it serves the publication it made at this step.
    Frozen,
}

/// The birthday a restore enters.
#[derive(Clone, Copy, Debug)]
enum Birthday {
    /// The original wallet's birthday.
    Original,
    /// This percentage of the way from the original birthday to the tip.
    Between(u32),
    /// The restore's own day.
    Today,
}

/// One planned step.
#[derive(Clone, Debug)]
enum Step {
    Sync(usize),
    Quote(usize),
    Fund(usize),
    Status {
        swap: usize,
        status: &'static str,
        amount: Option<u64>,
    },
    /// One NEAR transaction paying each (swap, value).
    Pay(Vec<(usize, u64)>),
    Spend {
        w: W,
        mode: SpendMode,
    },
    Restore {
        slot: usize,
        birthday: Birthday,
        accounts: u8,
    },
    AddAccount {
        fresh: bool,
    },
    Directory {
        slot: usize,
        up: bool,
    },
    Fault {
        slot: usize,
        kind: FaultKind,
    },
    Publication(Option<PubKind>),
    Reorg {
        depth: u32,
        tail: u32,
        /// NEAR pays the removed payouts again in new transactions this long after,
        /// instead of the same transactions being mined again at once.
        late: Option<i64>,
        /// Every device syncs just before, so each has scanned the blocks replaced.
        synced: bool,
    },
    Recheck(W),
    Restart(usize),
}

/// A generated world.
#[derive(Clone, Debug)]
struct Plan {
    seed: u64,
    horizon: i64,
    skew: i64,
    fresh: bool,
    a2: bool,
    read_lag: i64,
    /// NEAR pays with signed transactions, which a reorg can return to the chain.
    real_payouts: bool,
    swaps: Vec<SwapPlan>,
    steps: Vec<(i64, Step)>,
    final_rechecks: Vec<W>,
    notes: Vec<String>,
}

impl Plan {
    /// The world seed `seed` generates.
    fn generate(seed: u64, profile: Profile) -> Self {
        let mut r = Rng::new(seed);
        let horizon = r.weighted(&[(8 * HOUR, 30), (2 * DAY, 40), (5 * DAY, 20), (35 * DAY, 10)]);
        let fresh = r.chance(40);
        let skew = if r.chance(15) {
            r.pick(&[5 * MINUTE, 2 * HOUR, -2 * HOUR, DAY, -DAY])
        } else {
            0
        };
        let a2 = r.chance(25);
        let read_lag = r.weighted(&[(MINUTE, 85), (30 * MINUTE, 10), (6 * HOUR, 5)]);
        let reorg = profile == Profile::Reorg || r.chance(25);
        let mut s = Schedule::new();
        let mut notes = vec![format!("horizon {}", span_of(horizon))];
        if fresh {
            notes.push("A's seed is fresh".into());
        }
        if skew != 0 {
            notes.push(format!("A's clock {}", span_of_signed(skew)));
        }
        if read_lag != MINUTE {
            notes.push(format!("NEAR feed {} behind", span_of(read_lag)));
        }
        if a2 {
            notes.push("A2 installs the seed alongside A".into());
        }
        let second = r.chance(20).then(|| r.range(10 * MINUTE, horizon / 3));
        if let Some(at) = second {
            let fresh = r.chance(50);
            s.at(at, Step::AddAccount { fresh });
            notes.push(format!(
                "A adds a second account at +{}{}",
                span_of(at),
                if fresh { ", fresh" } else { "" }
            ));
        }
        let count = if profile == Profile::Late {
            r.weighted(&[(3usize, 40), (4, 30), (6, 30)])
        } else {
            r.weighted(&[(1usize, 10), (2, 25), (3, 30), (4, 20), (6, 15)])
        };
        let mut swaps = Vec::new();
        let mut payouts: Vec<(i64, Vec<(usize, u64)>)> = Vec::new();
        for _ in 0..count {
            let id = swaps.len();
            let mut wallet = W { slot: A, acct: 0 };
            let mut lo = 10 * MINUTE;
            if let Some(at) = second.filter(|_| r.chance(30)) {
                wallet.acct = 1;
                lo = at + 10 * MINUTE;
            } else if a2 && r.chance(35) {
                wallet.slot = A2;
            }
            let quote_at = r.range(lo, (horizon * 6 / 10).max(lo + HOUR));
            let refund = wallet.slot == A && r.chance(30);
            if refund {
                let deadline_in = r.pick(&[20 * MINUTE, HOUR, 3 * HOUR]);
                swaps.push(SwapPlan {
                    kind: Kind::Refund,
                    wallet,
                    deadline_in,
                });
                let note = plan_refund(&mut r, &mut s, &mut payouts, id, quote_at);
                notes.push(format!(
                    "R-swap {id} on {} at +{}: {note}",
                    wallet.name(),
                    span_of(quote_at)
                ));
            } else {
                let deadline_in = r.pick(&[20 * MINUTE, HOUR, 3 * HOUR, DAY]);
                swaps.push(SwapPlan {
                    kind: Kind::Incoming,
                    wallet,
                    deadline_in,
                });
                let note = plan_incoming(&mut r, &mut s, &mut payouts, id, quote_at, deadline_in);
                notes.push(format!(
                    "I-swap {id} on {} at +{}, deadline {}: {note}",
                    wallet.name(),
                    span_of(quote_at),
                    span_of(deadline_in)
                ));
            }
        }
        // NEAR sometimes batches two swaps' payouts into one transaction.
        if !reorg && payouts.len() >= 2 && r.chance(15) {
            let (i, j) = (0, 1);
            if payouts[i].1[0].0 != payouts[j].1[0].0 {
                let at = payouts[i].0.max(payouts[j].0);
                let other = payouts.remove(j);
                payouts[i].0 = at;
                payouts[i].1.extend(other.1);
                notes.push("NEAR pays two swaps in one transaction".into());
            }
        }
        let last = payouts
            .iter()
            .map(|(at, _)| *at)
            .max()
            .unwrap_or(0)
            .max(horizon);
        let end = last + 2 * HOUR;
        // Seed restores, sometimes just after a payout.
        let late = profile == Profile::Late;
        let restores = if late {
            r.weighted(&[(1usize, 60), (2, 40)])
        } else {
            r.weighted(&[(0usize, 35), (1, 45), (2, 20)])
        };
        let mut created = vec![(A, 0)];
        if a2 {
            created.push((A2, 0));
        }
        for k in 0..restores {
            let slot = [B1, B2][k];
            let at = if !payouts.is_empty() && r.chance(25) {
                let i = r.range(0, payouts.len() as i64) as usize;
                payouts[i].0 + r.pick(&[BLOCK_SECS, 3 * BLOCK_SECS, HOUR])
            } else {
                r.range(if late { horizon / 2 } else { 20 * MINUTE }, horizon)
            };
            let between = Birthday::Between(r.range(10, 95) as u32);
            let birthday = r.weighted(&[
                (Birthday::Original, 65),
                (between, 20),
                (Birthday::Today, 15),
            ]);
            let accounts = if second.is_some_and(|t| t < at) && r.chance(70) {
                2
            } else {
                1
            };
            s.at(
                at,
                Step::Restore {
                    slot,
                    birthday,
                    accounts,
                },
            );
            let mut note = format!(
                "{} restores at +{}, birthday {birthday:?}, {accounts} account(s)",
                NAMES[slot],
                span_of(at)
            );
            let trouble = if late {
                [(0, 0), (1, 70), (2, 0), (3, 30)]
            } else {
                [(0, 60), (1, 15), (2, 10), (3, 15)]
            };
            match r.weighted(&trouble) {
                1 => {
                    let len = r.range(10 * MINUTE, 6 * HOUR);
                    s.at(at, Step::Directory { slot, up: false });
                    s.at(at + len, Step::Directory { slot, up: true });
                    note.push_str(&format!(", directory down for {}", span_of(len)));
                }
                2 => {
                    let status = r.pick(&[503u16, 429, 410]);
                    s.at(
                        at,
                        Step::Fault {
                            slot,
                            kind: FaultKind::Http(status),
                        },
                    );
                    note.push_str(&format!(", directory answers {status} at first"));
                }
                3 => {
                    let n = r.range(0, 9) as usize;
                    s.at(
                        at,
                        Step::Fault {
                            slot,
                            kind: FaultKind::StopAfter(n),
                        },
                    );
                    note.push_str(&format!(", the app stops after {n} directory requests"));
                }
                _ => {}
            }
            // The app syncs at once, after any trouble above takes hold.
            s.at(at, Step::Sync(slot));
            notes.push(note);
            created.push((slot, at));
            // The restored device quotes incoming swaps of its own.
            if r.chance(40) {
                for _ in 0..r.weighted(&[(1usize, 70), (2, 30)]) {
                    let quote_at = at + r.range(30 * MINUTE, DAY);
                    if quote_at >= end - HOUR {
                        continue;
                    }
                    let id = swaps.len();
                    let deadline_in = r.pick(&[20 * MINUTE, HOUR, 3 * HOUR]);
                    let wallet = W { slot, acct: 0 };
                    swaps.push(SwapPlan {
                        kind: Kind::Incoming,
                        wallet,
                        deadline_in,
                    });
                    let note =
                        plan_incoming(&mut r, &mut s, &mut payouts, id, quote_at, deadline_in);
                    notes.push(format!(
                        "I-swap {id} on {} at +{}, deadline {}: {note}",
                        wallet.name(),
                        span_of(quote_at),
                        span_of(deadline_in)
                    ));
                }
            }
        }
        // Spends of one-time notes, through ordinary sends.
        let spends = if late {
            r.weighted(&[(2usize, 50), (3, 50)])
        } else {
            r.weighted(&[(0usize, 50), (1, 25), (2, 17), (3, 8)])
        };
        for _ in 0..spends {
            let at = r.range(horizon / 4, if late { horizon / 2 } else { end });
            let candidates: Vec<usize> = created
                .iter()
                .filter(|(slot, t)| *t < at && *slot != A2)
                .map(|(slot, _)| *slot)
                .collect();
            let slot = if r.chance(65) { A } else { r.pick(&candidates) };
            let acct = if second.is_some_and(|t| t < at) && slot == A && r.chance(25) {
                1
            } else {
                0
            };
            let mode = r.pick(&[SpendMode::Change, SpendMode::Exact, SpendMode::Max]);
            let w = W { slot, acct };
            s.at(at, Step::Spend { w, mode });
            notes.push(format!(
                "{} spends ({mode:?}) at +{}",
                w.name(),
                span_of(at)
            ));
        }
        // Syncs, each device with maybe one offline period.
        for &(slot, at) in &created {
            sync_steps(
                &mut r,
                &mut s,
                slot,
                at + 5 * MINUTE,
                end,
                horizon,
                &mut notes,
            );
        }
        // Directory trouble for A.
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
        if r.chance(15) {
            let at = r.range(HOUR, horizon);
            let kind = if r.chance(50) {
                FaultKind::Http(r.pick(&[503u16, 429, 410]))
            } else {
                FaultKind::StopAfter(r.range(0, 6) as usize)
            };
            s.at(at, Step::Fault { slot: A, kind });
            notes.push(format!("A's directory fault {kind:?} at +{}", span_of(at)));
        }
        // A reorg, maybe aimed just past a payout, maybe with a stalled indexer.
        let mut reorg_at = None;
        if reorg {
            let at = if !payouts.is_empty() && r.chance(60) {
                let i = r.range(0, payouts.len() as i64) as usize;
                payouts[i].0 + r.range(1, 19) * BLOCK_SECS
            } else {
                r.range(horizon * 15 / 100, horizon * 85 / 100).max(HOUR)
            };
            let depth = r.pick(&[2u32, 3, 4, 7, 10, 12, 18, 25]);
            let tail = r.range(0, 6) as u32;
            let late = r
                .chance(30)
                .then(|| r.pick(&[30 * MINUTE, 6 * HOUR, 2 * DAY]));
            let synced = r.chance(70);
            s.at(
                at,
                Step::Reorg {
                    depth,
                    tail,
                    late,
                    synced,
                },
            );
            notes.push(format!(
                "{depth}-block reorg at +{}{}",
                span_of(at),
                late.map_or(String::new(), |l| format!(
                    ", payouts paid again {} later",
                    span_of(l)
                ))
            ));
            reorg_at = Some(at);
        }
        // The publication goes wrong for a while.
        if r.chance(25) {
            let kind = r.pick(&[
                PubKind::Lag(20),
                PubKind::Lag(60),
                PubKind::Bad(Bad::TreeSize),
                PubKind::Bad(Bad::Hash),
                PubKind::Frozen,
            ]);
            let at = match (kind, reorg_at) {
                (PubKind::Frozen, Some(t)) => t - BLOCK_SECS,
                _ => r.range(HOUR, horizon),
            };
            let len = r.range(10 * MINUTE, 6 * HOUR);
            s.at(at, Step::Publication(Some(kind)));
            s.at(at + len, Step::Publication(None));
            notes.push(format!(
                "publication {kind:?} at +{} for {}",
                span_of(at),
                span_of(len)
            ));
        }
        if r.chance(15) {
            let at = r.range(HOUR, horizon);
            s.at(at, Step::Restart(A));
            notes.push(format!("A's app restarts at +{}", span_of(at)));
        }
        if r.chance(15) {
            let at = r.range(horizon / 2, end);
            let options: Vec<(usize, i64)> =
                created.iter().copied().filter(|(_, t)| *t < at).collect();
            let (slot, _) = r.pick(&options);
            let w = W { slot, acct: 0 };
            s.at(at, Step::Recheck(w));
            notes.push(format!(
                "{} runs Check swap history at +{}",
                w.name(),
                span_of(at)
            ));
        }
        let mut final_rechecks = Vec::new();
        for &(slot, _) in &created {
            if r.chance(25) {
                final_rechecks.push(W { slot, acct: 0 });
            }
        }
        if !final_rechecks.is_empty() {
            let names: Vec<_> = final_rechecks.iter().map(|w| w.name()).collect();
            notes.push(format!(
                "at the end {} run Check swap history",
                names.join(", ")
            ));
        }
        for (at, outs) in payouts {
            s.at(at, Step::Pay(outs));
        }
        Self {
            seed,
            horizon,
            skew,
            fresh,
            a2,
            read_lag,
            real_payouts: reorg,
            swaps,
            steps: s.into_steps(),
            final_rechecks,
            notes,
        }
    }

    /// The report's parameters.
    fn params(&self) -> Vec<(String, String)> {
        vec![
            ("seed".into(), self.seed.to_string()),
            ("swaps".into(), self.swaps.len().to_string()),
            ("steps".into(), self.steps.len().to_string()),
            ("second install".into(), self.a2.to_string()),
            ("fresh seed".into(), self.fresh.to_string()),
            ("A clock skew".into(), format!("{} s", self.skew)),
            ("feed read lag".into(), span_of(self.read_lag)),
            ("reorg".into(), self.real_payouts.to_string()),
            ("horizon".into(), span_of(self.horizon)),
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

/// `secs` with its sign.
fn span_of_signed(secs: i64) -> String {
    if secs < 0 {
        format!("-{}", span_of(-secs))
    } else {
        format!("+{}", span_of(secs))
    }
}

/// Plans an incoming swap quoted at `quote_at`: NEAR's payouts and statuses.
fn plan_incoming(
    r: &mut Rng,
    s: &mut Schedule<Step>,
    payouts: &mut Vec<(i64, Vec<(usize, u64)>)>,
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
    if r.chance(30) {
        // Unpaid: never deposited, refunded on the source chain, or paid very late.
        let mode = r.weighted(&[(0, 35), (1, 25), (2, 10), (3, 15), (4, 15)]);
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
                return format!("unpaid, {end}");
            }
            3 => {
                // Abandoned, reclaimed, then deposited late after all and paid.
                status(s, quote_at + MINUTE, "PENDING_DEPOSIT", None);
                let reclaim = deadline + RECEIVE_RECLAIM_SECONDS + r.range(MINUTE, HOUR);
                status(s, reclaim, "PENDING_DEPOSIT", None);
                let at = reclaim + r.pick(&[HOUR, DAY]);
                let v = r.pick(&[ZEC / 2, ZEC]);
                payouts.push((at, vec![(id, v)]));
                return format!("abandoned and reclaimed, then paid {} late", zec(v));
            }
            _ => return "never deposited, NEAR silent".into(),
        }
    }
    let deposit_at = quote_at + r.range(MINUTE, (deadline_in * 9 / 10).max(2 * MINUTE));
    let timing = r.weighted(&[(0, 75), (1, 15), (2, 10)]);
    let p1 = match timing {
        0 => deposit_at + r.pick(&[2 * MINUTE, 10 * MINUTE, 40 * MINUTE, 2 * HOUR]),
        1 => deadline + r.pick(&[DAY, 7 * DAY]),
        _ => deadline + r.pick(&[29 * DAY, 31 * DAY]),
    };
    let v1 = r.pick(&[ZEC / 2, ZEC, 5 * ZEC / 4]);
    let mut note = format!(
        "paid {} at deadline{}",
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
            payouts.push((p1, vec![(id, v1), (id, v2)]));
            note.push_str(&format!(", and {} in the same transaction", zec(v2)));
        } else {
            payouts.push((p1, vec![(id, v1)]));
            payouts.push((p1 + gap, vec![(id, v2)]));
            note.push_str(&format!(", and {} {} later", zec(v2), span_of(gap)));
        }
    } else {
        payouts.push((p1, vec![(id, v1)]));
    }
    let mode = r.weighted(&[(0, 60), (1, 20), (2, 20)]);
    if mode != 1 {
        if r.chance(50) {
            status(s, quote_at + MINUTE, "PENDING_DEPOSIT", None);
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
                r.weighted(&[(Some(total), 60), (None, 40)])
            };
            status(s, at, "SUCCESS", amount);
            note.push_str(&format!(
                "; SUCCESS at payout{} amountOut {}",
                span_of_signed(at - p1),
                amount.map_or("missing".to_string(), zec)
            ));
        }
        1 => note.push_str("; NEAR silent"),
        _ => note.push_str("; statuses stop at PROCESSING"),
    }
    note
}

/// Plans a ZEC-to-X swap quoted at `quote_at`: its funding, NEAR's refunds and statuses.
fn plan_refund(
    r: &mut Rng,
    s: &mut Schedule<Step>,
    payouts: &mut Vec<(i64, Vec<(usize, u64)>)>,
    id: usize,
    quote_at: i64,
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
    if r.chance(15) {
        if r.chance(50) {
            status(s, quote_at + MINUTE, "PENDING_DEPOSIT", None);
        }
        return "never funded".into();
    }
    let fund_at = quote_at + r.pick(&[MINUTE, 5 * MINUTE]);
    s.at(fund_at, Step::Fund(id));
    let deposit = ZEC / 2;
    let mut note = format!("funds {}", zec(deposit));
    if r.chance(80) {
        status(s, fund_at + 5 * MINUTE, "PROCESSING", None);
    }
    match r.weighted(&[(0, 50), (1, 20), (2, 30)]) {
        0 => {
            let delay = r.weighted(&[
                (30 * MINUTE, 20),
                (2 * HOUR, 20),
                (DAY, 20),
                (7 * DAY, 15),
                (25 * DAY, 10),
                (31 * DAY, 15),
            ]);
            let refund_at = fund_at + delay;
            let v = if r.chance(75) {
                deposit - 10_000
            } else {
                deposit / 2
            };
            payouts.push((refund_at, vec![(id, v)]));
            note.push_str(&format!(
                "; refunded {} {} after funding",
                zec(v),
                span_of(delay)
            ));
            let at = refund_at + r.pick(&[-MINUTE, MINUTE, HOUR]);
            match r.weighted(&[(0, 60), (1, 15), (2, 10), (3, 15)]) {
                0 => status(s, at, "REFUNDED", Some(v)),
                1 => status(s, at, "FAILED", Some(v)),
                2 => status(s, at, "REFUNDED", None),
                _ => note.push_str(", NEAR silent"),
            }
            if r.chance(15) {
                let gap = r.pick(&[BLOCK_SECS, HOUR, 7 * DAY]);
                payouts.push((refund_at + gap, vec![(id, ZEC / 20)]));
                note.push_str(&format!(", refunded again {} later", span_of(gap)));
            }
        }
        1 => {
            let v = deposit / 4;
            let at = fund_at + r.pick(&[HOUR, DAY]);
            payouts.push((at, vec![(id, v)]));
            status(s, at + r.pick(&[-MINUTE, MINUTE]), "SUCCESS", Some(v));
            note.push_str(&format!("; SUCCESS with an excess refund of {}", zec(v)));
        }
        _ => {
            let at = fund_at + r.pick(&[30 * MINUTE, 2 * HOUR]);
            status(s, at, "SUCCESS", None);
            note.push_str("; SUCCESS, no refund");
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
    let every = r
        .pick(&[15 * MINUTE, HOUR, 3 * HOUR, 12 * HOUR])
        .max(horizon / 30)
        .max((to - from) / 30);
    let offline = r.chance(35).then(|| {
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

/// A one-time key of the seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct KeyRef {
    acct: u8,
    refund: bool,
    index: u64,
}

impl KeyRef {
    /// `R3` or `I0`, with `#1` for the second account.
    fn label(self) -> String {
        let p = if self.refund { "R" } else { "I" };
        if self.acct == 0 {
            format!("{p}{}", self.index)
        } else {
            format!("{p}{}#{}", self.index, self.acct)
        }
    }
}

/// A swap as it ran.
#[derive(Default)]
struct SwapRt {
    key: Option<KeyRef>,
    fvk: Option<FullViewingKey>,
    incoming: Option<IncomingSwap>,
    refund: Option<RefundSwap>,
    quoted_height: u32,
    deadline: i64,
    funded_height: Option<u32>,
    /// Statuses the quoting wallet recorded: chain time, status and amount.
    statuses: Vec<(i64, &'static str, Option<u64>)>,
    payouts: u32,
}

/// A NEAR payment to a one-time key.
struct OPay {
    label: String,
    swap: usize,
    key: KeyRef,
    mined: Mined,
    alive: bool,
    tx: Option<Transaction>,
}

/// A transaction one of the seed's wallets built, which a reorg mines again.
struct OwnTx {
    tx: Transaction,
    height: u32,
    alive: bool,
}

/// NEAR was given `key` at `at` (chain time) by wallet `w`.
struct Given {
    key: KeyRef,
    at: i64,
    w: W,
}

/// A discovery pass a wallet completed.
#[derive(Clone, Copy, Debug)]
struct Pass {
    end: u32,
    /// When the NEAR feed the pass's filters came from was last read.
    feed_until: i64,
    /// The pass a Check swap history started.
    recheck: bool,
    /// The wallet's first completed pass.
    first: bool,
}

/// How a wallet credited a payment.
#[derive(Clone, Copy, Debug)]
struct Credit {
    class: Class,
    height: u32,
}

/// One wallet note as the oracle reads it.
struct Note {
    id: ([u8; 32], u32),
    value: u64,
    nf: Option<[u8; 32]>,
    mined: Option<u32>,
    one_time: bool,
    spent: bool,
}

/// Directory requests by kind, for one sync.
#[derive(Default)]
struct Requests {
    filters: u32,
    witnesses: u32,
    queries: u32,
    total: u32,
}

impl Requests {
    /// Classifies `requests`.
    fn of(requests: &[String]) -> Self {
        let mut r = Self::default();
        for q in requests {
            r.total += 1;
            if q.contains("/filters/") {
                r.filters += 1;
            } else if q.contains("/witness/") {
                r.witnesses += 1;
            } else if q.ends_with("/query") {
                r.queries += 1;
            }
        }
        r
    }
}

/// Runs a plan against the harness and checks it with the oracle.
struct Exec<'p> {
    plan: &'p Plan,
    /// Each slot's device, which syncs every account on it.
    slots: [Option<Dev>; 4],
    /// Each wallet account's handle.
    wallets: BTreeMap<W, Dev>,
    births: BTreeMap<W, u32>,
    /// Accounts declared fresh, which have no discovery.
    fresh: BTreeSet<W>,
    swaps: Vec<SwapRt>,
    pays: Vec<OPay>,
    own: Vec<OwnTx>,
    given: Vec<Given>,
    /// Payments NEAR pays again after a reorg removed them: (due time, payment).
    repay: Vec<(i64, usize)>,
    passes: BTreeMap<W, Vec<Pass>>,
    rechecking: BTreeSet<W>,
    /// Wallets running a Check swap history, whose finds count as the recheck's.
    in_recheck: BTreeSet<W>,
    credits: BTreeMap<(W, ([u8; 32], u32)), Credit>,
    /// Ordinary funds paid to each account at setup.
    funds: Vec<Mined>,
    /// Slots whose directory has trouble this sync, which the cost checks excuse.
    troubled: BTreeSet<usize>,
    /// The publication is odd for everyone.
    odd_publication: bool,
    /// Per slot, runs of consecutive stable syncs downloading (filters, witnesses, lookups).
    streaks: BTreeMap<usize, (u32, u32, u32)>,
    /// Each slot's sync heights.
    synced_at: BTreeMap<usize, Vec<u32>>,
    violations: Vec<String>,
    /// Violation names already reported, each once.
    reported: BTreeSet<String>,
    trace: Vec<String>,
    t0: i64,
    floor: u32,
    birthday: u32,
    step: usize,
    stranger: orchard::Address,
}

impl<'p> Exec<'p> {
    /// A run of `plan` that has not started.
    fn new(plan: &'p Plan) -> Self {
        Self {
            plan,
            slots: [None; 4],
            wallets: BTreeMap::new(),
            births: BTreeMap::new(),
            fresh: BTreeSet::new(),
            swaps: (0..plan.swaps.len()).map(|_| SwapRt::default()).collect(),
            pays: Vec::new(),
            own: Vec::new(),
            given: Vec::new(),
            repay: Vec::new(),
            passes: BTreeMap::new(),
            rechecking: BTreeSet::new(),
            in_recheck: BTreeSet::new(),
            credits: BTreeMap::new(),
            funds: Vec::new(),
            troubled: BTreeSet::new(),
            odd_publication: false,
            streaks: BTreeMap::new(),
            synced_at: BTreeMap::new(),
            violations: Vec::new(),
            reported: BTreeSet::new(),
            trace: Vec::new(),
            t0: 0,
            floor: 0,
            birthday: 0,
            step: 0,
            stranger: FullViewingKey::from(&SpendingKey::from_bytes([0xf5; 32]).expect("a key"))
                .address_at(0u32, Scope::External),
        }
    }

    /// Adds a trace line and a timeline entry.
    fn note(&mut self, ctx: &mut Ctx, actor: &str, text: impl Into<String>) {
        let text = text.into();
        self.trace.push(format!(
            "#{} t+{} h{} {actor}: {text}",
            self.step,
            span_of(ctx.chain.now() - self.t0),
            u32::from(ctx.chain.tip())
        ));
        // `ONE_TIME_IVK_FUZZ_TRACE` streams the trace while a replay runs.
        if std::env::var_os("ONE_TIME_IVK_FUZZ_TRACE").is_some() {
            eprintln!("{}", self.trace.last().expect("just pushed"));
        }
        ctx.log(actor, text);
    }

    /// Records a violation `name` once, with `detail`.
    fn violation(&mut self, ctx: &mut Ctx, name: String, detail: String) {
        if !self.reported.insert(name.clone()) {
            return;
        }
        let text = format!("{name}: {detail}");
        self.trace.push(format!("#{} VIOLATION {text}", self.step));
        ctx.log("oracle", format!("violation: {text}"));
        ctx.check(name, false, detail);
        self.violations.push(text);
    }

    /// Runs the plan, then stabilizes the world and judges it.
    fn run(&mut self, ctx: &mut Ctx, skip: &BTreeSet<usize>) {
        let plan = self.plan;
        ctx.near.read_lag = plan.read_lag;
        ctx.log("plan", plan.notes.join("; "));
        ctx.mine(20);
        let birthday = ctx.chain.tip() + 1;
        self.birthday = u32::from(birthday);
        ctx.mine(5);
        let a = ctx.device_with_skew("A", SEED, birthday, plan.skew);
        ctx.dev(a).feed_clock = true;
        if plan.fresh {
            ctx.dev(a).mark_fresh();
            self.fresh.insert(W { slot: A, acct: 0 });
        }
        self.add(A, 0, a);
        self.births.insert(W { slot: A, acct: 0 }, self.birthday);
        if plan.a2 {
            let a2 = ctx.device("A2", SEED, birthday);
            ctx.dev(a2).feed_clock = true;
            self.add(A2, 0, a2);
            self.births.insert(W { slot: A2, acct: 0 }, self.birthday);
        }
        let fvk = ctx.get(a).fvk.clone();
        self.funds.push(ctx.pay(
            "A's Ironwood funds",
            "A's address",
            &fvk,
            FUNDS,
            Payer::Wallet,
        ));
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
        self.floor = u32::from(ctx.chain.tip());
        self.t0 = ctx.chain.now();
        self.sync(ctx, A);
        self.sync(ctx, A);
        if plan.a2 {
            self.sync(ctx, A2);
            self.sync(ctx, A2);
        }
        for (i, (at, step)) in plan.steps.iter().enumerate() {
            self.step = i;
            if skip.contains(&i) {
                continue;
            }
            let at = self.t0 + at;
            self.repay_due(ctx, at);
            match step {
                Step::Pay(_) => ctx.chain.mine_until_next_at(at),
                _ => ctx.chain.mine_until(at),
            }
            self.run_step(ctx, step.clone());
        }
        self.step = plan.steps.len();
        let end = ctx.chain.now() + HOUR;
        self.repay_due(ctx, end);
        self.finish(ctx);
    }

    /// Registers wallet account (`slot`, `acct`) with handle `dev`.
    fn add(&mut self, slot: usize, acct: u8, dev: Dev) {
        let w = W { slot, acct };
        if acct == 0 {
            self.slots[slot] = Some(dev);
        }
        self.wallets.insert(w, dev);
    }

    /// Pays again, in new transactions, the payouts whose time has come.
    fn repay_due(&mut self, ctx: &mut Ctx, until: i64) {
        let due: Vec<(i64, usize)> = self
            .repay
            .iter()
            .copied()
            .filter(|(t, _)| *t <= until)
            .collect();
        self.repay.retain(|(t, _)| *t > until);
        for (at, i) in due {
            ctx.chain.mine_until_next_at(at);
            let (swap, value) = (self.pays[i].swap, self.pays[i].mined.value);
            let label = format!("{} (paid again)", self.pays[i].label);
            self.pay(ctx, &[(swap, value)], Some(label));
        }
    }

    /// Runs one planned step.
    fn run_step(&mut self, ctx: &mut Ctx, step: Step) {
        match step {
            Step::Sync(slot) => {
                if self.slots[slot].is_some() {
                    self.sync(ctx, slot);
                }
            }
            Step::Quote(swap) => self.quote(ctx, swap),
            Step::Fund(swap) => self.fund(ctx, swap),
            Step::Status {
                swap,
                status,
                amount,
            } => self.status(ctx, swap, status, amount),
            Step::Pay(outs) => self.pay(ctx, &outs, None),
            Step::Spend { w, mode } => self.spend(ctx, w, mode),
            Step::Restore {
                slot,
                birthday,
                accounts,
            } => self.restore(ctx, slot, birthday, accounts),
            Step::AddAccount { fresh } => {
                let a = self.slots[A].expect("A");
                let birthday = ctx.chain.tip() + 1;
                ctx.mine(1);
                let a1 = ctx.add_account(a, "A#1", SEED, birthday);
                let w = W { slot: A, acct: 1 };
                if fresh {
                    ctx.dev(a1).mark_fresh();
                    self.fresh.insert(w);
                }
                self.add(A, 1, a1);
                self.births.insert(w, u32::from(birthday));
                let fvk = ctx.get(a1).fvk.clone();
                self.funds.push(ctx.pay(
                    "A#1's Ironwood funds",
                    "A#1's address",
                    &fvk,
                    FUNDS,
                    Payer::Wallet,
                ));
                // The funds are a fake output, which a reorg could not mine again, so no
                // reorg reaches below them.
                self.floor = u32::from(ctx.chain.tip());
                self.note(
                    ctx,
                    "A",
                    format!("adds account #1, birthday {}", u32::from(birthday)),
                );
                self.sync(ctx, A);
            }
            Step::Directory { slot, up } => {
                if let Some(dev) = self.slots[slot] {
                    ctx.dev(dev).reach.directory = up;
                    if up {
                        self.troubled.remove(&slot);
                    } else {
                        self.troubled.insert(slot);
                    }
                    let text = if up { "reachable again" } else { "unreachable" };
                    self.note(ctx, "directory", format!("{text} for {}", NAMES[slot]));
                }
            }
            Step::Fault { slot, kind } => {
                if let Some(dev) = self.slots[slot] {
                    match kind {
                        FaultKind::Http(status) => {
                            ctx.dev(dev).reach.directory_faults = vec![status; 3]
                        }
                        FaultKind::StopAfter(n) => {
                            ctx.dev(dev).reach.endpoint_faults = vec![Fault {
                                request: "",
                                after: n,
                                status: None,
                            }]
                        }
                    }
                    self.troubled.insert(slot);
                    self.note(
                        ctx,
                        "directory",
                        format!("{kind:?} for {}'s next discovery", NAMES[slot]),
                    );
                }
            }
            Step::Publication(kind) => self.publication(ctx, kind),
            Step::Reorg {
                depth,
                tail,
                late,
                synced,
            } => {
                if synced {
                    for slot in 0..4 {
                        if self.slots[slot].is_some() {
                            self.sync(ctx, slot);
                        }
                    }
                }
                self.reorg(ctx, depth, tail, late)
            }
            Step::Recheck(w) => {
                if self.wallets.contains_key(&w) {
                    self.recheck(ctx, w, false);
                }
            }
            Step::Restart(slot) => {
                if let Some(dev) = self.slots[slot] {
                    ctx.restart(dev);
                    self.note(ctx, NAMES[slot], "the app restarts");
                }
            }
        }
    }

    /// Sets every device's publication to `kind`, or back to a faithful one.
    fn publication(&mut self, ctx: &mut Ctx, kind: Option<PubKind>) {
        let mut options = crate::harness::directory::Options::default();
        match kind {
            None => {}
            Some(PubKind::Lag(depth)) => options.depth = depth,
            Some(PubKind::Bad(bad)) => options.bad = Some(bad),
            Some(PubKind::Frozen) => {
                let frozen = Frozen::capture(&ctx.chain, &ctx.near, ctx.chain.now(), &options);
                options.frozen = Some(Arc::new(frozen));
            }
        }
        self.odd_publication = kind.is_some();
        for dev in self.slots.iter().flatten().copied().collect::<Vec<_>>() {
            ctx.dev(dev).reach.publication = options.clone();
        }
        let text = kind.map_or("faithful again".to_string(), |k| format!("{k:?}"));
        self.note(ctx, "directory", format!("publication {text}"));
    }

    /// Syncs `slot`'s device, then runs the oracle on its accounts.
    fn sync(&mut self, ctx: &mut Ctx, slot: usize) -> SyncReport {
        let dev = self.slots[slot].expect("the device exists");
        let report = ctx.sync(dev);
        self.synced_at
            .entry(slot)
            .or_default()
            .push(u32::from(ctx.chain.tip()));
        let req = Requests::of(&report.requests);
        let mut text = format!(
            "{} syncs: scanned {}, found {}+{}, {} requests ({} filters, {} witnesses, {} queries)",
            NAMES[slot],
            report.scanned_blocks,
            report.found_live,
            report.found_by_discovery,
            req.total,
            req.filters,
            req.witnesses,
            req.queries
        );
        if report.pending {
            text.push_str(", pending");
        }
        for p in &report.problems {
            text.push_str(&format!("; {p}"));
        }
        self.note(ctx, NAMES[slot], text);
        self.costs(ctx, slot, &req);
        // An outage lasts until its directory step; a fault hits one discovery run.
        if ctx.get(dev).reach.directory {
            self.troubled.remove(&slot);
        }
        self.observe(ctx, slot);
        self.safety(ctx, slot);
        report
    }

    /// Checks one sync's directory requests on `slot`.
    fn costs(&mut self, ctx: &mut Ctx, slot: usize, req: &Requests) {
        let accounts = self.wallets.keys().filter(|w| w.slot == slot).count() as u32;
        if req.filters > 2 * accounts || req.witnesses > 2 * accounts {
            self.violation(
                ctx,
                format!(
                    "{} downloads directory material at most once per discovery run",
                    NAMES[slot]
                ),
                format!(
                    "{} filter and {} witness downloads in one sync of {accounts} account(s)",
                    req.filters, req.witnesses
                ),
            );
        }
        let stable = !self.troubled.contains(&slot) && !self.odd_publication;
        let streak = self.streaks.entry(slot).or_default();
        if !stable {
            *streak = (0, 0, 0);
            return;
        }
        streak.0 = if req.filters > 0 { streak.0 + 1 } else { 0 };
        streak.1 = if req.witnesses > 0 { streak.1 + 1 } else { 0 };
        streak.2 = if req.queries > 0 { streak.2 + 1 } else { 0 };
        let (f, w, q) = *streak;
        for (what, n, limit) in [
            ("filters", f, STREAK),
            ("witnesses", w, STREAK),
            ("lookups", q, 2 * STREAK),
        ] {
            if n > limit {
                self.violation(
                    ctx,
                    format!("{}'s {what} downloads stop", NAMES[slot]),
                    format!("{n} consecutive stable syncs download {what}"),
                );
            }
        }
    }

    /// Reads every account on `slot`: new credits, and completed discovery passes.
    fn observe(&mut self, ctx: &mut Ctx, slot: usize) {
        let ws: Vec<W> = self
            .wallets
            .keys()
            .copied()
            .filter(|w| w.slot == slot)
            .collect();
        for w in ws {
            let dev = self.wallets[&w];
            let candidates = candidates(ctx, dev);
            for n in notes(ctx, dev).into_iter().filter(|n| n.one_time) {
                let Some(height) = n.mined else { continue };
                let class = if self.in_recheck.contains(&w) {
                    Class::FoundAfterRecheck
                } else if candidates.contains(&n.id) {
                    Class::FoundByDiscovery
                } else {
                    Class::FoundLive
                };
                self.credits
                    .entry((w, n.id))
                    .and_modify(|c| c.height = height)
                    .or_insert(Credit { class, height });
            }
            if self.fresh.contains(&w) {
                continue;
            }
            let account = ctx.get(dev).account;
            let Some(status) = ctx.get(dev).discovery(&ctx.chain, account) else {
                continue;
            };
            let Some(publication) = status.publication.filter(|_| status.complete) else {
                continue;
            };
            let end = u32::from(publication.height);
            let recheck = self.rechecking.remove(&w);
            let known = self.passes.entry(w).or_default();
            if !recheck && known.last().is_some_and(|p| p.end == end) {
                continue;
            }
            let pass = Pass {
                end,
                feed_until: ctx.near.read_until(ctx.chain.now()),
                recheck,
                first: known.is_empty(),
            };
            known.push(pass);
            self.note(
                ctx,
                &w.name(),
                format!(
                    "discovery complete through {end}{}",
                    if recheck { " (Check swap history)" } else { "" }
                ),
            );
            if pass.first || pass.recheck {
                self.judge_pass(ctx, w, pass);
            }
        }
    }

    /// The highest key index discovery's search reaches for `purpose` of account `acct`,
    /// against a publication through `end` whose feed was read until `feed_until`: the
    /// first window, then on until `GAP` unused keys in a row.
    fn reach(&self, acct: u8, refund: bool, end: u32, feed_until: i64, feed_started: i64) -> u64 {
        let used: BTreeSet<u64> = self
            .given
            .iter()
            .filter(|g| g.key.acct == acct && g.key.refund == refund)
            .filter(|g| g.at >= feed_started && g.at <= feed_until)
            .map(|g| g.key.index)
            .chain(
                self.pays
                    .iter()
                    .filter(|p| p.alive && p.key.acct == acct && p.key.refund == refund)
                    .filter(|p| u32::from(p.mined.height) <= end)
                    .map(|p| p.key.index),
            )
            .collect();
        let mut reach = FIRST_WINDOW;
        let mut i = 0;
        while i < reach {
            if used.contains(&i) {
                reach = reach.max(i + 1 + GAP);
            }
            i += 1;
        }
        reach
    }

    /// Whether a completed pass `pass` of `w` promises payment `i`: a NEAR payment at or
    /// after the birthday, through the publication's end, to a key the search reaches.
    fn pass_promises(&self, ctx: &Ctx, w: W, pass: &Pass, i: usize) -> bool {
        let p = &self.pays[i];
        let h = u32::from(p.mined.height);
        p.alive
            && p.key.acct == w.acct
            && h >= self.births[&w]
            && h <= pass.end
            && p.key.index
                < self.reach(
                    w.acct,
                    p.key.refund,
                    pass.end,
                    pass.feed_until,
                    ctx.near.feed_started,
                )
    }

    /// Judges a completed pass: it must hold every payment it promises.
    fn judge_pass(&mut self, ctx: &mut Ctx, w: W, pass: Pass) {
        let missing: Vec<String> = (0..self.pays.len())
            .filter(|&i| self.pass_promises(ctx, w, &pass, i))
            .filter(|&i| !self.credits.contains_key(&(w, self.pays[i].mined.id())))
            .map(|i| {
                let p = &self.pays[i];
                format!(
                    "{} to {} at {}",
                    p.label,
                    p.key.label(),
                    u32::from(p.mined.height)
                )
            })
            .collect();
        if !missing.is_empty() {
            self.violation(
                ctx,
                format!(
                    "{}'s complete discovery holds every payment it lists",
                    w.name()
                ),
                format!(
                    "discovery reports complete through {} (birthday {}) without {missing:?}",
                    pass.end, self.births[&w]
                ),
            );
        }
    }

    /// The oracle's checks of `slot`'s accounts against the chain after a sync.
    fn safety(&mut self, ctx: &mut Ctx, slot: usize) {
        let ws: Vec<W> = self
            .wallets
            .keys()
            .copied()
            .filter(|w| w.slot == slot)
            .collect();
        let spent = ctx.chain.nullifier_heights();
        let tip = u32::from(ctx.chain.tip());
        for w in ws {
            let dev = self.wallets[&w];
            let ledger = self.ledger(ctx, w);
            let notes = notes(ctx, dev);
            let name = w.name();
            // Spent shown unspent.
            let shown: Vec<String> = notes
                .iter()
                .filter(|n| n.mined.is_some() && !n.spent)
                .filter_map(|n| n.nf.and_then(|nf| spent.get(&nf).map(|h| (n, *h))))
                .map(|(n, h)| format!("{} ({}) spent at {h}", short(n.id), zec(n.value)))
                .collect();
            if !shown.is_empty() {
                self.violation(
                    ctx,
                    format!("{name} never shows a spent note as unspent"),
                    format!("unspent in the wallet, spent on chain: {shown:?}"),
                );
            }
            // Notes the chain does not have where the wallet says.
            let phantom: Vec<String> = notes
                .iter()
                .filter(|n| n.mined.is_some_and(|h| h <= tip))
                .filter(|n| {
                    ledger
                        .get(&n.id)
                        .is_none_or(|(h, _, _)| Some(*h) != n.mined)
                })
                .map(|n| format!("{} at {:?}", short(n.id), n.mined))
                .collect();
            if !phantom.is_empty() {
                self.violation(
                    ctx,
                    format!("{name} holds only notes the chain has"),
                    format!("not on the chain where the wallet has them: {phantom:?}"),
                );
            }
            let mut nfs = BTreeSet::new();
            let twice: Vec<String> = notes
                .iter()
                .filter(|n| n.mined.is_some())
                .filter_map(|n| n.nf)
                .filter(|nf| !nfs.insert(*nf))
                .map(|nf| hex(&nf[..4]))
                .collect();
            if !twice.is_empty() {
                self.violation(
                    ctx,
                    format!("{name} credits no note twice"),
                    format!("nullifiers held twice: {twice:?}"),
                );
            }
            // Balance against what the chain still holds for the account, plus payouts a
            // reorg removed whose transactions have not expired.
            let unspent: u64 = ledger
                .values()
                .filter(|(_, _, nf)| !spent.contains_key(nf))
                .map(|(_, v, _)| v)
                .sum();
            let limbo: u64 = self
                .pays
                .iter()
                .filter(|p| !p.alive && p.key.acct == w.acct)
                .filter(|p| {
                    p.tx.as_ref()
                        .is_none_or(|tx| u32::from(tx.expiry_height()) + 1 >= tip)
                })
                .map(|p| p.mined.value)
                .sum();
            let balance = ctx.get(dev).balance();
            if balance > unspent + limbo {
                self.violation(
                    ctx,
                    format!("{name}'s balance never exceeds what the chain holds for it"),
                    format!(
                        "balance {}, chain unspent {} plus {} in removed payouts",
                        zec(balance),
                        zec(unspent),
                        zec(limbo)
                    ),
                );
            }
        }
    }

    /// Every output the chain holds for `w`'s account: (txid, action) to (height, value,
    /// nullifier).
    fn ledger(&self, ctx: &Ctx, w: W) -> BTreeMap<([u8; 32], u32), (u32, u64, [u8; 32])> {
        let dev = self.wallets[&w];
        let fvk = ctx.get(dev).fvk.clone();
        let mut ledger = BTreeMap::new();
        let mine: BTreeSet<[u8; 43]> = self
            .wallets
            .iter()
            .filter(|(v, _)| v.acct == w.acct)
            .flat_map(|(_, d)| ctx.get(*d).derived_receivers())
            .chain(std::iter::once(
                fvk.address_at(0u32, Scope::External).to_raw_address_bytes(),
            ))
            .collect();
        for m in ctx.chain.mined() {
            if mine.contains(&m.receiver) {
                ledger.insert(m.id(), (u32::from(m.height), m.value, m.nullifier));
            }
        }
        let ivks = [fvk.to_ivk(Scope::External), fvk.to_ivk(Scope::Internal)];
        for (tx, height) in ctx.chain.mined_txs() {
            let Some(bundle) = tx.ironwood_bundle() else {
                continue;
            };
            for (idx, _, note, _, _) in bundle.decrypt_outputs_with_keys(&ivks) {
                let id = (
                    *tx.txid().as_ref(),
                    u32::try_from(idx).expect("few actions"),
                );
                ledger.insert(
                    id,
                    (
                        u32::from(height),
                        note.value().inner(),
                        note.nullifier(&fvk).to_bytes(),
                    ),
                );
            }
        }
        ledger
    }

    /// The address-reuse rules (`ProviderSeen`): a wallet never issues an address it gave
    /// NEAR, nor one NEAR's seen set holds. Another install's quote inside the feed's read
    /// lag is the documented two-installs gap.
    fn check_reuse(&mut self, ctx: &mut Ctx, w: W, key: KeyRef) {
        let until = ctx.near.read_until(ctx.chain.now());
        let mut violations = Vec::new();
        let mut gaps = Vec::new();
        for g in self.given.iter().filter(|g| g.key == key) {
            if g.w.slot == w.slot {
                violations.push(format!(
                    "{} gave NEAR {} itself at +{}",
                    g.w.name(),
                    key.label(),
                    span_of(g.at - self.t0)
                ));
            } else if g.at >= ctx.near.feed_started && g.at <= until {
                violations.push(format!(
                    "{} gave NEAR {} at +{}, which the seen set read until +{} holds",
                    g.w.name(),
                    key.label(),
                    span_of(g.at - self.t0),
                    span_of(until - self.t0)
                ));
            } else {
                gaps.push(format!(
                    "{} gave NEAR {} after the feed's last read",
                    g.w.name(),
                    key.label()
                ));
            }
        }
        let paid = self.pays.iter().any(|p| p.alive && p.key == key);
        if paid && gaps.is_empty() {
            violations.push(format!("the chain holds a payment to {}", key.label()));
        }
        if !violations.is_empty() {
            self.violation(
                ctx,
                format!("{} never reissues {}", w.name(), key.label()),
                violations.join("; "),
            );
        } else if !gaps.is_empty() {
            ctx.documented_gap(
                format!("{} reissues {} inside the feed's read lag", w.name(), key.label()),
                true,
                format!("{}; ProviderSeen: another install's quote within the read lag can be issued again", gaps.join("; ")),
            );
        }
    }

    /// Quotes planned swap `swap` on its wallet, after syncing its device as the app does.
    fn quote(&mut self, ctx: &mut Ctx, swap: usize) {
        let plan = self.plan.swaps[swap];
        let Some(&dev) = self.wallets.get(&plan.wallet) else {
            return;
        };
        self.sync(ctx, plan.wallet.slot);
        let name = plan.wallet.name();
        let quoted_height = u32::from(ctx.chain.tip());
        let (key, fvk) = match plan.kind {
            Kind::Incoming => {
                let Ok(q) = ctx.quote_incoming(dev, plan.deadline_in) else {
                    self.note(ctx, &name, format!("cannot quote swap {swap}"));
                    return;
                };
                let key = KeyRef {
                    acct: plan.wallet.acct,
                    refund: false,
                    index: q.index,
                };
                let fvk = q.fvk.clone();
                self.swaps[swap].deadline = q.deposit.deadline;
                self.swaps[swap].incoming = Some(q);
                (key, fvk)
            }
            Kind::Refund => {
                let Ok(q) = ctx.quote_refund(dev, plan.deadline_in) else {
                    self.note(ctx, &name, format!("cannot quote swap {swap}"));
                    return;
                };
                let key = KeyRef {
                    acct: plan.wallet.acct,
                    refund: true,
                    index: q.index,
                };
                let fvk = q.fvk.clone();
                self.swaps[swap].deadline = ctx.chain.now() + plan.deadline_in;
                self.swaps[swap].refund = Some(q);
                (key, fvk)
            }
        };
        self.note(ctx, &name, format!("quotes swap {swap} on {}", key.label()));
        self.check_reuse(ctx, plan.wallet, key);
        self.given.push(Given {
            key,
            at: ctx.chain.now(),
            w: plan.wallet,
        });
        let rt = &mut self.swaps[swap];
        rt.key = Some(key);
        rt.fvk = Some(fvk);
        rt.quoted_height = quoted_height;
        self.observe(ctx, plan.wallet.slot);
    }

    /// Funds planned ZEC-to-X swap `swap` from its wallet.
    fn fund(&mut self, ctx: &mut Ctx, swap: usize) {
        let plan = self.plan.swaps[swap];
        let Some(quoted) = self.swaps[swap].refund.clone() else {
            return;
        };
        let dev = self.wallets[&plan.wallet];
        let amount = ZEC / 2;
        for attempt in 0..6 {
            if ctx.get(dev).spendable_balance() >= amount + 4 * FUNDING_FEE {
                break;
            }
            if attempt > 0 {
                ctx.mine(1);
            }
            self.sync(ctx, plan.wallet.slot);
        }
        if ctx.get(dev).spendable_balance() < amount + 4 * FUNDING_FEE {
            self.note(
                ctx,
                &plan.wallet.name(),
                "gives up funding: not enough is spendable",
            );
            return;
        }
        let (height, tx) = ctx.fund_refund(dev, &quoted, amount);
        self.own.push(OwnTx {
            tx,
            height: u32::from(height),
            alive: true,
        });
        self.swaps[swap].funded_height = Some(u32::from(height));
        self.note(
            ctx,
            &plan.wallet.name(),
            format!("funds swap {swap}, mined at {}", u32::from(height)),
        );
    }

    /// Records a NEAR status for planned swap `swap` on its wallet.
    fn status(&mut self, ctx: &mut Ctx, swap: usize, status: &'static str, amount: Option<u64>) {
        let plan = self.plan.swaps[swap];
        let Some(key) = self.swaps[swap].key else {
            return;
        };
        if key.refund && self.swaps[swap].funded_height.is_none() && status != "PENDING_DEPOSIT" {
            return;
        }
        let dev = self.wallets[&plan.wallet];
        if key.refund {
            let quoted = self.swaps[swap].refund.clone().expect("a refund swap");
            ctx.observe_refund(dev, &quoted, status, amount);
        } else {
            let quoted = self.swaps[swap].incoming.clone().expect("an incoming swap");
            ctx.observe_incoming(dev, &quoted, status, amount);
        }
        let now = ctx.chain.now();
        self.swaps[swap].statuses.push((now, status, amount));
        self.note(
            ctx,
            &plan.wallet.name(),
            format!(
                "records {status} for swap {swap}{}",
                amount.map_or(String::new(), |v| format!(" ({})", zec(v)))
            ),
        );
    }

    /// NEAR pays each (swap, value) of `outs` in one transaction.
    fn pay(&mut self, ctx: &mut Ctx, outs: &[(usize, u64)], label: Option<String>) {
        let outs: Vec<(usize, u64)> = outs
            .iter()
            .copied()
            .filter(|(swap, _)| {
                let rt = &self.swaps[*swap];
                rt.key.is_some() && (rt.refund.is_none() || rt.funded_height.is_some())
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
            labels.push(
                label
                    .clone()
                    .unwrap_or_else(|| format!("{what} {} of swap {swap}", rt.payouts)),
            );
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
            let key = self.swaps[*swap].key.expect("quoted");
            self.note(
                ctx,
                "NEAR",
                format!(
                    "{label}: pays {} to {} at {}",
                    zec(m.value),
                    key.label(),
                    u32::from(m.height)
                ),
            );
            self.pays.push(OPay {
                label,
                swap: *swap,
                key,
                mined: m,
                alive: true,
                tx,
            });
        }
    }

    /// Wallet `w` spends one-time notes in an ordinary send to a stranger, as `mode` says,
    /// after a sync; consensus must accept the send.
    fn spend(&mut self, ctx: &mut Ctx, w: W, mode: SpendMode) {
        let Some(&dev) = self.wallets.get(&w) else {
            return;
        };
        self.sync(ctx, w.slot);
        if ctx.get(dev).unspent_one_time_value() == 0 {
            self.note(ctx, &w.name(), "has no one-time notes to spend");
            return;
        }
        let spendable = ctx.get(dev).spendable_balance();
        let built = match mode {
            SpendMode::Change => ctx.dev(dev).send_ordinary(self.stranger, 10_000),
            SpendMode::Max => ctx.dev(dev).send_max(self.stranger),
            SpendMode::Exact => {
                let mut built = Err("nothing spendable".to_string());
                for fee in (2..12).map(|actions| actions * 5_000u64) {
                    let Some(value) = spendable.checked_sub(fee).filter(|v| *v > 0) else {
                        break;
                    };
                    built = ctx.dev(dev).send_ordinary(self.stranger, value);
                    if built.is_ok() {
                        break;
                    }
                }
                built
            }
        };
        let tx = match built {
            Ok(tx) => tx,
            Err(why) => {
                self.note(ctx, &w.name(), format!("cannot spend ({mode:?}): {why}"));
                return;
            }
        };
        if let Err(why) = ctx.chain.accepts(&tx) {
            self.violation(
                ctx,
                format!("{}'s sends are valid", w.name()),
                format!("consensus would reject a {mode:?} send: {why}"),
            );
            return;
        }
        let change_outputs = tx.ironwood_bundle().map_or(0, |b| b.actions().len());
        let height = ctx.chain.mine_tx(&tx);
        self.own.push(OwnTx {
            tx,
            height: u32::from(height),
            alive: true,
        });
        self.note(
            ctx,
            &w.name(),
            format!(
                "spends ({mode:?}) in a send of {change_outputs} actions mined at {}",
                u32::from(height)
            ),
        );
        self.sync(ctx, w.slot);
    }

    /// Restores the seed on a new device in `slot`.
    fn restore(&mut self, ctx: &mut Ctx, slot: usize, birthday: Birthday, accounts: u8) {
        let tip = u32::from(ctx.chain.tip());
        let height = match birthday {
            Birthday::Original => self.birthday,
            Birthday::Between(pct) => self.birthday + (tip - self.birthday) * pct / 100,
            Birthday::Today => tip.saturating_sub(10).max(self.birthday),
        };
        let height = BlockHeight::from(height.max(self.birthday));
        let dev = ctx.device(NAMES[slot], SEED, height);
        ctx.dev(dev).feed_clock = true;
        self.add(slot, 0, dev);
        self.births.insert(W { slot, acct: 0 }, u32::from(height));
        if accounts > 1 {
            let a1_birth = self
                .births
                .get(&W { slot: A, acct: 1 })
                .copied()
                .unwrap_or(u32::from(height));
            let birth = BlockHeight::from(a1_birth.max(u32::from(height)));
            let h = ctx.add_account(dev, &format!("{}#1", NAMES[slot]), SEED, birth);
            self.add(slot, 1, h);
            self.births.insert(W { slot, acct: 1 }, u32::from(birth));
        }
        self.note(
            ctx,
            NAMES[slot],
            format!(
                "restores the seed, birthday {}, {accounts} account(s)",
                u32::from(height)
            ),
        );
    }

    /// A reorg `depth` blocks deep. The wallets' transactions it removes are mined again
    /// on the new branch; NEAR's payouts are too, or, with `late`, paid again in new
    /// transactions that much later. The new branch outgrows the old by `tail` blocks.
    fn reorg(&mut self, ctx: &mut Ctx, depth: u32, tail: u32, late: Option<i64>) {
        let tip = ctx.chain.tip();
        let to = u32::from(tip).saturating_sub(depth).max(self.floor);
        if to >= u32::from(tip) {
            return;
        }
        ctx.reorg(BlockHeight::from(to));
        self.note(
            ctx,
            "chain",
            format!("reorg: blocks above {to} are replaced"),
        );
        let mut again: Vec<(u32, bool, usize)> = Vec::new();
        for (i, p) in self.pays.iter_mut().enumerate() {
            if p.alive && u32::from(p.mined.height) > to {
                p.alive = false;
                again.push((u32::from(p.mined.height), false, i));
            }
        }
        for (i, o) in self.own.iter_mut().enumerate() {
            if o.alive && o.height > to {
                o.alive = false;
                again.push((o.height, true, i));
            }
        }
        again.sort();
        let now = ctx.chain.now();
        for (old, own, i) in again {
            while u32::from(ctx.chain.tip()) + 1 < old {
                ctx.mine(1);
            }
            if own {
                let height = ctx.chain.mine_tx(&self.own[i].tx);
                self.own[i].height = u32::from(height);
                self.own[i].alive = true;
                self.note(
                    ctx,
                    "chain",
                    format!(
                        "a wallet's transaction is mined again at {}",
                        u32::from(height)
                    ),
                );
            } else if let Some(delay) = late {
                self.repay.push((now + delay, i));
                self.note(
                    ctx,
                    "NEAR",
                    format!(
                        "{} will be paid again in {}",
                        self.pays[i].label,
                        span_of(delay)
                    ),
                );
            } else {
                let p = &self.pays[i];
                let tx = p.tx.clone().expect("a signed payout");
                let fvk = self.swaps[p.swap].fvk.clone().expect("a key");
                let (label, value) = (p.label.clone(), p.mined.value);
                let mined = ctx.remine(&label, &tx, &fvk, value, Payer::Near);
                self.note(
                    ctx,
                    "chain",
                    format!("{label} is mined again at {}", u32::from(mined.height)),
                );
                let p = &mut self.pays[i];
                p.mined = mined;
                p.alive = true;
            }
        }
        while ctx.chain.tip() <= tip {
            ctx.mine(1);
        }
        ctx.mine(tail);
    }

    /// Runs Check swap history on `w`, then syncs its device until its pass completes, at
    /// most a day of chain time.
    fn recheck(&mut self, ctx: &mut Ctx, w: W, judge: bool) {
        let dev = self.wallets[&w];
        self.sync(ctx, w.slot);
        ctx.dev(dev).begin_recheck();
        // A fresh account asked to recheck runs the pass as a restored one does.
        self.fresh.remove(&w);
        self.note(ctx, &w.name(), "runs Check swap history");
        self.rechecking.insert(w);
        self.in_recheck.insert(w);
        let started = ctx.chain.now();
        while ctx.chain.now() < started + DAY {
            self.sync(ctx, w.slot);
            if !self.rechecking.contains(&w) {
                break;
            }
            ctx.chain.mine_until(ctx.chain.now() + 10 * MINUTE);
        }
        // A few more syncs, as the app's polling would, still counted as the recheck's.
        for _ in 0..3 {
            ctx.mine(1);
            self.sync(ctx, w.slot);
        }
        self.in_recheck.remove(&w);
        if judge && self.rechecking.contains(&w) {
            self.violation(
                ctx,
                format!("{}'s Check swap history completes", w.name()),
                "discovery was not complete a day after Check swap history".into(),
            );
        }
    }

    /// Stabilizes the world, then judges liveness, quiet syncs, final rechecks and the
    /// payments the contract promises.
    fn finish(&mut self, ctx: &mut Ctx) {
        self.publication(ctx, None);
        for dev in self.slots.iter().flatten().copied().collect::<Vec<_>>() {
            let reach = &mut ctx.dev(dev).reach;
            reach.directory = true;
            reach.directory_faults.clear();
            reach.endpoint_faults.clear();
        }
        self.troubled.clear();
        self.note(ctx, "oracle", "the world is stable from here");
        ctx.mine(3);
        // Liveness: within a day of chain time, past any lookup backoff, every wallet's
        // discovery completes.
        let started = ctx.chain.now();
        let slots: Vec<usize> = (0..4).filter(|s| self.slots[*s].is_some()).collect();
        let mut done: BTreeSet<usize> = BTreeSet::new();
        while ctx.chain.now() < started + 26 * HOUR && done.len() < slots.len() {
            for &slot in &slots {
                if done.contains(&slot) {
                    continue;
                }
                let report = self.sync(ctx, slot);
                if !report.pending && report.problems.is_empty() {
                    done.insert(slot);
                }
            }
            ctx.chain.mine_until(ctx.chain.now() + 30 * MINUTE);
        }
        for &slot in &slots {
            if !done.contains(&slot) {
                self.violation(
                    ctx,
                    format!(
                        "{}'s discovery completes once the world is stable",
                        NAMES[slot]
                    ),
                    "still pending after 26 hours of stable chain time".into(),
                );
            }
        }
        // Quiet: once a sync leaves nothing pending and makes no request (work a scan
        // registers, such as a funding memo's key, may still cost one more), the next
        // syncs make no directory request either.
        for &slot in &slots {
            let mut quiet = 0;
            let mut requests = Vec::new();
            for _ in 0..8 {
                ctx.mine(1);
                let report = self.sync(ctx, slot);
                if quiet > 0 && !report.requests.is_empty() {
                    requests = report.requests.clone();
                    break;
                }
                if !report.pending && report.requests.is_empty() {
                    quiet += 1;
                    if quiet > 3 {
                        break;
                    }
                }
            }
            if quiet <= 3 {
                let detail = if requests.is_empty() {
                    "no sync left nothing pending without a request".to_string()
                } else {
                    format!("after a quiet sync, a sync made {requests:?}")
                };
                self.violation(
                    ctx,
                    format!("{}'s quiet syncs make no directory requests", NAMES[slot]),
                    detail,
                );
            }
        }
        for w in self.plan.final_rechecks.clone() {
            if self.wallets.contains_key(&w) {
                self.recheck(ctx, w, true);
            }
        }
        self.judge(ctx);
        // What the world exercised, for the report and coverage counts.
        for slot in 0..4 {
            let Some(dev) = self.slots[slot] else {
                continue;
            };
            let late: i64 = ctx
                .get(dev)
                .conn()
                .query_row("SELECT COUNT(*) FROM harness_late", [], |r| r.get(0))
                .expect("late candidates");
            let rewinds = ctx.get(dev).rewinds.len();
            ctx.metric(
                format!("{} late candidates", NAMES[slot]),
                late as f64,
                "payments",
            );
            ctx.metric(
                format!("{} rewinds", NAMES[slot]),
                rewinds as f64,
                "rewinds",
            );
        }
        let passes: usize = self.passes.values().map(Vec::len).sum();
        ctx.metric("completed discovery passes", passes as f64, "passes");
        ctx.metric("one-time payments", self.pays.len() as f64, "payments");
    }

    /// Judges every payment for every wallet account of its seed account.
    fn judge(&mut self, ctx: &mut Ctx) {
        let ws: Vec<W> = self.wallets.keys().copied().collect();
        for w in ws {
            for i in 0..self.pays.len() {
                if !self.pays[i].alive || self.pays[i].key.acct != w.acct {
                    continue;
                }
                let id = self.pays[i].mined.id();
                let credit = self.credits.get(&(w, id)).copied();
                // The wallet must still hold it where the chain has it.
                let held = ctx.get(self.wallets[&w]).receipt(id);
                let actual = match (credit, &held) {
                    (Some(c), Some(r))
                        if r.mined_height == Some(u32::from(self.pays[i].mined.height)) =>
                    {
                        c.class
                    }
                    _ => Class::Missed,
                };
                let promise = self.promise(ctx, w, i);
                let p = &self.pays[i];
                let (expected, rationale) = match promise {
                    Some((class, why)) => (class, why),
                    None if credit.is_some() && held.is_none() => (
                        Class::FoundAutomatically,
                        "the wallet credited it once; a reorg cannot strand a receipt".into(),
                    ),
                    None => (
                        if actual.found() {
                            actual
                        } else {
                            Class::MissedDocumented
                        },
                        format!("not judged: {}", self.unpromised(ctx, w, i)),
                    ),
                };
                let ok = match expected {
                    Class::FoundAfterRecheck => actual.found(),
                    e => e.satisfied_by(actual),
                };
                ctx.judged(PaymentResult {
                    payment: p.label.clone(),
                    key: p.key.label(),
                    wallet: w.name(),
                    value: p.mined.value,
                    height: u32::from(p.mined.height),
                    day: day_of(block_time(p.mined.height)),
                    payer: p.mined.payer.label().into(),
                    expected: if ok { actual } else { expected },
                    actual,
                    rationale: rationale.clone(),
                });
                if !ok {
                    let name = format!("{} credits {}", w.name(), p.label);
                    let detail = format!(
                        "{} to {} at {} ({}): {rationale}; actual {}",
                        p.label,
                        p.key.label(),
                        u32::from(p.mined.height),
                        zec(p.mined.value),
                        actual.label()
                    );
                    self.violation(ctx, name, detail);
                }
            }
        }
    }

    /// Why no rule of [`Self::promise`] covers wallet `w`'s payment `i`, for the report.
    fn unpromised(&self, ctx: &Ctx, w: W, i: usize) -> String {
        let p = &self.pays[i];
        let h = u32::from(p.mined.height);
        if h < self.births[&w] {
            return format!("before {}'s birthday {}", w.name(), self.births[&w]);
        }
        let passes = self.passes.get(&w).map(Vec::as_slice).unwrap_or(&[]);
        let judged: Vec<&Pass> = passes.iter().filter(|p| p.first || p.recheck).collect();
        if self.plan.swaps[p.swap].wallet == w {
            return "its own key, after a status that lets the key close or past the limit".into();
        }
        if judged.is_empty() {
            return format!(
                "{} has no first or recheck pass (a fresh account)",
                w.name()
            );
        }
        if judged.iter().all(|pass| pass.end < h) {
            return format!(
                "after every first or recheck pass of {} (last through {})",
                w.name(),
                judged.iter().map(|p| p.end).max().unwrap_or(0)
            );
        }
        let reach = judged
            .iter()
            .map(|pass| {
                self.reach(
                    w.acct,
                    p.key.refund,
                    pass.end,
                    pass.feed_until,
                    ctx.near.feed_started,
                )
            })
            .max()
            .unwrap_or(0);
        if p.key.index >= reach {
            return format!("beyond the search's reach {reach}");
        }
        "no rule".into()
    }

    /// What the documented contract promises wallet `w` of payment `i`, and why, if
    /// anything: found live by the wallet that quoted the key while it scans, found by a
    /// completed first or Check swap history discovery pass whose publication lists it,
    /// or found live in a restored incoming key's 24-hour watch.
    fn promise(&self, ctx: &Ctx, w: W, i: usize) -> Option<(Class, String)> {
        let p = &self.pays[i];
        let h = u32::from(p.mined.height);
        let t = block_time(p.mined.height);
        if h < self.births[&w] {
            return None;
        }
        let rt = &self.swaps[p.swap];
        let plan = self.plan.swaps[p.swap];
        // Live: the quoting wallet scans its key until its statuses let it close.
        if plan.wallet == w {
            let from = rt.funded_height.unwrap_or(rt.quoted_height);
            let limit = rt.deadline + COMPLETION_LIMIT_SECS - DAY;
            if h > from && t < limit && self.open_for(i) {
                // Its own discovery may list the payment first (a fresh account runs a
                // pass once issuance registers a seen key for a lookup).
                return Some((
                    Class::FoundAutomatically,
                    format!(
                        "{} quoted {} and scans it until a final status or 30 days past the deadline",
                        w.name(),
                        p.key.label()
                    ),
                ));
            }
        }
        let passes = self.passes.get(&w).map(Vec::as_slice).unwrap_or(&[]);
        for pass in passes.iter().filter(|p| p.first || p.recheck) {
            if self.pass_promises(ctx, w, pass, i) {
                let class = if pass.recheck {
                    Class::FoundAfterRecheck
                } else {
                    Class::FoundAutomatically
                };
                return Some((
                    class,
                    format!(
                        "{}'s {} discovery pass completed through {} and its search reaches {}",
                        w.name(),
                        if pass.recheck {
                            "Check swap history"
                        } else {
                            "first"
                        },
                        pass.end,
                        p.key.label()
                    ),
                ));
            }
        }
        // A refund key another device funded: the wallet recovers it from the funding memo
        // and discovery looks it up in its next run (see `discover`), so a refund already
        // on chain when the wallet first scanned past the memo is found a few syncs later.
        if let Some(funded) = rt.funded_height.filter(|f| *f >= self.births[&w]) {
            let tips = self
                .synced_at
                .get(&w.slot)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let first = tips.iter().position(|t| *t >= funded + 3);
            let listed = first.is_some_and(|i| tips[i] >= h + 3 && tips.len() - i >= 3);
            if p.key.refund && plan.wallet.slot != w.slot && listed {
                return Some((
                    Class::FoundAutomatically,
                    format!(
                        "{} first scanned past {}'s funding memo at {funded} after this refund, \
                         and discovery looks up a key registered after it finished in its next run",
                        w.name(),
                        p.key.label()
                    ),
                ));
            }
        }
        // A restored recent incoming key scans for a day after the first pass finds it.
        let first = passes.iter().find(|p| p.first)?;
        let reach = self.reach(
            w.acct,
            p.key.refund,
            first.end,
            first.feed_until,
            ctx.near.feed_started,
        );
        let stale = self.plan.read_lag > RECENT_SET_MAX_AGE_SECS;
        let recent = stale
            || self.given.iter().any(|g| {
                g.key == p.key
                    && g.at > first.feed_until - RESTORE_WATCH_SECS + MARGIN
                    && g.at <= first.feed_until
            });
        let watch_end = block_time(BlockHeight::from(first.end)) + RESTORE_WATCH_SECS - MARGIN;
        if !p.key.refund
            && plan.wallet.slot != w.slot
            && h > first.end
            && t < watch_end
            && recent
            && p.key.index < reach
        {
            return Some((
                Class::FoundAutomatically,
                format!(
                    "NEAR was given {} within a day of {}'s first discovery pass, so the restored key scans for 24 hours",
                    p.key.label(),
                    w.name()
                ),
            ));
        }
        None
    }
}

impl Exec<'_> {
    /// Whether the statuses the quoting wallet recorded before payment `i` (with a margin)
    /// keep its key open for it (see `close_finished_one_time_keys` and `reap`): none yet,
    /// one still in progress, an inconclusive end, or one expecting a receipt that the
    /// key's earlier payments do not cover yet. Not after a final status expecting nothing,
    /// nor once an unpaid reservation could be reclaimed.
    fn open_for(&self, i: usize) -> bool {
        let p = &self.pays[i];
        let t = block_time(p.mined.height);
        let rt = &self.swaps[p.swap];
        let earlier: u64 = self
            .pays
            .iter()
            .filter(|q| q.alive && q.key == p.key && q.mined.height < p.mined.height)
            .map(|q| q.mined.value)
            .sum();
        let Some(&(at, status, amount)) = rt
            .statuses
            .iter()
            .rev()
            .find(|(at, _, _)| *at < t - 10 * MINUTE)
        else {
            return true;
        };
        let refund = p.key.refund;
        match status {
            "PENDING_DEPOSIT" => earlier > 0 || at < rt.deadline + RECEIVE_RECLAIM_SECONDS,
            "KNOWN_DEPOSIT_TX" | "INCOMPLETE_DEPOSIT" | "PROCESSING" => true,
            "SUCCESS" if refund && amount.is_none() => true,
            "REFUNDED" | "FAILED" if !refund => false,
            "SUCCESS" | "REFUNDED" | "FAILED" => earlier < amount.unwrap_or(1),
            _ => false,
        }
    }
}

/// `id` shortened for a trace: its txid's first bytes and action index.
fn short(id: ([u8; 32], u32)) -> String {
    format!("{}:{}", hex(&id.0[..4]), id.1)
}

/// `bytes` in lowercase hex.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Every Ironwood note `dev`'s account holds, as the oracle reads it.
fn notes(ctx: &Ctx, dev: Dev) -> Vec<Note> {
    let device = ctx.get(dev);
    let conn = device.conn();
    let account = device.account.expose_uuid().as_bytes().to_vec();
    let mut stmt = conn
        .prepare(
            "SELECT t.txid, n.action_index, n.value, n.nf, t.mined_height,
                n.one_time_key_id IS NOT NULL,
                EXISTS(SELECT 1 FROM ironwood_received_note_spends s
                    JOIN transactions t2 ON t2.id_tx = s.transaction_id
                    WHERE s.ironwood_received_note_id = n.id
                      AND (t2.mined_height IS NOT NULL OR t2.expiry_height = 0
                           OR t2.expiry_height > (SELECT MAX(height) FROM blocks)))
             FROM ironwood_received_notes n
             JOIN transactions t ON t.id_tx = n.transaction_id
             JOIN accounts a ON a.id = n.account_id
             WHERE a.uuid = ?1",
        )
        .expect("a note query");
    stmt.query_map([account], |row| {
        let txid: Vec<u8> = row.get(0)?;
        let nf: Option<Vec<u8>> = row.get(3)?;
        Ok(Note {
            id: (txid.try_into().expect("32-byte txid"), row.get(1)?),
            value: row.get::<_, i64>(2)? as u64,
            nf: nf.map(|nf| nf.try_into().expect("32-byte nullifier")),
            mined: row.get(4)?,
            one_time: row.get(5)?,
            spent: row.get(6)?,
        })
    })
    .expect("notes")
    .collect::<Result<_, _>>()
    .expect("notes decode")
}

/// The outputs directory lookups listed as payments in `dev`'s wallet file.
fn candidates(ctx: &Ctx, dev: Dev) -> BTreeSet<([u8; 32], u32)> {
    let conn = ctx.get(dev).conn();
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
