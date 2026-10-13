//! Scale and cost: how many keys scan at once, what each costs a scan, what a restore
//! downloads after many swaps, and how long Check swap history's replay runs. These run
//! one at a time after the other scenarios, since they time work.

use std::time::Instant;

use orchard::keys::{FullViewingKey, SpendingKey};
use zakura_one_time_ivk::Purpose;
use zakura_one_time_ivk_scenarios::Class;

use super::{COST, Scenario, span};
use crate::harness::{
    Ctx,
    chain::{DAY, HOUR, MINUTE, Payer, Traffic, ZEC},
    near::Role,
};

const SEED: [u8; 32] = [0x77; 32];
const VALUE: u64 = ZEC / 100;

pub fn all() -> Vec<Scenario> {
    let mut scenarios = Vec::new();
    for timely in [true, false] {
        scenarios.push(open_keys_over_time(10, 10, timely));
    }
    scenarios.push(scan_cost_by_open_keys());
    for (swaps, recent) in [(10, false), (100, false), (100, true), (450, false)] {
        scenarios.push(restore_after_swaps(swaps, recent));
    }
    for age in [30 * DAY, 90 * DAY, 180 * DAY] {
        scenarios.push(recheck_replay(age, 10, Parity::Even));
    }
    // The same late find at an odd and an even tree position (see `Parity`).
    for parity in [Parity::Odd, Parity::Even] {
        scenarios.push(recheck_replay(12 * DAY, 10, parity));
    }
    scenarios
}

/// A wallet created after 20 blocks and synced.
fn wallet(
    ctx: &mut Ctx,
    name: &str,
) -> (crate::harness::Dev, zcash_protocol::consensus::BlockHeight) {
    ctx.mine(20);
    let birthday = ctx.chain.tip() + 1;
    ctx.mine(5);
    let dev = ctx.device(name, SEED, birthday);
    ctx.sync(dev);
    (dev, birthday)
}

fn open_keys_over_time(per_day: usize, days: i64, timely: bool) -> Scenario {
    let mode = if timely {
        "timely-statuses"
    } else {
        "near-silent"
    };
    Scenario {
        id: format!("J1-open-keys-{per_day}-swaps-a-day-for-{days}d-{mode}"),
        group: COST,
        title: format!(
            "{per_day} incoming swaps a day for {days} days, {}",
            if timely {
                "NEAR reporting and paying within the hour"
            } else {
                "NEAR never answering"
            }
        ),
        summary: "Every open key is one more incoming viewing key to trial-decrypt each Ironwood \
            action with. Settled swaps close after 10 confirmations; swaps without a final status \
            stay open until 30 days after their deadline."
            .into(),
        params: vec![
            ("swaps per day".into(), per_day.to_string()),
            ("days".into(), days.to_string()),
            ("NEAR".into(), mode.into()),
        ],
        slow: false,
        run: Box::new(move |ctx| {
            let (a, _) = wallet(ctx, "A");
            let mut peak = 0;
            for day in 0..days {
                for _ in 0..per_day {
                    let swap = ctx.quote_incoming(a, HOUR).expect("the quote issues");
                    peak = peak.max(ctx.get(a).scanning().len());
                    if timely {
                        ctx.wait(20 * MINUTE);
                        ctx.pay("payout", &swap.label(), &swap.fvk, VALUE, Payer::Near);
                        ctx.observe_incoming(a, &swap, "SUCCESS", Some(VALUE));
                    }
                    ctx.wait(DAY / per_day as i64 - if timely { 20 * MINUTE } else { 0 });
                    ctx.sync(a);
                    peak = peak.max(ctx.get(a).scanning().len());
                }
                let open = ctx.get(a).scanning().len();
                ctx.metric(
                    format!("open keys at the end of day {}", day + 1),
                    open as f64,
                    "keys",
                );
            }
            ctx.metric("peak open keys", peak as f64, "keys");
            let bound = if timely {
                per_day
            } else {
                per_day * days as usize
            };
            ctx.check(
                "open keys stay within the closing rules",
                peak <= bound,
                format!("peak {peak}, bound {bound}"),
            );
        }),
    }
}

fn scan_cost_by_open_keys() -> Scenario {
    Scenario {
        id: "J2-scan-cost-by-open-keys".into(),
        group: COST,
        title: "Scan time for 500 blocks of 20 Ironwood actions with 0 to 100 open keys".into(),
        summary: "Measures what each open one-time key adds to scanning: 10,000 foreign actions \
            scanned with 0, 10, 30 and 100 incoming keys open."
            .into(),
        params: vec![
            ("blocks".into(), "500".into()),
            ("actions per block".into(), "20".into()),
        ],
        slow: true,
        run: Box::new(|ctx| {
            let (a, _) = wallet(ctx, "A");
            let mut opened = 0;
            let mut baseline = None;
            for target in [0usize, 10, 30, 100] {
                while opened < target {
                    let swap = ctx.quote_incoming(a, 3 * DAY).expect("the quote issues");
                    ctx.observe_incoming(a, &swap, "PENDING_DEPOSIT", None);
                    opened += 1;
                    if opened % 10 == 0 {
                        ctx.mine(1);
                        ctx.sync(a);
                    }
                }
                ctx.mine(1);
                ctx.sync(a);
                let open = ctx.get(a).scanning().len();
                ctx.chain.traffic = Traffic {
                    every: 1,
                    outputs: 20,
                };
                ctx.mine(500);
                ctx.chain.traffic = Traffic::default();
                let started = Instant::now();
                ctx.scan_only(a);
                let ms = started.elapsed().as_secs_f64() * 1000.0;
                ctx.log(
                    "A",
                    format!("scans 500 blocks of 20 actions with {open} keys open in {ms:.0} ms"),
                );
                ctx.metric(format!("scan time with {open} open keys"), ms, "ms");
                let base = *baseline.get_or_insert(ms);
                if open > 0 {
                    let per = (ms - base) * 1000.0 / (open as f64 * 10_000.0);
                    ctx.metric(
                        format!("added time per key per action ({open} keys)"),
                        per,
                        "µs",
                    );
                }
            }
        }),
    }
}

fn restore_after_swaps(swaps: u64, recent: bool) -> Scenario {
    let when = if recent {
        "within-the-day"
    } else {
        "two-days-earlier"
    };
    Scenario {
        id: format!("J3-restore-after-{swaps}-paid-swaps-{when}"),
        group: COST,
        title: format!(
            "Restore a seed whose {swaps} incoming addresses were paid {}",
            if recent {
                "within the last day"
            } else {
                "two days earlier"
            }
        ),
        summary: "A restore sweeps every paid key through the receiver directory: one PIR lookup \
            per payment page, or the whole row file past about 400 lookups. Keys NEAR was given in \
            the last day then scan for 24 hours. Every payment must be credited to its key, and \
            after a restart the next quote must take an address past every paid one and find its \
            payout live."
            .into(),
        params: vec![
            ("paid addresses".into(), swaps.to_string()),
            ("paid".into(), when.into()),
        ],
        slow: swaps > 200,
        run: Box::new(move |ctx| {
            ctx.mine(20);
            let birthday = ctx.chain.tip() + 1;
            ctx.mine(5);
            // The seed's owner quoted and was paid on another device; only the chain and
            // NEAR's feed remember it.
            let owner = ctx.device("A", SEED, birthday);
            let mut paid = Vec::new();
            let now = ctx.chain.now();
            for chunk in (0..swaps).collect::<Vec<_>>().chunks(25) {
                let keys: Vec<_> = chunk
                    .iter()
                    .map(|i| (format!("I{i}"), ctx.get(owner).key(Purpose::Receive, *i)))
                    .collect();
                for (_, fvk) in &keys {
                    ctx.near
                        .give(crate::harness::chain::receiver_of(fvk), now, Role::Payout);
                }
                let outputs: Vec<_> = keys.iter().map(|(k, f)| (k.as_str(), f, VALUE)).collect();
                paid.extend(ctx.pay_many("payouts", &outputs, Payer::Near));
                ctx.mine(1);
            }
            ctx.wait(if recent { HOUR } else { 2 * DAY });
            let b = ctx.device("B", SEED, birthday);
            let started = Instant::now();
            let mut syncs = 0;
            loop {
                let report = ctx.sync(b);
                syncs += 1;
                if !report.pending && report.problems.is_empty() || syncs >= 1_000 {
                    break;
                }
            }
            let ms = started.elapsed().as_secs_f64() * 1000.0;
            ctx.metric("restore wall time", ms, "ms");
            ctx.metric("restore syncs until quiet", f64::from(syncs), "syncs");
            ctx.metric(
                "keys scanning after the restore",
                ctx.get(b).scanning().len() as f64,
                "keys",
            );
            let pending = ctx.get(b).history_pending();
            ctx.check(
                "no sweeps or queued payments remain after the restore",
                !pending,
                format!("{syncs} syncs, pending {pending}"),
            );
            let wrong: Vec<String> = paid
                .iter()
                .enumerate()
                .filter_map(|(i, m)| {
                    let key = format!("I{i}");
                    let receipt = ctx.get(b).receipt(m.id());
                    let class = ctx.get(b).found(m.id()).map(|f| f.class);
                    let right = receipt
                        .as_ref()
                        .is_some_and(|r| r.key.as_ref() == Some(&key) && r.value == VALUE)
                        && class == Some(Class::FoundBySweep);
                    (!right).then(|| format!("{key}: {receipt:?}, {class:?}"))
                })
                .collect();
            ctx.check(
                format!(
                    "B's sweeps credit every one of the {swaps} payouts to its key, with its value"
                ),
                wrong.is_empty(),
                format!(
                    "{} wrong or missing{}",
                    wrong.len(),
                    wrong
                        .first()
                        .map_or(String::new(), |w| format!(", first {w}"))
                ),
            );
            for (i, m) in paid.iter().enumerate() {
                if i < 3 || i + 1 == paid.len() {
                    ctx.expect(
                        b,
                        &format!("payout to I{i}"),
                        &format!("I{i}"),
                        m,
                        Class::FoundBySweep,
                        "A restore sweeps paid keys through the directory.",
                    );
                }
            }
            ctx.restart(b);
            let next = ctx
                .quote_incoming(b, HOUR)
                .expect("B quotes after its restore");
            ctx.check(
                "B's next address follows every paid and seen one",
                next.index >= swaps,
                format!("issued {}, after I0 to I{}", next.label(), swaps - 1),
            );
            ctx.wait(20 * MINUTE);
            let label = "payout after the restore";
            let payout = ctx.pay(label, &next.label(), &next.fvk, VALUE, Payer::Near);
            ctx.observe_incoming(b, &next, "SUCCESS", Some(VALUE));
            ctx.mine(1);
            ctx.sync(b);
            ctx.expect(
                b,
                label,
                &next.label(),
                &payout,
                Class::FoundLive,
                "B issued the address after its restore, so its key scans from the quote.",
            );
            ctx.check_balance(b, (swaps + 1) * VALUE);
            if swaps == 10 {
                ctx.spend_one_time_notes(b);
            }
        }),
    }
}

/// Which side of its sibling pair a payment's leaf lands on in the note commitment tree.
/// A late find at an odd position needs its left sibling, an output the wallet scanned
/// past long ago; at an even position the sibling comes after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Parity {
    Odd,
    Even,
}

fn recheck_replay(age: i64, every: u32, parity: Parity) -> Scenario {
    let side = match parity {
        Parity::Odd => "odd",
        Parity::Even => "even",
    };
    let cost = age > 20 * DAY;
    Scenario {
        id: if cost {
            format!("J4-recheck-replay-wallet-{}-old", span(age))
        } else {
            format!(
                "E10-late-find-at-{side}-tree-position-wallet-{}-old",
                span(age)
            )
        },
        group: if cost { COST } else { super::RESTORE },
        title: if cost {
            format!(
                "Check swap history finds a late payment on a {}-old wallet",
                span(age)
            )
        } else {
            format!(
                "Check swap history finds a late payment at an {side} tree position on a {}-old wallet",
                span(age)
            )
        },
        summary: if cost {
            "Crediting a payment Check swap history finds can wait on a replay of the wallet's \
            history since its birthday, because ordinary wallets keep only about 100 blocks of \
            Ironwood spend evidence. Measures that replay. The payment lands at an even tree \
            position, so E10's odd-position failure does not mask the measurement."
                .into()
        } else {
            "The same late find twice, differing only in whether the payment's leaf is the right \
            (odd) or left (even) child of its pair. After the spend-history replay, applying the \
            payment needs the wallet's tree root at a recent checkpoint."
                .into()
        },
        params: vec![
            ("wallet age".into(), span(age)),
            (
                "background traffic".into(),
                format!("one Ironwood output every {every} blocks"),
            ),
            ("late payment position".into(), side.into()),
        ],
        slow: age > 60 * DAY,
        run: Box::new(move |ctx| {
            ctx.chain.traffic = Traffic { every, outputs: 1 };
            let (a, _) = wallet(ctx, "A");
            let swap = ctx.quote_incoming(a, HOUR).expect("the quote issues");
            ctx.wait(20 * MINUTE);
            ctx.pay("payout", &swap.label(), &swap.fvk, ZEC, Payer::Near);
            ctx.observe_incoming(a, &swap, "SUCCESS", Some(ZEC));
            ctx.mine(12);
            ctx.sync(a);
            ctx.wait(age - DAY);
            ctx.sync(a);
            // Land the payment on the requested side of its pair.
            let want_odd = parity == Parity::Odd;
            if (ctx.chain.commitments().len() % 2 == 1) != want_odd {
                let foreign =
                    FullViewingKey::from(&SpendingKey::from_bytes([0xf6; 32]).expect("a key"));
                ctx.pay(
                    "someone else's output",
                    "a stranger",
                    &foreign,
                    VALUE,
                    Payer::Wallet,
                );
            }
            let late = ctx.pay(
                "late payment",
                &swap.label(),
                &swap.fvk,
                ZEC / 2,
                Payer::Near,
            );
            ctx.metric(
                "late payment's tree position",
                late.position as f64,
                "position",
            );
            ctx.wait(DAY);
            ctx.sync(a);
            let scanned_before = ctx.get(a).scanned_blocks;
            let started = Instant::now();
            ctx.check_swap_history(a);
            let ms = started.elapsed().as_secs_f64() * 1000.0;
            let replayed = ctx.get(a).scanned_blocks - scanned_before;
            ctx.metric(
                "blocks scanned by Check swap history",
                replayed as f64,
                "blocks",
            );
            ctx.metric("Check swap history wall time", ms, "ms");
            ctx.expect(
                a,
                "late payment",
                &swap.label(),
                &late,
                Class::FoundAfterRecheck,
                "A later payment to a closed key that was already paid is found only by Check swap history.",
            );
            ctx.spend_one_time_notes(a);
        }),
    }
}
