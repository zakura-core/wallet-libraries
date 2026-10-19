//! Incoming (X to ZEC) swaps: NEAR pays a one-time incoming address, and wallets find
//! the payout live, after being offline, or after a restore from seed.

use zakura_one_time_ivk_scenarios::Class;
use zcash_protocol::consensus::BlockHeight;

use super::{LIVE, OFFLINE, RESTORE, STATUSES, Scenario, Schedule, span};
use crate::harness::{
    Ctx, Dev,
    chain::{BLOCK_SECS, DAY, HOUR, MINUTE, Payer, ZEC, block_time},
    device::IncomingSwap,
};

const SEED: [u8; 32] = [0x42; 32];
const HALF: u64 = ZEC / 2;
/// Confirmations a receipt needs before its key can close.
const CONFIRMATIONS: u32 = 10;

const OPEN_LIVE: &str = "The key was open: an incoming key scans from its reservation until its swap settles (a final status and every receipt confirmed 10 times), or 30 days after its deadline.";
const RESTORE_DISCOVERY: &str = "A restore tests its incoming receiver window against the receiver directory's paid sets, which list NEAR's zero-OVK payouts, and looks each paid key up, one page per payment.";
const OWN_OVK: &str = "The payer used its own OVK, so the receiver directory cannot list the payment, and a key that is not scanning cannot find it.";

pub fn all() -> Vec<Scenario> {
    let mut scenarios = Vec::new();
    // Two payouts to one incoming address, from the same transaction to three months
    // apart, with the original wallet online throughout or offline in between.
    let gaps = [
        None,
        Some(BLOCK_SECS),
        Some(4 * BLOCK_SECS),
        Some(HOUR),
        Some(DAY),
        Some(7 * DAY),
        Some(21 * DAY),
        Some(90 * DAY),
    ];
    for gap in gaps {
        for payer in [Payer::Near, Payer::Wallet] {
            for offline in [false, true] {
                // One transaction has one sender, and nobody syncs inside a block.
                if gap.is_none() && (payer == Payer::Wallet || offline) {
                    continue;
                }
                scenarios.push(paid_twice(gap, payer, offline));
            }
        }
    }
    for after in [HOUR, 12 * HOUR, 23 * HOUR, 25 * HOUR, 7 * DAY] {
        for fresh in [true, false] {
            scenarios.push(restore_in_flight(after, fresh));
        }
    }
    // Either side of discovery's first window, and past the gap that follows it.
    for unpaid in [40, 100, 130] {
        for covered in [true, false] {
            scenarios.push(beyond_lookahead(unpaid, covered));
        }
    }
    for after_deadline in [HOUR, 29 * DAY, 31 * DAY, 60 * DAY] {
        scenarios.push(provider_silent(after_deadline));
    }
    for amount in [None, Some(ZEC + HALF)] {
        scenarios.push(split_payout(amount));
    }
    scenarios
}

/// An incoming swap whose deposit NEAR has seen, ready for its payout.
struct Started {
    a: Dev,
    birthday: BlockHeight,
    swap: IncomingSwap,
    key: String,
}

/// Creates wallet A, quotes an incoming swap with a one-hour deadline, and records NEAR
/// seeing the deposit 20 minutes later. Returns 30 minutes after the quote.
fn start_incoming(ctx: &mut Ctx) -> Started {
    ctx.mine(20);
    let birthday = ctx.chain.tip() + 1;
    ctx.mine(5);
    let a = ctx.device("A", SEED, birthday);
    ctx.sync(a);
    let swap = ctx
        .quote_incoming(a, HOUR)
        .expect("the first incoming quote issues");
    let key = swap.label();
    ctx.wait(20 * MINUTE);
    ctx.observe_incoming(a, &swap, "KNOWN_DEPOSIT_TX", None);
    ctx.wait(10 * MINUTE);
    Started {
        a,
        birthday,
        swap,
        key,
    }
}

/// Confirmations of a block at `height` at the chain tip.
fn confirmations(ctx: &Ctx, height: BlockHeight) -> u32 {
    u32::from(ctx.chain.tip()) + 1 - u32::from(height)
}

fn payer_name(payer: Payer) -> &'static str {
    match payer {
        Payer::Near => "near",
        Payer::Wallet => "wallet",
    }
}

/// NEAR pays an incoming address, then the same address is paid again after `gap`
/// (in the same transaction when `None`). Wallet A made the swap; wallet B restores
/// the seed a day after the second payment.
fn paid_twice(gap: Option<i64>, payer2: Payer, offline: bool) -> Scenario {
    let gap_name = gap.map_or("same-tx".to_string(), span);
    let mode = if offline { "offline" } else { "online" };
    let id = format!(
        "{}-incoming-twice-{gap_name}-{}-{mode}",
        if offline { "D1" } else { "C2" },
        payer_name(payer2)
    );
    let title = format!(
        "Incoming address paid twice, {} apart, second by {}, A {mode} in between",
        gap.map_or("in one transaction".to_string(), span),
        payer2.label()
    );
    let summary = "NEAR pays a one-time incoming address, then the same address is paid again. \
        Shows when the device that made the swap finds the second payment (live, through \
        recovery once its key closed, or never) and what a later seed restore finds."
        .to_string();
    let params = vec![
        ("gap".into(), gap_name.clone()),
        ("second payer".into(), payer2.label().into()),
        ("wallet A".into(), mode.into()),
    ];
    Scenario {
        id,
        group: if offline { OFFLINE } else { LIVE },
        title,
        summary,
        params,
        slow: gap.is_some_and(|g| g > 30 * DAY),
        run: Box::new(move |ctx| {
            let s = start_incoming(ctx);
            let (a, key, fvk) = (s.a, s.key.clone(), s.swap.fvk.clone());
            // The predicted state of the key, from the documented closing rule.
            let mut open = true;
            let mut status_recorded = false;
            let (p1, p2, open_when_paid);
            match gap {
                None => {
                    let both = ctx.pay_many(
                        "payouts 1 and 2",
                        &[(&key, &fvk, ZEC), (&key, &fvk, HALF)],
                        Payer::Near,
                    );
                    p1 = both[0].clone();
                    p2 = both[1].clone();
                    open_when_paid = true;
                }
                Some(gap) => {
                    p1 = ctx.pay("payout 1", &key, &fvk, ZEC, Payer::Near);
                    let t1 = block_time(p1.height);
                    enum Step {
                        Pay,
                        Sync,
                        Status,
                    }
                    let mut plan = Schedule::new();
                    plan.at(t1 + gap, Step::Pay);
                    if !offline {
                        plan.at(t1 + BLOCK_SECS, Step::Sync);
                        plan.at(t1 + 5 * MINUTE, Step::Status);
                        plan.at(t1 + 12 * BLOCK_SECS, Step::Sync);
                        let mut day = t1 + DAY;
                        while day < t1 + gap {
                            plan.at(day, Step::Sync);
                            day += DAY;
                        }
                    }
                    let mut paid = None;
                    let mut open_then = true;
                    for (at, step) in plan.into_steps() {
                        if paid.is_some() {
                            break;
                        }
                        match step {
                            Step::Pay => {
                                ctx.chain.mine_until_next_at(at);
                                paid = Some(ctx.pay("payout 2", &key, &fvk, HALF, payer2));
                                open_then = open;
                            }
                            Step::Sync => {
                                ctx.chain.mine_until(at);
                                ctx.sync(a);
                                if open
                                    && status_recorded
                                    && confirmations(ctx, p1.height) >= CONFIRMATIONS
                                {
                                    open = false;
                                    ctx.check_key_open(a, &key, false);
                                }
                            }
                            Step::Status => {
                                ctx.chain.mine_until(at);
                                ctx.observe_incoming(a, &s.swap, "SUCCESS", Some(ZEC));
                                status_recorded = true;
                            }
                        }
                    }
                    p2 = paid.expect("payout 2 was scheduled");
                    open_when_paid = open_then;
                }
            }
            ctx.mine(1);
            if !status_recorded {
                ctx.observe_incoming(a, &s.swap, "SUCCESS", Some(ZEC));
            }
            ctx.sync(a);
            ctx.wait(DAY);
            ctx.sync(a);
            let b = ctx.device("B", SEED, s.birthday);
            ctx.sync(b);
            ctx.sync(b);

            ctx.expect(a, "payout 1", &key, &p1, Class::FoundLive, OPEN_LIVE);
            let (a2, why) = if open_when_paid {
                (
                    Class::FoundLive,
                    if offline {
                        "A was offline from payout 1 until after payout 2. Keys close only at a scanned tip, so the key was still open when A scanned both payouts."
                    } else {
                        "The key was still open when payout 2 was mined: it closes only once every receipt has 10 confirmations at a tip the wallet scanned."
                    },
                )
            } else if payer2 == Payer::Near {
                (
                    Class::FoundByDiscovery,
                    "The key had closed with a known payment, but it stays registered, so recovery tests it against the bucket holding payout 2 and looks it up.",
                )
            } else {
                (
                    Class::MissedDocumented,
                    "The key had closed, and the payer used its own OVK, so the receiver directory cannot list the payment and recovery cannot find it.",
                )
            };
            ctx.expect(a, "payout 2", &key, &p2, a2, why);
            ctx.expect(
                b,
                "payout 1",
                &key,
                &p1,
                Class::FoundByDiscovery,
                RESTORE_DISCOVERY,
            );
            let (b2, why) = match payer2 {
                Payer::Near => (Class::FoundByDiscovery, RESTORE_DISCOVERY),
                Payer::Wallet => (Class::MissedDocumented, OWN_OVK),
            };
            ctx.expect(b, "payout 2", &key, &p2, b2, why);
            ctx.check_balance(a, ZEC + if a2.found() { HALF } else { 0 });
            ctx.check_balance(b, ZEC + if b2.found() { HALF } else { 0 });
        }),
    }
}

/// Wallet A quotes an incoming swap; half an hour later the seed is restored on wallet B
/// (A's device is gone). NEAR pays `after` the restore, with NEAR's feed `fresh` or stale,
/// which recovery does not depend on.
fn restore_in_flight(after: i64, fresh: bool) -> Scenario {
    let feed = if fresh { "fresh" } else { "stale" };
    Scenario {
        id: format!("E2-restore-in-flight-payout-{}-{feed}-feed", span(after)),
        group: RESTORE,
        title: format!(
            "Restore while an incoming swap is in flight, payout {} later, {feed} NEAR feed",
            span(after)
        ),
        summary:
            "The seed is restored on a new device while NEAR still owes a payout. The address \
            is in the restored receiver window, so recovery finds the payout from the bucket that \
            holds it, however late, without scanning the key."
                .into(),
        params: vec![
            ("payout after restore".into(), span(after)),
            ("NEAR feed".into(), feed.into()),
        ],
        slow: false,
        run: Box::new(move |ctx| {
            let s = start_incoming(ctx);
            if !fresh {
                // The feed's last complete read began half an hour ago, past the
                // 15-minute freshness a wallet trusts a recent set within.
                ctx.near.read_lag = 30 * MINUTE;
            }
            let b = ctx.device("B", SEED, s.birthday);
            ctx.sync(b);
            let open_keys = ctx.get(b).scanning().len();
            ctx.metric(
                "B keys scanning after its restore's recovery",
                open_keys as f64,
                "keys",
            );
            let t = ctx.chain.now();
            let mut day = t + DAY;
            while day < t + after {
                ctx.chain.mine_until(day);
                ctx.sync(b);
                day += DAY;
            }
            ctx.chain.mine_until_next_at(t + after);
            let payout = ctx.pay("payout", &s.key, &s.swap.fvk, ZEC, Payer::Near);
            ctx.mine(1);
            ctx.sync(b);
            ctx.wait(HOUR);
            ctx.sync(b);
            ctx.expect(
                b,
                "payout",
                &s.key,
                &payout,
                Class::FoundByDiscovery,
                "The address is in B's receiver window, so the bucket holding the payout tests it and recovery looks it up.",
            );
            ctx.check_balance(b, ZEC);
            if after == HOUR && fresh {
                ctx.spend_one_time_notes(b);
            }
        }),
    }
}

/// Wallet A quotes `unpaid` incoming swaps that NEAR never pays, then one it does. B
/// restores the seed. When NEAR's feed `covered` the quotes, the seen set grows the
/// receiver window past them; otherwise it ends 30 indices above the last payment.
fn beyond_lookahead(unpaid: u64, covered: bool) -> Scenario {
    let feed = if covered {
        "feed-covers"
    } else {
        "feed-missed"
    };
    Scenario {
        id: format!("E5-lookahead-{unpaid}-unpaid-then-paid-{feed}"),
        group: RESTORE,
        title: format!(
            "{unpaid} unpaid incoming quotes, then a paid one; NEAR's seen set {} them",
            if covered { "covers" } else { "misses" }
        ),
        summary: "A restore's receiver window covers the first 100 incoming keys, and grows to 30 \
            past every index a payment or NEAR's seen set shows used; quotes NEAR's feed never \
            recorded do not count, so a payment past both is never found."
            .into(),
        params: vec![
            ("unpaid quotes first".into(), unpaid.to_string()),
            (
                "seen set".into(),
                if covered {
                    "covers them"
                } else {
                    "misses them"
                }
                .into(),
            ),
        ],
        slow: false,
        run: Box::new(move |ctx| {
            ctx.mine(20);
            let birthday = ctx.chain.tip() + 1;
            ctx.mine(5);
            let a = ctx.device("A", SEED, birthday);
            ctx.sync(a);
            for _ in 0..unpaid {
                let swap = ctx.quote_incoming(a, HOUR).expect("an unpaid quote issues");
                ctx.wait(10 * MINUTE);
                ctx.observe_incoming(a, &swap, "REFUNDED", None);
                ctx.mine(1);
                ctx.sync(a);
            }
            let swap = ctx.quote_incoming(a, HOUR).expect("the paid quote issues");
            ctx.check(
                "the paid quote's index",
                swap.index == unpaid,
                format!("{} (expected I{unpaid})", swap.label()),
            );
            ctx.wait(30 * MINUTE);
            let payout = ctx.pay("payout", &swap.label(), &swap.fvk, ZEC, Payer::Near);
            ctx.mine(1);
            ctx.observe_incoming(a, &swap, "SUCCESS", Some(ZEC));
            ctx.sync(a);
            ctx.wait(DAY);
            if !covered {
                // The directory's NEAR feed now starts after every quote, as one deployed
                // with a later `--near-since` would: its seen set holds none of them.
                ctx.near.feed_started = ctx.chain.now() - HOUR;
                ctx.log(
                    "directory",
                    "NEAR feed restarted: its seen set starts an hour ago",
                );
            }
            let b = ctx.device("B", SEED, birthday);
            for _ in 0..3 {
                ctx.sync(b);
            }
            ctx.expect(
                a,
                "payout",
                &swap.label(),
                &payout,
                Class::FoundLive,
                OPEN_LIVE,
            );
            let (class, why) = if covered || unpaid < WINDOW_FLOOR {
                (
                    Class::FoundByDiscovery,
                    if covered {
                        "Every unpaid quote is in NEAR's seen set, and seen hits grow the receiver window like payments, so it reaches the paid index."
                    } else {
                        "The paid index is among the first 100, which the receiver window always covers."
                    },
                )
            } else {
                (
                    Class::MissedDocumented,
                    "NEAR's seen set never recorded the unpaid quotes, so the receiver window ends 30 indices past the last used one beyond the first 100, and an incoming index past that is never tested.",
                )
            };
            ctx.expect(b, "payout", &swap.label(), &payout, class, why);
            ctx.check_balance(b, if class.found() { ZEC } else { 0 });
        }),
    }
}

/// Indices every receiver window covers from zero (the SQLite store's `WINDOW_FLOOR`).
const WINDOW_FLOOR: u64 = 100;

/// NEAR never reports a status after the quote, then pays `after_deadline` past the
/// deposit deadline. The key scans until 30 days after the deadline.
fn provider_silent(after_deadline: i64) -> Scenario {
    Scenario {
        id: format!(
            "H2-silent-provider-payout-deadline+{}",
            span(after_deadline)
        ),
        group: STATUSES,
        title: format!(
            "NEAR never reports a status and pays {} after the deadline",
            span(after_deadline)
        ),
        summary: "Without a final status a key scans until 30 days after its deadline \
            (COMPLETION_LIMIT_SECS). A payout before then is found live; a later one only by \
            Check swap history."
            .into(),
        params: vec![("payout after deadline".into(), span(after_deadline))],
        slow: after_deadline > 30 * DAY,
        run: Box::new(move |ctx| {
            ctx.mine(20);
            let birthday = ctx.chain.tip() + 1;
            ctx.mine(5);
            let a = ctx.device("A", SEED, birthday);
            ctx.sync(a);
            let swap = ctx.quote_incoming(a, HOUR).expect("the quote issues");
            let key = swap.label();
            let deadline = swap.deposit.deadline;
            let pay_at = deadline + after_deadline;
            let mut day = ctx.chain.now() + DAY;
            while day < pay_at {
                ctx.chain.mine_until(day);
                ctx.sync(a);
                day += DAY;
            }
            ctx.chain.mine_until_next_at(pay_at);
            let payout = ctx.pay("payout", &key, &swap.fvk, ZEC, Payer::Near);
            ctx.mine(1);
            ctx.sync(a);
            ctx.wait(DAY);
            ctx.sync(a);
            let within = after_deadline < 30 * DAY;
            if !within {
                ctx.check_swap_history(a);
            }
            let (class, why) = if within {
                (
                    Class::FoundLive,
                    "With no final status the key scans until 30 days after its deadline (COMPLETION_LIMIT_SECS).",
                )
            } else {
                (
                    Class::FoundAfterRecheck,
                    "The key closed unpaid at its 30-day limit, and discovery never refreshes a closed key on its own, so Check swap history finds the payment (recheck_one_time_key_history).",
                )
            };
            ctx.expect(a, "payout", &key, &payout, class, why);
            ctx.check_balance(a, ZEC);
            if !within {
                ctx.spend_one_time_notes(a);
            }
        }),
    }
}

/// NEAR pays an incoming swap in two transactions an hour apart and reports SUCCESS
/// after the first, with `amount_out` either missing or the total.
fn split_payout(amount_out: Option<u64>) -> Scenario {
    let name = if amount_out.is_some() {
        "with-total"
    } else {
        "without-amount"
    };
    Scenario {
        id: format!("H3-split-payout-success-{name}"),
        group: STATUSES,
        title: format!(
            "NEAR pays in two parts an hour apart; SUCCESS reported {}",
            if amount_out.is_some() {
                "with the total amountOut"
            } else {
                "without amountOut"
            }
        ),
        summary: "A final status closes a key once its receipts cover what the provider promised. \
            Without an amount the store expects one zatoshi, so the key can close after the first \
            part, and recovery finds the second from its bucket."
            .into(),
        params: vec![(
            "amountOut".into(),
            amount_out.map_or("missing".into(), |v| format!("{v} zat")),
        )],
        slow: false,
        run: Box::new(move |ctx| {
            let s = start_incoming(ctx);
            let (a, key, fvk) = (s.a, s.key.clone(), s.swap.fvk.clone());
            let p1 = ctx.pay("payout part 1", &key, &fvk, ZEC, Payer::Near);
            ctx.mine(1);
            ctx.observe_incoming(a, &s.swap, "SUCCESS", amount_out);
            ctx.sync(a);
            ctx.mine(CONFIRMATIONS + 2);
            ctx.sync(a);
            ctx.wait(HOUR);
            let p2 = ctx.pay("payout part 2", &key, &fvk, HALF, Payer::Near);
            ctx.mine(1);
            ctx.sync(a);
            ctx.wait(DAY);
            ctx.sync(a);
            ctx.expect(a, "payout part 1", &key, &p1, Class::FoundLive, OPEN_LIVE);
            let (class, why) = if amount_out.is_some() {
                (
                    Class::FoundLive,
                    "SUCCESS promised the total, so the key stays open until confirmed receipts cover it.",
                )
            } else {
                (
                    Class::FoundByDiscovery,
                    "SUCCESS without amountOut expects one zatoshi, so the key closes once the first part has 10 confirmations; the key stays registered, so recovery tests it against the bucket holding the second part.",
                )
            };
            ctx.expect(a, "payout part 2", &key, &p2, class, why);
            ctx.check_balance(a, ZEC + HALF);
        }),
    }
}
