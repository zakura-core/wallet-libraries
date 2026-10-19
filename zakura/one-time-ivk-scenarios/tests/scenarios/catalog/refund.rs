//! ZEC-to-X swaps: the wallet funds NEAR's deposit with a refund memo on its Ironwood
//! change, and NEAR's refunds come back to the swap's one-time refund key.

use zakura_one_time_ivk_scenarios::Class;
use zcash_protocol::consensus::BlockHeight;

use super::{FUNDING, RESTORE, Scenario, span};
use crate::harness::{
    Ctx, Dev,
    chain::{DAY, HOUR, MINUTE, Payer, ZEC},
    device::RefundSwap,
};

const SEED: [u8; 32] = [0x24; 32];
/// What the wallet starts with in its ordinary Ironwood address.
const FUNDS: u64 = 3 * ZEC;
/// The deposit it sends NEAR.
const DEPOSIT: u64 = ZEC;

const REFUND_OPEN: &str = "A refund key scans from its funding transaction while NEAR owes a refund: until the refund is received and confirmed 10 times, or 30 days after the deadline.";
const RESTORE_MEMO: &str = "A restore recovers the refund key from the refund memo on its funding transaction's Ironwood change, then looks it up in the receiver directory, which lists NEAR's zero-OVK refund.";

pub fn all() -> Vec<Scenario> {
    let mut scenarios = Vec::new();
    for delay in [30 * MINUTE, DAY, 25 * DAY, 40 * DAY] {
        scenarios.push(refund_once(delay));
    }
    for gap in [None, Some(HOUR), Some(7 * DAY), Some(21 * DAY)] {
        scenarios.push(refunded_twice(gap));
    }
    for delay in [HOUR, 23 * HOUR, 25 * HOUR, 5 * DAY] {
        scenarios.push(restore_before_refund(delay));
    }
    scenarios
}

/// A funded ZEC-to-X swap whose deposit NEAR has seen.
struct Funded {
    a: Dev,
    birthday: BlockHeight,
    swap: RefundSwap,
    key: String,
}

/// Creates wallet A with Ironwood funds, quotes a ZEC-to-X swap with a one-hour
/// deadline, funds its deposit with the refund memo, and records NEAR processing it.
fn fund_swap(ctx: &mut Ctx) -> Funded {
    ctx.mine(20);
    let birthday = ctx.chain.tip() + 1;
    ctx.mine(5);
    let a = ctx.device("A", SEED, birthday);
    let fvk = ctx.get(a).fvk.clone();
    ctx.pay(
        "A's Ironwood funds",
        "A's address",
        &fvk,
        FUNDS,
        Payer::Wallet,
    );
    ctx.mine(10);
    ctx.sync(a);
    let swap = ctx.quote_refund(a, HOUR).expect("the refund key reserves");
    let key = swap.label();
    ctx.fund_refund(a, &swap, DEPOSIT);
    ctx.mine(1);
    ctx.sync(a);
    ctx.check_key_open(a, &key, true);
    ctx.wait(10 * MINUTE);
    ctx.observe_refund(a, &swap, "PROCESSING", None);
    Funded {
        a,
        birthday,
        swap,
        key,
    }
}

/// NEAR refunds the whole deposit `delay` after funding, reporting REFUNDED as it pays.
/// Wallet A syncs daily; B restores the seed a day after the refund.
fn refund_once(delay: i64) -> Scenario {
    Scenario {
        id: format!("B1-refund-after-{}", span(delay)),
        group: FUNDING,
        title: format!("NEAR refunds a ZEC-to-X swap {} after funding", span(delay)),
        summary:
            "The deposit carries a refund memo naming the swap's one-time refund key. Shows that \
            the funding wallet finds the refund while the key scans, that recovery finds a refund \
            after the 30-day limit, and that a restore recovers the key from the memo."
                .into(),
        params: vec![("refund after funding".into(), span(delay))],
        slow: delay > 30 * DAY,
        run: Box::new(move |ctx| {
            let f = fund_swap(ctx);
            let start = ctx.chain.now();
            let mut day = start + DAY;
            while day < start + delay {
                ctx.chain.mine_until(day);
                ctx.sync(f.a);
                day += DAY;
            }
            ctx.chain.mine_until_next_at(start + delay);
            let refund = ctx.pay("refund", &f.key, &f.swap.fvk, DEPOSIT - 10_000, Payer::Near);
            ctx.observe_refund(f.a, &f.swap, "REFUNDED", Some(DEPOSIT - 10_000));
            ctx.mine(1);
            ctx.sync(f.a);
            ctx.wait(DAY);
            ctx.sync(f.a);
            let b = ctx.device("B", SEED, f.birthday);
            ctx.sync(b);
            ctx.sync(b);
            let (class, why) = if delay < 30 * DAY {
                (Class::FoundLive, REFUND_OPEN)
            } else {
                (
                    Class::FoundByDiscovery,
                    "The key closed unpaid 30 days after the deadline, but it stays registered, so recovery tests it against the bucket holding the refund.",
                )
            };
            ctx.expect(f.a, "refund", &f.key, &refund, class, why);
            ctx.expect(
                b,
                "refund",
                &f.key,
                &refund,
                Class::FoundByDiscovery,
                RESTORE_MEMO,
            );
            ctx.check_same_balance(f.a, b);
            if delay == 30 * MINUTE {
                ctx.spend_one_time_notes(f.a);
            }
        }),
    }
}

/// NEAR refunds part of the deposit an hour after funding (reporting SUCCESS with that
/// refundedAmount), then refunds again after `gap` (in the same transaction when
/// `None`), as for a duplicate or corrected deposit.
fn refunded_twice(gap: Option<i64>) -> Scenario {
    let name = gap.map_or("same-tx".to_string(), span);
    Scenario {
        id: format!("B5-refund-twice-{name}"),
        group: FUNDING,
        title: format!(
            "NEAR refunds a swap twice, {}",
            gap.map_or("in one transaction".to_string(), |g| format!(
                "{} apart",
                span(g)
            ))
        ),
        summary: "A refund key closes once its receipts cover the refunded amount NEAR reported. \
            Recovery finds a second refund to the same key after that, on the funding wallet and \
            on a restore."
            .into(),
        params: vec![("gap".into(), name.clone())],
        slow: false,
        run: Box::new(move |ctx| {
            let f = fund_swap(ctx);
            ctx.wait(HOUR);
            let (first, second);
            match gap {
                None => {
                    let both = ctx.pay_many(
                        "refunds 1 and 2",
                        &[
                            (&f.key, &f.swap.fvk, 3 * ZEC / 10),
                            (&f.key, &f.swap.fvk, 2 * ZEC / 10),
                        ],
                        Payer::Near,
                    );
                    first = both[0].clone();
                    second = both[1].clone();
                    ctx.observe_refund(f.a, &f.swap, "SUCCESS", Some(3 * ZEC / 10));
                    ctx.mine(1);
                    ctx.sync(f.a);
                }
                Some(gap) => {
                    first = ctx.pay("refund 1", &f.key, &f.swap.fvk, 3 * ZEC / 10, Payer::Near);
                    ctx.observe_refund(f.a, &f.swap, "SUCCESS", Some(3 * ZEC / 10));
                    ctx.mine(1);
                    ctx.sync(f.a);
                    ctx.mine(12);
                    ctx.sync(f.a);
                    let t = ctx.chain.now();
                    let mut day = t + DAY;
                    while day < t + gap {
                        ctx.chain.mine_until(day);
                        ctx.sync(f.a);
                        day += DAY;
                    }
                    ctx.chain.mine_until_next_at(t + gap);
                    second = ctx.pay("refund 2", &f.key, &f.swap.fvk, 2 * ZEC / 10, Payer::Near);
                    ctx.mine(1);
                    ctx.sync(f.a);
                }
            }
            ctx.wait(DAY);
            ctx.sync(f.a);
            let b = ctx.device("B", SEED, f.birthday);
            ctx.sync(b);
            ctx.sync(b);
            ctx.expect(
                f.a,
                "refund 1",
                &f.key,
                &first,
                Class::FoundLive,
                REFUND_OPEN,
            );
            let (class, why) = if gap.is_none_or(|g| g < 12 * 75) {
                (
                    Class::FoundLive,
                    "Both refunds arrived before the key could close.",
                )
            } else {
                (
                    Class::FoundByDiscovery,
                    "The key closed once refund 1 covered the reported refundedAmount and had 10 confirmations, but it stays registered, so recovery tests it against the bucket holding refund 2.",
                )
            };
            ctx.expect(f.a, "refund 2", &f.key, &second, class, why);
            ctx.expect(
                b,
                "refund 1",
                &f.key,
                &first,
                Class::FoundByDiscovery,
                RESTORE_MEMO,
            );
            ctx.expect(
                b,
                "refund 2",
                &f.key,
                &second,
                Class::FoundByDiscovery,
                RESTORE_MEMO,
            );
            ctx.check_same_balance(f.a, b);
        }),
    }
}

/// A funds a ZEC-to-X swap, then its device is lost: B restores the seed half an hour
/// after funding, and NEAR refunds `delay` after the restore.
fn restore_before_refund(delay: i64) -> Scenario {
    Scenario {
        id: format!("E2-restore-before-refund-{}", span(delay)),
        group: RESTORE,
        title: format!(
            "Restore while a refund is owed, refund {} after the restore",
            span(delay)
        ),
        summary: "A restore recovers the refund key from the funding memo, so recovery tests it \
            against every later bucket and finds the refund however late, without scanning the key."
            .into(),
        params: vec![("refund after restore".into(), span(delay))],
        slow: false,
        run: Box::new(move |ctx| {
            let f = fund_swap(ctx);
            ctx.wait(20 * MINUTE);
            let b = ctx.device("B", SEED, f.birthday);
            ctx.sync(b);
            ctx.sync(b);
            let t = ctx.chain.now();
            let mut day = t + DAY;
            while day < t + delay {
                ctx.chain.mine_until(day);
                ctx.sync(b);
                day += DAY;
            }
            ctx.chain.mine_until_next_at(t + delay);
            let refund = ctx.pay("refund", &f.key, &f.swap.fvk, DEPOSIT - 10_000, Payer::Near);
            ctx.mine(1);
            ctx.sync(b);
            ctx.wait(HOUR);
            ctx.sync(b);
            ctx.expect(
                b,
                "refund",
                &f.key,
                &refund,
                Class::FoundAutomatically,
                "B recovered the refund key from the funding memo, so the bucket holding the refund tests it and recovery looks it up.",
            );
            if delay == 25 * HOUR {
                ctx.spend_one_time_notes(b);
            }
        }),
    }
}
