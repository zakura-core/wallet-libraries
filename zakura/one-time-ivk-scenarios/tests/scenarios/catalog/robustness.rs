//! Robustness: receiver directory failures, a quiet chain, device clocks that drift,
//! payouts seen in the mempool, and spending what one-time keys received.

use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use zakura_one_time_ivk::Purpose;
use zakura_one_time_ivk_scenarios::Class;
use zcash_client_sqlite::wallet::one_time_ivk::swap::ReservationPolicy;

use super::{LIVE, OFFLINE, RESTORE, SPENDING, Scenario, span};
use crate::harness::{
    Ctx, Dev,
    chain::{DAY, HOUR, MINUTE, Mined, Payer, Traffic, ZEC, receiver_of},
    device::IncomingSwap,
    directory::Fault,
    near::Role,
};

const SEED: [u8; 32] = [0x66; 32];

pub fn all() -> Vec<Scenario> {
    let mut scenarios = vec![
        directory_down_at_restore(),
        omitted_payment(),
        quiet_chain(),
    ];
    for status in [503, 429, 410] {
        scenarios.push(directory_errors(status));
    }
    for stops in [false, true] {
        scenarios.push(directory_fails_on_a_later_page(stops));
    }
    for (skew, after_deadline) in [(5 * DAY, 29 * DAY), (-2 * DAY, 31 * DAY)] {
        scenarios.push(clock_skew(skew, after_deadline));
    }
    scenarios.push(mempool_then_mined());
    scenarios.push(mempool_then_dropped());
    scenarios.push(one_time_notes_spent_first());
    scenarios
}

/// Wallet A quotes an incoming swap that NEAR pays a day later and settles. Returns A,
/// its birthday, the swap and the payout, a day after the payout.
fn paid_swap(
    ctx: &mut Ctx,
) -> (
    Dev,
    zcash_protocol::consensus::BlockHeight,
    IncomingSwap,
    Mined,
) {
    ctx.mine(20);
    let birthday = ctx.chain.tip() + 1;
    ctx.mine(5);
    let a = ctx.device("A", SEED, birthday);
    ctx.sync(a);
    let swap = ctx.quote_incoming(a, HOUR).expect("the quote issues");
    ctx.wait(20 * MINUTE);
    let payout = ctx.pay("payout", &swap.label(), &swap.fvk, ZEC, Payer::Near);
    ctx.observe_incoming(a, &swap, "SUCCESS", Some(ZEC));
    ctx.mine(12);
    ctx.sync(a);
    ctx.wait(DAY);
    (a, birthday, swap, payout)
}

/// B syncs every `every` for `span`, as Vizor's polling would.
fn keep_syncing(ctx: &mut Ctx, b: Dev, every: i64, span: i64) {
    let end = ctx.chain.now() + span;
    while ctx.chain.now() < end {
        ctx.wait(every);
        ctx.sync(b);
    }
}

fn directory_down_at_restore() -> Scenario {
    Scenario {
        id: "E7-directory-down-at-restore".into(),
        group: RESTORE,
        title: "The receiver directory is down when the seed is restored, and back an hour later"
            .into(),
        summary: "Without the directory a restore cannot check its windows against the seen set, \
            so it cannot issue new addresses either (Gap). Recovery runs once the directory answers."
            .into(),
        params: vec![("outage".into(), "1h".into())],
        slow: false,
        run: Box::new(|ctx| {
            let (_, birthday, swap, payout) = paid_swap(ctx);
            let b = ctx.device("B", SEED, birthday);
            ctx.dev(b).reach.directory = false;
            ctx.log("directory", "unreachable");
            ctx.sync(b);
            let quote = ctx.prepare_incoming(b);
            ctx.check(
                "B cannot issue an address before its seen check",
                quote == Err(ReservationPolicy::Gap),
                format!("{quote:?}"),
            );
            ctx.wait(HOUR);
            ctx.dev(b).reach.directory = true;
            ctx.log("directory", "reachable again");
            keep_syncing(ctx, b, 10 * MINUTE, HOUR);
            ctx.expect(
                b,
                "payout",
                &swap.label(),
                &payout,
                Class::FoundByDiscovery,
                "Recovery runs once the directory answers.",
            );
        }),
    }
}

fn directory_errors(status: u16) -> Scenario {
    Scenario {
        id: format!("E7-directory-answers-{status}-at-restore"),
        group: RESTORE,
        title: format!(
            "The receiver directory answers HTTP {status} to a restore's first requests"
        ),
        summary: "409 and 410 mean a new publication; anything else, 429 included, is a retryable \
            transport failure that backs the key off. Either way the payment is found by a later \
            recovery run."
            .into(),
        params: vec![("status".into(), status.to_string())],
        slow: false,
        run: Box::new(move |ctx| {
            let (_, birthday, swap, payout) = paid_swap(ctx);
            let b = ctx.device("B", SEED, birthday);
            ctx.dev(b).reach.directory_faults = vec![status; 3];
            ctx.log(
                "directory",
                format!("answers the next 3 requests with HTTP {status}"),
            );
            ctx.sync(b);
            keep_syncing(ctx, b, 10 * MINUTE, 3 * HOUR);
            ctx.expect(
                b,
                "payout",
                &swap.label(),
                &payout,
                Class::FoundByDiscovery,
                "A later recovery run finds the payment after the failures.",
            );
        }),
    }
}

/// A restore's recovery loses the directory on I1's second payment page, after reading
/// I1's first and finishing I0. The directory answers HTTP 503, or, when `stops`, the app
/// stops during the request and its next sync's witness download fails too. Every payment
/// must be credited once in the end, and I1's retry must wait out its backoff.
fn directory_fails_on_a_later_page(stops: bool) -> Scenario {
    let what = if stops {
        "the app stops during the request, then the witness download fails"
    } else {
        "the directory answers HTTP 503"
    };
    Scenario {
        id: if stops {
            "E7-app-stops-mid-lookup-then-witnesses-fail".into()
        } else {
            "E7-directory-fails-a-later-page".into()
        },
        group: RESTORE,
        title: format!("A restore's lookup of a twice-paid key fails on its second page: {what}"),
        summary:
            "A lookup keeps each page it reads as its cursor, and a failure partway backs the \
            key off while the others finish. The late path admits the payments already read \
            meanwhile. Once retried, the lookup resumes from its cursor, and every payment is \
            credited exactly once."
                .into(),
        params: vec![("failure".into(), what.into())],
        slow: false,
        run: Box::new(move |ctx| {
            ctx.mine(20);
            let birthday = ctx.chain.tip() + 1;
            ctx.mine(5);
            // The seed's owner quoted and was paid on another device.
            let owner = ctx.device("A", SEED, birthday);
            let values = [ZEC / 10, 2 * ZEC / 10, 3 * ZEC / 10, 4 * ZEC / 10];
            let paid_to = [0, 1, 1, 2];
            for index in 0..3 {
                let fvk = ctx.get(owner).key(Purpose::Receive, index);
                ctx.near
                    .give(receiver_of(&fvk), ctx.chain.now(), Role::Payout);
            }
            let mut payouts = Vec::new();
            for (&index, &value) in paid_to.iter().zip(&values) {
                let fvk = ctx.get(owner).key(Purpose::Receive, index);
                let label = format!("I{index}");
                payouts.push((
                    label.clone(),
                    ctx.pay("payout", &label, &fvk, value, Payer::Near),
                ));
                ctx.mine(1);
            }
            ctx.wait(2 * DAY);
            let b = ctx.device("B", SEED, birthday);
            // Recovery tests a bucket or snapshot only once the scan stored its last block, so
            // B scans first and its next run makes the lookups.
            ctx.scan_only(b);
            // Lookups run in key order: I0's page, then I1's two pages.
            let fault = Fault {
                request: "POST /v1/receiver/query",
                after: 2,
                status: if stops { None } else { Some(503) },
            };
            ctx.dev(b).reach.endpoint_faults = vec![fault];
            ctx.log("directory", format!("I1's second payment page: {what}"));
            let failed_at = ctx.chain.now();
            ctx.sync(b);
            let receipts = |ctx: &Ctx| {
                (0..3)
                    .map(|i| ctx.get(b).incoming_receipts(i))
                    .collect::<Vec<_>>()
            };
            let after_failure = receipts(ctx);
            // The late path admits every page read before the failure, and I1 then waits out
            // its backoff. A stopped app records no walk, but the restarted app's run after
            // the scan reads every page.
            let read = if stops { [1, 2, 1] } else { [1, 1, 1] };
            ctx.check(
                "the late path admits every payment read in the sync",
                after_failure == read,
                format!("receipts per key {after_failure:?}"),
            );
            let backoff = ctx.get(b).lookup_state(Purpose::Receive, 1);
            if !stops {
                ctx.check(
                    "I1's failed page backs its lookup off for 60 s",
                    backoff.is_some_and(|s| {
                        s.attempts == 1
                            && s.next_attempt_at == failed_at + 60
                            && s.done_height.is_none()
                    }),
                    format!("{backoff:?}, failed at {failed_at}"),
                );
            }
            if stops {
                ctx.dev(b).reach.endpoint_faults = vec![Fault {
                    request: "GET /v1/receiver/witness",
                    after: 0,
                    status: Some(503),
                }];
                ctx.log("directory", "the next witness download answers HTTP 503");
            }
            // Within I1's backoff: the next sync runs at the same chain time.
            ctx.sync(b);
            let waiting = ctx.get(b).lookup_state(Purpose::Receive, 1);
            if !stops {
                ctx.check(
                    "I1 is not retried within its backoff",
                    waiting == backoff,
                    format!("{waiting:?}"),
                );
            }
            keep_syncing(ctx, b, 10 * MINUTE, HOUR);
            let retried = ctx.get(b).lookup_state(Purpose::Receive, 1);
            ctx.check(
                "I1's lookup resumes once its backoff passes, and finishes",
                retried.is_some_and(|s| s.done_height.is_some()),
                format!("{retried:?}"),
            );
            let settled = receipts(ctx);
            let pending = ctx.get(b).history_pending();
            ctx.check(
                "every payment is credited exactly once",
                settled == [1, 2, 1] && !pending,
                format!("receipts per key {settled:?}, history pending {pending}"),
            );
            for (label, payout) in &payouts {
                ctx.expect(
                    b,
                    "payout",
                    label,
                    payout,
                    Class::FoundAutomatically,
                    "Recovery looks each paid key up, and the late path admits each payment.",
                );
            }
            ctx.check_balance(b, values.iter().sum());
        }),
    }
}

fn omitted_payment() -> Scenario {
    Scenario {
        id: "E7-indexer-omits-then-lists-payment".into(),
        group: RESTORE,
        title: "The directory's first publications omit a payment, later ones list it".into(),
        summary: "An empty page zero means no indexed payment, not an unused address. Once the \
            indexer lists the payment, the directory corrects its published history under a new \
            epoch, so recovery bootstraps again and finds it."
            .into(),
        params: Vec::new(),
        slow: false,
        run: Box::new(|ctx| {
            let (_, birthday, swap, payout) = paid_swap(ctx);
            let b = ctx.device("B", SEED, birthday);
            ctx.dev(b).reach.publication.omit.insert(payout.position);
            ctx.log("directory", "publications omit the payout");
            ctx.sync(b);
            ctx.sync(b);
            ctx.wait(HOUR);
            ctx.dev(b).reach.publication.omit.clear();
            ctx.dev(b).reach.publication.epoch += 1;
            ctx.log(
                "directory",
                "publications list the payout again, under a new payment-history epoch",
            );
            keep_syncing(ctx, b, 10 * MINUTE, HOUR);
            ctx.expect(
                b,
                "payout",
                &swap.label(),
                &payout,
                Class::FoundByDiscovery,
                "The correction's new epoch drops B's coverage, so B bootstraps again from the corrected cumulative snapshot and looks the key up.",
            );
        }),
    }
}

fn quiet_chain() -> Scenario {
    Scenario {
        id: "E7-quiet-chain-defers-restore".into(),
        group: RESTORE,
        title: "A restore on a chain with no shielded outputs for 300 blocks".into(),
        summary: "Recovery tests a bucket only once the scan stored its last block, so a restore \
            finds the payment late, and a late payment needs a tree checkpoint within 100 blocks \
            of its path's anchor, which a quiet chain may lack. It is admitted once shielded \
            activity resumes, if not before."
            .into(),
        params: vec![("quiet blocks".into(), "300".into())],
        slow: false,
        run: Box::new(|ctx| {
            let (_, birthday, swap, payout) = paid_swap(ctx);
            ctx.chain.traffic = Traffic {
                every: 10,
                outputs: 0,
            };
            ctx.mine(300);
            ctx.log("chain", "300 blocks without shielded outputs");
            let b = ctx.device("B", SEED, birthday);
            ctx.sync(b);
            ctx.sync(b);
            let early = ctx.get(b).found(payout.id()).is_some();
            ctx.chain.traffic = Traffic::default();
            ctx.log("chain", "shielded activity resumes");
            keep_syncing(ctx, b, 10 * MINUTE, HOUR);
            ctx.metric(
                "credited while the chain was quiet",
                f64::from(u8::from(early)),
                "payments",
            );
            ctx.expect(b, "payout", &swap.label(), &payout, Class::FoundByDiscovery, "Recovery looks the paid key up and the late path admits the payment once a checkpoint anchors its path.");
        }),
    }
}

fn clock_skew(skew: i64, after_deadline: i64) -> Scenario {
    let direction = if skew > 0 { "fast" } else { "slow" };
    Scenario {
        id: format!(
            "D2-clock-{}-{direction}-payout-deadline+{}",
            span(skew.abs()),
            span(after_deadline)
        ),
        group: OFFLINE,
        title: format!(
            "A device clock {} {direction}, NEAR silent, payout {} after the deadline",
            span(skew.abs()),
            span(after_deadline)
        ),
        summary: "A device clock that drifts must not close keys early or strand payouts. Closing \
            uses the earlier of the device clock and the tip's block time, and the stored deadline \
            is the earlier of the device's request and NEAR's answer."
            .into(),
        params: vec![
            (
                "device clock".into(),
                format!("{}{}", if skew > 0 { "+" } else { "-" }, span(skew.abs())),
            ),
            ("payout after deadline".into(), span(after_deadline)),
        ],
        slow: true,
        run: Box::new(move |ctx| {
            ctx.mine(20);
            let birthday = ctx.chain.tip() + 1;
            ctx.mine(5);
            let a = ctx.device_with_skew("A", SEED, birthday, skew);
            ctx.sync(a);
            let swap = ctx.quote_incoming(a, HOUR).expect("the quote issues");
            let pay_at = swap.deposit.deadline + after_deadline;
            let mut day = ctx.chain.now() + DAY;
            while day < pay_at {
                ctx.chain.mine_until(day);
                ctx.sync(a);
                day += DAY;
            }
            ctx.chain.mine_until_next_at(pay_at);
            let payout = ctx.pay("payout", &swap.label(), &swap.fvk, ZEC, Payer::Near);
            ctx.mine(1);
            ctx.sync(a);
            let (class, why) = if after_deadline < 30 * DAY {
                (
                    Class::FoundLive,
                    "Closing uses the earlier of the device clock and the tip's block time, so a fast clock cannot close the key before 30 days of chain time.",
                )
            } else {
                (
                    Class::FoundByDiscovery,
                    "The stored deadline is the earlier of the device's request and NEAR's answer, so a slow clock does not extend scanning in chain time; the key closes unpaid at 30 days and the paid filter finds the payout.",
                )
            };
            ctx.expect(a, "payout", &swap.label(), &payout, class, why);
        }),
    }
}

fn mempool_then_mined() -> Scenario {
    Scenario {
        id: "C8-payout-in-mempool-then-mined".into(),
        group: LIVE,
        title: "NEAR's payout is seen in the mempool, then mined".into(),
        summary:
            "Vizor shows a mempool payout to an open one-time key as pending, then confirms it \
            when mined."
                .into(),
        params: Vec::new(),
        slow: false,
        run: Box::new(|ctx| {
            ctx.mine(20);
            let birthday = ctx.chain.tip() + 1;
            ctx.mine(5);
            let a = ctx.device("A", SEED, birthday);
            ctx.sync(a);
            let swap = ctx.quote_incoming(a, HOUR).expect("the quote issues");
            ctx.wait(20 * MINUTE);
            let tx = ctx.near_tx(&swap.fvk, ZEC, Payer::Near);
            ctx.mempool(a, "the payout", &tx);
            let pending = ctx.get(a).balance();
            ctx.check(
                "the mempool payout shows as pending",
                pending == ZEC,
                format!("balance {pending} zat"),
            );
            ctx.mine(2);
            let payout = ctx.mine_payment("the payout", &tx, &swap.fvk, ZEC, Payer::Near);
            ctx.mine(1);
            ctx.sync(a);
            let b = ctx.device("B", SEED, birthday);
            ctx.sync(b);
            ctx.expect(
                a,
                "payout",
                &swap.label(),
                &payout,
                Class::FoundLive,
                "Found in the mempool while the key was open, then mined.",
            );
            ctx.expect(
                b,
                "payout",
                &swap.label(),
                &payout,
                Class::FoundAutomatically,
                "A restore finds the mined payout.",
            );
            ctx.check_balance(a, ZEC);
        }),
    }
}

fn mempool_then_dropped() -> Scenario {
    Scenario {
        id: "C8-payout-in-mempool-never-mined".into(),
        group: LIVE,
        title: "NEAR's payout is seen in the mempool and never mined".into(),
        summary: "A mempool payout to an open one-time key shows as pending, not spendable, and \
            must leave the balance once it expires unmined."
            .into(),
        params: Vec::new(),
        slow: false,
        run: Box::new(|ctx| {
            ctx.mine(20);
            let birthday = ctx.chain.tip() + 1;
            ctx.mine(5);
            let a = ctx.device("A", SEED, birthday);
            ctx.sync(a);
            let swap = ctx.quote_incoming(a, HOUR).expect("the quote issues");
            ctx.wait(20 * MINUTE);
            let tx = ctx.near_tx(&swap.fvk, ZEC, Payer::Near);
            ctx.mempool(a, "the payout", &tx);
            let (pending, spendable) = (ctx.get(a).balance(), ctx.get(a).spendable_balance());
            ctx.check(
                "the mempool payout is credited as pending",
                pending == ZEC && spendable == 0,
                format!("balance {pending} zat, of which {spendable} zat spendable"),
            );
            ctx.mine(60);
            ctx.sync(a);
            ctx.check_key_open(a, &swap.label(), true);
            ctx.check_balance(a, 0);
        }),
    }
}

fn one_time_notes_spent_first() -> Scenario {
    Scenario {
        id: "G1-one-time-notes-spent-first".into(),
        group: SPENDING,
        title: "An ordinary send spends one-time-key notes first in spare input slots".into(),
        summary:
            "Spending one-time-key notes first moves their value into ordinary change that any \
            seed restore can find. The restored wallet must end with the same balance."
                .into(),
        params: Vec::new(),
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
                2 * ZEC,
                Payer::Wallet,
            );
            ctx.mine(10);
            ctx.sync(a);
            let swap = ctx.quote_incoming(a, HOUR).expect("the quote issues");
            ctx.wait(20 * MINUTE);
            let payout = ctx.pay("payout", &swap.label(), &swap.fvk, ZEC / 2, Payer::Near);
            ctx.observe_incoming(a, &swap, "SUCCESS", Some(ZEC / 2));
            ctx.mine(12);
            ctx.sync(a);
            let before = ctx.get(a).unspent_one_time_value();
            let foreign =
                FullViewingKey::from(&SpendingKey::from_bytes([0xf5; 32]).expect("a key"))
                    .address_at(0u32, Scope::External);
            let tx = ctx
                .dev(a)
                .send_ordinary(foreign, ZEC / 10)
                .expect("the send builds");
            let height = ctx.chain.mine_tx(&tx);
            ctx.log(
                "A",
                format!(
                    "sends 0.1 ZEC to a foreign address, mined at {}",
                    u32::from(height)
                ),
            );
            ctx.mine(2);
            ctx.sync(a);
            let after = ctx.get(a).unspent_one_time_value();
            ctx.check(
                "the send spent the one-time-key note",
                before == ZEC / 2 && after == 0,
                format!("unspent one-time value {before} zat before, {after} zat after"),
            );
            let b = ctx.device("B", SEED, birthday);
            ctx.sync(b);
            ctx.expect(
                a,
                "payout",
                &swap.label(),
                &payout,
                Class::FoundLive,
                "The key was open.",
            );
            ctx.check_same_balance(a, b);
        }),
    }
}
