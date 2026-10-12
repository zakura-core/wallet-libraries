//! Robustness: receiver directory failures, a quiet chain, device clocks that drift,
//! payouts seen in the mempool, and spending what one-time keys received.

use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use zakura_one_time_ivk_scenarios::Class;
use zcash_client_sqlite::wallet::one_time_ivk::swap::ReservationPolicy;

use super::{LIVE, OFFLINE, RESTORE, SPENDING, Scenario, span};
use crate::harness::{
    Ctx, Dev,
    chain::{DAY, HOUR, MINUTE, Mined, Payer, Traffic, ZEC},
    device::IncomingSwap,
};

const SEED: [u8; 32] = [0x66; 32];

pub fn all() -> Vec<Scenario> {
    let mut scenarios = vec![directory_down_at_restore(), omitted_payment(), quiet_chain()];
    for status in [503, 429, 410] {
        scenarios.push(directory_errors(status));
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
fn paid_swap(ctx: &mut Ctx) -> (Dev, zcash_protocol::consensus::BlockHeight, IncomingSwap, Mined) {
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
        title: "The receiver directory is down when the seed is restored, and back an hour later".into(),
        summary: "Without the directory a restore cannot sweep its keys, so it cannot issue new \
            addresses either (Gap). The sweep runs once the directory answers."
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
                "B cannot issue an address while its lookahead is unswept",
                quote == Err(ReservationPolicy::Gap),
                format!("{quote:?}"),
            );
            ctx.wait(HOUR);
            ctx.dev(b).reach.directory = true;
            ctx.log("directory", "reachable again");
            keep_syncing(ctx, b, 10 * MINUTE, HOUR);
            ctx.expect(b, "payout", &swap.label(), &payout, Class::FoundBySweep, "The sweep runs once the directory answers.");
        }),
    }
}

fn directory_errors(status: u16) -> Scenario {
    Scenario {
        id: format!("E7-directory-answers-{status}-at-restore"),
        group: RESTORE,
        title: format!("The receiver directory answers HTTP {status} to a restore's first requests"),
        summary: "409 and 410 mean a new publication; anything else, 429 included, is a retryable \
            transport failure that backs the key off. Either way the payment is found by a later \
            sweep."
            .into(),
        params: vec![("status".into(), status.to_string())],
        slow: false,
        run: Box::new(move |ctx| {
            let (_, birthday, swap, payout) = paid_swap(ctx);
            let b = ctx.device("B", SEED, birthday);
            ctx.dev(b).reach.directory_faults = vec![status; 3];
            ctx.log("directory", format!("answers the next 3 requests with HTTP {status}"));
            ctx.sync(b);
            keep_syncing(ctx, b, 10 * MINUTE, 3 * HOUR);
            ctx.expect(b, "payout", &swap.label(), &payout, Class::FoundBySweep, "A failed sweep backs off and a later one finds the payment.");
        }),
    }
}

fn omitted_payment() -> Scenario {
    Scenario {
        id: "E7-indexer-omits-then-lists-payment".into(),
        group: RESTORE,
        title: "The directory's first publications omit a payment, later ones list it".into(),
        summary: "An empty page zero means no indexed payment, not an unused address. A key the \
            restore closed unpaid is checked against each newer publication's paid filter, which \
            finds the payment once the indexer lists it."
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
            ctx.log("directory", "publications list the payout again");
            keep_syncing(ctx, b, 10 * MINUTE, HOUR);
            ctx.expect(
                b,
                "payout",
                &swap.label(),
                &payout,
                Class::FoundBySweep,
                "The restored key closed unpaid; a newer publication's paid filter holds it (record_paid_filter_check).",
            );
        }),
    }
}

fn quiet_chain() -> Scenario {
    Scenario {
        id: "E7-quiet-chain-defers-restore".into(),
        group: RESTORE,
        title: "A restore on a chain with no shielded outputs for 300 blocks".into(),
        summary: "A sweep applies a payment only with a tree checkpoint within 100 blocks of the \
            publication, and wallets checkpoint only blocks with shielded outputs. On a quiet chain \
            (regtest, or a quiet period) the payment waits until activity resumes."
            .into(),
        params: vec![("quiet blocks".into(), "300".into())],
        slow: false,
        run: Box::new(|ctx| {
            let (_, birthday, swap, payout) = paid_swap(ctx);
            ctx.chain.traffic = Traffic { every: 10, outputs: 0 };
            ctx.mine(300);
            ctx.log("chain", "300 blocks without shielded outputs");
            let b = ctx.device("B", SEED, birthday);
            ctx.sync(b);
            ctx.sync(b);
            let early = ctx.get(b).found(payout.id()).is_some();
            ctx.chain.traffic = Traffic::default();
            ctx.log("chain", "shielded activity resumes");
            keep_syncing(ctx, b, 10 * MINUTE, HOUR);
            ctx.check(
                "the payment waited for a checkpoint near the publication",
                !early,
                if early { "credited on the quiet chain" } else { "deferred while the chain was quiet" },
            );
            ctx.expect(b, "payout", &swap.label(), &payout, Class::FoundBySweep, "The deferred payment is applied once the wallet has a recent checkpoint.");
        }),
    }
}

fn clock_skew(skew: i64, after_deadline: i64) -> Scenario {
    let direction = if skew > 0 { "fast" } else { "slow" };
    Scenario {
        id: format!("D2-clock-{}-{direction}-payout-deadline+{}", span(skew.abs()), span(after_deadline)),
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
            ("device clock".into(), format!("{}{}", if skew > 0 { "+" } else { "-" }, span(skew.abs()))),
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
                    Class::FoundBySweep,
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
        summary: "Vizor shows a mempool payout to an open one-time key as pending, then confirms it \
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
            ctx.check("the mempool payout shows as pending", pending == ZEC, format!("balance {pending} zat"));
            ctx.mine(2);
            let payout = ctx.mine_payment("the payout", &tx, &swap.fvk, ZEC, Payer::Near);
            ctx.mine(1);
            ctx.sync(a);
            let b = ctx.device("B", SEED, birthday);
            ctx.sync(b);
            ctx.expect(a, "payout", &swap.label(), &payout, Class::FoundLive, "Found in the mempool while the key was open, then mined.");
            ctx.expect(b, "payout", &swap.label(), &payout, Class::FoundAutomatically, "A restore finds the mined payout.");
            ctx.check_balance(a, ZEC);
        }),
    }
}

fn mempool_then_dropped() -> Scenario {
    Scenario {
        id: "C8-payout-in-mempool-never-mined".into(),
        group: LIVE,
        title: "NEAR's payout is seen in the mempool and never mined".into(),
        summary: "A pending payout that never confirms must leave the balance once it expires.".into(),
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
        summary: "Spending one-time-key notes first moves their value into ordinary change that any \
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
            ctx.pay("A's Ironwood funds", "A's address", &fvk, 2 * ZEC, Payer::Wallet);
            ctx.mine(10);
            ctx.sync(a);
            let swap = ctx.quote_incoming(a, HOUR).expect("the quote issues");
            ctx.wait(20 * MINUTE);
            let payout = ctx.pay("payout", &swap.label(), &swap.fvk, ZEC / 2, Payer::Near);
            ctx.observe_incoming(a, &swap, "SUCCESS", Some(ZEC / 2));
            ctx.mine(12);
            ctx.sync(a);
            let before = ctx.get(a).unspent_one_time_value();
            let foreign = FullViewingKey::from(&SpendingKey::from_bytes([0xf5; 32]).expect("a key"))
                .address_at(0u32, Scope::External);
            let tx = ctx.dev(a).send_ordinary(foreign, ZEC / 10);
            let height = ctx.chain.mine_tx(&tx);
            ctx.log("A", format!("sends 0.1 ZEC to a foreign address, mined at {}", u32::from(height)));
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
            ctx.expect(a, "payout", &swap.label(), &payout, Class::FoundLive, "The key was open.");
            ctx.check_same_balance(a, b);
        }),
    }
}
