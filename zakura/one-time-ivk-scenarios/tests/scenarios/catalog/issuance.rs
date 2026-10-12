//! Issuance: which one-time addresses a wallet hands NEAR. Privacy rests on two rules:
//! an address NEAR was given is never issued for another swap, and neither is one that
//! was paid.

use zcash_client_sqlite::wallet::one_time_ivk::swap::{OperationOutcome, ReservationPolicy};

use super::{ISSUANCE, Scenario, span};
use crate::harness::{
    Ctx, Dev,
    chain::{DAY, HOUR, MINUTE, Payer, ZEC},
};

const SEED: [u8; 32] = [0x33; 32];

pub fn all() -> Vec<Scenario> {
    let mut scenarios = vec![
        incoming_indices_advance(),
        rejected_quote_reuses_address(),
        refund_indices_across_restore(),
        unknown_outcomes_hit_the_limit(),
    ];
    for covered in [true, false] {
        scenarios.push(restore_never_reissues(covered));
    }
    for lag in [MINUTE, 30 * MINUTE] {
        for after in [2 * MINUTE, 20 * MINUTE, 2 * HOUR] {
            scenarios.push(two_devices_incoming(after, lag));
        }
    }
    for funded in [false, true] {
        scenarios.push(two_devices_refund(funded));
    }
    scenarios
}

/// A wallet created after 20 blocks, synced so its lookahead is swept.
fn wallet(ctx: &mut Ctx, name: &str) -> Dev {
    ctx.mine(20);
    let birthday = ctx.chain.tip() + 1;
    ctx.mine(5);
    let dev = ctx.device(name, SEED, birthday);
    ctx.sync(dev);
    dev
}

fn incoming_indices_advance() -> Scenario {
    Scenario {
        id: "A2-incoming-indices-advance".into(),
        group: ISSUANCE,
        title: "Each accepted incoming quote takes a new address, even after NEAR refunds it".into(),
        summary: "An accepted quote gives NEAR the address, so it is never issued again, whatever \
            happens to the swap."
            .into(),
        params: vec![("quotes".into(), "6".into())],
        slow: false,
        run: Box::new(|ctx| {
            let a = wallet(ctx, "A");
            let mut indices = Vec::new();
            for _ in 0..5 {
                let swap = ctx.quote_incoming(a, HOUR).expect("the quote issues");
                indices.push(swap.index);
                ctx.wait(10 * MINUTE);
                ctx.observe_incoming(a, &swap, "REFUNDED", None);
                ctx.mine(1);
                ctx.sync(a);
            }
            let sixth = ctx.quote_incoming(a, HOUR).expect("the sixth quote issues");
            indices.push(sixth.index);
            let distinct = indices.iter().collect::<std::collections::BTreeSet<_>>().len();
            ctx.check(
                "six accepted quotes use six addresses",
                distinct == indices.len(),
                format!("indices {indices:?}"),
            );
            ctx.check(
                "addresses are issued in order",
                indices == (0..6).collect::<Vec<u64>>(),
                format!("indices {indices:?}"),
            );
        }),
    }
}

fn rejected_quote_reuses_address() -> Scenario {
    Scenario {
        id: "A3-rejected-quote-holds-address-back".into(),
        group: ISSUANCE,
        title: "A quote NEAR rejects releases its address, which is reissued only when nothing fresh is left".into(),
        summary: "A rejection releases the request's hold on the address, but the wallet still \
            prefers a never-quoted address, so the next quote gets a fresh one."
            .into(),
        params: Vec::new(),
        slow: false,
        run: Box::new(|ctx| {
            let a = wallet(ctx, "A");
            let index = ctx.prepare_incoming(a)
                .expect("a reservation");
            let request = ctx.begin_incoming(a, index, HOUR)
                .expect("the request is saved");
            ctx.finish_incoming(a, &request, &OperationOutcome::Rejected);
            ctx.log("A", format!("NEAR rejects the quote request for I{index}"));
            let next = ctx.quote_incoming(a, HOUR).expect("the next quote issues");
            ctx.check(
                "the next quote takes a fresh address",
                next.index == index + 1,
                format!(
                    "rejected I{index}, next {}; reservations.rs: an address the provider was given without seeing it is reissued only when the gap rule leaves no fresh one",
                    next.label()
                ),
            );
        }),
    }
}

fn refund_indices_across_restore() -> Scenario {
    Scenario {
        id: "A1-refund-indices-across-restore".into(),
        group: ISSUANCE,
        title: "A restore never reissues a refund key the seed already funded".into(),
        summary: "Refund keys are recovered from their funding memos before a restored wallet \
            reserves a new one."
            .into(),
        params: Vec::new(),
        slow: false,
        run: Box::new(|ctx| {
            let a = wallet(ctx, "A");
            let birthday = ctx.chain.tip() - 5;
            let fvk = ctx.get(a).fvk.clone();
            ctx.pay("A's Ironwood funds", "A's address", &fvk, 3 * ZEC, Payer::Wallet);
            ctx.mine(10);
            ctx.sync(a);
            for _ in 0..2 {
                let swap = ctx.quote_refund(a, HOUR).expect("a refund key");
                ctx.fund_refund(a, &swap, ZEC / 2);
                ctx.mine(10);
                ctx.sync(a);
            }
            ctx.wait(HOUR);
            let b = ctx.device("B", SEED, birthday);
            ctx.sync(b);
            ctx.sync(b);
            let next = ctx.quote_refund(b, HOUR).expect("B reserves a refund key");
            ctx.check(
                "B's first refund key follows A's two",
                next.index == 2,
                format!("B reserved {}", next.label()),
            );
        }),
    }
}

fn unknown_outcomes_hit_the_limit() -> Scenario {
    Scenario {
        id: "A7-unknown-outcomes-hit-the-limit".into(),
        group: ISSUANCE,
        title: "30 quote requests with unknown outcomes, then an outage ends".into(),
        summary: "A request whose outcome is unknown, such as a timeout, holds its address without \
            moving the recovery gap. After 30 of them issuance waits (Limit). Once their deadlines \
            and the two-hour cooldown pass, the lowest is reissued, though NEAR may have seen it."
            .into(),
        params: vec![("unknown outcomes".into(), "30".into())],
        slow: false,
        run: Box::new(|ctx| {
            let a = wallet(ctx, "A");
            for _ in 0..30 {
                let index = ctx.prepare_incoming(a).expect("a reservation");
                ctx.begin_incoming(a, index, HOUR).expect("the request is saved");
                ctx.mine(1);
                ctx.sync(a);
            }
            ctx.log("A", "30 quote requests time out without an answer");
            let blocked = ctx.prepare_incoming(a);
            ctx.check(
                "the 31st reservation waits",
                blocked == Err(ReservationPolicy::Limit),
                format!("{blocked:?}"),
            );
            ctx.wait(3 * HOUR);
            ctx.sync(a);
            let after = ctx.prepare_incoming(a);
            ctx.log("A", format!("after the deadlines and cooldown: {after:?}"));
            ctx.documented_gap(
                "an address from a request with an unknown outcome is reissued once nothing fresh is left",
                after == Ok(0),
                format!(
                    "reserved {after:?}; reservations.rs: an address the provider was given without seeing it is reissued only when the gap rule leaves no fresh one"
                ),
            );
        }),
    }
}

fn restore_never_reissues(covered: bool) -> Scenario {
    let feed = if covered { "feed-covers" } else { "feed-missed" };
    Scenario {
        id: format!("A5-restore-never-reissues-{feed}"),
        group: ISSUANCE,
        title: format!(
            "A restore issues after every paid and seen address; NEAR's seen set {} the old quotes",
            if covered { "covers" } else { "misses" }
        ),
        summary: "A restored wallet knows its old incoming addresses only from payments and NEAR's \
            seen set. With the seen set, it skips every address NEAR was given; without it, it can \
            reissue an unpaid one."
            .into(),
        params: vec![("seen set".into(), if covered { "covers" } else { "misses" }.into())],
        slow: false,
        run: Box::new(move |ctx| {
            let a = wallet(ctx, "A");
            let birthday = ctx.chain.tip() - 5;
            let paid = ctx.quote_incoming(a, HOUR).expect("I0");
            ctx.wait(20 * MINUTE);
            ctx.pay("payout", &paid.label(), &paid.fvk, ZEC, Payer::Near);
            ctx.observe_incoming(a, &paid, "SUCCESS", Some(ZEC));
            ctx.mine(12);
            ctx.sync(a);
            for _ in 0..2 {
                let unpaid = ctx.quote_incoming(a, HOUR).expect("an unpaid quote");
                ctx.wait(10 * MINUTE);
                ctx.observe_incoming(a, &unpaid, "REFUNDED", None);
                ctx.mine(1);
                ctx.sync(a);
            }
            ctx.wait(DAY);
            if !covered {
                ctx.near.feed_started = ctx.chain.now() - HOUR;
                ctx.log("directory", "NEAR feed restarted: its seen set starts an hour ago");
            }
            let b = ctx.device("B", SEED, birthday);
            ctx.sync(b);
            ctx.sync(b);
            let next = ctx.quote_incoming(b, HOUR).expect("B quotes");
            if covered {
                ctx.check(
                    "B's first address follows every address NEAR was given",
                    next.index == 3,
                    format!("B issued {}", next.label()),
                );
            } else {
                ctx.documented_gap(
                    "B reissues an unpaid address NEAR's seen set does not hold",
                    next.index == 1,
                    format!(
                        "B issued {}; ProviderSeen: an address another device quoted is known only through the set",
                        next.label()
                    ),
                );
            }
        }),
    }
}

fn two_devices_incoming(after: i64, lag: i64) -> Scenario {
    Scenario {
        id: format!("A9-two-devices-incoming-{}-later-lag-{}", span(after), span(lag)),
        group: ISSUANCE,
        title: format!(
            "Two devices on one seed quote incoming swaps {} apart, NEAR feed {} behind",
            span(after),
            span(lag)
        ),
        summary: "A device learns of another's quotes only from NEAR's seen set, which lags the \
            feed's last read. Inside that lag both devices can give NEAR the same address."
            .into(),
        params: vec![
            ("second quote after".into(), span(after)),
            ("feed read lag".into(), span(lag)),
        ],
        slow: false,
        run: Box::new(move |ctx| {
            ctx.near.read_lag = lag;
            let a = wallet(ctx, "A");
            let birthday = ctx.chain.tip() - 5;
            let b = ctx.device("B", SEED, birthday);
            ctx.sync(b);
            let first = ctx.quote_incoming(a, HOUR).expect("A quotes");
            ctx.wait(after);
            ctx.sync(b);
            let second = ctx.quote_incoming(b, HOUR).expect("B quotes");
            let reused = second.index == first.index;
            if after > lag {
                ctx.check(
                    "B does not reuse an address NEAR's seen set holds",
                    !reused,
                    format!("A issued {}, B issued {}", first.label(), second.label()),
                );
            } else {
                ctx.documented_gap(
                    "B can reuse A's address inside the feed's read lag",
                    reused,
                    format!(
                        "A issued {}, B issued {}; ProviderSeen: one quoted within the feed's read lag can still be issued again",
                        first.label(),
                        second.label()
                    ),
                );
            }
        }),
    }
}

fn two_devices_refund(funded: bool) -> Scenario {
    let state = if funded { "after-a-funds" } else { "before-a-funds" };
    Scenario {
        id: format!("A9-two-devices-refund-{state}"),
        group: ISSUANCE,
        title: format!(
            "Two devices on one seed reserve refund keys two hours apart, {}",
            if funded { "after A's funding is mined" } else { "before A funds its swap" }
        ),
        summary: "A refund key is known to another device once its funding memo is on chain. Before \
            that, reserve_refund_key relies on NEAR's seen set, which the receiver directory fills \
            with payout addresses only."
            .into(),
        params: vec![("A's swap".into(), if funded { "funded" } else { "quoted only" }.into())],
        slow: false,
        run: Box::new(move |ctx| {
            let a = wallet(ctx, "A");
            let birthday = ctx.chain.tip() - 5;
            let fvk = ctx.get(a).fvk.clone();
            ctx.pay("A's Ironwood funds", "A's address", &fvk, 3 * ZEC, Payer::Wallet);
            ctx.mine(10);
            ctx.sync(a);
            let b = ctx.device("B", SEED, birthday);
            ctx.sync(b);
            let first = ctx.quote_refund(a, HOUR).expect("A reserves");
            if funded {
                ctx.fund_refund(a, &first, ZEC);
                ctx.mine(10);
            }
            ctx.wait(2 * HOUR);
            ctx.sync(b);
            ctx.sync(b);
            let second = ctx.quote_refund(b, HOUR).expect("B reserves");
            ctx.check(
                "B never gives NEAR a refund address A gave it",
                second.index != first.index,
                format!(
                    "A reserved {}, B reserved {}{}",
                    first.label(),
                    second.label(),
                    if funded {
                        ""
                    } else {
                        "; reserve_refund_key skips seen-set hits, but the receiver directory's seen set holds payout addresses only"
                    }
                ),
            );
        }),
    }
}
