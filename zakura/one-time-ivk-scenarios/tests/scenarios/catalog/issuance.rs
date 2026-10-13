//! Issuance: which one-time addresses a wallet hands NEAR. Privacy rests on two rules:
//! an address NEAR was given is never issued for another swap, and neither is one that
//! was paid.

use zakura_one_time_ivk::Purpose;
use zakura_one_time_ivk_scenarios::Class;
use zcash_client_sqlite::wallet::one_time_ivk::swap::{
    OperationOutcome, RECEIVE_GAP_LIMIT, RECEIVE_RECLAIM_SECONDS, ReceiveDeposit,
    ReservationPolicy, SEEN_SLACK_SECONDS,
};

use super::{ISSUANCE, Scenario, span};
use crate::harness::{
    Ctx, Dev,
    chain::{DAY, HOUR, MINUTE, Payer, ZEC, receiver_of},
    device::IncomingSwap,
    near::Role,
};

const SEED: [u8; 32] = [0x33; 32];

pub fn all() -> Vec<Scenario> {
    let mut scenarios = vec![
        incoming_indices_advance(),
        rejected_quotes_hold_addresses_back(),
        refund_indices_across_restore(),
        unknown_outcomes_hit_the_limit(),
    ];
    for lag in [MINUTE, 6 * HOUR] {
        scenarios.push(lost_answer_near_saw(lag));
    }
    for started in [false, true] {
        scenarios.push(restart_resumes_request(started));
    }
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

/// Reserves an address on `dev` and saves a quote request for it with a one-hour
/// deadline, as the app does before the request leaves. Like the app, it answers `Gap`
/// and `Coverage` by syncing and trying again, at most three times. Returns the index and
/// the request, or the refusal.
fn request_quote(ctx: &mut Ctx, dev: Dev) -> Result<(u64, String), ReservationPolicy> {
    let mut attempt = 0;
    loop {
        let saved = ctx
            .prepare_incoming(dev)
            .and_then(|index| Ok((index, ctx.begin_incoming(dev, index, HOUR)?)));
        match saved {
            Err(ReservationPolicy::Gap | ReservationPolicy::Coverage) if attempt < 3 => {
                attempt += 1;
                ctx.sync(dev);
            }
            saved => return saved,
        }
    }
}

fn incoming_indices_advance() -> Scenario {
    Scenario {
        id: "A2-incoming-indices-advance".into(),
        group: ISSUANCE,
        title: "Each accepted incoming quote takes a new address, even after NEAR refunds it"
            .into(),
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
            let distinct = indices
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len();
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

/// Wallet A's quote requests are rejected until they fill the window. Their deadlines
/// and the reclaim grace pass, the app restarts, and NEAR's seen set covers the requests
/// without holding any of them. Issuance must wait rather than reissue a rejected address.
fn rejected_quotes_hold_addresses_back() -> Scenario {
    Scenario {
        id: "A3-rejected-quote-holds-address-back".into(),
        group: ISSUANCE,
        title: "Rejected quotes fill the window, and their addresses are never issued again".into(),
        summary: "A rejected quote request still gave NEAR the address, so the address is never \
            issued again. Once rejections fill the 30-index window, issuance waits, even after \
            the deadlines and the reclaim grace pass, the app restarts, and NEAR's seen set \
            covers the requests without holding them."
            .into(),
        params: vec![("rejected quotes".into(), RECEIVE_GAP_LIMIT.to_string())],
        slow: false,
        run: Box::new(|ctx| {
            let a = wallet(ctx, "A");
            let mut rejected = Vec::new();
            let refused = loop {
                match request_quote(ctx, a) {
                    Ok((index, request)) => {
                        ctx.finish_incoming(a, &request, &OperationOutcome::Rejected);
                        rejected.push(index);
                    }
                    Err(policy) => break policy,
                }
                assert!(
                    rejected.len() <= 2 * RECEIVE_GAP_LIMIT as usize,
                    "issuance never waits"
                );
                ctx.mine(1);
                ctx.sync(a);
            };
            let last_request = ctx.chain.now();
            ctx.log(
                "A",
                format!(
                    "NEAR rejects {} quote requests, and its feed lists none of them; then issuance refuses: {refused:?}",
                    rejected.len()
                ),
            );
            ctx.check(
                "each rejection moves the next quote to a fresh address",
                rejected == (0..RECEIVE_GAP_LIMIT).collect::<Vec<_>>(),
                format!("rejected {rejected:?}"),
            );
            ctx.check(
                "issuance waits once rejections fill the window",
                refused == ReservationPolicy::Limit,
                format!("{refused:?}"),
            );
            ctx.wait(HOUR + RECEIVE_RECLAIM_SECONDS + HOUR);
            ctx.restart(a);
            ctx.mine(1);
            ctx.sync(a);
            let now = ctx.chain.now();
            let held: Vec<u64> = rejected
                .iter()
                .copied()
                .filter(|&i| {
                    let receiver = receiver_of(&ctx.get(a).key(Purpose::Receive, i));
                    ctx.near.seen(&receiver, now)
                })
                .collect();
            let covered = ctx.near.read_until(now) - SEEN_SLACK_SECONDS > last_request;
            ctx.check(
                "NEAR's seen set covers the rejected requests and holds none of them",
                covered && held.is_empty(),
                format!(
                    "read until {} s after the last request, slack {SEEN_SLACK_SECONDS} s; holds {held:?}",
                    ctx.near.read_until(now) - last_request
                ),
            );
            let after = ctx.prepare_incoming(a);
            ctx.log(
                "A",
                format!("after the deadlines, the reclaim grace and a restart: {after:?}"),
            );
            ctx.check(
                "issuance waits rather than reissue a rejected address",
                after == Err(ReservationPolicy::Limit),
                format!(
                    "{after:?}; ProviderSeen: an incoming address counts as seen if the provider rejected a quote for it, since the request still gave it the address"
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
            ctx.pay(
                "A's Ironwood funds",
                "A's address",
                &fvk,
                3 * ZEC,
                Payer::Wallet,
            );
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
        summary:
            "A request whose outcome is unknown, such as a timeout, holds its address without \
            moving the recovery gap. After 30 of them issuance waits (Limit). Once their deadlines \
            and the two-hour cooldown pass, the lowest is reissued, though NEAR may have seen it."
                .into(),
        params: vec![("unknown outcomes".into(), "30".into())],
        slow: false,
        run: Box::new(|ctx| {
            let a = wallet(ctx, "A");
            for _ in 0..30 {
                let index = ctx.prepare_incoming(a).expect("a reservation");
                ctx.begin_incoming(a, index, HOUR)
                    .expect("the request is saved");
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

/// Saves quote requests on `dev` that never reach NEAR, a block apart, until issuance
/// refuses one. Returns the indices issued and the refusal.
fn requests_until_refused(ctx: &mut Ctx, dev: Dev) -> (Vec<u64>, ReservationPolicy) {
    let mut issued = Vec::new();
    loop {
        match request_quote(ctx, dev) {
            Ok((index, _)) => issued.push(index),
            Err(policy) => return (issued, policy),
        }
        assert!(
            issued.len() <= 2 * RECEIVE_GAP_LIMIT as usize,
            "issuance never waits"
        );
        ctx.mine(1);
        ctx.sync(dev);
    }
}

/// Wallet A sends a quote request for I0 that reaches NEAR, but its answer is lost, and
/// the app restarts. A then saves quote requests that never reach NEAR until issuance
/// waits, and NEAR's feed, `lag` behind, catches up. After the deadlines and cooldown, A
/// goes through the window again, reusing only addresses NEAR never received.
fn lost_answer_near_saw(lag: i64) -> Scenario {
    let behind = lag > HOUR;
    Scenario {
        id: format!("A4-lost-answer-near-saw-feed-{}-behind", span(lag)),
        group: ISSUANCE,
        title: format!(
            "NEAR receives a quote request whose answer is lost, the app restarts, and later quotes fill the window; NEAR feed {} behind",
            span(lag)
        ),
        summary: "A request whose answer was lost still gave NEAR the address. Once NEAR's seen \
            set holds it, the address is never issued again. When later requests that never \
            reached NEAR fill the 30-index window, issuance waits, then reuses only those, \
            never the address NEAR saw."
            .into(),
        params: vec![
            ("feed read lag".into(), span(lag)),
            (
                "later requests".into(),
                "until issuance waits, twice".into(),
            ),
        ],
        slow: false,
        run: Box::new(move |ctx| {
            ctx.near.read_lag = lag;
            let a = wallet(ctx, "A");
            let (index, _) = request_quote(ctx, a).expect("the request is saved");
            let exposed = receiver_of(&ctx.get(a).key(Purpose::Receive, index));
            ctx.near.give(exposed, ctx.chain.now(), Role::Payout);
            ctx.log(
                "A",
                format!("NEAR receives the quote request for I{index}, but its answer is lost"),
            );
            ctx.restart(a);
            ctx.mine(1);
            ctx.sync(a);
            let (issued, refused) = requests_until_refused(ctx, a);
            ctx.log(
                "A",
                format!(
                    "{} more quote requests, none reaching NEAR, then issuance refuses: {refused:?}",
                    issued.len()
                ),
            );
            ctx.check(
                "issuance waits once the window holds no fresh address",
                refused == ReservationPolicy::Limit,
                format!("{refused:?} after issuing {issued:?}"),
            );
            ctx.wait(3 * HOUR);
            ctx.sync(a);
            if behind {
                let waiting = ctx.prepare_incoming(a);
                ctx.check(
                    "issuance still waits while NEAR's feed has not read the requests",
                    waiting == Err(ReservationPolicy::Limit),
                    format!(
                        "{waiting:?}; ProviderSeen: a quote outside the set's read, widened by SEEN_SLACK_SECONDS, counts as seen"
                    ),
                );
                ctx.near.read_lag = MINUTE;
                ctx.log("directory", "NEAR feed catches up: it trails by a minute");
                ctx.mine(1);
                ctx.sync(a);
            }
            let (again, refused_again) = requests_until_refused(ctx, a);
            ctx.log(
                "A",
                format!(
                    "after the deadlines and cooldown, {} more quote requests, then issuance refuses: {refused_again:?}",
                    again.len()
                ),
            );
            // NEAR's set holds I0, which moves the gap one past it; with the feed behind,
            // the first pass filled only the 29 indices up to the old bound.
            let expected = if behind { RECEIVE_GAP_LIMIT } else { 1 };
            ctx.check(
                format!("issuance resumes at I{expected}"),
                again.first() == Some(&expected),
                format!(
                    "issued {again:?}; reservations.rs: an address the provider was given without seeing it is reissued only when the gap rule leaves no fresh one, and one the set holds moves the gap"
                ),
            );
            let given: Vec<u64> = again
                .iter()
                .copied()
                .filter(|&i| {
                    let receiver = receiver_of(&ctx.get(a).key(Purpose::Receive, i));
                    ctx.near.was_given(&receiver)
                })
                .collect();
            ctx.check(
                "the second pass issues only addresses NEAR never received",
                !again.is_empty() && given.is_empty(),
                format!("issued {again:?}, NEAR received {given:?}"),
            );
            ctx.check(
                format!("I{index}, which NEAR received, is never issued again"),
                !issued.contains(&index) && !again.contains(&index),
                format!("first pass {issued:?}, second pass {again:?}"),
            );
        }),
    }
}

/// Wallet A's quote for I0 is accepted (and, when `started`, started), then the app
/// restarts. A resumes the request by its identity, NEAR pays the receiver stored with
/// it, and A credits that payment once.
fn restart_resumes_request(started: bool) -> Scenario {
    let stage = if started { "start" } else { "acceptance" };
    Scenario {
        id: format!("A11-restart-after-{stage}-resumes-the-request"),
        group: ISSUANCE,
        title: format!(
            "The app restarts after a quote is {}, then resumes it by its request",
            if started { "started" } else { "accepted" }
        ),
        summary: "A quote request's identity is saved before it leaves the device. After a \
            restart the app resumes the request, shows the deposit instructions the store kept, \
            and NEAR pays the address stored with the request. The wallet credits that payment \
            once, and the next quote takes another address."
            .into(),
        params: vec![("restart after".into(), stage.into())],
        slow: false,
        run: Box::new(move |ctx| {
            let a = wallet(ctx, "A");
            let (index, request) = request_quote(ctx, a).expect("the request is saved");
            let fvk = ctx.get(a).key(Purpose::Receive, index);
            ctx.near
                .give(receiver_of(&fvk), ctx.chain.now(), Role::Payout);
            let deposit = ReceiveDeposit {
                address: ctx.near.deposit_address(),
                memo: None,
                deadline: ctx.chain.now() + HOUR,
            };
            ctx.finish_incoming(a, &request, &OperationOutcome::Accepted(deposit.clone()));
            ctx.log(
                "A",
                format!(
                    "NEAR accepts the quote for I{index}: deposit to {}",
                    deposit.address
                ),
            );
            if started {
                let shown = ctx.start_incoming(a, &request);
                ctx.check(
                    "the quote starts",
                    shown.as_ref() == Ok(&deposit),
                    format!("{shown:?}"),
                );
            }
            ctx.restart(a);
            ctx.mine(1);
            ctx.sync(a);
            let resumed = ctx.start_incoming(a, &request);
            ctx.log("A", format!("resumes request {request}: {resumed:?}"));
            ctx.check(
                "the resumed request shows NEAR's deposit instructions",
                resumed.as_ref() == Ok(&deposit),
                format!("{resumed:?}"),
            );
            let stored = ctx.get(a).request_receiver(&request);
            ctx.check(
                format!("the request's stored receiver is I{index}, the address NEAR was given"),
                stored == Some((index, receiver_of(&fvk))),
                format!("stored {:?}", stored.map(|(i, _)| i)),
            );
            let (stored_index, stored_receiver) = stored.expect("the request is stored");
            let payee = ctx.get(a).key(Purpose::Receive, stored_index);
            assert_eq!(
                receiver_of(&payee),
                stored_receiver,
                "the payee is the stored receiver"
            );
            let next = ctx.quote_incoming(a, HOUR).expect("another quote issues");
            ctx.check(
                "the next quote takes another address",
                next.index != stored_index,
                format!("resumed I{stored_index}, next {}", next.label()),
            );
            ctx.wait(20 * MINUTE);
            let key = format!("I{stored_index}");
            let payout = ctx.pay("payout", &key, &payee, ZEC, Payer::Near);
            let swap = IncomingSwap {
                index: stored_index,
                fvk: payee,
                deposit,
            };
            ctx.observe_incoming(a, &swap, "SUCCESS", Some(ZEC));
            ctx.mine(12);
            ctx.sync(a);
            let receipts = ctx.get(a).incoming_receipts(stored_index);
            ctx.check(
                format!("A credits one payment to {key}"),
                receipts == 1,
                format!("{receipts} receipts"),
            );
            ctx.expect(
                a,
                "payout",
                &key,
                &payout,
                Class::FoundLive,
                "The resumed reservation keeps its key open until its swap settles.",
            );
            ctx.check_balance(a, ZEC);
        }),
    }
}

fn restore_never_reissues(covered: bool) -> Scenario {
    let feed = if covered {
        "feed-covers"
    } else {
        "feed-missed"
    };
    Scenario {
        id: format!("A5-restore-never-reissues-{feed}"),
        group: ISSUANCE,
        title: format!(
            "A restore issues after every paid and seen address; NEAR's seen set {} the old quotes",
            if covered { "covers" } else { "misses" }
        ),
        summary:
            "A restored wallet knows its old incoming addresses only from payments and NEAR's \
            seen set. With the seen set, it skips every address NEAR was given; without it, it can \
            reissue an unpaid one."
                .into(),
        params: vec![(
            "seen set".into(),
            if covered { "covers" } else { "misses" }.into(),
        )],
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
                ctx.log(
                    "directory",
                    "NEAR feed restarted: its seen set starts an hour ago",
                );
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
        id: format!(
            "A9-two-devices-incoming-{}-later-lag-{}",
            span(after),
            span(lag)
        ),
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
    let state = if funded {
        "after-a-funds"
    } else {
        "before-a-funds"
    };
    Scenario {
        id: format!("A9-two-devices-refund-{state}"),
        group: ISSUANCE,
        title: format!(
            "Two devices on one seed reserve refund keys two hours apart, {}",
            if funded {
                "after A's funding is mined"
            } else {
                "before A funds its swap"
            }
        ),
        summary:
            "A refund key is known to another device once its funding memo is on chain. Before \
            that, reserve_refund_key relies on NEAR's seen set, which holds the refund addresses \
            NEAR was given as well as payout addresses."
                .into(),
        params: vec![(
            "A's swap".into(),
            if funded { "funded" } else { "quoted only" }.into(),
        )],
        slow: false,
        run: Box::new(move |ctx| {
            let a = wallet(ctx, "A");
            let birthday = ctx.chain.tip() - 5;
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
                    "A reserved {}, B reserved {}",
                    first.label(),
                    second.label()
                ),
            );
        }),
    }
}
