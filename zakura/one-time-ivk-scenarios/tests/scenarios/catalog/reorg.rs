//! Reorgs: payments and funding transactions that leave the chain, come back, or land
//! near a wallet's rewind.

use zakura_one_time_ivk_scenarios::Class;

use super::{REORGS, Scenario};
use crate::harness::{
    Ctx, Dev,
    chain::{DAY, HOUR, MINUTE, Payer, ZEC},
};

const SEED: [u8; 32] = [0x55; 32];

pub fn all() -> Vec<Scenario> {
    vec![
        ordinary_payment_dropped(),
        payout_reorged_and_remined(),
        payout_dropped(),
        deep_reorg_after_close(),
        funding_reorged_and_remined(),
        restored_key_near_rewind(),
    ]
}

/// A wallet created after 20 blocks and synced, with its birthday.
fn wallet(ctx: &mut Ctx) -> (Dev, zcash_protocol::consensus::BlockHeight) {
    ctx.mine(20);
    let birthday = ctx.chain.tip() + 1;
    ctx.mine(5);
    let a = ctx.device("A", SEED, birthday);
    ctx.sync(a);
    ctx.mine(30);
    ctx.sync(a);
    (a, birthday)
}

/// Blocks a dropped transaction stays pending before its expiry height passes, with margin.
const PAST_EXPIRY: u32 = 60;

fn ordinary_payment_dropped() -> Scenario {
    Scenario {
        id: "F0-control-ordinary-payment-dropped".into(),
        group: REORGS,
        title: "Control: a payment to the wallet's ordinary address is reorged out for good".into(),
        summary: "The same reorg as F1b, paid to the account's own address, to tell one-time IVK \
            behavior apart from the wallet's general reorg handling. The wallet fetches an ordinary \
            payment in full, so it knows the expiry height after which a dropped payment is gone."
            .into(),
        params: Vec::new(),
        slow: false,
        run: Box::new(|ctx| {
            let (a, _) = wallet(ctx);
            let fvk = ctx.get(a).fvk.clone();
            let (payment, _) = ctx.pay_tx("payment", "A's address", &fvk, ZEC, Payer::Wallet);
            ctx.mine(2);
            ctx.sync(a);
            ctx.reorg(payment.height - 1);
            ctx.mine(PAST_EXPIRY);
            ctx.sync(a);
            let balance = ctx.get(a).balance();
            let view = ctx.get(a).tx_view(payment.id().0);
            ctx.check(
                "A drops a payment the reorg removed once its expiry passes",
                balance == 0,
                format!("balance {balance} zat; dropped transaction {view}"),
            );
            ctx.check_balance(a, 0);
        }),
    }
}

fn payout_reorged_and_remined() -> Scenario {
    Scenario {
        id: "F1a-payout-reorged-then-mined-again".into(),
        group: REORGS,
        title: "A payout is reorged out and the same transaction is mined again".into(),
        summary:
            "The common reorg: NEAR's payout returns to the mempool and lands in the new branch. \
            The wallet must keep it once, at its new height."
                .into(),
        params: Vec::new(),
        slow: false,
        run: Box::new(|ctx| {
            let (a, birthday) = wallet(ctx);
            let swap = ctx.quote_incoming(a, HOUR).expect("the quote issues");
            let key = swap.label();
            ctx.wait(20 * MINUTE);
            let (first, tx) = ctx.pay_tx("payout", &key, &swap.fvk, ZEC, Payer::Near);
            ctx.mine(2);
            ctx.sync(a);
            ctx.reorg(first.height - 1);
            ctx.mine(2);
            let again = ctx.remine("payout", &tx, &swap.fvk, ZEC, Payer::Near);
            ctx.observe_incoming(a, &swap, "SUCCESS", Some(ZEC));
            ctx.mine(12);
            ctx.sync(a);
            let b = ctx.device("B", SEED, birthday);
            ctx.sync(b);
            ctx.expect(
                a,
                "payout (mined again)",
                &key,
                &again,
                Class::FoundLive,
                "The wallet found the payout before the reorg and keeps it at its new height.",
            );
            ctx.expect(
                b,
                "payout (mined again)",
                &key,
                &again,
                Class::FoundAutomatically,
                "The directory lists the surviving branch's payment.",
            );
            ctx.check_balance(a, ZEC);
            ctx.check_same_balance(a, b);
        }),
    }
}

fn payout_dropped() -> Scenario {
    Scenario {
        id: "F1b-payout-reorged-out-for-good".into(),
        group: REORGS,
        title: "A payout is reorged out and never mined again".into(),
        summary: "A one-time-key payout is never fetched in full (it carries no memo the wallet \
            reads), so the wallet may never learn its expiry height. Checks whether a payout the \
            chain lost still counts in the balance, unlike the ordinary payment in F0."
            .into(),
        params: Vec::new(),
        slow: false,
        run: Box::new(|ctx| {
            let (a, _) = wallet(ctx);
            let swap = ctx.quote_incoming(a, HOUR).expect("the quote issues");
            let key = swap.label();
            ctx.wait(20 * MINUTE);
            let (payout, _) = ctx.pay_tx("payout", &key, &swap.fvk, ZEC, Payer::Near);
            ctx.mine(2);
            ctx.sync(a);
            ctx.reorg(payout.height - 1);
            ctx.mine(PAST_EXPIRY);
            ctx.sync(a);
            let balance = ctx.get(a).balance();
            let view = ctx.get(a).tx_view(payout.id().0);
            ctx.check(
                "A drops a payout the reorg removed once its expiry passes",
                balance == 0,
                format!("balance {balance} zat; dropped transaction {view}"),
            );
            ctx.check_key_open(a, &key, true);
            ctx.check_balance(a, 0);
        }),
    }
}

fn deep_reorg_after_close() -> Scenario {
    Scenario {
        id: "F2-deep-reorg-after-close-payout-mined-again".into(),
        group: REORGS,
        title: "A reorg deeper than 10 confirmations un-mines a payout after its key closed; the payout is mined again".into(),
        summary: "close_finished_one_time_keys: no status reopens a closed key, but a rewind does when \
            it un-mines a receipt. The returning payout must be found at its new height."
            .into(),
        params: vec![("reorg depth".into(), "16 blocks".into())],
        slow: false,
        run: Box::new(|ctx| {
            let (a, _) = wallet(ctx);
            let swap = ctx.quote_incoming(a, HOUR).expect("the quote issues");
            let key = swap.label();
            ctx.wait(20 * MINUTE);
            let (first, tx) = ctx.pay_tx("payout", &key, &swap.fvk, ZEC, Payer::Near);
            ctx.observe_incoming(a, &swap, "SUCCESS", Some(ZEC));
            ctx.mine(14);
            ctx.sync(a);
            ctx.check_key_open(a, &key, false);
            ctx.reorg(first.height - 1);
            ctx.mine(2);
            let again = ctx.remine("payout", &tx, &swap.fvk, ZEC, Payer::Near);
            ctx.mine(20);
            ctx.sync(a);
            ctx.expect(
                a,
                "payout (mined again)",
                &key,
                &again,
                Class::FoundLive,
                "The wallet found it before the reorg; the rewind reopened the key, which finds it at its new height.",
            );
            ctx.check_balance(a, ZEC);
        }),
    }
}

fn funding_reorged_and_remined() -> Scenario {
    Scenario {
        id: "F3-funding-reorged-and-remined".into(),
        group: REORGS,
        title: "A swap's funding transaction is reorged out and mined again".into(),
        summary: "The refund key started scanning when its funding transaction was stored. After \
            the transaction returns on the new branch, NEAR's refund is still found."
            .into(),
        params: Vec::new(),
        slow: false,
        run: Box::new(|ctx| {
            let (a, birthday) = wallet(ctx);
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
            let key = swap.label();
            let (funded_at, tx) = ctx.fund_refund(a, &swap, ZEC);
            ctx.mine(2);
            ctx.sync(a);
            ctx.reorg(funded_at - 1);
            ctx.mine(1);
            let again = ctx.chain.mine_tx(&tx);
            ctx.log(
                "chain",
                format!(
                    "the funding transaction is mined again at {}",
                    u32::from(again)
                ),
            );
            ctx.mine(3);
            ctx.sync(a);
            ctx.check_key_open(a, &key, true);
            ctx.wait(HOUR);
            let refund = ctx.pay("refund", &key, &swap.fvk, ZEC - 10_000, Payer::Near);
            ctx.observe_refund(a, &swap, "REFUNDED", Some(ZEC - 10_000));
            ctx.mine(1);
            ctx.sync(a);
            let b = ctx.device("B", SEED, birthday);
            ctx.sync(b);
            ctx.expect(
                a,
                "refund",
                &key,
                &refund,
                Class::FoundLive,
                "The refund key scans from its funding transaction.",
            );
            ctx.expect(
                b,
                "refund",
                &key,
                &refund,
                Class::FoundAutomatically,
                "A restore recovers the refund key from the funding memo on the surviving branch, then finds the refund by its sweep or the rescan the sweep starts.",
            );
            ctx.check_same_balance(a, b);
        }),
    }
}

fn restored_key_near_rewind() -> Scenario {
    Scenario {
        id: "F4-restored-key-near-a-rewind".into(),
        group: REORGS,
        title: "A reorg rewinds a restored wallet just after it swept a paid key".into(),
        summary: "A restored key that is not recent closes at its lookup without ever scanning. A \
            rewind that reopens keys with receipts near the truncation, while keeping the sweep's \
            lookup, can leave such a key neither scanning nor closed, so a later payment is never \
            rechecked. This scenario checks whether that happens."
            .into(),
        params: vec![(
            "rewind".into(),
            "10 blocks below a conflict 12 blocks above the payment".into(),
        )],
        slow: false,
        run: Box::new(|ctx| {
            let (a, birthday) = wallet(ctx);
            let swap = ctx.quote_incoming(a, HOUR).expect("the quote issues");
            let key = swap.label();
            // NEAR pays two days later, so the address is no longer in its recent set.
            ctx.wait(2 * DAY);
            let first = ctx.pay("late payout", &key, &swap.fvk, ZEC, Payer::Near);
            let h = first.height;
            ctx.chain
                .mine_until_next_at(crate::harness::chain::block_time(h + 4));
            let b = ctx.device("B", SEED, birthday);
            ctx.sync(b);
            ctx.chain
                .mine_until(crate::harness::chain::block_time(h + 15));
            ctx.sync(b);
            ctx.reorg(h + 11);
            ctx.mine(6);
            ctx.sync(b);
            let state = ctx.get(b).keys().into_iter().find(|k| k.label() == key);
            let limbo = state
                .as_ref()
                .is_some_and(|k| k.active_from.is_none() && k.closed_at.is_none());
            ctx.check(
                format!("B's {key} is scanning or closed after the rewind"),
                !limbo,
                format!("{state:?}"),
            );
            ctx.wait(DAY);
            let second = ctx.pay("second payment", &key, &swap.fvk, ZEC / 2, Payer::Near);
            ctx.mine(1);
            ctx.sync(b);
            ctx.wait(HOUR);
            ctx.sync(b);
            ctx.check_swap_history(b);
            ctx.expect(
                b,
                "late payout",
                &key,
                &first,
                Class::FoundBySweep,
                "A restore sweeps the incoming lookahead through the receiver directory.",
            );
            ctx.expect(
                b,
                "second payment",
                &key,
                &second,
                Class::FoundAfterRecheck,
                "A later payment to a closed key that was already paid is found by Check swap history.",
            );
        }),
    }
}
