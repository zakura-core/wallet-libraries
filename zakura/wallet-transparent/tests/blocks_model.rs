//! The block model checks itself: extraction follows the publisher's rules,
//! the reducer refuses to invent, and the two fixture forms agree.

mod common;

use common::blocks::*;
use common::*;
use transparent_filter::ScriptBytes;

fn s(tag: u32) -> ScriptBytes {
    script(tag)
}

#[test]
fn extraction_indexes_a_spend_under_the_consumed_output_script() {
    let mut chain = Chain::synthetic(DEFAULT_LAYOUT);
    let out = chain.pay(FIRST + 5, s(1), 50);
    chain.spend(FIRST + 2 * SPAN + 10, &[out], &[(s(2), 49)]);
    let events = extract(&chain);
    let facts: Vec<Fact> = events
        .iter()
        .flatten()
        .map(|(script, e)| Fact::of(script.as_slice(), e))
        .collect();
    assert!(facts.iter().any(
        |f| matches!(f, Fact::Receive { script, value: 50, .. } if script == s(1).as_slice())
    ));
    assert!(
        facts.iter().any(|f| matches!(f, Fact::Spend { script, spent_output_index: 0, .. } if script == s(1).as_slice())),
        "the spend is indexed under the script it consumed, not the one it paid"
    );
    assert!(facts.iter().any(
        |f| matches!(f, Fact::Receive { script, value: 49, .. } if script == s(2).as_slice())
    ));
    assert_eq!(events[0].len(), 1);
    assert_eq!(events[2].len(), 2);
}

#[test]
fn extraction_marks_first_inputless_transaction_outputs_coinbase() {
    let mut chain = Chain::synthetic(DEFAULT_LAYOUT);
    chain.pay(FIRST + 1, s(1), 5);
    chain.coinbase(FIRST + 1, s(2), 625_000_000);
    let events = extract(&chain);
    let coinbase: Vec<bool> = events[0]
        .iter()
        .map(|(_, e)| matches!(e, transparent_events::TransparentEvent::Receive(r) if r.coinbase))
        .collect();
    assert_eq!(coinbase.iter().filter(|c| **c).count(), 1);
    let (first, _) = &events[0]
        .iter()
        .find(|(_, e)| e.transaction_index() == 0)
        .unwrap();
    assert_eq!(
        first.as_slice(),
        s(2).as_slice(),
        "the coinbase is the first transaction"
    );
}

#[test]
#[should_panic(expected = "double-spends")]
fn the_reducer_refuses_a_double_spend() {
    let mut chain = Chain::synthetic(DEFAULT_LAYOUT);
    let out = chain.pay(FIRST + 5, s(1), 50);
    chain.spend(FIRST + 7, &[out], &[(s(2), 49)]);
    chain.spend(FIRST + 9, &[out], &[(s(3), 1)]);
    let _ = reduce(&chain, &[s(1)], FIRST, chain.last());
}

#[test]
fn the_reducer_counts_a_spend_of_a_receive_below_the_floor_as_unresolved() {
    let mut chain = Chain::synthetic(DEFAULT_LAYOUT);
    let out = chain.pay(FIRST + 5, s(1), 50);
    chain.spend(FIRST + SPAN + 7, &[out], &[(s(2), 49)]);
    let expected = reduce(&chain, &[s(1)], FIRST + SPAN, chain.last());
    assert_eq!(expected.unresolved, 1);
    assert!(expected.utxos.is_empty());
    assert!(
        expected.spends.is_empty(),
        "an unresolved spend is not a resolved one"
    );
    assert_eq!(expected.events.len(), 1, "the spend event itself is held");
    assert_eq!(expected.balance, 0);
    let whole = reduce(&chain, &[s(1)], FIRST, chain.last());
    assert_eq!(whole.unresolved, 0);
    assert_eq!(whole.spends.len(), 1);
    assert_eq!(whole.history.len(), 2);
}

#[test]
fn the_reducer_keeps_a_zero_balance_history() {
    let mut chain = Chain::synthetic(DEFAULT_LAYOUT);
    let out = chain.pay(FIRST + 5, s(1), 50);
    let spend = chain.spend(FIRST + 6, &[out], &[(s(2), 49)]);
    let expected = reduce(&chain, &[s(1)], FIRST, chain.last());
    assert_eq!(expected.balance, 0);
    assert!(expected.utxos.is_empty());
    assert_eq!(expected.history[&spend], (FIRST + 6, 0, 50));
    assert_eq!(expected.history[&out.txid], (FIRST + 5, 50, 0));
}

#[test]
fn extraction_of_the_legacy_chain_equals_the_legacy_events() {
    // The suite's trusted fixture, rebuilt as blocks and extracted again: the
    // same events come out, transaction indices aside, which the legacy
    // fixture assigns arbitrarily.
    let (db, account) = wallet();
    let mine = my_scripts(&db, account);
    let legacy = chain(&mine);
    let rebuilt = chain_from_events(DEFAULT_LAYOUT, &legacy);
    let extracted = extract(&rebuilt);
    let norm = |events: &Events| -> std::collections::BTreeSet<Fact> {
        events
            .iter()
            .flatten()
            .map(|(script, e)| Fact::of(script.as_slice(), e).without_index())
            .collect()
    };
    assert_eq!(norm(&extracted), norm(&legacy));
    // And the reducer over the rebuilt blocks agrees with the library's
    // replay of the legacy events on every count it shares.
    let expected = reduce(&rebuilt, &mine, FIRST, rebuilt.last());
    let replayed = traverse(&legacy, &mine);
    assert_eq!(expected.balance, replayed.confirmed_balance());
    assert_eq!(expected.utxos.len(), replayed.utxos().count());
    assert_eq!(expected.spends.len(), replayed.spends().len());
    assert_eq!(expected.history.len(), replayed.history().len());
}

#[test]
fn the_jsonl_sample_loads_and_chains() {
    let Ok(path) = std::env::var("ZAKURA_TRANSPARENT_BLOCKS_JSONL") else {
        eprintln!("ZAKURA_TRANSPARENT_BLOCKS_JSONL unset; skipping");
        return;
    };
    let layout = Layout {
        first: 3_470_268,
        span: 192,
        shards: 6,
    };
    let chain = Chain::load_jsonl(std::path::Path::new(&path), layout);
    assert_eq!(chain.blocks.len(), 1153);
    let candidates = chain.candidate_scripts();
    assert!(candidates.iter().any(|c| c.is_p2pkh() && c.spends > 0));
    assert!(candidates.iter().any(|c| c.coinbase));
    let events = extract(&chain);
    assert!(events.iter().all(|shard| !shard.is_empty()));
}
