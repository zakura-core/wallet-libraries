//! Replay the retained public-chain JSONL sample through the actual codec and builder.
//! Usage: gzip -dc .../mainnet-day.jsonl.gz | cargo run -p transparent-shard --example layout_census
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    io::{self, BufRead},
    time::Instant,
};
use zakura_transparent_private_server::shard::{
    build_directory_shard,
    packing::{HistoryLayout, PackedDemand},
};
use zakura_transparent_private_shared::events::{ReceiveEvent, SpendEvent, TransparentEvent, Txid};
use zakura_transparent_private_shared::filter::{BlockHash, ScriptBytes};
use zakura_transparent_private_shared::shard::{
    candidate_rows, decode_directory_row, decode_page_row, page_tag_salt, script_tag, tag_salt,
    DECOUPLED_2K_8K,
};

#[derive(Deserialize)]
struct Block {
    height: u32,
    hash: String,
    transactions: Vec<Tx>,
}
#[derive(Deserialize)]
struct Tx {
    index: u16,
    txid: String,
    vin: Vec<Input>,
    vout: Vec<Output>,
}
#[derive(Deserialize)]
struct Input {
    txid: String,
    n: u32,
    script: String,
}
#[derive(Deserialize)]
struct Output {
    n: u32,
    value_zat: u64,
    script: String,
}
fn txid(text: &str) -> Txid {
    let mut bytes: [u8; 32] = hex::decode(text)
        .expect("hex txid")
        .try_into()
        .expect("32-byte txid");
    bytes.reverse();
    Txid(bytes)
}
fn supported(script: &[u8]) -> bool {
    script.len() == 25 && script.starts_with(&[0x76, 0xa9, 0x14]) && script.ends_with(&[0x88, 0xac])
        || script.len() == 23 && script.starts_with(&[0xa9, 0x14]) && script.ends_with(&[0x87])
}
fn main() {
    let mut histories: BTreeMap<Vec<u8>, Vec<TransparentEvent>> = BTreeMap::new();
    let mut first = None;
    let mut end = 0;
    let mut terminal = [0; 32];
    let mut blocks = 0;
    for line in io::stdin().lock().lines() {
        let value: serde_json::Value = serde_json::from_str(&line.expect("input")).expect("JSON");
        if value["type"] != "block" {
            continue;
        }
        let block: Block = serde_json::from_value(value).expect("block");
        first.get_or_insert(block.height);
        end = block.height;
        terminal = txid(&block.hash).0;
        blocks += 1;
        for tx in block.transactions {
            let id = txid(&tx.txid);
            for output in tx.vout {
                let script = hex::decode(output.script).expect("script");
                if !supported(&script) {
                    continue;
                }
                histories
                    .entry(script)
                    .or_default()
                    .push(TransparentEvent::Receive(ReceiveEvent {
                        metadata: None,
                        height: block.height,
                        txid: id,
                        transaction_index: tx.index,
                        output_index: output.n,
                        value: output.value_zat,
                        coinbase: tx.index == 0,
                    }));
            }
            for (index, input) in tx.vin.into_iter().enumerate() {
                let script = hex::decode(input.script).expect("script");
                if !supported(&script) {
                    continue;
                }
                histories
                    .entry(script)
                    .or_default()
                    .push(TransparentEvent::Spend(SpendEvent {
                        metadata: None,
                        height: block.height,
                        spending_txid: id,
                        transaction_index: tx.index,
                        input_index: index.try_into().expect("input index"),
                        spent_txid: txid(&input.txid),
                        spent_output_index: input.n,
                    }));
            }
        }
    }
    let mut baseline_classes = [0u64; 47];
    let mut baseline_rows = 0;
    let mut directory_bytes = 0;
    let mut demand = PackedDemand::default();
    for history in histories.values_mut() {
        history.sort_by_key(TransparentEvent::sort_key);
        let paged = history.len().saturating_sub(2);
        if paged > 46 {
            baseline_rows += (paged as u64).div_ceil(46);
        } else if paged != 0 {
            baseline_classes[paged] += 1;
        }
        let mut summary = HistoryLayout::default();
        for event in history {
            summary.push(*event, 2);
        }
        directory_bytes += summary.directory_bytes();
        demand.shift(&HistoryLayout::default(), &summary);
    }
    for (p, count) in baseline_classes.iter().enumerate().skip(1) {
        baseline_rows += count.div_ceil((4092 / (34 + 87 * p)) as u64);
    }
    let events: Vec<_> = histories
        .iter()
        .flat_map(|(script, events)| {
            events
                .iter()
                .map(move |event| (ScriptBytes::new(script.clone()), *event))
        })
        .collect();
    let started = Instant::now();
    // One directory shard with one page shard: every event but a script's
    // newest two is pushed into it, which is the run the sample measures.
    let start = first.expect("blocks") as u64;
    let by_height: Vec<(u64, Vec<(ScriptBytes, TransparentEvent)>)> = (start..=end as u64)
        .map(|height| {
            (
                height,
                events
                    .iter()
                    .filter(|(_, event)| u64::from(event.height()) == height)
                    .cloned()
                    .collect(),
            )
        })
        .collect();
    let (built, children) = build_directory_shard(
        0,
        &DECOUPLED_2K_8K,
        BlockHash([0; 32]),
        zakura_transparent_private_shared::filter::profile::RANGE_PROFILE_V2.name,
        by_height,
        &[end as u64],
        &|_| BlockHash(terminal),
        true,
    )
    .expect("build");
    let child = &children[0];
    let build_ms = started.elapsed().as_millis();
    assert_eq!(child.page_rows, demand.rows());
    let salt = tag_salt(0, &BlockHash(terminal), built.tag_salt_counter);
    let mut verified = 0;
    for (script, expected) in &histories {
        let tag = script_tag(&salt, script);
        let candidates = candidate_rows(
            0,
            script,
            DECOUPLED_2K_8K.directory_rows * u64::from(built.directory_segments()),
        );
        let choice = built
            .choice
            .as_ref()
            .expect("choice table")
            .choice(0, script);
        let entry = decode_directory_row(built.directory_row(candidates[choice]), 1)
            .expect("directory")
            .into_iter()
            .find(|e| e.tag == tag)
            .expect("present");
        let mut recovered = entry.inline.clone();
        if let Some((_, base)) = entry.head() {
            let page_salt = page_tag_salt(
                0,
                0,
                child.end_height,
                &child.terminal_block_hash,
                child.tag_salt_counter,
            );
            let tag = script_tag(&page_salt, script);
            let first = decode_page_row(child.page_row(&DECOUPLED_2K_8K, u64::from(base)))
                .expect("first page")
                .into_iter()
                .find(|e| e.tag == tag)
                .expect("fragment");
            let count = first.fragment_count;
            for ordinal in 0..count {
                let page =
                    decode_page_row(child.page_row(&DECOUPLED_2K_8K, u64::from(base + ordinal)))
                        .expect("page")
                        .into_iter()
                        .find(|e| e.tag == tag)
                        .expect("fragment");
                assert_eq!((page.ordinal, page.fragment_count), (ordinal, count));
                recovered.extend(page.events);
            }
        }
        recovered.sort_by_key(TransparentEvent::sort_key);
        assert_eq!(&recovered, expected);
        verified += 1;
    }
    println!(
        "{}",
        serde_json::json!({
            "schema": zakura_transparent_private_shared::shard::SCHEMA, "classification": "bounded public-chain sample; actual builder and decoded histories; not full-chain capacity",
            "start_height": first, "end_height": end, "blocks": blocks, "scripts": histories.len(), "events": events.len(),
            "v9_required_page_rows": baseline_rows, "v12_required_page_rows": child.page_rows,
            "v9_directory_entry_bytes": histories.len()*192, "v12_directory_entry_bytes": directory_bytes,
            "directory_segments": built.directory_segments(), "page_segments": child.segments,
            "fragments": child.fragments, "verified_histories": verified, "build_ms": build_ms,
            "page_capacity_gain_percent": (baseline_rows as f64 / child.page_rows as f64 - 1.0)*100.0
        })
    );
}
