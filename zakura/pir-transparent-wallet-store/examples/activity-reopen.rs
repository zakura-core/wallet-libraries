//! Reopen retained real HTTP recoveries and export facts for an independent comparison.
use serde_json::json;
use std::path::{Path, PathBuf};
use transparent_events::FeeState;
use transparent_wallet::WalletStore;
use transparent_wallet_store::SqliteStore;

fn databases(root: &Path, paths: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            databases(&path, paths)?;
        } else if path.extension().is_some_and(|e| e == "sqlite") {
            paths.push(path);
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(std::env::args().nth(1).ok_or("store root required")?);
    let mut paths = Vec::new();
    databases(&root, &mut paths)?;
    paths.sort();
    if paths.is_empty() {
        return Err("no retained databases".into());
    }
    for path in paths {
        let store = SqliteStore::open(&path)?;
        let identity = store.set_identity()?.ok_or("missing set identity")?;
        if identity.shard_schema != transparent_shard::SCHEMA {
            return Err("recovery used an incompatible schema".into());
        }
        let events = store.events()?;
        if events.iter().any(|e| e.event.metadata().is_none()) {
            return Err("v11 recovery lost transaction metadata".into());
        }
        let entries = store.scripts()?;
        let ledger = store.ledger()?;
        let mut summaries = Vec::new();
        for summary in ledger.history() {
            let mut complete = true;
            for script in &entries {
                let mut through = script.required_from;
                let mut ranges = store.coverage(&script.script)?;
                ranges.sort_by_key(|r| r.start_height);
                for range in ranges {
                    if range.start_height <= through {
                        through = through.max(range.end_height.saturating_add(1));
                    }
                }
                complete &= through > u64::from(summary.height);
            }
            let metadata = summary
                .metadata
                .ok_or("history lost transaction metadata")?;
            let fee = match metadata.fee {
                FeeState::Exact(value) => json!({"state": "exact", "value": value}),
                FeeState::Unknown => json!({"state": "unknown"}),
                FeeState::NotApplicable => json!({"state": "not-applicable"}),
            };
            summaries.push(json!({"txid": hex::encode(summary.txid.0), "height": summary.height,
                "received": summary.received, "spent": summary.spent, "net": summary.net().to_string(),
                "owned_inputs": summary.owned_input_count, "unresolved_inputs": summary.unresolved_input_count,
                "fee": fee, "input_count": metadata.transparent_input_count,
                "shielded": metadata.has_shielded_components, "owned_effects_complete": complete,
                "aggregate_payment": summary.aggregate_payment(complete)}));
        }
        println!(
            "{}",
            json!({"database": path, "schema": identity.shard_schema,
            "set_identity": identity.digest(), "anchor": store.anchor()?, "pending": store.pending()?.len(),
            "last_commit": store.last_commit()?, "summaries": summaries,
            "events": events.iter().map(|event| json!({"script": hex::encode(&event.script),
                "bytes": hex::encode(event.event.to_bytes()), "shard_id": event.shard_id,
                "revision": event.revision_digest})).collect::<Vec<_>>()})
        );
    }
    Ok(())
}
