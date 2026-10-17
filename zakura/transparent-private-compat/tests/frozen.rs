//! The current crates against the frozen baseline under `baseline/`: the
//! publisher's bytes and digests, and wallets left interrupted by the baseline
//! and by the release Vizor ships, reopened and resumed.

use std::collections::BTreeMap;
use std::path::Path;

use zakura_transparent_private_compat::dump;

mod api {
    include!("common/current_api.rs");
}

include!("../src/vectors.rs");

#[allow(dead_code)]
mod scenario {
    use super::{api, dump};
    include!("../src/scenario.rs");
}

fn baseline(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("baseline")
        .join(name)
}

/// Names whose values differ, with both values, for a readable failure.
fn differences(
    expected: &BTreeMap<String, String>,
    actual: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut out = Vec::new();
    for (name, value) in expected {
        match actual.get(name) {
            Some(found) if found == value => {}
            Some(found) => out.push(format!("{name}: baseline {value}, now {found}")),
            None => out.push(format!("{name}: missing now")),
        }
    }
    for name in actual.keys().filter(|name| !expected.contains_key(*name)) {
        out.push(format!("{name}: new"));
    }
    out
}

#[test]
fn the_publisher_writes_the_baseline_bytes() {
    let expected: BTreeMap<String, String> =
        serde_json::from_str(&std::fs::read_to_string(baseline("vectors.json")).unwrap()).unwrap();
    let work = tempfile::tempdir().unwrap();
    let actual = vectors(work.path());
    let differences = differences(&expected, &actual);
    assert!(
        differences.is_empty(),
        "{} differences:\n{}",
        differences.len(),
        differences.join("\n")
    );
    assert!(expected.len() >= 290, "{} frozen vectors", expected.len());
}

pub(crate) fn interrupted(name: &str) -> scenario::Interrupted {
    let dir = baseline(name);
    scenario::Interrupted {
        account: std::fs::read_to_string(dir.join("account")).unwrap(),
        owned: std::fs::read_to_string(dir.join("owned"))
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect(),
        wallet_sql: std::fs::read_to_string(dir.join("wallet.sql")).unwrap(),
        companion_sql: std::fs::read_to_string(dir.join("companion.sql")).unwrap(),
        notes: Vec::new(),
    }
}

/// Reopens and resumes the wallet `source` left interrupted, and compares both
/// databases after every step, and what every pass reported, with what the
/// baseline did from the same files.
fn resumes_as_the_baseline_did(source: &str, frozen: &str) {
    let expected: scenario::Resumed = serde_json::from_str(
        &std::fs::read_to_string(baseline(&format!("resumed-{frozen}.json"))).unwrap(),
    )
    .unwrap();
    let expected_notes =
        std::fs::read_to_string(baseline(&format!("resumed-{frozen}.txt"))).unwrap();
    let work = tempfile::tempdir().unwrap();
    let (actual, notes) = scenario::resume(&interrupted(source), work.path());
    assert_eq!(
        actual.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>()
    );
    for (step, snapshot) in &expected {
        let found = &actual[step];
        assert_eq!(
            found.user_version, snapshot.user_version,
            "{step}: user version"
        );
        assert_eq!(found.objects, snapshot.objects, "{step}: SQL objects");
        for (table, rows) in &snapshot.tables {
            assert_eq!(
                found.tables.get(table),
                Some(rows),
                "{step}: rows of {table}"
            );
        }
        assert_eq!(found.tables.len(), snapshot.tables.len(), "{step}: tables");
    }
    assert_eq!(notes.join("\n") + "\n", expected_notes, "pass reports");
}

/// The frozen wallets hold unfinished work of every kind: filter and setup
/// caches, a failure count, export receipts the wallet committed but the
/// companion never acknowledged, cached page runs (baseline) or pending page
/// retrievals (the released crates), and the wallet's own recovered facts.
#[test]
fn the_frozen_wallets_hold_unfinished_work() {
    for source in ["interrupted", "interrupted-rc1"] {
        let resumed: scenario::Resumed = serde_json::from_str(
            &std::fs::read_to_string(baseline(if source == "interrupted" {
                "resumed-baseline.json"
            } else {
                "resumed-rc1.json"
            }))
            .unwrap(),
        )
        .unwrap();
        let companion = &resumed["restored/companion"].tables;
        let unfinished = if source == "interrupted" {
            "run_cache"
        } else {
            "pending_work"
        };
        for table in [
            "filter_cache",
            "setup_cache",
            "failed_entries",
            "pir_bridge_exports",
            unfinished,
        ] {
            assert!(companion[table].rows > 0, "{source}: no {table}");
        }
        let wallet = &resumed["restored/wallet"].tables;
        for table in [
            "tpir_qualified_revisions",
            "tpir_receive_events",
            "tpir_coverage",
        ] {
            assert!(wallet[table].rows > 0, "{source}: no {table}");
        }
    }
}

#[test]
fn a_baseline_wallet_interrupted_before_acknowledgment_resumes_unchanged() {
    resumes_as_the_baseline_did("interrupted", "baseline");
}

#[test]
fn a_wallet_interrupted_by_the_released_crates_resumes_unchanged() {
    resumes_as_the_baseline_did("interrupted-rc1", "rc1");
}
