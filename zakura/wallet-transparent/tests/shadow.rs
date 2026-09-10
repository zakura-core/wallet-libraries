//! The shadow comparison: a profile the application synced for validation is
//! read without being touched, compared with the block reducer's
//! reconstruction, and reported by counts and digests alone. The recovery
//! profile beside it is never opened.

mod common;

use std::path::Path;

use common::blocks::*;
use common::catalogue::*;
use common::*;
use transparent_wallet::WorkLimits;
use zakura_wallet_transparent::shadow::{
    ShadowError, ShadowSnapshot, check_marker, compare, read_shadow_snapshot, run_compare,
    tree_digests,
};

fn marker(dir: &Path, mode: &str) {
    std::fs::write(
        dir.join("profile.json"),
        format!(
            "{{\"namespace\":\"org.valargroup.zakura-recovery-beta\",\"mode\":\"{mode}\",\"network\":\"main\"}}\n"
        ),
    )
    .unwrap();
}

/// The reducer's expectation in the snapshot's form.
fn snapshot_of(expected: &Expected, chain: &Chain) -> ShadowSnapshot {
    let mut snapshot = ShadowSnapshot {
        anchor_height: Some(chain.last() as u32),
        anchor_hash: Some(chain.hash(chain.last()).to_display_hex()),
        completion: None,
        ..ShadowSnapshot::default()
    };
    for fact in &expected.events {
        let (script, event) = fact_to_event(fact);
        snapshot.add_event(&script, &event);
    }
    snapshot
}

fn fact_to_event(fact: &Fact) -> (Vec<u8>, transparent_events::TransparentEvent) {
    use transparent_events::{ReceiveEvent, SpendEvent, TransparentEvent, Txid};
    match fact {
        Fact::Receive {
            script,
            height,
            txid,
            tx_index,
            output_index,
            value,
            coinbase,
        } => (
            script.clone(),
            TransparentEvent::Receive(ReceiveEvent {
                height: *height,
                txid: Txid(*txid),
                transaction_index: *tx_index,
                output_index: *output_index,
                value: *value,
                coinbase: *coinbase,
            }),
        ),
        Fact::Spend {
            script,
            height,
            spending_txid,
            tx_index,
            input_index,
            spent_txid,
            spent_output_index,
        } => (
            script.clone(),
            TransparentEvent::Spend(SpendEvent {
                height: *height,
                spending_txid: Txid(*spending_txid),
                transaction_index: *tx_index,
                input_index: *input_index,
                spent_txid: Txid(*spent_txid),
                spent_output_index: *spent_output_index,
            }),
        ),
    }
}

/// A shadow profile that has recovered the catalogue and been closed.
async fn synced_shadow_profile() -> (tempfile::TempDir, Chain, Expected) {
    let home = tempfile::tempdir().unwrap();
    marker(home.path(), "shadow");
    let (mut db, account) = wallet_on_disk(home.path());
    let (chain, cast) = catalogue(&mut db, account);
    accept_layout(&db, DEFAULT_LAYOUT, SHARDS, chain.hash_fn());
    let dir = tempfile::tempdir().unwrap();
    let (map, base, _) = served(&chain, dir.path()).await;
    let (db, _, progress) = recover(db, base, dir.path(), &map, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());
    let expected = reduce(&chain, &cast.all, FIRST, chain.last());
    drop(db);
    (home, chain, expected)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_shadow_snapshot_of_a_recovered_wallet_equals_the_independent_reconstruction() {
    let (home, chain, expected) = synced_shadow_profile().await;
    let actual = read_shadow_snapshot(home.path()).unwrap();
    let wanted = snapshot_of(&expected, &chain);
    let comparison = compare(&actual, &wanted);
    assert!(comparison.equal, "{:?}", comparison.sanitized());
    assert_eq!(actual.completion.as_deref(), Some("complete"));
    assert_eq!(actual.balance(), expected.balance);
    assert_eq!(
        actual.digest(),
        {
            let mut w = wanted.clone();
            w.completion = actual.completion.clone();
            w.digest()
        },
        "the digest covers the ledger, not the completion word"
    );
    let report = comparison.sanitized();
    assert_eq!(report.result, "equal");
    assert!(report.balance_equal && report.anchor_equal);
    assert_eq!(
        report.actual_receives,
        expected
            .events
            .iter()
            .filter(|f| matches!(f, Fact::Receive { .. }))
            .count()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn reading_a_shadow_profile_writes_nothing() {
    let (home, _, _) = synced_shadow_profile().await;
    let before = tree_digests(home.path()).unwrap();
    assert!(before.contains_key("cache.db") && before.contains_key("wallet.db"));
    assert!(
        !before.contains_key("cache.db-wal")
            || std::fs::metadata(home.path().join("cache.db-wal"))
                .unwrap()
                .len()
                == 0
    );
    let _ = read_shadow_snapshot(home.path()).unwrap();
    let _ = read_shadow_snapshot(home.path()).unwrap();
    let after = tree_digests(home.path()).unwrap();
    assert_eq!(before, after, "reading changed a file");
    assert!(!home.path().join("cache.db-shm").exists() || before.contains_key("cache.db-shm"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mismatch_is_reported_by_count_and_digest_only() {
    let (home, chain, expected) = synced_shadow_profile().await;
    // A scratch copy with one receive removed and one value changed.
    let scratch = tempfile::tempdir().unwrap();
    for file in ["profile.json", "wallet.db", "cache.db"] {
        std::fs::copy(home.path().join(file), scratch.path().join(file)).unwrap();
    }
    {
        let conn = rusqlite::Connection::open(scratch.path().join("cache.db")).unwrap();
        conn.execute("DELETE FROM transparent_receive_events WHERE rowid = (SELECT MIN(rowid) FROM transparent_receive_events)", []).unwrap();
        conn.pragma_update(None, "journal_mode", "DELETE").unwrap();
    }
    let actual = read_shadow_snapshot(scratch.path()).unwrap();
    let wanted = snapshot_of(&expected, &chain);
    let comparison = compare(&actual, &wanted);
    assert!(!comparison.equal);
    assert_eq!(comparison.missing_receives.len(), 1);
    let report = comparison.sanitized();
    assert_eq!(report.result, "differs");
    assert_eq!(report.missing_receives, 1);
    assert_eq!(report.expected_receives, report.actual_receives + 1);
    let text = serde_json::to_string(&report).unwrap();
    // Nothing in the report is an outpoint, a txid or a script: the only
    // long hex strings are the two digests.
    let hex_runs: Vec<&str> = text
        .split(|c: char| !c.is_ascii_hexdigit())
        .filter(|s| s.len() >= 40)
        .collect();
    assert_eq!(hex_runs.len(), 2, "{text}");
    for key in comparison
        .missing_receives
        .iter()
        .chain(actual.receives.keys())
    {
        let txid = key.split(':').next().unwrap();
        assert!(!text.contains(txid), "a txid leaked into the report");
    }
    // The detail does name them, and is for a local file only.
    let detail = comparison.detail().to_string();
    assert!(detail.contains(&comparison.missing_receives[0]));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_profile_that_is_not_a_shadow_profile_is_refused_before_it_is_opened() {
    let home = tempfile::tempdir().unwrap();
    marker(home.path(), "recovery");
    // No database at all: a refusal that came from opening one would look
    // different from a refusal that came from the marker.
    let error = read_shadow_snapshot(home.path()).unwrap_err();
    assert!(matches!(error, ShadowError::NotShadow(..)), "{error}");
    assert_eq!(error.exit_code(), 3);
    assert!(check_marker(home.path()).is_err());
    marker(home.path(), "shadow");
    assert!(check_marker(home.path()).is_ok());
    let error = read_shadow_snapshot(home.path()).unwrap_err();
    assert!(
        matches!(error, ShadowError::Read(..)),
        "a shadow marker with no database is a read error: {error}"
    );
    // Another application's marker is refused too.
    std::fs::write(
        home.path().join("profile.json"),
        "{\"namespace\":\"com.example.other\",\"mode\":\"shadow\"}",
    )
    .unwrap();
    assert!(matches!(
        check_marker(home.path()).unwrap_err(),
        ShadowError::NotShadow(..)
    ));
    // No marker: refused.
    std::fs::remove_file(home.path().join("profile.json")).unwrap();
    assert!(matches!(
        check_marker(home.path()).unwrap_err(),
        ShadowError::NotShadow(..)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_recovery_profile_is_untouched_by_a_shadow_comparison() {
    let (shadow, chain, expected) = synced_shadow_profile().await;
    // A recovery profile beside it, with its own wallet.
    let recovery = tempfile::tempdir().unwrap();
    marker(recovery.path(), "recovery");
    {
        let (mut db, account) = wallet_on_disk(recovery.path());
        let _ = catalogue(&mut db, account);
    }
    let recovery_before = tree_digests(recovery.path()).unwrap();
    let shadow_before = tree_digests(shadow.path()).unwrap();

    let out = tempfile::tempdir().unwrap();
    let expected_path = out.path().join("expected.json");
    std::fs::write(
        &expected_path,
        serde_json::to_string(&snapshot_of(&expected, &chain)).unwrap(),
    )
    .unwrap();
    let report_path = out.path().join("report.json");
    let detail_path = out.path().join("detail.json");
    let code = run_compare(
        shadow.path(),
        &expected_path,
        &report_path,
        Some(&detail_path),
        &[recovery.path().to_path_buf()],
    )
    .unwrap();
    assert_eq!(code, 0, "equal");
    assert_eq!(
        tree_digests(recovery.path()).unwrap(),
        recovery_before,
        "the recovery profile is untouched"
    );
    assert_eq!(
        tree_digests(shadow.path()).unwrap(),
        shadow_before,
        "the shadow profile is untouched"
    );
    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).unwrap();
    assert_eq!(report["result"], "equal");
    assert!(detail_path.exists());

    // Pointed at the recovery profile, the comparison refuses before opening.
    let code = run_compare(recovery.path(), &expected_path, &report_path, None, &[]);
    assert!(matches!(code, Err(ShadowError::NotShadow(..))));
    assert_eq!(tree_digests(recovery.path()).unwrap(), recovery_before);

    // And a busy profile is refused rather than read around.
    let busy = tempfile::tempdir().unwrap();
    marker(busy.path(), "shadow");
    for file in ["wallet.db", "cache.db"] {
        std::fs::copy(shadow.path().join(file), busy.path().join(file)).unwrap();
    }
    std::fs::write(busy.path().join("cache.db-wal"), b"not empty").unwrap();
    let error = read_shadow_snapshot(busy.path()).unwrap_err();
    assert!(matches!(error, ShadowError::Busy(..)), "{error}");
    assert_eq!(error.exit_code(), 4);
}
