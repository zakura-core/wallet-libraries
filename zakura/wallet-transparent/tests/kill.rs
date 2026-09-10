//! The process dies in the middle of a private query.
//!
//! Not a stop signal and not an error: `SIGKILL`, with the store, the
//! adapter, the HTTP transport and the service all real and the wallet's
//! files on disk. The service holds a chosen query so the kill lands while
//! that query is in flight; the parent reopens the files, checks them, and
//! resumes.
//!
//! The child is this test binary re-executed with one test selected, so
//! there is no second program to keep in step with the harness.

mod common;

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::blocks::*;
use common::catalogue::*;
use common::*;
use transparent_wallet::WorkLimits;
use transparent_wallet::http::{HttpOptions, HttpShardTransport};
use zakura_wallet_core::AccountId;
use zakura_wallet_store::WalletDb;

const CHILD: &str = "ZAKURA_KILL_CHILD";

/// The child's whole life: open the wallet the parent made, recover against
/// the parent's service, and print heights and counts as it goes.
#[test]
fn kill_child_entry() {
    let Ok(_) = std::env::var(CHILD) else {
        return;
    };
    let home = std::path::PathBuf::from(std::env::var("ZAKURA_KILL_HOME").unwrap());
    let set = std::path::PathBuf::from(std::env::var("ZAKURA_KILL_SET").unwrap());
    let shards = std::env::var("ZAKURA_KILL_SHARDS").unwrap();
    let mut db = WalletDb::open(&home.join("wallet.db"), &home.join("cache.db")).unwrap();
    let map: transparent_filter::ShardMap =
        serde_json::from_slice(&std::fs::read(set.join("shards.json")).unwrap()).unwrap();
    let mut filters = Filters::load(&set, &map);
    let mut transport = HttpShardTransport::new(&shards, &HttpOptions::default()).unwrap();
    println!(
        "phase=recovering commits={}",
        db.transparent_last_commit().unwrap()
    );
    let result = pir().recover_with(&mut db, &mut filters, &mut transport);
    println!(
        "phase=done commits={} result={}",
        db.transparent_last_commit().unwrap(),
        match &result {
            Ok(p) => format!("{:?}", p.completion),
            Err(e) => format!("error: {e}"),
        }
    );
}

struct Killed {
    home: tempfile::TempDir,
    set: tempfile::TempDir,
    map: transparent_filter::ShardMap,
    account: AccountId,
    chain: Chain,
    cast: Cast,
}

/// Runs the child against a service holding the request `hold` names,
/// kills it while that request is in flight, and returns the files.
async fn kill_during(hold: HoldOn) -> Killed {
    let home = tempfile::tempdir().unwrap();
    let (mut db, account) = wallet_on_disk(home.path());
    let (chain, cast) = catalogue(&mut db, account);
    accept_layout(&db, DEFAULT_LAYOUT, SHARDS, chain.hash_fn());
    drop(db);
    let set = tempfile::tempdir().unwrap();
    let map = publish_layout(
        set.path(),
        &extract(&chain),
        DEFAULT_LAYOUT,
        tiers,
        0,
        "",
        chain.hash_fn(),
    );
    let faults = Faults::hold(hold.clone());
    let (base, _handle) = serve_with(set.path(), faults).await;

    let exe = std::env::current_exe().unwrap();
    let mut child = Command::new(exe)
        .args([
            "kill_child_entry",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, "1")
        .env("ZAKURA_KILL_HOME", home.path())
        .env("ZAKURA_KILL_SET", set.path())
        .env("ZAKURA_KILL_SHARDS", &base)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();

    let started = Instant::now();
    while !hold.is_in_flight() {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("the child finished before the held query arrived: {status}");
        }
        assert!(
            started.elapsed() < Duration::from_secs(120),
            "the held query never arrived"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // The query is in flight. Kill.
    child.kill().unwrap();
    let status = child.wait().unwrap();
    assert!(!status.success(), "the child was killed: {status}");
    let mut output = String::new();
    std::io::Read::read_to_string(child.stdout.as_mut().unwrap(), &mut output).unwrap();
    assert!(
        output.contains("phase=recovering"),
        "the child had started: {output}"
    );
    assert!(
        !output.contains("phase=done"),
        "the child did not finish: {output}"
    );
    hold.release();
    Killed {
        home,
        set,
        map,
        account,
        chain,
        cast,
    }
}

fn intact(db: &WalletDb) {
    for schema in ["main", "cache"] {
        let ok: String = db
            .connection()
            .query_row(&format!("PRAGMA {schema}.integrity_check"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(ok, "ok", "{schema} is intact after the kill");
    }
}

/// Reopens the killed wallet's files and checks the state a kill leaves.
fn reopened(killed: &Killed) -> (WalletDb, Snapshot, Expected) {
    let mut db = reopen(killed.home.path());
    intact(&db);
    let after = Snapshot::of(&db);
    assert_eq!(
        after.completion.as_deref(),
        Some("sync-in-progress"),
        "a killed run cannot write its reason; the facade turns this into `interrupted` on open"
    );
    assert_eq!(after.anchor, None, "nothing was accepted as complete");
    let expected = reduce(&killed.chain, &killed.cast.all, FIRST, killed.chain.last());
    for (script, event) in stored_events(&db) {
        assert!(
            expected.events.contains(&Fact::of(&script, &event)),
            "only true events were committed"
        );
    }
    assert_projection_matches_ledger(&mut db, killed.account);
    (db, after, expected)
}

/// The next run finishes exactly, with nothing duplicated.
async fn resumes(killed: Killed, db: WalletDb, after: &Snapshot, expected: &Expected) {
    let base = serve(killed.set.path()).await;
    let (mut db, second, progress) = recover(
        db,
        base,
        killed.set.path(),
        &killed.map,
        WorkLimits::UNLIMITED,
    )
    .await;
    complete(&progress.unwrap());
    assert!(db.transparent_last_commit().unwrap() > after.last_commit);
    compare_blocks(&mut db, killed.account, expected);
    assert_projection_matches_ledger(&mut db, killed.account);
    assert_eq!(
        state(&db, killed.account).completion.as_deref(),
        Some("complete")
    );
    let (fresh, fresh_account) = wallet();
    let mut fresh = fresh;
    let _ = catalogue(&mut fresh, fresh_account);
    accept_layout(&fresh, DEFAULT_LAYOUT, SHARDS, killed.chain.hash_fn());
    let base = serve(killed.set.path()).await;
    let (_, whole, _) = recover(
        fresh,
        base,
        killed.set.path(),
        &killed.map,
        WorkLimits::UNLIMITED,
    )
    .await;
    assert!(
        second.queries <= whole.queries,
        "resuming ({}) cost no more than starting over ({})",
        second.queries,
        whole.queries
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_process_killed_during_the_first_query_reopens_with_nothing_committed_and_no_completion()
{
    let killed = kill_during(HoldOn::new(0, Some("directory"), 1)).await;
    let (db, after, expected) = reopened(&killed);
    assert_eq!(
        after.last_commit, 0,
        "nothing was committed before the first query"
    );
    assert!(after.events.is_empty());
    assert!(after.pending.is_empty());
    resumes(killed, db, &after, &expected).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_process_killed_during_a_directory_query_reopens_with_only_prior_shards() {
    let killed = kill_during(HoldOn::new(1, Some("directory"), 1)).await;
    let (db, after, expected) = reopened(&killed);
    assert_eq!(
        after.last_commit, 1,
        "the first shard's commit landed and no other"
    );
    assert!(
        after.events.iter().all(|e| e.shard_id == 0),
        "only the first shard's events are held"
    );
    assert!(!after.events.is_empty());
    assert!(after.pending.is_empty());
    resumes(killed, db, &after, &expected).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_process_killed_during_a_page_query_keeps_its_pending_rows() {
    // Shard 1 holds the paged history: its directory commit lands with the
    // pages owed, the first page is fetched and committed, and the kill
    // lands on the second.
    let killed = kill_during(HoldOn::new(1, Some("pages"), 2)).await;
    let (db, after, expected) = reopened(&killed);
    assert!(
        after.last_commit >= 2,
        "the first shard and the paged shard's directory landed: {}",
        after.last_commit
    );
    let owed: Vec<_> = after.pending.iter().filter(|p| p.shard_id == 1).collect();
    assert!(!owed.is_empty(), "the pages still owed are on disk");
    assert!(
        owed.iter().all(|p| p.next_ordinal >= 1),
        "the page that was fetched is not owed again"
    );
    assert!(
        after.events.iter().any(|e| e.shard_id == 1),
        "the directory's inline events are held"
    );
    resumes(killed, db, &after, &expected).await;
}
