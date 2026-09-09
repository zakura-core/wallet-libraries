//! Deriving transparent addresses, and the private ledger's memory.
//!
//! The ledger is the only thing that discovers transparent funds — see
//! `docs/zakura_transparent_pir.md` — so everything it gets wrong is invisible
//! rather than merely late. The cases below are the ones where a plausible
//! implementation is silently wrong: an output at a script the wallet never
//! derived, a retry that differs from what was kept, a rewind that leaves
//! coverage above the blocks it rested on, and a script whose required height
//! quietly moves forward.

use zakura_wallet_core::AccountId;
use zakura_wallet_store::{
    GapLimits, RecoveredOutput, RecoveredSpend, WalletDb,
    testing::test_db,
    transparent::{
        CommitError, CoverageKind, EventKey, LedgerEvent, PendingPages, ShardCommit,
        TransparentAnchor, TransparentScript,
    },
};
use zcash_protocol::{
    TxId,
    consensus::{BlockHeight, Network},
};

fn params() -> Network {
    Network::MainNetwork
}

fn h(n: u32) -> BlockHeight {
    BlockHeight::from_u32(n)
}

fn wallet() -> (WalletDb, AccountId) {
    let mut db = test_db().unwrap();
    let id = db
        .create_account(
            &params(),
            &[5u8; 32],
            zip32::AccountId::try_from(0).unwrap(),
            h(100),
        )
        .unwrap();
    db.update_chain_tip(&params(), h(1_000)).unwrap();
    (db, id)
}

fn watched_addresses(db: &WalletDb) -> Vec<(i64, String)> {
    db.connection()
        .prepare(
            "SELECT id, transparent_address FROM cache.addresses
             WHERE transparent_address IS NOT NULL
             ORDER BY key_scope, transparent_child_index",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn an_account_derives_a_full_window_of_watchable_addresses() {
    // Without this the wallet is watching nothing, and a transparent payment
    // has no second chance: there is no trial decryption to find it later.
    let (mut db, id) = wallet();
    let limits = GapLimits::default();

    // Creating the account derived the window; there is nothing left to add.
    // Waiting to be asked would leave a gap between the account existing and
    // the wallet watching anything, and a payment arriving in that gap is one
    // it can never recognise afterwards.
    let added = db
        .maintain_transparent_addresses(&params(), id, &limits)
        .expect("the account has a transparent key");
    assert_eq!(added, 0, "creating the account already filled the window");

    let addresses = watched_addresses(&db);
    assert_eq!(
        addresses.len(),
        (limits.external + limits.internal) as usize,
        "both scopes are watched, at their own widths"
    );

    // Real addresses, not placeholders, and all distinct: two indices deriving
    // the same address would mean the derivation is not doing anything.
    let encoded: std::collections::BTreeSet<_> = addresses.iter().map(|(_, a)| a.clone()).collect();
    assert_eq!(encoded.len(), addresses.len(), "every address is distinct");
    assert!(
        addresses.iter().all(|(_, a)| a.starts_with('t')),
        "mainnet transparent addresses are t-addresses"
    );

    // Idempotent, which is what lets it run after every batch.
    let again = db
        .maintain_transparent_addresses(&params(), id, &limits)
        .unwrap();
    assert_eq!(again, 0, "a full window needs no widening");
    assert_eq!(watched_addresses(&db).len(), addresses.len());
}

#[test]
fn the_watch_set_covers_every_derived_address() {
    let (mut db, id) = wallet();
    db.maintain_transparent_addresses(&params(), id, &GapLimits::default())
        .unwrap();

    let watch = db.transparent_watch().expect("the watch set builds");
    assert_eq!(watch.addresses.len(), watched_addresses(&db).len());
    assert!(
        watch.addresses.iter().all(|a| !a.script.is_empty()),
        "a watched address without a script matches nothing"
    );
}

// ------------------------------------------------------ the private ledger

/// The scripts of the account's watched addresses, in derivation order.
fn scripts(db: &WalletDb) -> Vec<Vec<u8>> {
    db.connection()
        .prepare(
            "SELECT transparent_script FROM cache.addresses
             WHERE transparent_script IS NOT NULL
             ORDER BY key_scope, transparent_child_index",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn txid(n: u8) -> TxId {
    TxId::from_bytes([n; 32])
}

fn count(db: &WalletDb, table: &str) -> i64 {
    db.connection()
        .query_row(&format!("SELECT COUNT(*) FROM cache.{table}"), [], |r| {
            r.get(0)
        })
        .unwrap()
}

/// An opaque event record: what the protocol encodes, which this crate never
/// reads. The real encoding carries the value, so a differing value is a
/// differing record; this stands in for that.
fn record(tag: u8, value: u64) -> Vec<u8> {
    let mut bytes = vec![tag; 96];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    bytes
}

fn receive(
    script: &[u8],
    tx: u8,
    index: u32,
    value: u64,
    height: u32,
) -> (LedgerEvent, RecoveredOutput) {
    (
        LedgerEvent {
            key: EventKey::Receive {
                txid: txid(tx),
                output_index: index,
            },
            script: script.to_vec(),
            height: h(height),
            record: record(tx, value),
            shard_id: 0,
            revision_digest: "r0".into(),
        },
        RecoveredOutput {
            txid: txid(tx),
            output_index: index,
            script: script.to_vec(),
            value,
            mined_height: Some(h(height)),
            observed_at: h(height),
            coinbase: Some(false),
        },
    )
}

fn spend(
    script: &[u8],
    spender: u8,
    spent: u8,
    spent_index: u32,
    height: u32,
) -> (LedgerEvent, RecoveredSpend) {
    (
        LedgerEvent {
            key: EventKey::Spend {
                spending_txid: txid(spender),
                input_index: 0,
                spent_txid: txid(spent),
                spent_output_index: spent_index,
            },
            script: script.to_vec(),
            height: h(height),
            record: record(spender, 0),
            shard_id: 0,
            revision_digest: "r0".into(),
        },
        RecoveredSpend {
            spending_txid: txid(spender),
            height: h(height),
            spent_txid: txid(spent),
            spent_output_index: spent_index,
        },
    )
}

fn commit(
    shard_id: u64,
    revision: &str,
    sealed: bool,
    range: (u32, u32),
    covered: Vec<Vec<u8>>,
) -> ShardCommit {
    ShardCommit {
        shard_id,
        revision_digest: revision.into(),
        sealed,
        start_height: h(range.0),
        end_height: h(range.1),
        terminal_block_hash: format!("{:064x}", range.1),
        source_anchor: None,
        events: Vec::new(),
        outputs: Vec::new(),
        spends: Vec::new(),
        covered_scripts: covered,
        pending_upsert: Vec::new(),
        pending_complete: Vec::new(),
    }
}

fn with_receive(mut commit: ShardCommit, event: (LedgerEvent, RecoveredOutput)) -> ShardCommit {
    let (mut event, output) = event;
    event.shard_id = commit.shard_id;
    event.revision_digest = commit.revision_digest.clone();
    commit.events.push(event);
    commit.outputs.push(output);
    commit
}

fn with_spend(mut commit: ShardCommit, event: (LedgerEvent, RecoveredSpend)) -> ShardCommit {
    let (mut event, spend) = event;
    event.shard_id = commit.shard_id;
    event.revision_digest = commit.revision_digest.clone();
    commit.events.push(event);
    commit.spends.push(spend);
    commit
}

fn registered(db: &mut WalletDb, id: AccountId, script: &[u8], from: u32) {
    db.add_transparent_scripts(&[TransparentScript {
        script: script.to_vec(),
        account: id,
        imported: false,
        required_from: h(from),
    }])
    .unwrap();
}

#[test]
fn a_committed_receive_is_a_balance_and_a_coverage_together() {
    let (mut db, id) = wallet();
    let script = scripts(&db)[0].clone();
    registered(&mut db, id, &script, 100);

    let first = db
        .commit_transparent_shard(&with_receive(
            commit(0, "r0", true, (100, 899), vec![script.clone()]),
            receive(&script, 1, 0, 250_000, 500),
        ))
        .expect("the commit applies");
    assert_eq!(first, 1);

    let balance = db.transparent_balance(id).unwrap();
    assert_eq!(balance.total().into_u64(), 250_000);
    assert_eq!(
        balance.spendable.into_u64(),
        250_000,
        "a recovered event states coinbase-ness exactly, so maturity is decidable"
    );

    let mine = db
        .transparent_coverage(id, h(100))
        .unwrap()
        .into_iter()
        .find(|c| c.script == script)
        .unwrap();
    assert_eq!(mine.covered_through, h(899));
    assert_eq!(mine.settled_through, h(899));

    // The other scripts were not asked about, and say so: the account's
    // coverage is its least-read script, one below the birthday.
    let state = db.transparent_state(id, h(100)).unwrap();
    assert_eq!(state.covered_through, Some(h(99)));
    assert_eq!(state.unresolved_spends, 0);
    assert_eq!(state.anchor, None, "no sync has accepted an anchor");
}

#[test]
fn a_repeated_commit_writes_nothing_new_and_a_differing_one_is_refused_whole() {
    let (mut db, id) = wallet();
    let script = scripts(&db)[0].clone();
    registered(&mut db, id, &script, 100);
    let once = with_receive(
        commit(0, "r0", true, (100, 899), vec![script.clone()]),
        receive(&script, 1, 0, 250_000, 500),
    );
    db.commit_transparent_shard(&once).unwrap();
    let events = db.transparent_events().unwrap();
    let outputs = count(&db, "transparent_received_outputs");

    // The same again: a new commit id, nothing else.
    let again = db.commit_transparent_shard(&once).unwrap();
    assert_eq!(again, 2);
    assert_eq!(db.transparent_events().unwrap(), events);
    assert_eq!(count(&db, "transparent_received_outputs"), outputs);

    // The same outpoint with other contents, beside a perfectly good new
    // receive: neither is written.
    let other = scripts(&db)[1].clone();
    registered(&mut db, id, &other, 100);
    let mut differing = with_receive(
        commit(
            0,
            "r0",
            true,
            (100, 899),
            vec![script.clone(), other.clone()],
        ),
        receive(&script, 1, 0, 999, 500),
    );
    differing = with_receive(differing, receive(&other, 3, 0, 1, 600));
    match db.commit_transparent_shard(&differing) {
        Err(CommitError::ConflictingReceive {
            output_index: 0, ..
        }) => {}
        other => panic!("expected a conflicting receive, got {other:?}"),
    }
    assert_eq!(
        db.transparent_events().unwrap(),
        events,
        "nothing was written"
    );
    assert!(db.transparent_coverage_of(&other).unwrap().is_empty());
    assert_eq!(
        db.transparent_balance(id).unwrap().total().into_u64(),
        250_000
    );

    // The same output spent by two transactions is a double spend.
    let double = with_spend(
        commit(1, "r1", true, (900, 999), vec![script.clone()]),
        spend(&script, 7, 1, 0, 950),
    );
    db.commit_transparent_shard(&double).unwrap();
    let twice = with_spend(
        commit(1, "r1", true, (900, 999), vec![script.clone()]),
        spend(&script, 8, 1, 0, 951),
    );
    match db.commit_transparent_shard(&twice) {
        Err(CommitError::DoubleSpend {
            spent_output_index: 0,
            ..
        }) => {}
        other => panic!("expected a double spend, got {other:?}"),
    }
    assert_eq!(db.transparent_last_commit().unwrap(), 3);
}

#[test]
fn a_spend_resolves_against_a_receive_kept_by_an_earlier_commit() {
    // The case a one-shot sync cannot handle and the store exists for: the
    // receive was found last month, the spend is found today.
    let (mut db, id) = wallet();
    let script = scripts(&db)[0].clone();
    registered(&mut db, id, &script, 100);
    db.commit_transparent_shard(&with_receive(
        commit(0, "r0", true, (100, 499), vec![script.clone()]),
        receive(&script, 1, 0, 250_000, 300),
    ))
    .unwrap();
    db.commit_transparent_shard(&with_spend(
        commit(1, "r1", true, (500, 899), vec![script.clone()]),
        spend(&script, 2, 1, 0, 600),
    ))
    .unwrap();

    assert_eq!(count(&db, "transparent_received_output_spends"), 1);
    assert_eq!(
        db.transparent_balance(id).unwrap().total().into_u64(),
        0,
        "the output is spent, so it is not in the balance"
    );
    let state = db.transparent_state(id, h(100)).unwrap();
    assert_eq!(state.unresolved_spends, 0);
}

#[test]
fn a_spend_of_an_output_never_seen_is_counted_not_absorbed() {
    // Absorbing one leaves an output in the balance that something has already
    // consumed: too high, and looking entirely ordinary. And it attaches the
    // moment the output arrives, however much later that is.
    let (mut db, id) = wallet();
    let script = scripts(&db)[0].clone();
    registered(&mut db, id, &script, 100);
    db.commit_transparent_shard(&with_spend(
        commit(1, "r1", true, (500, 899), vec![script.clone()]),
        spend(&script, 2, 1, 0, 600),
    ))
    .unwrap();
    assert_eq!(
        db.transparent_state(id, h(100)).unwrap().unresolved_spends,
        1
    );
    assert_eq!(count(&db, "transparent_received_outputs"), 0);

    db.commit_transparent_shard(&with_receive(
        commit(0, "r0", true, (100, 499), vec![script.clone()]),
        receive(&script, 1, 0, 250_000, 300),
    ))
    .unwrap();
    assert_eq!(
        db.transparent_state(id, h(100)).unwrap().unresolved_spends,
        0
    );
    assert_eq!(
        count(&db, "transparent_received_output_spends"),
        1,
        "the spend kept from before attaches to the output that arrived after it"
    );
    assert_eq!(db.transparent_balance(id).unwrap().total().into_u64(), 0);
}

#[test]
fn an_output_at_a_script_the_wallet_never_derived_is_refused() {
    // Not something to absorb quietly: the service answered about somebody
    // else, and storing it would credit another person's funds to this wallet.
    let (mut db, id) = wallet();
    let script = scripts(&db)[0].clone();
    registered(&mut db, id, &script, 100);
    let foreign = vec![0x76, 0xa9, 0x14, 0xff];
    let err = db
        .commit_transparent_shard(&with_receive(
            commit(0, "r0", true, (100, 899), vec![script.clone()]),
            receive(&foreign, 9, 0, 100_000, 500),
        ))
        .expect_err("an unknown script must be refused");
    assert!(
        format!("{err}").contains("never derived"),
        "the error should say why it was refused, got: {err}"
    );
    assert!(
        db.transparent_events().unwrap().is_empty(),
        "nothing was written"
    );
    assert!(db.transparent_coverage_of(&script).unwrap().is_empty());
}

#[test]
fn a_required_height_is_never_raised() {
    // Moving the birthday forward cannot substitute for retaining an old
    // receive: the spend found later needs it.
    let (mut db, id) = wallet();
    let script = scripts(&db)[0].clone();
    registered(&mut db, id, &script, 100);
    registered(&mut db, id, &script, 500);
    let kept = db
        .transparent_scripts()
        .unwrap()
        .into_iter()
        .find(|s| s.script == script)
        .unwrap();
    assert_eq!(kept.required_from, h(100));

    registered(&mut db, id, &script, 50);
    let lowered = db
        .transparent_scripts()
        .unwrap()
        .into_iter()
        .find(|s| s.script == script)
        .unwrap();
    assert_eq!(
        lowered.required_from,
        h(50),
        "lowering is allowed; it only asks for more"
    );
}

#[test]
fn a_rollback_removes_the_suffix_from_the_ledger_and_the_balance_alike() {
    let (mut db, id) = wallet();
    let script = scripts(&db)[0].clone();
    registered(&mut db, id, &script, 100);
    let mut old = with_receive(
        commit(0, "r0", true, (100, 499), vec![script.clone()]),
        receive(&script, 1, 0, 250_000, 300),
    );
    old = with_receive(old, receive(&script, 3, 0, 1_000, 450));
    db.commit_transparent_shard(&old).unwrap();
    let mut tail = with_spend(
        commit(1, "r1", false, (500, 599), vec![script.clone()]),
        spend(&script, 2, 1, 0, 550),
    );
    tail = with_receive(tail, receive(&script, 4, 0, 5_000, 560));
    tail.pending_upsert.push(PendingPages {
        id: None,
        shard_id: 1,
        revision_digest: "r1".into(),
        script: script.clone(),
        first_page: 0,
        page_count: 2,
        total_events: 9,
        inline: Vec::new(),
        next_ordinal: 0,
        attempts: 0,
        validated_events: 0,
        target_anchor: None,
    });
    db.commit_transparent_shard(&tail).unwrap();
    db.commit_transparent_anchor(
        &TransparentAnchor {
            height: h(599),
            hash: "tail".into(),
        },
        h(499),
        h(599),
    )
    .unwrap();
    assert_eq!(
        db.transparent_balance(id).unwrap().total().into_u64(),
        6_000
    );
    assert_eq!(db.transparent_pending().unwrap().len(), 1);

    db.rollback_transparent_above(h(499), "tail replaced")
        .unwrap();

    assert_eq!(
        db.transparent_events().unwrap().len(),
        2,
        "the tail's events are gone"
    );
    assert_eq!(
        db.transparent_balance(id).unwrap().total().into_u64(),
        251_000,
        "the spend above the cut is released and the receive above it is gone"
    );
    let ranges = db.transparent_coverage_of(&script).unwrap();
    assert_eq!(ranges.len(), 1);
    assert_eq!(ranges[0].end_height, h(499));
    assert_eq!(ranges[0].kind, CoverageKind::Settled);
    assert!(db.transparent_provisional_coverage().unwrap().is_empty());
    assert!(
        db.transparent_pending().unwrap().is_empty(),
        "pending work of the replaced revision is gone with it"
    );
    assert!(
        db.transparent_anchor().unwrap().is_none(),
        "an unscanned rollback height cannot establish an anchor"
    );
}

#[test]
fn the_wallets_own_rewind_rolls_the_ledger_back_with_everything_else() {
    // A rewind is the wallet saying the blocks above a height are gone. Coverage
    // that rested on them would name a height nothing re-reads; the ledger
    // follows the cut in the same transaction.
    let (mut db, id) = wallet();
    let script = scripts(&db)[0].clone();
    registered(&mut db, id, &script, 100);
    db.commit_transparent_shard(&with_receive(
        commit(0, "r0", true, (100, 499), vec![script.clone()]),
        receive(&script, 1, 0, 250_000, 300),
    ))
    .unwrap();
    db.commit_transparent_shard(&with_receive(
        commit(1, "r1", true, (500, 899), vec![script.clone()]),
        receive(&script, 2, 0, 1_000, 700),
    ))
    .unwrap();
    assert_eq!(
        db.transparent_state(id, h(100)).unwrap().covered_through,
        Some(h(99))
    );
    let mine = |db: &WalletDb| {
        db.transparent_coverage(id, h(100))
            .unwrap()
            .into_iter()
            .find(|c| c.script == script)
            .unwrap()
            .covered_through
    };
    assert_eq!(mine(&db), h(899));

    db.truncate_to(h(499)).unwrap();

    assert_eq!(mine(&db), h(499), "coverage ends where the chain now ends");
    assert_eq!(db.transparent_events().unwrap().len(), 1);
    assert_eq!(
        db.transparent_balance(id).unwrap().total().into_u64(),
        250_000
    );
}

#[test]
fn coverage_is_read_contiguously_from_the_required_height() {
    // A range that does not join the one before it is not coverage the wallet
    // can rely on: a gap between them is history nobody read.
    let (mut db, id) = wallet();
    let script = scripts(&db)[0].clone();
    registered(&mut db, id, &script, 100);
    db.commit_transparent_shard(&commit(0, "r0", true, (100, 299), vec![script.clone()]))
        .unwrap();
    db.commit_transparent_shard(&commit(2, "r2", false, (500, 599), vec![script.clone()]))
        .unwrap();
    let mine = db
        .transparent_coverage(id, h(100))
        .unwrap()
        .into_iter()
        .find(|c| c.script == script)
        .unwrap();
    assert_eq!(mine.covered_through, h(299), "the gap at 300 stops it");

    db.commit_transparent_shard(&commit(1, "r1", true, (300, 499), vec![script.clone()]))
        .unwrap();
    let mine = db
        .transparent_coverage(id, h(100))
        .unwrap()
        .into_iter()
        .find(|c| c.script == script)
        .unwrap();
    assert_eq!(mine.covered_through, h(599));
    assert_eq!(mine.settled_through, h(499), "the tail is provisional");
    assert_eq!(
        db.transparent_state(id, h(100)).unwrap().provisional_shards,
        1
    );

    db.promote_transparent_provisional(2, "r2").unwrap();
    let mine = db
        .transparent_coverage(id, h(100))
        .unwrap()
        .into_iter()
        .find(|c| c.script == script)
        .unwrap();
    assert_eq!(mine.settled_through, h(599));
    assert_eq!(
        db.transparent_state(id, h(100)).unwrap().provisional_shards,
        0
    );
}

#[test]
fn a_script_never_read_reports_coverage_below_the_birthday() {
    // Reported rather than omitted: the caller uses this to decide whether the
    // balance is current, and a missing script must count as unread rather
    // than be skipped.
    let (mut db, id) = wallet();
    db.maintain_transparent_addresses(&params(), id, &GapLimits::default())
        .unwrap();

    let coverage = db.transparent_coverage(id, h(100)).unwrap();
    assert_eq!(coverage.len(), watched_addresses(&db).len());
    assert!(
        coverage
            .iter()
            .all(|c| c.covered_through == h(99) && c.settled_through == h(99)),
        "a script with no row starts one below the birthday"
    );
    let state = db.transparent_state(id, h(100)).unwrap();
    assert_eq!(state.completion, None, "no sync has run");
    assert_eq!(state.pending_pages, 0);
    // The account as a whole has no coverage, not coverage through block 99:
    // a height on screen reads as progress, and none has been made.
    assert_eq!(state.covered_through, None);
    assert_eq!(state.settled_through, None);

    // Once one script has been read, the account's coverage is the lowest of
    // its scripts, and the unread ones hold it below the birthday.
    let script = scripts(&db)[0].clone();
    registered(&mut db, id, &script, 100);
    db.commit_transparent_shard(&commit(0, "r0", true, (100, 199), vec![script]))
        .unwrap();
    let state = db.transparent_state(id, h(100)).unwrap();
    assert_eq!(state.covered_through, Some(h(99)));
}

#[test]
fn the_reason_a_sync_stopped_is_kept_beside_the_balance() {
    let (mut db, id) = wallet();
    db.put_transparent_completion("query-budget").unwrap();
    assert_eq!(
        db.transparent_state(id, h(100))
            .unwrap()
            .completion
            .as_deref(),
        Some("query-budget")
    );
    assert!(
        db.transparent_set().unwrap().is_none(),
        "recording a reason does not bind the store to a lineage"
    );
    db.put_transparent_completion("complete").unwrap();
    assert_eq!(
        db.transparent_completion().unwrap().as_deref(),
        Some("complete")
    );
}

#[test]
fn schema_three_is_rejected_without_erasing_wallet_data() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = dir.path().join("wallet.db");
    let cache = dir.path().join("cache.db");
    let mut db = WalletDb::open(&wallet, &cache).unwrap();
    db.set_meta_u32("layout_version", 3).unwrap();
    db.set_meta_u32("preserved_marker", 42).unwrap();
    drop(db);
    assert!(matches!(
        WalletDb::open(&wallet, &cache),
        Err(zakura_wallet_store::Error::VersionMismatch {
            found: 3,
            expected: 4,
            ..
        })
    ));
    let connection = rusqlite::Connection::open(&wallet).unwrap();
    let marker: u32 = connection
        .query_row(
            "SELECT value FROM wallet_meta WHERE key = 'preserved_marker'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(marker, 42);
    assert!(cache.exists());
}

// ---------------------------------------------------- append cost (M2)

/// SQLite's count of rows changed on this connection so far.
fn total_changes(db: &WalletDb) -> u64 {
    db.connection()
        .query_row("SELECT total_changes()", [], |r| r.get(0))
        .unwrap()
}

/// M0 measured `2N + 2` row changes for the checkpoint after N: every append
/// read the script's whole coverage, deleted it and wrote it back, so a long
/// recovery paid for its own progress twice over. An append is now one row
/// plus the commit record, whatever came before it.
#[test]
fn appending_a_checkpoint_writes_only_its_own_row() {
    for prior in [0u32, 10, 100, 1_000] {
        let (mut db, id) = wallet();
        let script = scripts(&db)[0].clone();
        registered(&mut db, id, &script, 100);
        for i in 0..prior {
            db.commit_transparent_shard(&commit(
                u64::from(i),
                "m2",
                true,
                (100 + i, 100 + i),
                vec![script.clone()],
            ))
            .unwrap();
        }

        let before = total_changes(&db);
        let started = std::time::Instant::now();
        db.commit_transparent_shard(&commit(
            u64::from(prior),
            "m2",
            true,
            (100 + prior, 100 + prior),
            vec![script.clone()],
        ))
        .unwrap();
        let elapsed = started.elapsed().as_nanos();
        let changes = total_changes(&db) - before;
        let rows = db.transparent_coverage_of(&script).unwrap();
        println!(
            "M2_COVERAGE {{\"prior_checkpoints\":{prior},\"sql_row_changes\":{changes},\"elapsed_ns\":{elapsed},\"coverage_rows\":{}}}",
            rows.len()
        );
        assert!(
            changes <= 3,
            "the append after {prior} checkpoints changed {changes} rows"
        );
        assert_eq!(rows.len(), prior as usize + 1);
        assert_eq!(rows.first().unwrap().start_height, h(100));
        assert_eq!(rows.last().unwrap().end_height, h(100 + prior));
        // Contiguous from the required height: nothing was lost on the way.
        let mine = db
            .transparent_coverage(id, h(100))
            .unwrap()
            .into_iter()
            .find(|c| c.script == script)
            .unwrap();
        assert_eq!(mine.covered_through, h(100 + prior));
    }
}

/// The three ways a start-keyed row can already exist, and what each costs.
#[test]
fn a_retry_writes_nothing_and_an_extension_replaces_one_row() {
    let (mut db, id) = wallet();
    let script = scripts(&db)[0].clone();
    registered(&mut db, id, &script, 100);
    for i in 0..50u32 {
        db.commit_transparent_shard(&commit(
            u64::from(i),
            "r",
            true,
            (100 + i * 10, 109 + i * 10),
            vec![script.clone()],
        ))
        .unwrap();
    }
    // The tail: an unsealed shard whose accepted prefix will grow.
    db.commit_transparent_shard(&commit(
        50,
        "tail-a",
        false,
        (600, 640),
        vec![script.clone()],
    ))
    .unwrap();
    let held = db.transparent_coverage_of(&script).unwrap();
    assert_eq!(held.len(), 51);

    // An identical retry: only the commit record is written.
    let before = total_changes(&db);
    db.commit_transparent_shard(&commit(
        50,
        "tail-a",
        false,
        (600, 640),
        vec![script.clone()],
    ))
    .unwrap();
    assert_eq!(total_changes(&db) - before, 1, "a retry rewrote coverage");
    assert_eq!(db.transparent_coverage_of(&script).unwrap(), held);

    // The same shard read to a later target: its row is replaced in place.
    let before = total_changes(&db);
    db.commit_transparent_shard(&commit(
        50,
        "tail-b",
        false,
        (600, 680),
        vec![script.clone()],
    ))
    .unwrap();
    assert_eq!(
        total_changes(&db) - before,
        2,
        "an extension rewrote coverage"
    );
    let now = db.transparent_coverage_of(&script).unwrap();
    assert_eq!(now.len(), 51);
    assert_eq!(
        now[..50],
        held[..50],
        "the fifty settled rows are untouched"
    );
    assert_eq!(now[50].end_height, h(680));
    assert_eq!(now[50].revision_digest, "tail-b");
    assert_eq!(
        db.transparent_coverage(id, h(100))
            .unwrap()
            .into_iter()
            .find(|c| c.script == script)
            .unwrap()
            .covered_through,
        h(680)
    );

    // A rollback inside the tail, then the re-read at the lower target:
    // still one row, and the accepted ancestor's hash is what it rests on.
    db.rollback_transparent_to(
        &TransparentAnchor {
            height: h(650),
            hash: format!("{:064x}", 650),
        },
        "reorg",
    )
    .unwrap();
    let rolled = db.transparent_coverage_of(&script).unwrap();
    assert_eq!(rolled[50].end_height, h(650));
    assert_eq!(rolled[50].terminal_block_hash, format!("{:064x}", 650));
    let before = total_changes(&db);
    db.commit_transparent_shard(&commit(
        50,
        "tail-c",
        false,
        (600, 650),
        vec![script.clone()],
    ))
    .unwrap();
    assert_eq!(total_changes(&db) - before, 2);
    assert_eq!(db.transparent_coverage_of(&script).unwrap().len(), 51);
}

// ---------------------------------------------------- layouts and messages

/// A wallet another build wrote is refused before this one writes to it.
/// Opening used to create the tables it was missing and switch it to WAL
/// first, and only then read the version: a wallet that was going to be
/// refused was altered on the way.
#[test]
fn an_unsupported_layout_is_refused_before_the_files_are_touched() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = dir.path().join("wallet.db");
    let cache = dir.path().join("cache.db");
    let mut db = WalletDb::open(&wallet, &cache).unwrap();
    db.set_meta_u32("layout_version", 3).unwrap();
    db.set_meta_u32("preserved_marker", 42).unwrap();
    drop(db);
    // Fold the write-ahead logs into the files so the bytes on disk are the
    // whole database, then remember them.
    {
        let conn = rusqlite::Connection::open(&wallet).unwrap();
        conn.execute("ATTACH DATABASE ?1 AS cache", [cache.to_string_lossy()])
            .unwrap();
        conn.execute_batch(
            "PRAGMA wal_checkpoint(TRUNCATE); PRAGMA cache.wal_checkpoint(TRUNCATE);",
        )
        .unwrap();
    }
    let wallet_before = std::fs::read(&wallet).unwrap();
    let cache_before = std::fs::read(&cache).unwrap();
    let wal_len = |base: &std::path::Path| {
        let mut name = base.as_os_str().to_owned();
        name.push("-wal");
        std::fs::metadata(name).map(|m| m.len()).unwrap_or(0)
    };
    assert_eq!(wal_len(&wallet), 0);
    assert_eq!(wal_len(&cache), 0);

    assert!(matches!(
        WalletDb::open(&wallet, &cache),
        Err(zakura_wallet_store::Error::VersionMismatch {
            found: 3,
            expected: 4,
            ..
        })
    ));
    assert!(matches!(
        WalletDb::preflight(&wallet),
        Err(zakura_wallet_store::Error::VersionMismatch { found: 3, .. })
    ));

    assert_eq!(
        std::fs::read(&wallet).unwrap(),
        wallet_before,
        "wallet.db changed"
    );
    assert_eq!(
        std::fs::read(&cache).unwrap(),
        cache_before,
        "cache.db changed"
    );
    assert_eq!(wal_len(&wallet), 0, "wallet.db-wal was written");
    assert_eq!(wal_len(&cache), 0, "cache.db-wal was written");
}

/// A wallet that does not exist yet, or has no versions yet, passes: there is
/// nothing to disagree with.
#[test]
fn a_new_wallet_passes_the_preflight() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = dir.path().join("wallet.db");
    WalletDb::preflight(&wallet).unwrap();
    let cache = dir.path().join("cache.db");
    let db = WalletDb::open(&wallet, &cache).unwrap();
    drop(db);
    WalletDb::preflight(&wallet).unwrap();
}

/// The message that refuses somebody else's output reaches logs and screens,
/// so the script — an address — must not be in it.
#[test]
fn a_refused_script_is_not_named_in_the_error() {
    let (mut db, id) = wallet();
    let script = scripts(&db)[0].clone();
    registered(&mut db, id, &script, 100);
    let foreign = vec![0x76, 0xa9, 0x14, 0xde, 0xad, 0xbe, 0xef, 0x88, 0xac];
    let commit = with_receive(
        commit(0, "r0", true, (100, 199), vec![script]),
        receive(&foreign, 1, 0, 1, 150),
    );
    let error = db
        .commit_transparent_shard(&commit)
        .unwrap_err()
        .to_string();
    assert!(error.contains("never derived"), "{error}");
    assert!(!error.contains("deadbeef"), "the script leaked: {error}");
    assert!(!error.contains("76a914"), "the script leaked: {error}");
}
