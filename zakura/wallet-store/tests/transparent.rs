//! Deriving transparent addresses, and committing a private ledger.
//!
//! The ledger is the only thing that discovers transparent funds — see
//! `docs/zakura_transparent_pir.md` — so everything it gets wrong is invisible
//! rather than merely late. The cases below are the ones where a plausible
//! implementation is silently wrong: an output at a script the wallet never
//! derived, a spend of an output the run never saw, and coverage that advances
//! past what was actually read.

use zakura_wallet_core::AccountId;
use zakura_wallet_store::{
    GapLimits, ProvisionalRevision, RecoveredOutput, RecoveredSpend, ScriptCoverage,
    TransparentLedger, UnresolvedSpend, WalletDb, testing::test_db,
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
    let encoded: std::collections::BTreeSet<_> =
        addresses.iter().map(|(_, a)| a.clone()).collect();
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

/// The script of the account's first watched address, with its row id.
fn first_script(db: &WalletDb) -> (i64, Vec<u8>) {
    db.connection()
        .query_row(
            "SELECT id, transparent_script FROM cache.addresses
             WHERE transparent_script IS NOT NULL
             ORDER BY key_scope, transparent_child_index LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
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

fn covering(script: &[u8], account: AccountId, settled: u32, covered: u32) -> ScriptCoverage {
    ScriptCoverage {
        script: script.to_vec(),
        account,
        settled_through: h(settled),
        covered_through: h(covered),
    }
}

#[test]
fn a_recovered_output_becomes_a_balance_and_a_coverage() {
    let (mut db, id) = wallet();
    let (_, script) = first_script(&db);

    db.apply_transparent_ledger(&TransparentLedger {
        outputs: vec![RecoveredOutput {
            txid: txid(1),
            output_index: 0,
            script: script.clone(),
            value: 250_000,
            mined_height: Some(h(500)),
            observed_at: h(500),
            coinbase: Some(false),
        }],
        coverage: vec![covering(&script, id, 900, 900)],
        ..Default::default()
    })
    .expect("the ledger applies");

    let balance = db.transparent_balance(id).unwrap();
    assert_eq!(balance.total().into_u64(), 250_000);
    assert_eq!(
        balance.spendable.into_u64(),
        250_000,
        "a recovered event states coinbase-ness exactly, so maturity is decidable"
    );

    let state = db.transparent_state(id, h(100)).unwrap();
    assert_eq!(state.covered_through, Some(h(100 - 1)), "one script covered, the rest not");
    assert_eq!(state.unresolved_spends, 0);
}

#[test]
fn a_recovered_spend_removes_the_output_it_consumed() {
    let (mut db, id) = wallet();
    let (_, script) = first_script(&db);

    db.apply_transparent_ledger(&TransparentLedger {
        outputs: vec![RecoveredOutput {
            txid: txid(1),
            output_index: 0,
            script: script.clone(),
            value: 250_000,
            mined_height: Some(h(500)),
            observed_at: h(500),
            coinbase: Some(false),
        }],
        spends: vec![RecoveredSpend {
            spending_txid: txid(2),
            height: h(600),
            spent_txid: txid(1),
            spent_output_index: 0,
        }],
        coverage: vec![covering(&script, id, 900, 900)],
        ..Default::default()
    })
    .unwrap();

    assert_eq!(count(&db, "transparent_received_output_spends"), 1);
    assert_eq!(
        db.transparent_balance(id).unwrap().total().into_u64(),
        0,
        "the output is spent, so it is not in the balance"
    );
}

#[test]
fn an_output_the_run_only_saw_spent_is_stored_without_a_height_it_does_not_know() {
    // A confirmed spend carries the value and script of what it consumed and
    // not the height that output was created at. Writing the spend's own
    // height there would put a wrong number into the history that nothing
    // could later contradict.
    let (mut db, id) = wallet();
    let (_, script) = first_script(&db);

    db.apply_transparent_ledger(&TransparentLedger {
        outputs: vec![RecoveredOutput {
            txid: txid(1),
            output_index: 0,
            script: script.clone(),
            value: 250_000,
            mined_height: None,
            observed_at: h(600),
            coinbase: None,
        }],
        spends: vec![RecoveredSpend {
            spending_txid: txid(2),
            height: h(600),
            spent_txid: txid(1),
            spent_output_index: 0,
        }],
        coverage: vec![covering(&script, id, 900, 900)],
        ..Default::default()
    })
    .unwrap();

    let mined: Option<u32> = db
        .connection()
        .query_row(
            "SELECT mined_height FROM cache.transactions WHERE txid = ?1",
            [&[1u8; 32][..]],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(mined, None, "the creating height is unknown, and stays unknown");
    assert_eq!(
        count(&db, "transparent_received_output_spends"),
        1,
        "but the spend still attaches, which is the reason to store the row at all"
    );
}

#[test]
fn an_output_at_a_script_the_wallet_never_derived_is_refused() {
    // Not something to absorb quietly: the service answered about somebody
    // else, and storing it would credit another person's funds to this wallet.
    let (mut db, id) = wallet();
    let (_, script) = first_script(&db);

    let err = db
        .apply_transparent_ledger(&TransparentLedger {
            outputs: vec![RecoveredOutput {
                txid: txid(9),
                output_index: 0,
                script: vec![0x76, 0xa9, 0x14, 0xff],
                value: 100_000,
                mined_height: Some(h(500)),
                observed_at: h(500),
                coinbase: Some(false),
            }],
            coverage: vec![covering(&script, id, 900, 900)],
            ..Default::default()
        })
        .expect_err("an unknown script must be refused");
    assert!(
        format!("{err}").contains("never derived"),
        "the error should say why it was refused, got: {err}"
    );
}

#[test]
fn an_unresolved_spend_is_recorded_rather_than_absorbed() {
    // Absorbing one leaves an output in the balance that something has already
    // consumed: too high, and looking entirely ordinary.
    let (mut db, id) = wallet();
    let (_, script) = first_script(&db);

    db.apply_transparent_ledger(&TransparentLedger {
        unresolved: vec![UnresolvedSpend {
            spending_txid: txid(4),
            input_index: 1,
            spent_txid: txid(3),
            spent_output_index: 0,
            height: h(700),
            script: script.clone(),
        }],
        coverage: vec![covering(&script, id, 900, 900)],
        ..Default::default()
    })
    .unwrap();

    assert_eq!(db.transparent_state(id, h(100)).unwrap().unresolved_spends, 1);

    // A later run that resolved it must clear it: these three sets describe the
    // state a run *ended* in, not everything ever seen.
    db.apply_transparent_ledger(&TransparentLedger {
        coverage: vec![covering(&script, id, 950, 950)],
        ..Default::default()
    })
    .unwrap();
    assert_eq!(db.transparent_state(id, h(100)).unwrap().unresolved_spends, 0);
}

#[test]
fn coverage_never_moves_backwards() {
    // A run that read a shorter range has not un-read the longer one. Coverage
    // that could retreat would let a transient failure quietly re-open a range
    // the wallet already paid private queries to close.
    let (mut db, id) = wallet();
    let (_, script) = first_script(&db);

    db.apply_transparent_ledger(&TransparentLedger {
        coverage: vec![covering(&script, id, 900, 950)],
        ..Default::default()
    })
    .unwrap();
    db.apply_transparent_ledger(&TransparentLedger {
        coverage: vec![covering(&script, id, 500, 500)],
        ..Default::default()
    })
    .unwrap();

    let coverage = db.transparent_coverage(id, h(100)).unwrap();
    let mine = coverage
        .iter()
        .find(|c| c.script == script)
        .expect("the script has a coverage row");
    assert_eq!(mine.settled_through, h(900));
    assert_eq!(mine.covered_through, h(950));
}

#[test]
fn a_script_never_read_reports_coverage_below_the_birthday() {
    // Reported rather than omitted: the caller uses this to decide where to
    // start reading, and a missing script must start from the beginning rather
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
}

#[test]
fn provisional_coverage_is_replaced_by_the_run_that_supersedes_it() {
    // A revision replaces its predecessor rather than extending it, so the
    // rows describing which revisions the current coverage rests on cannot
    // accumulate.
    let (mut db, id) = wallet();
    let (_, script) = first_script(&db);

    db.apply_transparent_ledger(&TransparentLedger {
        coverage: vec![covering(&script, id, 900, 950)],
        provisional: vec![ProvisionalRevision {
            shard_id: 7,
            revision: 1,
            manifest_digest: "abc".into(),
            end_height: h(950),
        }],
        ..Default::default()
    })
    .unwrap();
    assert_eq!(
        db.transparent_state(id, h(100)).unwrap().provisional_shards,
        1
    );

    db.apply_transparent_ledger(&TransparentLedger {
        coverage: vec![covering(&script, id, 960, 960)],
        ..Default::default()
    })
    .unwrap();
    assert_eq!(
        db.transparent_state(id, h(100)).unwrap().provisional_shards,
        0,
        "coverage that is now settled rests on no revision"
    );
}
