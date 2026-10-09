//! Failure injection: a full disk and aborted writes during every kind of ledger write, and a
//! crash before commit. Each failure leaves the prior state, and a retry reaches the state an
//! uninterrupted run reaches, checked against the oracle.

use std::{
    collections::BTreeSet,
    path::Path,
    sync::{Arc, Mutex},
};

use super::oracle::{
    Chain, assert_authority_agrees, assert_diagnostics_agree, external_at, promoted_oracle_wallet,
    recover, recovery_oracle_wallet, source,
};
use super::*;

/// One commit carrying everything the source holds for `account`'s current watch set.
fn whole_commit(
    st: &State,
    account: AccountUuid,
    chain: &Chain,
    revision: &RecoveryRevision,
) -> TransparentLedgerCommit<AccountUuid> {
    let ws = watch(st, account);
    let addresses: BTreeSet<_> = ws.addresses.iter().map(|w| w.address).collect();
    let (receives, spends) = source(chain, &addresses, ws.target.unwrap().height);
    let mut c = commit(&ws);
    c.revision = revision.clone();
    c.receives = receives;
    c.spends = spends;
    c.coverage = full_coverage(&ws);
    c
}

#[test]
fn a_full_disk_during_any_ledger_write_leaves_the_prior_state() {
    let (mut st, account, mut chain, owned, _) = recovery_oracle_wallet();
    let fixture = revision(1, true);
    // Enough outputs that recording them cannot fit in the pages the wallet already has.
    let b = st.test_account().unwrap().birthday().height();
    let e2 = external_at(&st, 2);
    let outputs: Vec<_> = (0..80).map(|n| (e2, 10_000 + n)).collect();
    chain.fund(b + 11, &outputs);

    // A candidate commit.
    let c = whole_commit(&st, account, &chain, &fixture);
    fill_disk(&st);
    let before = full_dump(conn(&st));
    assert_disk_full(apply(&mut st, c));
    assert_eq!(full_dump(conn(&st)), before);
    free_disk(&st);
    recover(&mut st, account, &chain, &fixture);
    assert_diagnostics_agree(&st, account, &chain, &owned);

    // Promotion.
    qualify(&mut st, &fixture);
    set_policy(&mut st, PrivateRequired);
    fill_disk(&st);
    let before = full_dump(conn(&st));
    assert_disk_full(promote(&mut st, account));
    assert_eq!(full_dump(conn(&st)), before);
    assert_eq!(lifecycle(&st, account), AccountLifecycle::Candidate);
    free_disk(&st);
    promote(&mut st, account).unwrap();
    let expected = assert_diagnostics_agree(&st, account, &chain, &owned);
    assert_authority_agrees(&st, account, &expected);

    // An active commit, projecting many outputs.
    scan_new_blocks(&mut st, 2);
    let tip = st.wallet().chain_height().unwrap().unwrap();
    let e31 = external_at(&st, 31);
    let outputs: Vec<_> = (0..40).map(|n| (e31, 10_000 + n)).collect();
    chain.fund(tip, &outputs);
    let c = whole_commit(&st, account, &chain, &fixture);
    fill_disk(&st);
    let before = full_dump(conn(&st));
    assert_disk_full(apply(&mut st, c));
    assert_eq!(full_dump(conn(&st)), before);
    free_disk(&st);
    recover(&mut st, account, &chain, &fixture);
    let expected = assert_diagnostics_agree(&st, account, &chain, &owned);
    assert_authority_agrees(&st, account, &expected);
    assert!(
        expected
            .receives
            .iter()
            .filter(|r| r.address == e31)
            .count()
            == 40
    );
}

#[test]
fn an_aborted_rewind_leaves_the_wallet_and_its_ledger_unchanged() {
    let (mut st, account, chain, owned, _) = promoted_oracle_wallet();
    let floor = st.test_account().unwrap().birthday().height() + 6;
    // The ledger's part of a rewind runs last, after the wallet's own truncation.
    conn(&st)
        .execute_batch(
            "CREATE TEMP TRIGGER fail_clip BEFORE UPDATE ON tpir_coverage
             BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        )
        .unwrap();
    let before = full_dump(conn(&st));
    assert!(matches!(
        st.wallet_mut().db_mut().truncate_to_height(floor),
        Err(SqliteClientError::DbError(_))
    ));
    assert_eq!(full_dump(conn(&st)), before);
    let expected = assert_diagnostics_agree(&st, account, &chain, &owned);
    assert_authority_agrees(&st, account, &expected);

    conn(&st).execute_batch("DROP TRIGGER fail_clip").unwrap();
    st.truncate_to_height(floor);
    assert_eq!(
        snapshot(&st, account).covered_through.map(|c| c.height),
        Some(floor)
    );
}

#[test]
fn an_aborted_demotion_keeps_private_authority() {
    let (mut st, account, chain, owned, _) = promoted_oracle_wallet();
    conn(&st)
        .execute_batch(
            "CREATE TEMP TRIGGER fail_demotion BEFORE DELETE ON tpir_active_accounts
             BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        )
        .unwrap();
    let before = full_dump(conn(&st));
    assert!(matches!(
        st.wallet_mut().db_mut().apply_transparent_policy(Public),
        Err(SqliteClientError::DbError(_))
    ));
    assert_eq!(full_dump(conn(&st)), before);
    let expected = assert_diagnostics_agree(&st, account, &chain, &owned);
    assert_authority_agrees(&st, account, &expected);

    conn(&st)
        .execute_batch("DROP TRIGGER fail_demotion")
        .unwrap();
    set_policy(&mut st, Public);
    assert_eq!(lifecycle(&st, account), AccountLifecycle::Candidate);
}

/// Copies the wallet at `path`, with its write-ahead log, as a crash would leave it on disk.
fn crash_copy(path: &Path) -> (tempfile::TempDir, Connection) {
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("wallet.db");
    std::fs::copy(path, &copy).unwrap();
    // SQLite names the log after the database path.
    let wal = std::path::PathBuf::from(format!("{}-wal", path.display()));
    if wal.exists() {
        std::fs::copy(&wal, dir.path().join("wallet.db-wal")).unwrap();
    }
    let conn = Connection::open(&copy).unwrap();
    (dir, conn)
}

#[test]
fn a_crash_before_commit_leaves_the_prior_state() {
    let (mut st, account, chain, owned, _) = recovery_oracle_wallet();
    let fixture = revision(1, true);
    recover(&mut st, account, &chain, &fixture);
    qualify(&mut st, &fixture);
    set_policy(&mut st, PrivateRequired);
    let mode: String = conn(&st)
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    let path = st.wallet().data_file_path().to_owned();
    let before = full_dump(conn(&st));

    // The process dies after promotion's writes, before its transaction commits.
    conn(&st).execute_batch("BEGIN IMMEDIATE").unwrap();
    promote(&mut st, account).unwrap();
    let (_dir, crashed) = crash_copy(&path);
    assert_eq!(full_dump(&crashed), before);

    // Once committed, a restart sees the promoted wallet.
    conn(&st).execute_batch("COMMIT").unwrap();
    let after = full_dump(conn(&st));
    assert_ne!(after, before);
    let (_dir, restarted) = crash_copy(&path);
    assert_eq!(full_dump(&restarted), after);
    let expected = assert_diagnostics_agree(&st, account, &chain, &owned);
    assert_authority_agrees(&st, account, &expected);
}

/// Copies the WAL immediately before the public operation commits its own transaction, and
/// again after it returns. The first copy must recover the prior state and the second the new
/// state. No production failpoint or externally held transaction is needed.
fn assert_recovery_at_commit(st: &mut State, operation: impl FnOnce(&mut State)) {
    let mode: String = conn(st)
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    let path = st.wallet().data_file_path().to_owned();
    let before = full_dump(conn(st));
    let copied = Arc::new(Mutex::new(None));
    let during_commit = Arc::clone(&copied);
    let uncommitted_path = path.clone();
    conn(st).commit_hook(Some(move || {
        let (_dir, crashed) = crash_copy(&uncommitted_path);
        *during_commit.lock().unwrap() = Some(full_dump(&crashed));
        false
    }));
    operation(st);
    conn(st).commit_hook(None::<fn() -> bool>);
    assert_eq!(copied.lock().unwrap().take(), Some(before.clone()));
    let after = full_dump(conn(st));
    assert_ne!(after, before);
    let (_dir, restarted) = crash_copy(&path);
    assert_eq!(full_dump(&restarted), after);
}

#[test]
fn rewind_and_demotion_recover_atomically_before_and_after_commit() {
    let (mut st, account, _, _, _) = promoted_oracle_wallet();
    let floor = st.test_account().unwrap().birthday().height() + 6;
    assert_recovery_at_commit(&mut st, |st| {
        st.wallet_mut().db_mut().truncate_to_height(floor).unwrap();
    });
    assert_eq!(
        snapshot(&st, account).covered_through.map(|c| c.height),
        Some(floor)
    );

    let (mut st, account, chain, owned, _) = promoted_oracle_wallet();
    // Start from the same pre-demotion state as an uninterrupted run.
    assert_authority_agrees(
        &st,
        account,
        &super::oracle::oracle(&chain, &owned, st.wallet().chain_height().unwrap().unwrap()),
    );
    assert_recovery_at_commit(&mut st, |st| set_policy(st, Public));
    assert_eq!(lifecycle(&st, account), AccountLifecycle::Candidate);
}

#[test]
fn candidate_and_active_commits_recover_atomically_before_and_after_commit() {
    let (mut st, account, chain, owned, _) = recovery_oracle_wallet();
    let fixture = revision(1, true);
    let c = whole_commit(&st, account, &chain, &fixture);
    assert_recovery_at_commit(&mut st, |st| {
        apply(st, c).unwrap();
    });
    recover(&mut st, account, &chain, &fixture);
    assert_diagnostics_agree(&st, account, &chain, &owned);

    let (mut st, account, mut chain, owned, fixture) = promoted_oracle_wallet();
    scan_new_blocks(&mut st, 2);
    let tip = st.wallet().chain_height().unwrap().unwrap();
    chain.fund(tip, &[(external_at(&st, 30), 10_000)]);
    let c = whole_commit(&st, account, &chain, &fixture);
    assert_recovery_at_commit(&mut st, |st| {
        apply(st, c).unwrap();
    });
    recover(&mut st, account, &chain, &fixture);
    let expected = assert_diagnostics_agree(&st, account, &chain, &owned);
    assert_authority_agrees(&st, account, &expected);
}
