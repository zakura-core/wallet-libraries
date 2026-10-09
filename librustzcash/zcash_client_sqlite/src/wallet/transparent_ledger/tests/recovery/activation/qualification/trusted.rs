//! Trusted commits: qualifying a revision and applying its commit in one transaction, under
//! `PrivateRequired`, without the test hook.

use zcash_client_backend::data_api::transparent_ledger::{
    TransactionMetadata, WholeTransactionFee,
};

use super::*;
use crate::wallet::transparent_ledger::REVISION_READER_VERSION;

fn trusted(
    st: &mut State,
    commit: TransparentLedgerCommit<AccountUuid>,
) -> Result<CommitOutcome, SqliteClientError> {
    st.wallet_mut()
        .db_mut()
        .qualify_and_apply_transparent_ledger_commit(commit)
}

/// Whether `revision` is stored and qualified.
fn is_qualified(st: &State, revision: &RecoveryRevision) -> bool {
    conn(st)
        .query_row(
            "SELECT EXISTS (
                 SELECT 1 FROM tpir_revisions r
                 JOIN tpir_qualified_revisions q ON q.revision_id = r.id
                 WHERE r.source = ?1 AND r.revision = ?2
             )",
            rusqlite::params![revision.source, revision.revision],
            |row| row.get(0),
        )
        .unwrap()
}

/// `revision`'s rows in each table that binds evidence to a revision: coverage, pending
/// pages, receive and spend observations, and transaction metadata.
fn rows_of(st: &State, revision: &RecoveryRevision) -> [i64; 5] {
    [
        "tpir_coverage",
        "tpir_pending_pages",
        "tpir_receive_observations",
        "tpir_spend_observations",
        "tpir_transaction_metadata",
    ]
    .map(|table| {
        conn(st)
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM {table} WHERE revision_id IN (
                         SELECT id FROM tpir_revisions WHERE source = ?1 AND revision = ?2
                     )"
                ),
                rusqlite::params![revision.source, revision.revision],
                |row| row.get(0),
            )
            .unwrap()
    })
}

/// The wallet's row id for the transparent output at `outpoint`.
fn output_id(st: &State, outpoint: &OutPoint) -> i64 {
    conn(st)
        .query_row(
            "SELECT o.id FROM transparent_received_outputs o
             JOIN transactions t ON t.id_tx = o.transaction_id
             WHERE t.txid = ?1 AND o.output_index = ?2",
            rusqlite::params![outpoint.hash(), outpoint.n()],
            |row| row.get(0),
        )
        .unwrap()
}

/// The sources an integrity rejection quarantined.
fn quarantined_sources(st: &State) -> Vec<Vec<u8>> {
    conn(st)
        .prepare("SELECT source FROM tpir_quarantined_sources")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// `dump` without the quarantine tables.
fn unquarantined(dump: Vec<(String, Vec<String>)>) -> Vec<(String, Vec<String>)> {
    dump.into_iter()
        .filter(|(table, _)| !table.starts_with("tpir_quarantined_"))
        .collect()
}

/// Trusted commits of `revision` covering every address `account` watches through the target,
/// with `receives` in the first, repeated until the window stops growing.
fn cover_trusted(
    st: &mut State,
    account: AccountUuid,
    revision: &RecoveryRevision,
    receives: Vec<ReceiveEvent>,
) {
    let mut receives = Some(receives);
    loop {
        let ws = watch(st, account);
        let mut c = commit(&ws);
        c.revision = revision.clone();
        c.receives = receives.take().unwrap_or_default();
        c.coverage = full_coverage(&ws);
        if !trusted(st, c).unwrap().window_grew {
            break;
        }
    }
}

/// A trusted commit of `revision` re-reporting `received`, covering every watched address.
fn trusted_commit(
    st: &State,
    account: AccountUuid,
    revision: &RecoveryRevision,
    received: &ReceiveEvent,
) -> TransparentLedgerCommit<AccountUuid> {
    let ws = watch(st, account);
    let mut c = commit(&ws);
    c.revision = revision.clone();
    c.receives = vec![received.clone()];
    c.coverage = full_coverage(&ws);
    c
}

/// A wallet under `PrivateRequired` whose account was recovered from trusted commits of the
/// provisional revision `revision(1, false)`, with one unspent receive, and promoted.
fn trusted_wallet() -> (State, AccountUuid, ReceiveEvent) {
    let (mut st, account) = recovery_wallet();
    let ws = watch(&st, account);
    let received = receive(1, external(&ws), 40_000, below_target(&ws, 3));
    cover_trusted(
        &mut st,
        account,
        &revision(1, false),
        vec![received.clone()],
    );
    promote(&mut st, account).unwrap();
    assert_eq!(
        snapshot(&st, account).authority,
        TransparentAuthority::Private
    );
    (st, account, received)
}

#[test]
fn a_trusted_commit_needs_private_required_on_the_handle_and_durably() {
    let (mut st, account) = recovery_wallet();
    for (handle, durable) in [
        (PrivateRequired, Public),
        (Public, PrivateRequired),
        (Public, Public),
    ] {
        let db = st.wallet_mut().db_mut();
        db.apply_transparent_policy(durable).unwrap();
        // The commit is current for the applied policy, so only the mode checks can refuse it.
        db.set_transparent_ledger_mode(PrivateRequired);
        let ws = watch(&st, account);
        let mut c = commit(&ws);
        c.revision = revision(1, false);
        c.receives = vec![receive(1, external(&ws), 40_000, below_target(&ws, 3))];
        c.coverage = full_coverage(&ws);
        st.wallet_mut().db_mut().set_transparent_ledger_mode(handle);

        let before = production_dump(conn(&st));
        let result = trusted(&mut st, c);
        // A weaker handle reads under a durable `PrivateRequired` policy, but never
        // qualifies under it.
        assert!(
            matches!(
                result,
                Err(SqliteClientError::TransparentRecoveryNotEnabled)
            ),
            "{handle:?} over {durable:?}: {result:?}"
        );
        assert_eq!(count(&st, "tpir_qualified_revisions"), 0);
        assert_eq!(count(&st, "tpir_revisions"), 0);
        assert_eq!(production_dump(conn(&st)), before);
    }

    // An ordinary commit observes the revision without trusting it; only a trusted commit
    // qualifies it.
    set_policy(&mut st, PrivateRequired);
    let fixture = revision(1, false);
    let ws = watch(&st, account);
    let received = receive(1, external(&ws), 40_000, below_target(&ws, 3));
    let c = trusted_commit(&st, account, &fixture, &received);
    apply(&mut st, c).unwrap();
    assert!(!is_qualified(&st, &fixture));
    let c = trusted_commit(&st, account, &fixture, &received);
    trusted(&mut st, c).unwrap();
    assert!(is_qualified(&st, &fixture));
}

#[test]
fn a_trusted_commit_qualifies_and_promotes_without_the_test_hook() {
    let (mut st, accounts) = recovery_wallet_with(0);
    let account = accounts[0];
    let fixture = revision(1, false);
    let received = recover_one(&mut st, account, fixture.clone(), 1);
    set_policy(&mut st, PrivateRequired);
    // Observed evidence alone cannot support promotion.
    assert!(blocked(promote(&mut st, account)).contains(&RecoveryBlocker::UnqualifiedRevision));
    assert!(!is_qualified(&st, &fixture));

    cover_trusted(&mut st, account, &fixture, vec![]);
    assert!(is_qualified(&st, &fixture));
    assert_eq!(count(&st, "tpir_qualified_revisions"), 1);
    assert_eq!(recovery(&st, account).blockers, vec![]);

    promote(&mut st, account).unwrap();
    assert_eq!(lifecycle(&st, account), AccountLifecycle::Active);
    let s = snapshot(&st, account);
    assert_eq!(s.authority, TransparentAuthority::Private);
    assert!(s.blockers.is_empty());
    assert_eq!(
        s.authorized.unwrap().regular.spendable_value(),
        received.value
    );
    assert_eq!(reader_version(&st), REVISION_READER_VERSION);
}

#[test]
fn trusted_replacement_withdraws_the_predecessor_in_the_same_transaction() {
    let (mut st, account) = recovery_wallet();
    let (r1, r2) = (revision(1, false), revision(2, false));
    let ws = watch(&st, account);
    // R1 also asserts transaction metadata, so that its withdrawal is observable.
    let shared = ReceiveEvent {
        metadata: Some(TransactionMetadata {
            fee: WholeTransactionFee::Unknown,
            transparent_input_count: 1,
            has_shielded_components: false,
        }),
        ..receive(1, external(&ws), 40_000, below_target(&ws, 3))
    };
    cover_trusted(&mut st, account, &r1, vec![shared.clone()]);
    promote(&mut st, account).unwrap();
    let output = output_id(&st, &shared.outpoint);
    let [coverage, pages, receives, spends, metadata] = rows_of(&st, &r1);
    assert!(coverage > 0 && receives > 0 && metadata > 0);
    assert_eq!((pages, spends), (0, 0));

    // R2 re-reports the shared receive without metadata; nothing qualified it beforehand.
    let c = trusted_commit(
        &st,
        account,
        &r2,
        &ReceiveEvent {
            metadata: None,
            ..shared.clone()
        },
    );
    assert_eq!(c.context.lifecycle, AccountLifecycle::Active);
    assert!(!trusted(&mut st, c).unwrap().window_grew);

    assert!(is_qualified(&st, &r2));
    assert_eq!(rows_of(&st, &r1), [0; 5]);
    assert_eq!(count(&st, "tpir_transaction_metadata"), 0);
    // The shared output was never removed from the wallet.
    assert_eq!(output_id(&st, &shared.outpoint), output);
    let s = snapshot(&st, account);
    assert_eq!(s.authority, TransparentAuthority::Private);
    assert_eq!(
        s.authorized.unwrap().regular.spendable_value(),
        shared.value
    );
}

#[test]
fn a_refused_trusted_commit_withdraws_nothing() {
    let (mut st, account, received) = trusted_wallet();
    let (r1, r2) = (revision(1, false), revision(2, false));
    let evidence = rows_of(&st, &r1);
    let before = full_dump(conn(&st));

    let unwatched = TransparentAddress::PublicKeyHash([0xee; 20]);
    let mut c = trusted_commit(&st, account, &r2, &received);
    c.coverage.push(AddressRange {
        address: unwatched,
        from: c.anchor.height,
        through: c.anchor.height,
    });
    assert_eq!(
        rejection(trusted(&mut st, c)),
        CommitRejection::Stale(StaleCommit::AddressNotWatched(unwatched))
    );

    assert!(!is_qualified(&st, &r2));
    assert_eq!(rows_of(&st, &r1), evidence);
    assert_eq!(full_dump(conn(&st)), before);
}

#[test]
fn a_trusted_commit_failing_after_qualification_rolls_back_the_replacement() {
    let (mut st, account, received) = trusted_wallet();
    let (r1, r2) = (revision(1, false), revision(2, false));
    let evidence = rows_of(&st, &r1);
    let before = full_dump(conn(&st));

    // Applying the facts fails after qualifying R2 has withdrawn R1's evidence.
    let mut c = trusted_commit(&st, account, &r2, &received);
    c.completed_pages = vec![b"unknown".to_vec()];
    assert_eq!(
        rejection(trusted(&mut st, c)),
        CommitRejection::Stale(StaleCommit::UnknownPage(b"unknown".to_vec()))
    );

    assert!(!is_qualified(&st, &r2));
    assert_eq!(rows_of(&st, &r1), evidence);
    assert_eq!(full_dump(conn(&st)), before);
    assert_eq!(
        snapshot(&st, account).authority,
        TransparentAuthority::Private
    );
}

#[test]
fn an_integrity_failure_in_a_trusted_commit_quarantines_without_qualifying() {
    let (mut st, account, received) = trusted_wallet();
    let (a, b) = (revision(1, false), revision(2, false));
    let evidence = rows_of(&st, &a);
    let before = unquarantined(full_dump(conn(&st)));

    // B contradicts itself only after qualifying it has withdrawn A's evidence.
    let ws = watch(&st, account);
    let placed = receive(9, external(&ws), 1_000, below_target(&ws, 1));
    let mut c = trusted_commit(&st, account, &b, &received);
    c.receives.push(placed.clone());
    c.receives.push(ReceiveEvent {
        mined_height: placed.mined_height - 1,
        ..placed.clone()
    });
    assert_eq!(
        rejection(trusted(&mut st, c)),
        CommitRejection::Integrity(IntegrityFailure::ReceivePlacement(placed.outpoint))
    );

    assert_eq!(quarantined_accounts(&st), vec![account]);
    assert_eq!(quarantined_sources(&st), vec![b.source.clone()]);
    assert!(!is_qualified(&st, &b));
    assert!(is_qualified(&st, &a));
    assert_eq!(rows_of(&st, &a), evidence);
    assert_eq!(unquarantined(full_dump(conn(&st))), before);
}

#[test]
fn a_colliding_trusted_revision_quarantines_without_qualifying() {
    let (mut st, account, received) = trusted_wallet();
    let r1 = revision(1, false);
    let evidence = rows_of(&st, &r1);
    let before = unquarantined(full_dump(conn(&st)));

    // A re-cut reusing R1's lineage under another identifier collides while being qualified,
    // before any of its facts apply.
    let recut = RecoveryRevision {
        revision: b"recut".to_vec(),
        ..r1.clone()
    };
    let c = trusted_commit(&st, account, &recut, &received);
    assert_eq!(
        rejection(trusted(&mut st, c)),
        CommitRejection::Integrity(IntegrityFailure::RevisionMismatch)
    );

    assert_eq!(quarantined_accounts(&st), vec![account]);
    assert_eq!(quarantined_sources(&st), vec![r1.source.clone()]);
    assert!(!is_qualified(&st, &recut));
    assert!(is_qualified(&st, &r1));
    assert_eq!(rows_of(&st, &r1), evidence);
    // The re-cut revision was not stored, and nothing but the quarantine changed.
    assert_eq!(unquarantined(full_dump(conn(&st))), before);
    assert_eq!(
        snapshot(&st, account).authority,
        TransparentAuthority::Unavailable
    );
}

#[test]
fn replaying_a_trusted_commit_is_idempotent() {
    let (mut st, account, received) = trusted_wallet();
    let c = trusted_commit(&st, account, &revision(1, false), &received);
    assert!(!trusted(&mut st, c.clone()).unwrap().window_grew);
    let production = production_dump(conn(&st));
    let before = full_dump(conn(&st));

    assert!(!trusted(&mut st, c).unwrap().window_grew);
    assert_eq!(production_dump(conn(&st)), production);
    assert_eq!(full_dump(conn(&st)), before);
}

#[test]
fn an_older_provisional_trusted_commit_is_stale() {
    let (mut st, account, received) = trusted_wallet();
    let c = trusted_commit(&st, account, &revision(2, false), &received);
    trusted(&mut st, c).unwrap();
    let before = full_dump(conn(&st));

    // Both the replaced revision and an older one never seen before.
    for older in [revision(1, false), revision(0, false)] {
        let c = trusted_commit(&st, account, &older, &received);
        assert_eq!(
            rejection(trusted(&mut st, c)),
            CommitRejection::Stale(StaleCommit::SupersededRevision)
        );
        assert_eq!(full_dump(conn(&st)), before);
    }
    assert!(!is_qualified(&st, &revision(0, false)));
}

#[test]
fn a_trusted_commit_from_before_a_policy_round_trip_is_stale() {
    let (mut st, account) = recovery_wallet();
    let ws = watch(&st, account);
    let received = receive(1, external(&ws), 40_000, below_target(&ws, 3));
    let c = trusted_commit(&st, account, &revision(1, false), &received);
    let captured = c.context.policy_generation;

    set_policy(&mut st, Public);
    set_policy(&mut st, PrivateRequired);
    let before = full_dump(conn(&st));
    assert!(matches!(
        trusted(&mut st, c),
        Err(SqliteClientError::StaleTransparentPolicy { expected, applied })
            if expected == captured && applied == captured + 2
    ));
    assert_eq!(count(&st, "tpir_qualified_revisions"), 0);
    assert_eq!(full_dump(conn(&st)), before);
}
