use super::*;

#[test]
fn candidate_observations_cannot_revoke_another_accounts_financial_evidence() {
    for with_facts in [false, true] {
        let (mut st, active, candidate, _) = active_and_candidate();
        let before = production_dump(conn(&st));
        let authority = snapshot(&st, active);
        let evidence = recovery(&st, active);
        let ws = watch(&st, candidate);
        let mut c = commit(&ws);
        c.revision = revision(2, false);
        if with_facts {
            c.receives = vec![receive(52, external(&ws), 60_000, below_target(&ws, 0))];
            c.coverage = full_coverage(&ws);
        }
        apply(&mut st, c).unwrap();
        assert_eq!(production_dump(conn(&st)), before);
        assert_eq!(snapshot(&st, active), authority);
        assert_eq!(recovery(&st, active), evidence);
        assert_eq!(reader_version(&st), 6);
        // Observing lineage 2 does not make the qualified lineage 1 stale.
        let mut c = commit(&watch(&st, active));
        c.revision = revision(1, false);
        apply(&mut st, c).unwrap();
        let reopened = crate::WalletDb::for_path(
            st.wallet().data_file_path(),
            *st.network(),
            crate::testing::db::test_clock(),
            crate::testing::db::test_rng(),
        )
        .unwrap()
        .with_transparent_ledger_mode(PrivateRequired);
        assert_eq!(production_dump(&reopened.conn), before);
        assert_eq!(
            reopened
                .transparent_ledger_snapshot(active, ConfirmationsPolicy::MIN)
                .unwrap(),
            authority
        );
    }
}

#[test]
fn only_a_trusted_transition_withdraws_projection_and_is_idempotent() {
    let (mut st, active, candidate, received) = active_and_candidate();
    let mut c = commit(&watch(&st, candidate));
    c.revision = revision(2, false);
    apply(&mut st, c).unwrap();
    assert_eq!(
        snapshot(&st, active).authority,
        TransparentAuthority::Private
    );
    qualify(&mut st, &revision(2, false));
    assert_eq!(
        snapshot(&st, active).authority,
        TransparentAuthority::Unavailable
    );
    assert!(recovery(&st, active).receives.is_empty());
    // Retained rows preserve historical provenance; evidence no longer authorizes the receive.
    assert_eq!(
        crate::wallet::transparent_ledger::tests::output_origins(conn(&st), &received.outpoint),
        vec![2]
    );
    let before = production_dump(conn(&st));
    let evidence = recovery(&st, active);
    qualify(&mut st, &revision(2, false));
    assert_eq!(production_dump(conn(&st)), before);
    assert_eq!(recovery(&st, active), evidence);
    let mut stale = commit(&watch(&st, candidate));
    stale.revision = revision(1, false);
    assert_eq!(
        rejection(apply(&mut st, stale)),
        CommitRejection::Stale(StaleCommit::SupersededRevision)
    );
}

#[test]
fn a_failed_trusted_replacement_rolls_back_qualification_and_all_accounts() {
    let (mut st, active, candidate, _) = active_and_candidate();
    let before = production_dump(conn(&st));
    let evidence = recovery(&st, active);
    let revisions = count(&st, "tpir_revisions");
    let qualified = count(&st, "tpir_qualified_revisions");
    conn(&st).execute_batch("CREATE TEMP TRIGGER fail_replacement BEFORE DELETE ON tpir_coverage BEGIN SELECT RAISE(ABORT, 'injected replacement failure'); END;").unwrap();
    assert!(
        st.wallet_mut()
            .db_mut()
            .qualify_transparent_revision(&revision(2, false))
            .is_err()
    );
    assert_eq!(production_dump(conn(&st)), before);
    assert_eq!(recovery(&st, active), evidence);
    assert_eq!(count(&st, "tpir_revisions"), revisions);
    assert_eq!(count(&st, "tpir_qualified_revisions"), qualified);
    assert_eq!(watch(&st, candidate).lifecycle, AccountLifecycle::Candidate);
}

#[test]
fn observed_higher_lineage_does_not_prevent_qualifying_an_older_observation() {
    let (mut st, account) = recovery_wallet();
    let mut c = commit(&watch(&st, account));
    c.revision = revision(2, false);
    apply(&mut st, c).unwrap();
    qualify(&mut st, &revision(1, false));
    let mut c = commit(&watch(&st, account));
    c.revision = revision(1, false);
    apply(&mut st, c).unwrap();
    assert_eq!(count(&st, "tpir_qualified_revisions"), 1);
}

#[test]
fn supported_coverage_combines_across_sources_and_stays_account_scoped() {
    let (mut st, accounts) = recovery_wallet_with(1);
    let ws = watch(&st, accounts[0]);
    let middle = ws.addresses[0].required_from + 3;
    let mut c = commit(&ws);
    c.coverage = full_coverage(&ws)
        .into_iter()
        .map(|mut r| {
            r.through = middle;
            r
        })
        .collect();
    apply(&mut st, c).unwrap();
    assert!(
        recovery(&st, accounts[0])
            .blockers
            .contains(&CandidateBlocker::IncompleteCoverage)
    );
    let mut c = commit(&ws);
    c.revision.source = b"second-source".to_vec();
    c.coverage = full_coverage(&ws)
        .into_iter()
        .map(|mut r| {
            r.from = middle + 1;
            r
        })
        .collect();
    apply(&mut st, c).unwrap();
    // Neither source covers the interval alone; together they do, for this account only.
    let r = recovery(&st, accounts[0]);
    assert_eq!(r.blockers, vec![]);
    assert_eq!(r.covered_through, ws.target.map(|t| t.height));
    assert!(
        recovery(&st, accounts[1])
            .blockers
            .contains(&CandidateBlocker::IncompleteCoverage)
    );
}
