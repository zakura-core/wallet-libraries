use super::*;

#[test]
fn wallet_summary_composes_with_private_authority_in_one_transaction() {
    let (mut st, account, _, _) = ready_wallet();
    promote(&mut st, account).unwrap();
    let expected = snapshot(&st, account);
    st.wallet_mut()
        .db_mut()
        .transactionally::<_, _, SqliteClientError>(|db| {
            let summary = db.get_wallet_summary(ConfirmationsPolicy::MIN)?.unwrap();
            assert_eq!(
                summary.account_balances()[&account]
                    .unshielded_regular_balance()
                    .total(),
                Zatoshis::ZERO
            );
            assert_eq!(
                db.transparent_ledger_snapshot(account, ConfirmationsPolicy::MIN)?,
                expected
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn wallet_summary_and_authority_share_a_snapshot_across_a_wal_writer() {
    let (mut st, active, candidate, _) = active_and_candidate();
    conn(&st).execute_batch("PRAGMA journal_mode=WAL;").unwrap();
    let mut writer = crate::WalletDb::for_path(
        st.wallet().data_file_path(),
        *st.network(),
        crate::testing::db::test_clock(),
        crate::testing::db::test_rng(),
    )
    .unwrap()
    .with_transparent_ledger_mode(PrivateRequired);
    let expected = snapshot(&st, active);
    st.wallet_mut()
        .db_mut()
        .transactionally::<_, _, SqliteClientError>(|reader| {
            reader.get_wallet_summary(ConfirmationsPolicy::MIN)?;
            // This trusted transition withdraws active evidence on the other connection.
            writer.qualify_transparent_revision(&revision(2, false))?;
            assert_eq!(
                reader.transparent_ledger_snapshot(active, ConfirmationsPolicy::MIN)?,
                expected
            );
            reader.get_wallet_summary(ConfirmationsPolicy::MIN)?;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        snapshot(&st, active).authority,
        TransparentAuthority::Unavailable
    );
    assert_eq!(watch(&st, candidate).lifecycle, AccountLifecycle::Candidate);
}

#[test]
fn per_account_balances_do_not_read_another_accounts_invalid_amounts() {
    let (mut st, accounts) = recovery_wallet_with(1);
    let rev = revision(1, true);
    qualify(&mut st, &rev);
    for (i, account) in accounts.iter().enumerate() {
        recover_completely(&mut st, *account, &rev, 81 + i as u8);
    }
    set_policy(&mut st, PrivateRequired);
    for account in &accounts {
        promote(&mut st, *account).unwrap();
    }
    let expected = snapshot(&st, accounts[0]);
    // Corruption in B proves A's read actually scopes its SQL, rather than computing
    // every account and selecting A afterward. Shared financial rules still reject B.
    conn(&st).execute("UPDATE transparent_received_outputs SET value_zat = ?1 WHERE account_id = (SELECT id FROM accounts WHERE uuid = ?2)", rusqlite::params![i64::MAX, accounts[1].0]).unwrap();
    assert_eq!(snapshot(&st, accounts[0]), expected);
    assert!(
        st.wallet()
            .db()
            .transparent_ledger_snapshot(accounts[1], ConfirmationsPolicy::MIN)
            .is_err()
    );
}

#[test]
fn empty_interval_promotion_grants_no_funds_and_missing_coverage_revokes_authority() {
    let (mut st, account) = recovery_wallet();
    let target = watch(&st, account).target.unwrap();
    conn(&st)
        .execute(
            "UPDATE accounts SET birthday_height = ?1 WHERE uuid = ?2",
            rusqlite::params![u32::from(target.height + 1), account.0],
        )
        .unwrap();
    set_policy(&mut st, PrivateRequired);
    assert_eq!(count(&st, "tpir_qualified_revisions"), 0);
    promote(&mut st, account).unwrap();
    assert_eq!(
        snapshot(&st, account).authority,
        TransparentAuthority::Private
    );
    assert_eq!(
        snapshot(&st, account).authorized.unwrap().regular.total(),
        Zatoshis::ZERO
    );
    assert_eq!(recovery(&st, account).blockers, vec![]);
    // The next block enters the required interval, and nothing covers it yet.
    scan_new_blocks(&mut st, 1);
    assert_eq!(
        snapshot(&st, account).authority,
        TransparentAuthority::Unavailable
    );
    assert!(
        recovery(&st, account)
            .blockers
            .contains(&CandidateBlocker::IncompleteCoverage)
    );
}
