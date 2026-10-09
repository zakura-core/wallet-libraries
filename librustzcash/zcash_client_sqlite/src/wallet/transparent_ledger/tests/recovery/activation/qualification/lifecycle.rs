//! Chain and account lifecycle around recovered state: reorgs of sealed and provisional
//! coverage, deleting an active account, lowering a birthday, and a policy round trip.

use super::*;

/// Coverage of `part` of `ws` through its target, from `revision`.
fn cover_part(
    st: &mut State,
    ws: &TransparentWatchSet<AccountUuid>,
    part: &[zcash_client_backend::data_api::transparent_ledger::WatchedAddress],
    revision: &RecoveryRevision,
) -> Result<CommitOutcome, SqliteClientError> {
    let mut c = commit(ws);
    c.revision = revision.clone();
    c.coverage = part
        .iter()
        .map(|w| AddressRange {
            address: w.address,
            from: w.required_from,
            through: ws.target.unwrap().height,
        })
        .collect();
    apply(st, c)
}

#[test]
fn a_reorg_clips_sealed_and_provisional_coverage_alike() {
    let (mut st, account) = recovery_wallet();
    let sealed = source(b"sealed", 1);
    let provisional = |lineage| RecoveryRevision {
        sealed: false,
        ..source(b"provisional", lineage)
    };
    let ws = watch(&st, account);
    let target = ws.target.unwrap().height;
    let (first, second) = ws.addresses.split_at(ws.addresses.len() / 2);
    cover_part(&mut st, &ws, first, &sealed).unwrap();
    cover_part(&mut st, &ws, second, &provisional(1)).unwrap();
    assert_eq!(recovery(&st, account).covered_through, Some(target));

    // A reorg clips both revisions' coverage to the retained block: sealing is a publisher's
    // promise about its own revision, not about the local chain.
    let floor = target - 3;
    st.truncate_to_height(floor);
    assert_eq!(recovery(&st, account).covered_through, Some(floor));
    let clipped: Vec<(u32, u32)> = conn(&st)
        .prepare("SELECT through_height, anchor_height FROM tpir_coverage")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(!clipped.is_empty());
    assert!(
        clipped
            .iter()
            .all(|(through, anchor)| *through == u32::from(floor) && *anchor == u32::from(floor))
    );
    // Work anchored on the replaced chain is stale.
    assert_eq!(
        rejected(&mut st, {
            let mut c = commit(&ws);
            c.coverage = full_coverage(&ws);
            c
        }),
        CommitRejection::Stale(StaleCommit::TargetNotAccepted)
    );

    // On the new chain, the sealed revision covers again, and the provisional source's next
    // revision supersedes the old one, whose remaining coverage goes with it.
    scan_new_blocks(&mut st, 5);
    let ws = watch(&st, account);
    let (first, second) = ws.addresses.split_at(ws.addresses.len() / 2);
    cover_part(&mut st, &ws, first, &sealed).unwrap();
    qualify(&mut st, &provisional(2));
    cover_part(&mut st, &ws, second, &provisional(2)).unwrap();
    let r = recovery(&st, account);
    assert_eq!(r.covered_through, Some(ws.target.unwrap().height));
    assert_eq!(r.blockers, vec![]);
    let superseded: i64 = conn(&st)
        .query_row(
            "SELECT COUNT(*) FROM tpir_coverage c JOIN tpir_revisions r ON r.id = c.revision_id
             WHERE r.source = ?1 AND r.lineage = 1",
            [b"provisional".as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(superseded, 0);
}

#[test]
fn deleting_an_active_account_keeps_the_other_accounts_ledger() {
    let (mut st, accounts) = recovery_wallet_with(1);
    let [kept, deleted] = accounts[..] else {
        unreachable!()
    };
    let fixture = revision(1, true);
    // One transaction pays both accounts.
    let (wk, wd) = (watch(&st, kept), watch(&st, deleted));
    let txid = [0x51; 32];
    let to_kept = ReceiveEvent {
        outpoint: OutPoint::new(txid, 0),
        ..receive(0, external(&wk), 30_000, below_target(&wk, 2))
    };
    let to_deleted = ReceiveEvent {
        outpoint: OutPoint::new(txid, 1),
        ..receive(0, external(&wd), 20_000, below_target(&wd, 2))
    };
    cover(&mut st, kept, &fixture, vec![to_kept.clone()]);
    cover(&mut st, deleted, &fixture, vec![to_deleted]);
    qualify(&mut st, &fixture);
    set_policy(&mut st, PrivateRequired);
    promote(&mut st, kept).unwrap();
    promote(&mut st, deleted).unwrap();

    let stale = watch(&st, deleted);
    let deleted_ref: i64 = conn(&st)
        .query_row(
            "SELECT id FROM accounts WHERE uuid = ?1",
            [deleted.0],
            |row| row.get(0),
        )
        .unwrap();
    st.wallet_mut().delete_account(deleted).unwrap();

    // Its ledger state is gone, and work captured for it is stale.
    for table in [
        "tpir_active_accounts",
        "tpir_candidate_windows",
        "tpir_coverage",
        "tpir_pending_pages",
        "tpir_receive_events",
        "tpir_spend_events",
    ] {
        let rows: i64 = conn(&st)
            .query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE account_id = ?1"),
                [deleted_ref],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 0, "{table} keeps the deleted account's rows");
    }
    let mut c = commit(&stale);
    c.coverage = full_coverage(&stale);
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Stale(StaleCommit::AccountUnknown)
    );

    // The other account keeps the shared transaction and its authority.
    assert_eq!(
        st.wallet().get_tx_height(TxId::from_bytes(txid)).unwrap(),
        Some(to_kept.mined_height)
    );
    let s = snapshot(&st, kept);
    assert_eq!(s.authority, TransparentAuthority::Private);
    assert_eq!(
        s.authorized.unwrap().regular.total(),
        Zatoshis::const_from_u64(30_000)
    );
    assert_eq!(
        super::super::super::super::records_without_origin(conn(&st)),
        0
    );
}

#[test]
fn lowering_an_active_accounts_birthday_pauses_authority_until_covered() {
    let (mut st, account) = recovery_wallet();
    let birthday = st.test_account().unwrap().birthday().height();
    let set_birthday = |st: &State, height: BlockHeight| {
        conn(st)
            .execute(
                "UPDATE accounts SET birthday_height = ?1 WHERE uuid = ?2",
                rusqlite::params![u32::from(height), account.0],
            )
            .unwrap();
    };
    // An account born three blocks into the scanned chain.
    set_birthday(&st, birthday + 3);
    let fixture = revision(1, true);
    let ws = watch(&st, account);
    assert!(ws.addresses.iter().all(|w| w.required_from == birthday + 3));
    let late = receive(1, external(&ws), 40_000, below_target(&ws, 1));
    cover(&mut st, account, &fixture, vec![late]);
    qualify(&mut st, &fixture);
    set_policy(&mut st, PrivateRequired);
    promote(&mut st, account).unwrap();
    assert_eq!(
        snapshot(&st, account).authority,
        TransparentAuthority::Private
    );

    // Its birthday is lowered, as a restore with an earlier birthday or a rewind that resets
    // it does. Coverage from the old birthday no longer suffices.
    set_birthday(&st, birthday);
    let s = snapshot(&st, account);
    assert_eq!(s.authority, TransparentAuthority::Unavailable);
    assert_eq!(
        s.blockers,
        vec![RecoveryBlocker::Recovery(
            CandidateBlocker::IncompleteCoverage
        )]
    );
    assert_eq!(s.last_known.unwrap().source, LastKnownSource::PrivateLedger);

    // Recovery from the new birthday finds an earlier payment and restores authority.
    let ws = watch(&st, account);
    let early = receive(2, external(&ws), 5_000, birthday + 1);
    cover(&mut st, account, &fixture, vec![early]);
    let s = snapshot(&st, account);
    assert_eq!(s.authority, TransparentAuthority::Private);
    assert_eq!(
        s.authorized.unwrap().regular.total(),
        Zatoshis::const_from_u64(45_000)
    );
}

#[test]
fn a_commit_captured_before_a_policy_round_trip_is_stale() {
    let (mut st, account, _) = active_wallet();
    let ws = watch(&st, account);
    assert_eq!(ws.lifecycle, AccountLifecycle::Active);

    set_policy(&mut st, Public);
    set_policy(&mut st, PrivateRequired);
    let mut c = commit(&ws);
    c.coverage = full_coverage(&ws);
    assert!(matches!(
        apply(&mut st, c),
        Err(SqliteClientError::StaleTransparentPolicy { .. })
    ));

    // The round trip demoted the account. A fresh run recovers it as a candidate, and it must
    // be promoted again before it holds authority.
    assert_eq!(lifecycle(&st, account), AccountLifecycle::Candidate);
    cover(&mut st, account, &revision(1, true), vec![]);
    let s = snapshot(&st, account);
    assert_eq!(s.authority, TransparentAuthority::Unavailable);
    assert_eq!(s.blockers, vec![RecoveryBlocker::NotActivated]);
    promote(&mut st, account).unwrap();
    assert_eq!(
        snapshot(&st, account).authority,
        TransparentAuthority::Private
    );
}
