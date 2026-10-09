use super::*;
use transparent::keys::NonHardenedChildIndex;
use zcash_keys::address::Address;

fn future_receiver(
    st: &State,
    account: AccountUuid,
) -> (
    TransparentAddress,
    NonHardenedChildIndex,
    secp256k1::PublicKey,
    TransparentAddress,
) {
    let ws = watch(st, account);
    let (edge, index) = ws
        .addresses
        .iter()
        .filter_map(|w| match w.origin {
            WatchOrigin::Derived { scope, index } if scope == TransparentKeyScope::EXTERNAL => {
                Some((w.address, index))
            }
            _ => None,
        })
        .max_by_key(|(_, i)| *i)
        .unwrap();
    let next = NonHardenedChildIndex::from_index(index.index() + 1).unwrap();
    let ufvk = st
        .test_account()
        .unwrap()
        .usk()
        .to_unified_full_viewing_key();
    let key = ufvk
        .transparent()
        .unwrap()
        .derive_address_pubkey(TransparentKeyScope::EXTERNAL, next)
        .unwrap();
    (TransparentAddress::from_pubkey(&key), next, key, edge)
}
fn grow(st: &mut State, account: AccountUuid, edge: TransparentAddress) {
    let ws = watch(st, account);
    let mut c = commit(&ws);
    c.receives = vec![receive(211, edge, 1_000, below_target(&ws, 2))];
    c.coverage = full_coverage(&ws);
    assert!(apply(st, c).unwrap().window_grew);
}
fn import(st: &mut State, owner: AccountUuid, key: secp256k1::PublicKey) {
    st.wallet_mut()
        .db_mut()
        .import_standalone_transparent_pubkey(owner, key)
        .unwrap();
}

#[test]
fn shared_activity_after_promotion_extends_discovery_across_reopen() {
    let (mut st, accounts) = recovery_wallet_with(1);
    let (a, b) = (accounts[0], accounts[1]);
    let gap = st.wallet().db().gap_limits.external();
    let high = 5 * gap;
    let shared_index = high + gap / 2;
    let ufvk = st
        .test_account()
        .unwrap()
        .usk()
        .to_unified_full_viewing_key();
    let derive_key = |index| {
        ufvk.transparent()
            .unwrap()
            .derive_address_pubkey(
                TransparentKeyScope::EXTERNAL,
                NonHardenedChildIndex::from_index(index).unwrap(),
            )
            .unwrap()
    };
    let address = |index| TransparentAddress::from_pubkey(&derive_key(index));
    let shared = address(shared_index);
    // A has allocated a distant address, but the first unused gap remains after index zero.
    crate::wallet::transparent::generate_address_range(
        conn(&st),
        st.network(),
        st.test_account().unwrap().account().internal_id(),
        TransparentKeyScope::EXTERNAL,
        zcash_keys::keys::UnifiedAddressRequest::unsafe_custom(
            zcash_keys::keys::ReceiverRequirement::Allow,
            zcash_keys::keys::ReceiverRequirement::Allow,
            zcash_keys::keys::ReceiverRequirement::Require,
        ),
        NonHardenedChildIndex::ZERO..NonHardenedChildIndex::from_index(high + 1).unwrap(),
        true,
    )
    .unwrap();
    import(&mut st, b, derive_key(shared_index));
    let ws = watch(&st, a);
    let mut c = commit(&ws);
    c.receives = vec![
        receive(220, address(0), 1_000, below_target(&ws, 2)),
        receive(221, address(high), 1_000, below_target(&ws, 1)),
    ];
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    let ws = watch(&st, a);
    let mut c = commit(&ws);
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    qualify(&mut st, &revision(1, true));
    set_policy(&mut st, PrivateRequired);
    promote(&mut st, a).unwrap();
    assert_eq!(reader_version(&st), 8);
    assert_eq!(snapshot(&st, a).authority, TransparentAuthority::Private);
    assert!(!watch(&st, a).addresses.iter().any(|w| w.address == shared));
    assert!(watch(&st, b).addresses.iter().any(|w| w.address == shared));
    let before = watch(&st, a);
    let ws = watch(&st, b);
    let mut c = commit(&ws);
    c.receives = vec![receive(222, shared, 20_000, below_target(&ws, 1))];
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    let effective = watch(&st, a);
    assert!(effective.addresses.len() > before.addresses.len());
    assert_eq!(
        snapshot(&st, a).authority,
        TransparentAuthority::Unavailable
    );
    assert!(
        recovery(&st, a)
            .blockers
            .contains(&CandidateBlocker::IncompleteCoverage)
    );
    let reopened = crate::WalletDb::for_path(
        st.wallet().data_file_path(),
        *st.network(),
        crate::testing::db::test_clock(),
        crate::testing::db::test_rng(),
    )
    .unwrap()
    .with_transparent_ledger_mode(PrivateRequired);
    assert_eq!(reopened.transparent_watch_set(a).unwrap(), effective);
    // Each discovered address is newly watched, so A has no coverage of it yet.
    for index in high + gap + 1..shared_index + gap + 1 {
        assert!(!before.addresses.iter().any(|w| w.address == address(index)));
        assert!(
            effective
                .addresses
                .iter()
                .any(|w| w.address == address(index))
        );
    }
    let mut c = commit(&effective);
    c.coverage = full_coverage(&effective);
    // Failing materialization must roll back coverage too, keeping authority unavailable.
    let before_materialization = production_dump(conn(&st));
    conn(&st).execute_batch("CREATE TEMP TRIGGER fail_materialization BEFORE INSERT ON addresses BEGIN SELECT RAISE(ABORT, 'injected materialization failure'); END;").unwrap();
    assert!(apply(&mut st, c.clone()).is_err());
    assert_eq!(production_dump(conn(&st)), before_materialization);
    assert_eq!(
        snapshot(&st, a).authority,
        TransparentAuthority::Unavailable
    );
    conn(&st)
        .execute_batch("DROP TRIGGER fail_materialization")
        .unwrap();
    apply(&mut st, c).unwrap();
    assert_eq!(snapshot(&st, a).authority, TransparentAuthority::Private);
    assert!(watch(&st, b).addresses.iter().any(|w| w.address == shared));
    // A receive in the newly discovered range is projectable, including when the wallet's
    // ordinary first-gap generation still chooses the earlier gap at index one.
    let ws = watch(&st, a);
    let mut c = commit(&ws);
    c.receives = vec![receive(
        223,
        address(high + gap + 1),
        30_000,
        below_target(&ws, 1),
    )];
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    let ws = watch(&st, a);
    let mut c = commit(&ws);
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    assert_eq!(snapshot(&st, a).authority, TransparentAuthority::Private);
    // Removing B releases the retained receiver; A must recover it before regaining authority.
    st.wallet_mut().delete_account(b).unwrap();
    let ws = watch(&st, a);
    assert!(ws.addresses.iter().any(|w| w.address == shared));
    assert_eq!(
        snapshot(&st, a).authority,
        TransparentAuthority::Unavailable
    );
    let mut c = commit(&ws);
    c.receives = vec![receive(222, shared, 20_000, below_target(&ws, 1))];
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    assert_eq!(snapshot(&st, a).authority, TransparentAuthority::Private);
    st.wallet_mut().delete_account(a).unwrap();
    assert_eq!(count(&st, "tpir_shared_derivations"), 0);
}

#[test]
fn imported_receiver_has_one_candidate_owner_in_either_commit_order() {
    for b_first in [false, true] {
        let (mut st, accounts) = recovery_wallet_with(1);
        let (a, b) = (accounts[0], accounts[1]);
        let (address, _, key, edge) = future_receiver(&st, a);
        import(&mut st, b, key);
        let before = production_dump(conn(&st));
        grow(&mut st, a, edge);
        assert!(!watch(&st, a).addresses.iter().any(|w| w.address == address));
        assert!(watch(&st, b).addresses.iter().any(|w| w.address == address));
        let a_watch_before_shared_activity = watch(&st, a);
        let mut a_commit = commit(&a_watch_before_shared_activity);
        a_commit.coverage = full_coverage(&watch(&st, a));
        let mut b_commit = commit(&watch(&st, b));
        b_commit.coverage = full_coverage(&watch(&st, b));
        b_commit.receives = vec![receive(
            212,
            address,
            20_000,
            below_target(&watch(&st, b), 1),
        )];
        for c in if b_first {
            vec![b_commit, a_commit]
        } else {
            vec![a_commit, b_commit]
        } {
            apply(&mut st, c).unwrap();
        }
        assert_eq!(production_dump(conn(&st)), before);
        assert_eq!(count(&st, "tpir_quarantined_accounts"), 0);
        assert!(
            !recovery(&st, a)
                .receives
                .iter()
                .any(|r| r.address == address)
        );
        assert!(
            recovery(&st, b)
                .receives
                .iter()
                .any(|r| r.address == address)
        );
        let reopened = crate::WalletDb::for_path(
            st.wallet().data_file_path(),
            *st.network(),
            crate::testing::db::test_clock(),
            crate::testing::db::test_rng(),
        )
        .unwrap()
        .with_transparent_ledger_mode(PrivateRequired);
        assert_eq!(reopened.transparent_watch_set(a).unwrap(), watch(&st, a));
        // B's activity extends A's effective window immediately, before A commits again.
        // Reads report the new gaps and remain observational, including across reopen.
        let effective = watch(&st, a);
        assert!(effective.addresses.len() > a_watch_before_shared_activity.addresses.len());
        assert!(
            recovery(&st, a)
                .blockers
                .contains(&CandidateBlocker::IncompleteCoverage)
        );
        assert_eq!(production_dump(conn(&st)), before);
        let mut c = commit(&effective);
        c.coverage = full_coverage(&effective);
        apply(&mut st, c).unwrap();
        qualify(&mut st, &revision(1, true));
        set_policy(&mut st, PrivateRequired);
        let encoded = Address::Transparent(address).encode(st.network());
        let owner = |st: &State| -> i64 {
            conn(st)
                .query_row(
                    "SELECT account_id FROM addresses WHERE cached_transparent_receiver_address = ?1",
                    [&encoded],
                    |row| row.get(0),
                )
                .unwrap()
        };
        let importer = owner(&st);
        // Promotion succeeds instead of refusing and rolling back on every retry. Writing the
        // window leaves the receiver with its owner; projecting A's receive at the window edge then
        // runs the wallet's gap-limit generation, which transfers the adjacent receiver under the
        // existing rule. A is active, and its watch set asks it to cover the receiver before its
        // authority returns.
        promote(&mut st, a).unwrap();
        assert_ne!(owner(&st), importer);
        assert!(watch(&st, a).addresses.iter().any(|w| w.address == address));
        assert!(!watch(&st, b).addresses.iter().any(|w| w.address == address));
        assert_ne!(snapshot(&st, a).authority, TransparentAuthority::Private);
        assert!(
            recovery(&st, a)
                .blockers
                .contains(&CandidateBlocker::IncompleteCoverage)
        );
        let mut c = commit(&watch(&st, a));
        c.coverage = full_coverage(&watch(&st, a));
        c.receives = vec![receive(
            212,
            address,
            20_000,
            below_target(&watch(&st, a), 1),
        )];
        apply(&mut st, c).unwrap();
        // New activity may grow the derivation window; complete the freshly scheduled gaps.
        for _ in 0..3 {
            if snapshot(&st, a).authority == TransparentAuthority::Private {
                break;
            }
            let ws = watch(&st, a);
            let mut c = commit(&ws);
            c.coverage = full_coverage(&ws);
            apply(&mut st, c).unwrap();
        }
        assert_eq!(snapshot(&st, a).authority, TransparentAuthority::Private);
    }
}

#[test]
fn import_after_candidate_recovery_discards_conflicting_work_without_quarantine() {
    let (mut st, accounts) = recovery_wallet_with(1);
    let (a, b) = (accounts[0], accounts[1]);
    let (address, _, key, edge) = future_receiver(&st, a);
    grow(&mut st, a, edge);
    let ws = watch(&st, a);
    let mut c = commit(&ws);
    c.receives = vec![receive(212, address, 20_000, below_target(&ws, 1))];
    c.coverage = full_coverage(&ws)
        .into_iter()
        .map(|r| AddressRange {
            through: r.through - 1,
            ..r
        })
        .collect();
    c.opened_pages = vec![PageRequest {
        page: b"owned-later".to_vec(),
        addresses: vec![address],
        from: ws.target.unwrap().height,
        through: ws.target.unwrap().height,
    }];
    apply(&mut st, c).unwrap();
    let mut stale = commit(&ws);
    stale.receives = vec![receive(212, address, 20_000, below_target(&ws, 1))];
    let received = stale.receives[0].clone();
    import(&mut st, b, key);
    assert!(
        !recovery(&st, a)
            .receives
            .iter()
            .any(|r| r.address == address)
    );
    assert!(watch(&st, a).pending_pages.is_empty());
    assert_eq!(
        rejection(apply(&mut st, stale)),
        CommitRejection::Stale(StaleCommit::AddressNotWatched(address))
    );
    assert_eq!(count(&st, "tpir_quarantined_accounts"), 0);
    let mut c = commit(&watch(&st, b));
    c.receives = vec![received];
    c.coverage = full_coverage(&watch(&st, b));
    apply(&mut st, c).unwrap();
}

#[test]
fn imported_ownership_filters_all_derivable_scopes() {
    for (slot, scope) in [
        TransparentKeyScope::EXTERNAL,
        TransparentKeyScope::INTERNAL,
        TransparentKeyScope::EPHEMERAL,
    ]
    .into_iter()
    .enumerate()
    {
        let (mut st, accounts) = recovery_wallet_with(1);
        let index = NonHardenedChildIndex::from_index(100).unwrap();
        let ufvk = st
            .test_account()
            .unwrap()
            .usk()
            .to_unified_full_viewing_key();
        let key = ufvk
            .transparent()
            .unwrap()
            .derive_address_pubkey(scope, index)
            .unwrap();
        let address = TransparentAddress::from_pubkey(&key);
        import(&mut st, accounts[1], key);
        conn(&st).execute("INSERT INTO tpir_candidate_windows(account_id,key_scope,end_index) VALUES (?1,?2,101)", rusqlite::params![st.test_account().unwrap().account().internal_id().0, slot]).unwrap();
        assert!(
            !watch(&st, accounts[0])
                .addresses
                .iter()
                .any(|w| w.address == address)
        );
        assert!(
            watch(&st, accounts[1])
                .addresses
                .iter()
                .any(|w| w.address == address)
        );
        let ws = watch(&st, accounts[0]);
        let mut c = commit(&ws);
        c.coverage = full_coverage(&ws);
        apply(&mut st, c).unwrap();
        qualify(&mut st, &revision(1, true));
        set_policy(&mut st, PrivateRequired);
        // Refusing metadata persistence rolls back promotion and every address it generated.
        let before = production_dump(conn(&st));
        conn(&st).execute_batch("CREATE TEMP TRIGGER fail_shared_origin BEFORE INSERT ON tpir_shared_derivations BEGIN SELECT RAISE(ABORT, 'injected shared origin failure'); END;").unwrap();
        assert!(promote(&mut st, accounts[0]).is_err());
        assert_eq!(production_dump(conn(&st)), before);
        assert_eq!(count(&st, "tpir_shared_derivations"), 0);
        conn(&st)
            .execute_batch("DROP TRIGGER fail_shared_origin")
            .unwrap();
        promote(&mut st, accounts[0]).unwrap();
        assert_eq!(reader_version(&st), 8);
        assert_eq!(count(&st, "tpir_shared_derivations"), 1);
        let ws = watch(&st, accounts[1]);
        let mut c = commit(&ws);
        c.receives = vec![receive(224, address, 10_000, below_target(&ws, 1))];
        c.coverage = full_coverage(&ws);
        apply(&mut st, c).unwrap();
        assert_eq!(
            snapshot(&st, accounts[0]).authority,
            TransparentAuthority::Unavailable
        );
        assert!(
            recovery(&st, accounts[0])
                .blockers
                .contains(&CandidateBlocker::IncompleteCoverage)
        );
    }
}

#[test]
fn ownership_cleanup_failure_rolls_back_the_import_and_evidence() {
    let (mut st, accounts) = recovery_wallet_with(1);
    let (address, _, key, edge) = future_receiver(&st, accounts[0]);
    grow(&mut st, accounts[0], edge);
    let ws = watch(&st, accounts[0]);
    let mut c = commit(&ws);
    c.receives = vec![receive(212, address, 20_000, below_target(&ws, 1))];
    apply(&mut st, c).unwrap();
    let before = production_dump(conn(&st));
    let evidence = recovery(&st, accounts[0]);
    conn(&st).execute_batch("CREATE TEMP TRIGGER fail_import_cleanup BEFORE DELETE ON tpir_receive_events BEGIN SELECT RAISE(ABORT, 'injected cleanup failure'); END;").unwrap();
    assert!(
        st.wallet_mut()
            .db_mut()
            .import_standalone_transparent_pubkey(accounts[1], key)
            .is_err()
    );
    assert_eq!(production_dump(conn(&st)), before);
    assert_eq!(recovery(&st, accounts[0]), evidence);
    assert!(
        watch(&st, accounts[0])
            .addresses
            .iter()
            .any(|w| w.address == address)
    );
}
