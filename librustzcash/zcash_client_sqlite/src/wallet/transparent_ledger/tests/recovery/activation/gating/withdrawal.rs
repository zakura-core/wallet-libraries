//! Receive withdrawal must revoke authority without forgetting independent wallet state.

use zcash_client_backend::{
    data_api::OutputLockStore as _,
    wallet::{LockOwner, OutputRef},
};
use zcash_protocol::PoolType;

use super::*;

/// A provisional receive and, optionally, a spend observed by an independent sealed source.
fn provisional_wallet(with_spend: bool) -> (State, AccountUuid, ReceiveEvent, RecoveryRevision) {
    let (mut st, accounts) = recovery_wallet_with(0);
    let account = accounts[0];
    let ws = watch(&st, account);
    let received = receive(31, external(&ws), 40_000, below_target(&ws, 4));
    let provisional = RecoveryRevision {
        sealed: false,
        ..source(b"receive-source", 1)
    };
    cover(&mut st, account, &provisional, vec![received.clone()]);
    qualify(&mut st, &provisional);
    if with_spend {
        let ws = watch(&st, account);
        let independent = source(b"spend-source", 1);
        let mut c = commit(&ws);
        c.revision = independent.clone();
        c.spends = vec![spend(32, &received, below_target(&ws, 2))];
        c.coverage = full_coverage(&ws);
        apply(&mut st, c).unwrap();
        qualify(&mut st, &independent);
    }
    set_policy(&mut st, PrivateRequired);
    promote(&mut st, account).unwrap();
    let replacement = RecoveryRevision {
        sealed: false,
        ..source(b"receive-source", 2)
    };
    (st, account, received, replacement)
}

#[test]
fn withdrawing_a_receive_preserves_an_independently_observed_spend() {
    let (mut st, account, received, replacement) = provisional_wallet(true);
    assert_eq!(spend_count(&st, &received.outpoint), 1);
    qualify(&mut st, &replacement);
    assert_eq!(spend_count(&st, &received.outpoint), 1);
    assert_eq!(count(&st, "tpir_spend_observations"), 1);

    // Only the receive is replayed. Its independently supported spend must stay linked.
    cover(&mut st, account, &replacement, vec![received.clone()]);
    let s = snapshot(&st, account);
    assert_eq!(s.authority, TransparentAuthority::Private);
    assert_eq!(s.recovered_unverified, Some(Zatoshis::ZERO));
    assert_eq!(s.authorized.unwrap().regular.total(), Zatoshis::ZERO);
    for selection in selections(
        &st,
        account,
        &[received.address],
        &received.outpoint,
        next_target(&st),
    ) {
        assert_eq!(selection.unwrap(), vec![]);
    }
}

#[test]
fn withdrawing_a_receive_preserves_a_locally_constructed_spend() {
    let (mut st, account, received, replacement) = provisional_wallet(false);
    super::coinbase::store_spend(&mut st, account, &received).unwrap();
    assert_eq!(spend_count(&st, &received.outpoint), 1);
    qualify(&mut st, &replacement);
    assert_eq!(spend_count(&st, &received.outpoint), 1);
    cover(&mut st, account, &replacement, vec![received.clone()]);
    assert_eq!(
        snapshot(&st, account).authorized.unwrap().regular.total(),
        Zatoshis::ZERO
    );
    for selection in selections(
        &st,
        account,
        &[received.address],
        &received.outpoint,
        next_target(&st),
    ) {
        assert_eq!(selection.unwrap(), vec![]);
    }
}

#[test]
fn trusted_withdrawal_fences_retained_rows_from_older_readers() {
    let (mut st, account, _, replacement) = provisional_wallet(false);
    // Demote the account so the replacement is recovered as a candidate.
    set_policy(&mut st, Public);
    set_policy(&mut st, PrivateRequired);
    // Simulate a wallet last activated by the previous Phase 4 reader.
    st.wallet().set_transparent_reader_version(4);
    cover(&mut st, account, &replacement, vec![]);
    assert_eq!(reader_version(&st), 6);
    qualify(&mut st, &replacement);
    assert_eq!(reader_version(&st), 6);
}

#[test]
fn a_failed_withdrawal_preserves_the_projection_and_revision_observations() {
    let (mut st, account, received, replacement) = provisional_wallet(true);
    st.wallet().set_transparent_reader_version(4);
    let before = production_dump(conn(&st));
    let observations = count(&st, "tpir_receive_observations");
    conn(&st)
        .execute_batch(
            "CREATE TEMP TRIGGER fail_withdrawal BEFORE DELETE ON tpir_receive_events
         BEGIN SELECT RAISE(ABORT, 'injected withdrawal failure'); END;",
        )
        .unwrap();
    assert!(matches!(
        st.wallet_mut()
            .db_mut()
            .qualify_transparent_revision(&replacement),
        Err(SqliteClientError::DbError(_))
    ));
    assert_eq!(production_dump(conn(&st)), before);
    assert_eq!(count(&st, "tpir_receive_observations"), observations);
    assert_eq!(reader_version(&st), 4);
    assert_eq!(spend_count(&st, &received.outpoint), 1);
    assert_eq!(
        snapshot(&st, account).authority,
        TransparentAuthority::Private
    );
}

#[test]
fn withdrawing_and_replaying_a_receive_preserves_its_reservation_across_reopen() {
    let (mut st, account, received, replacement) = provisional_wallet(false);
    let output = OutputRef::new(
        *received.outpoint.txid(),
        PoolType::Transparent,
        received.outpoint.n(),
    );
    let owner = LockOwner::new([41; 32]);
    let other = LockOwner::new([42; 32]);
    st.wallet_mut()
        .db_mut()
        .lock_outputs(&[output], owner, BlockHeight::from(u32::MAX))
        .unwrap();
    qualify(&mut st, &replacement);
    assert_eq!(
        st.wallet().db().get_locked_outputs(account).unwrap(),
        vec![output]
    );
    cover(&mut st, account, &replacement, vec![received.clone()]);

    let mut reopened = crate::WalletDb::for_path(
        st.wallet().data_file_path(),
        *st.network(),
        crate::testing::db::test_clock(),
        crate::testing::db::test_rng(),
    )
    .unwrap()
    .with_transparent_ledger_mode(PrivateRequired);
    assert_eq!(reopened.get_locked_outputs(account).unwrap(), vec![output]);
    assert!(!reopened.unlock_output(&output, other).unwrap());
    let [by_outpoint, by_address, by_addresses, by_account] = <[_; 4]>::try_from(selections(
        &st,
        account,
        &[received.address],
        &received.outpoint,
        next_target(&st),
    ))
    .unwrap();
    // Direct lookup permits an owner's reserved input; automatic selection excludes it.
    assert_eq!(by_outpoint.unwrap(), vec![received.outpoint.clone()]);
    for selection in [by_address, by_addresses, by_account] {
        assert_eq!(selection.unwrap(), vec![]);
    }
    assert!(reopened.unlock_output(&output, owner).unwrap());
    for selection in selections(
        &st,
        account,
        &[received.address],
        &received.outpoint,
        next_target(&st),
    ) {
        assert_eq!(selection.unwrap(), vec![received.outpoint.clone()]);
    }
}

#[test]
fn withdrawn_receive_is_not_public_value_and_does_not_block_reactivation() {
    let (mut st, account, received, replacement) = provisional_wallet(false);
    qualify(&mut st, &replacement);
    cover(&mut st, account, &replacement, vec![]);
    assert_eq!(
        snapshot(&st, account).authorized.unwrap().regular.total(),
        Zatoshis::ZERO
    );
    set_policy(&mut st, Public);
    assert_eq!(
        snapshot(&st, account).authorized.unwrap().regular.total(),
        Zatoshis::ZERO
    );
    assert!(
        st.wallet()
            .db()
            .get_transparent_balances(account, next_target(&st), ConfirmationsPolicy::MIN)
            .unwrap()
            .is_empty()
    );
    for selection in selections(
        &st,
        account,
        &[received.address],
        &received.outpoint,
        next_target(&st),
    ) {
        assert_eq!(selection.unwrap(), vec![]);
    }
    // Retained metadata remains available without a spend target.
    assert!(
        crate::wallet::transparent::get_wallet_transparent_output(
            conn(&st),
            &received.outpoint,
            None,
            &crate::wallet::transparent_ledger::InputAuthority::Public,
        )
        .unwrap()
        .is_some()
    );
    set_policy(&mut st, PrivateRequired);
    promote(&mut st, account).unwrap();
    assert_eq!(
        snapshot(&st, account).authorized.unwrap().regular.total(),
        Zatoshis::ZERO
    );
}
