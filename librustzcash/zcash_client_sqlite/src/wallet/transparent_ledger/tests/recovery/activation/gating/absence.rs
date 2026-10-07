//! Public absence observations must not constrain qualified private financial authority.

use zcash_client_backend::{data_api::SentTransaction, wallet::WalletTransparentOutput};

use super::*;

/// Records a public absence for a receive that the candidate ledger already knows about.
fn absent_public_output() -> (State, AccountUuid, ReceiveEvent) {
    let (mut st, account, unspent, _) = ready_wallet();
    set_policy(&mut st, Public);
    let output = WalletTransparentOutput::from_parts(
        unspent.outpoint.clone(),
        transparent::bundle::TxOut::new(unspent.value, unspent.address.script().into()),
        Some(unspent.mined_height),
        Some(account),
        None,
        None,
    )
    .unwrap();
    st.wallet_mut()
        .put_received_transparent_utxo(&output)
        .unwrap();
    scan_new_blocks(&mut st, 1);
    let tip = st.wallet().chain_height().unwrap().unwrap();
    let point = ChainPoint {
        height: tip,
        hash: crate::wallet::get_block_hash(conn(&st), tip)
            .unwrap()
            .unwrap(),
    };
    st.wallet_mut()
        .notify_transparent_utxos_observed(
            &unspent.address,
            BlockHeight::from_u32(0),
            point,
            point,
            &[],
        )
        .unwrap();
    assert_eq!(count(&st, "transparent_utxo_absences"), 1);
    (st, account, unspent)
}

fn private_recovery(st: &mut State, account: AccountUuid) {
    set_policy(st, PrivateShadow);
    let fixture = revision(1, true);
    cover(st, account, &fixture, vec![]);
    qualify(st, &fixture);
    set_policy(st, PrivateRequired);
    assert!(recovery(st, account).blockers.is_empty());
    promote(st, account).unwrap();
    assert_eq!(
        snapshot(st, account).authority,
        TransparentAuthority::Private
    );
}

#[test]
fn public_absence_does_not_override_qualified_private_balances_or_selection() {
    // Private coverage at the absence height or later must govern private reads. Switching
    // the handle alone, or supplying incomplete coverage, cannot restore spending authority.
    for later_blocks in [0, 1] {
        let (mut st, account, unspent) = absent_public_output();
        let target = next_target(&st);
        for selection in selections(&st, account, &[unspent.address], &unspent.outpoint, target) {
            assert_eq!(selection.unwrap(), vec![]);
        }
        assert_eq!(
            snapshot(&st, account).authorized.unwrap().regular.total(),
            Zatoshis::ZERO
        );

        set_policy(&mut st, PrivateShadow);
        for selection in selections(&st, account, &[unspent.address], &unspent.outpoint, target) {
            assert_eq!(selection.unwrap(), vec![]);
        }
        if later_blocks > 0 {
            scan_new_blocks(&mut st, later_blocks);
        }
        set_policy(&mut st, PrivateRequired);
        assert!(promote(&mut st, account).is_err());
        assert_eq!(
            snapshot(&st, account).authority,
            TransparentAuthority::Unavailable
        );
        all_unavailable(selections(
            &st,
            account,
            &[unspent.address],
            &unspent.outpoint,
            next_target(&st),
        ));

        private_recovery(&mut st, account);
        let s = snapshot(&st, account);
        assert!(s.blockers.is_empty());
        assert_eq!(
            s.authorized.unwrap().regular.spendable_value(),
            unspent.value
        );
        for selection in selections(
            &st,
            account,
            &[unspent.address],
            &unspent.outpoint,
            next_target(&st),
        ) {
            assert_eq!(selection.unwrap(), vec![unspent.outpoint.clone()]);
        }
        // The pending-balance query obeys the same authority rule as confirmed balances.
        let s = st
            .wallet()
            .db()
            .transparent_ledger_snapshot(
                account,
                ConfirmationsPolicy::new_symmetrical_unchecked(100, false),
            )
            .unwrap();
        let balance = s.authorized.unwrap().regular;
        assert_eq!(balance.spendable_value(), Zatoshis::ZERO);
        assert_eq!(balance.value_pending_spendability(), unspent.value);

        // Retaining public evidence preserves conservative behavior on a return to Public.
        assert_eq!(count(&st, "transparent_utxo_absences"), 1);
        set_policy(&mut st, Public);
        assert_eq!(
            snapshot(&st, account).authorized.unwrap().regular.total(),
            Zatoshis::ZERO
        );
        for selection in selections(
            &st,
            account,
            &[unspent.address],
            &unspent.outpoint,
            next_target(&st),
        ) {
            assert_eq!(selection.unwrap(), vec![]);
        }
    }
}

#[test]
fn private_submission_and_exact_retry_ignore_public_absence_but_preserve_spend_checks() {
    let (mut st, account, unspent) = absent_public_output();
    let tx = super::super::public_fixtures::transaction(
        vec![unspent.outpoint.clone()],
        vec![(super::super::public_fixtures::EXTERNAL, 30_000)],
    );
    assert!(matches!(
        st.wallet()
            .db()
            .check_transparent_transaction_inputs(&tx, &[], next_target(&st)),
        Err(SqliteClientError::TransparentAuthorityUnavailable)
    ));
    private_recovery(&mut st, account);
    let target = next_target(&st);
    st.wallet()
        .db()
        .check_transparent_transaction_inputs(&tx, &[], target)
        .unwrap();
    st.wallet_mut()
        .db_mut()
        .store_transactions_to_be_sent(&[SentTransaction::new(
            &tx,
            time::OffsetDateTime::UNIX_EPOCH,
            target,
            account,
            &[],
            Zatoshis::const_from_u64(10_000),
            std::slice::from_ref(&unspent.outpoint),
        )])
        .unwrap();

    // An exact-byte retry may reuse its own input, but ordinary selection and a competing
    // submission still exclude the recorded spend.
    st.wallet()
        .db()
        .check_transparent_transaction_inputs(&tx, &[], target)
        .unwrap();
    for selection in selections(&st, account, &[unspent.address], &unspent.outpoint, target) {
        assert_eq!(selection.unwrap(), vec![]);
    }
    assert_eq!(
        snapshot(&st, account).authorized.unwrap().regular.total(),
        Zatoshis::ZERO
    );
    let competing = super::super::public_fixtures::transaction(
        vec![unspent.outpoint.clone()],
        vec![(super::super::public_fixtures::EXTERNAL, 20_000)],
    );
    assert!(matches!(
        st.wallet()
            .db()
            .check_transparent_transaction_inputs(&competing, &[], target),
        Err(SqliteClientError::TransparentAuthorityUnavailable)
    ));
}
