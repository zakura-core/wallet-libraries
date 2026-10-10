//! A refused input check says whether waiting for private recovery can admit the inputs, from
//! the same read as the check.

use transparent::{
    address::Script,
    bundle::{Bundle, TxIn, TxOut},
};
use zcash_primitives::transaction::{
    Authorized, Transaction, TransactionData, TxVersion, builder::DEFAULT_TX_EXPIRY_DELTA,
};
use zcash_protocol::consensus::BranchId;

use crate::error::{AuthorityRefusal, RefusalReason};

use super::*;

/// A transaction spending `inputs`. Its signatures are synthetic: the check validates none.
fn spending(inputs: &[&OutPoint]) -> Transaction {
    TransactionData::<Authorized>::from_parts(
        TxVersion::V5,
        BranchId::Nu5,
        0,
        BlockHeight::from_u32(1_000_000),
        Some(Bundle {
            vin: inputs
                .iter()
                .map(|outpoint| TxIn::from_parts((*outpoint).clone(), Script::default(), u32::MAX))
                .collect(),
            vout: vec![TxOut::new(
                Zatoshis::const_from_u64(10_000),
                TransparentAddress::PublicKeyHash([7; 20]).script().into(),
            )],
            authorization: transparent::bundle::Authorized,
        }),
        None,
        None,
        None,
    )
    .freeze()
    .unwrap()
}

/// Checks a transaction spending `inputs` at `target`, returning the refusal.
fn check(st: &State, inputs: &[&OutPoint], target: TargetHeight) -> Result<(), AuthorityRefusal> {
    match st
        .wallet()
        .db()
        .check_transparent_transaction_inputs(&spending(inputs), &[], target)
    {
        Ok(()) => Ok(()),
        Err(SqliteClientError::TransparentAuthorityUnavailable(refusal)) => Err(refusal),
        Err(other) => panic!("not an authority refusal: {other:?}"),
    }
}

fn refused(reason: RefusalReason) -> Result<(), AuthorityRefusal> {
    Err(AuthorityRefusal::Refused(reason))
}

fn pending(account: AccountUuid) -> Result<(), AuthorityRefusal> {
    Err(AuthorityRefusal::Pending {
        accounts: vec![account],
    })
}

fn suspend_recovery(st: &State) {
    conn(st)
        .execute(
            "INSERT INTO tpir_quarantined_accounts SELECT id FROM accounts",
            [],
        )
        .unwrap();
}

#[test]
fn an_unspent_input_behind_coverage_is_pending_until_recovery_catches_up() {
    let (mut st, account, unspent) = active_wallet();
    assert_eq!(
        snapshot(&st, account).blockers,
        vec![RecoveryBlocker::Recovery(
            CandidateBlocker::IncompleteCoverage
        )]
    );
    let target = next_target(&st);
    let input = [&unspent.outpoint];
    assert_eq!(check(&st, &input, target), pending(account));
    // An input listed twice names its account once.
    assert_eq!(
        check(&st, &[&unspent.outpoint, &unspent.outpoint], target),
        pending(account)
    );
    // Direct lookup, account selection and final storage classify the same way.
    let lookup = st
        .wallet()
        .db()
        .get_unspent_transparent_output(&unspent.outpoint, target);
    assert!(
        matches!(
            &lookup,
            Err(SqliteClientError::TransparentAuthorityUnavailable(
                AuthorityRefusal::Pending { accounts }
            )) if accounts == &vec![account]
        ),
        "{lookup:?}"
    );
    for selection in selections(&st, account, &[unspent.address], &unspent.outpoint, target) {
        assert!(
            matches!(
                &selection,
                Err(SqliteClientError::TransparentAuthorityUnavailable(
                    AuthorityRefusal::Pending { .. }
                ))
            ),
            "{selection:?}"
        );
    }
    let stored = super::coinbase::store_spend(&mut st, account, &unspent);
    assert!(
        matches!(
            stored,
            Err(SqliteClientError::TransparentAuthorityUnavailable(
                AuthorityRefusal::Pending { .. }
            ))
        ),
        "{stored:?}"
    );

    // A target past the next block also waits for the chain to reach it. One at or below the
    // tip is never admitted, however far recovery gets.
    let ahead = TargetHeight::from(BlockHeight::from(target) + 1);
    assert_eq!(check(&st, &input, ahead), pending(account));
    let behind = TargetHeight::from(BlockHeight::from(target) - 1);
    assert_eq!(
        check(&st, &input, behind),
        refused(RefusalReason::StaleTarget)
    );

    // Once recovery covers the tip, the same check succeeds.
    cover(&mut st, account, &revision(1, true), vec![]);
    assert_eq!(check(&st, &input, target), Ok(()));
    assert_eq!(
        check(&st, &input, behind),
        refused(RefusalReason::StaleTarget)
    );
}

#[test]
fn spent_and_immature_inputs_behind_coverage_are_refused() {
    let (mut st, account, unspent, spent) = ready_wallet();
    activate_recovered_ledger(&mut st, account).unwrap();
    scan_new_blocks(&mut st, 2);
    let target = next_target(&st);
    assert_eq!(check(&st, &[&unspent.outpoint], target), pending(account));
    // The recovered spend is another transaction's, which the submission check names first;
    // final storage, which leaves competing spends to that check, finds the output spent.
    assert_eq!(
        check(&st, &[&spent.outpoint], target),
        refused(RefusalReason::CompetingSpend)
    );
    assert!(matches!(
        super::coinbase::store_spend(&mut st, account, &spent),
        Err(SqliteClientError::TransparentAuthorityUnavailable(
            AuthorityRefusal::Refused(RefusalReason::Spent)
        ))
    ));
    // One input that waiting cannot admit refuses the whole transaction, whichever comes first.
    for inputs in [
        [&unspent.outpoint, &spent.outpoint],
        [&spent.outpoint, &unspent.outpoint],
    ] {
        assert_eq!(
            check(&st, &inputs, target),
            refused(RefusalReason::CompetingSpend)
        );
    }

    let (mut st, account, coinbase, _) = super::coinbase::coinbase_wallet();
    scan_new_blocks(&mut st, 1);
    assert_eq!(
        snapshot(&st, account).blockers,
        vec![RecoveryBlocker::Recovery(
            CandidateBlocker::IncompleteCoverage
        )]
    );
    assert_eq!(
        check(&st, &[&coinbase.outpoint], next_target(&st)),
        refused(RefusalReason::ImmatureCoinbase)
    );
}

#[test]
fn an_unknown_input_is_refused() {
    let (st, account, unspent) = active_wallet();
    let unknown = OutPoint::new([0x99; 32], 0);
    let target = next_target(&st);
    assert_eq!(
        check(&st, &[&unknown], target),
        refused(RefusalReason::UnknownOutput)
    );
    assert_eq!(
        check(&st, &[&unspent.outpoint, &unknown], target),
        refused(RefusalReason::UnknownOutput)
    );
    assert_eq!(check(&st, &[&unspent.outpoint], target), pending(account));
}

#[test]
fn a_recovery_suspended_owner_is_refused_with_or_without_coverage() {
    // Behind coverage, recovery suspension is a blocker waiting does not clear.
    let (st, _, unspent) = active_wallet();
    suspend_recovery(&st);
    assert_eq!(
        check(&st, &[&unspent.outpoint], next_target(&st)),
        refused(RefusalReason::NotAdmitted)
    );

    // Covered through the tip, recovery suspension alone revokes authority.
    let (st, _, _, unspent) = eligible_wallet();
    let target = next_target(&st);
    assert_eq!(check(&st, &[&unspent.outpoint], target), Ok(()));
    suspend_recovery(&st);
    assert_eq!(
        check(&st, &[&unspent.outpoint], target),
        refused(RefusalReason::NotAdmitted)
    );
}

#[test]
fn an_owner_with_authority_refuses_an_output_outside_its_ledger() {
    let (st, _, _, unspent) = eligible_wallet();
    conn(&st)
        .execute_batch("UPDATE tpir_output_origins SET origin = 0 WHERE origin = 2")
        .unwrap();
    assert_eq!(
        check(&st, &[&unspent.outpoint], next_target(&st)),
        refused(RefusalReason::NotInLedger)
    );
}

#[test]
fn a_local_chain_behind_the_tip_alone_is_pending() {
    let (mut st, account, _, unspent) = eligible_wallet();
    let not_our_key = ExtendedSpendingKey::master(&[]).to_diversifiable_full_viewing_key();
    let value = Zatoshis::const_from_u64(10_000);
    let (start, _, _) = st.generate_next_block(&not_our_key, AddressType::DefaultExternal, value);
    let (tip, _, _) = st.generate_next_block(&not_our_key, AddressType::DefaultExternal, value);
    st.wallet_mut().update_chain_tip(tip).unwrap();
    assert_eq!(
        snapshot(&st, account).blockers,
        vec![RecoveryBlocker::ChainBehindTip]
    );
    let target = next_target(&st);
    assert_eq!(BlockHeight::from(target), tip + 1);
    assert_eq!(check(&st, &[&unspent.outpoint], target), pending(account));

    st.scan_cached_blocks(start, 2);
    cover(&mut st, account, &revision(1, true), vec![]);
    assert_eq!(check(&st, &[&unspent.outpoint], target), Ok(()));
}

#[test]
fn open_pages_and_unresolved_spends_are_not_admitted() {
    // Open pages over a block coverage has not reached yet, so coverage lags too.
    let (mut st, account, taddr, unspent) = eligible_wallet();
    scan_new_blocks(&mut st, 1);
    let ws = watch(&st, account);
    let at = ws.target.unwrap().height;
    let mut c = commit(&ws);
    c.opened_pages = vec![PageRequest {
        page: b"p1".to_vec(),
        addresses: vec![taddr],
        from: at,
        through: at,
    }];
    apply(&mut st, c).unwrap();
    assert!(
        snapshot(&st, account)
            .blockers
            .contains(&RecoveryBlocker::Recovery(CandidateBlocker::PendingPages))
    );
    assert_eq!(
        check(&st, &[&unspent.outpoint], next_target(&st)),
        refused(RefusalReason::NotAdmitted)
    );

    // An unresolved spend, also while coverage lags.
    let (mut st, account, _, unspent) = eligible_wallet();
    let ws = watch(&st, account);
    let missing = receive(9, external(&ws), 5_000, below_target(&ws, 3));
    let mut c = commit(&ws);
    c.spends = vec![spend(10, &missing, below_target(&ws, 1))];
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    assert_eq!(
        snapshot(&st, account).blockers,
        vec![RecoveryBlocker::Recovery(
            CandidateBlocker::UnresolvedSpends
        )]
    );
    let target = next_target(&st);
    assert_eq!(
        check(&st, &[&unspent.outpoint], target),
        refused(RefusalReason::NotAdmitted)
    );
    scan_new_blocks(&mut st, 1);
    assert_eq!(
        check(&st, &[&unspent.outpoint], next_target(&st)),
        refused(RefusalReason::NotAdmitted)
    );
}

#[test]
fn a_candidate_owner_is_not_admitted() {
    let (mut st, accounts) = recovery_wallet_with(0);
    let account = accounts[0];
    let taddr = external(&watch(&st, account));
    let outpoint = OutPoint::new([0x55; 32], 0);
    publicly(&mut st, |st| {
        crate::wallet::transparent_ledger::tests::put_public_utxo(
            st,
            &taddr,
            outpoint.clone(),
            30_000,
        )
    });
    assert_eq!(watch(&st, account).lifecycle, AccountLifecycle::Candidate);
    let target = next_target(&st);
    assert_eq!(
        check(&st, &[&outpoint], target),
        refused(RefusalReason::NotAdmitted)
    );
    for selection in selections(&st, account, &[taddr], &outpoint, target) {
        assert!(
            matches!(
                selection,
                Err(SqliteClientError::TransparentAuthorityUnavailable(
                    AuthorityRefusal::Refused(RefusalReason::NotAdmitted)
                ))
            ),
            "{selection:?}"
        );
    }
}

#[test]
fn address_selection_is_pending_when_any_owner_is() {
    let (mut st, accounts) = recovery_wallet_with(1);
    let fixture = revision(1, true);
    let mut funded = vec![];
    for (tag, account) in accounts.iter().enumerate() {
        let ws = watch(&st, *account);
        let received = receive(tag as u8 + 1, external(&ws), 40_000, below_target(&ws, 3));
        cover(&mut st, *account, &fixture, vec![received.clone()]);
        funded.push(received);
    }
    qualify(&mut st, &fixture);
    set_policy(&mut st, PrivateRequired);
    for account in &accounts {
        activate_recovered_ledger(&mut st, *account).unwrap();
    }
    // Both ledgers lag a new block; the second owner's recovery is also suspended.
    scan_new_blocks(&mut st, 1);
    conn(&st)
        .execute(
            "INSERT INTO tpir_quarantined_accounts SELECT id FROM accounts WHERE uuid = ?1",
            [accounts[1].expose_uuid()],
        )
        .unwrap();
    let target = next_target(&st);
    let select = |addresses: &[TransparentAddress]| {
        st.wallet()
            .db()
            .get_spendable_transparent_outputs_for_addresses(
                addresses,
                target,
                ConfirmationsPolicy::MIN,
                CoinbaseFilter::AllTransparentOutputs,
                LockFilter::Policy(&LockedInputPolicy::Exclude),
            )
            .map(|outputs| outputs.len())
    };
    let pending_only_first = |result: Result<usize, SqliteClientError>| {
        matches!(
            result,
            Err(SqliteClientError::TransparentAuthorityUnavailable(
                AuthorityRefusal::Pending { accounts: pending }
            )) if pending == vec![accounts[0]]
        )
    };
    // Waiting can admit the first owner, so selection over both is pending on it alone.
    assert!(pending_only_first(select(&[
        funded[0].address,
        funded[1].address
    ])));
    assert!(pending_only_first(select(&[
        funded[1].address,
        funded[0].address
    ])));
    assert!(matches!(
        select(&[funded[1].address]),
        Err(SqliteClientError::TransparentAuthorityUnavailable(
            AuthorityRefusal::Refused(RefusalReason::NotAdmitted)
        ))
    ));
}

/// Asserts that `refusal` names none of `received`'s outpoint, txid or address.
fn names_nothing_of(st: &State, refusal: &Result<(), AuthorityRefusal>, received: &ReceiveEvent) {
    let message = refusal.as_ref().unwrap_err().to_string();
    let txid = received.outpoint.txid();
    for identifier in [
        txid.to_string(),
        hex::encode(txid.as_ref()),
        format!("{:?}", received.outpoint),
        Address::from(received.address).encode(st.network()),
    ] {
        assert!(!message.contains(&identifier), "{message}");
    }
}

#[test]
fn a_rewound_receive_waits_for_recovery_to_place_it_again() {
    let (mut st, account, _, unspent) = eligible_wallet();
    let input = [&unspent.outpoint];
    assert_eq!(check(&st, &input, next_target(&st)), Ok(()));

    // A rewind below the receive clears its placement. The replacement chain reaches past it,
    // and the account's recovery has yet to cover that chain.
    let floor = unspent.mined_height - 2;
    st.truncate_to_height(floor);
    scan_new_blocks(&mut st, 4);
    assert_eq!(
        snapshot(&st, account).blockers,
        vec![RecoveryBlocker::Recovery(
            CandidateBlocker::IncompleteCoverage
        )]
    );
    let target = next_target(&st);
    let waiting = check(&st, &input, target);
    assert_eq!(waiting, pending(account));
    names_nothing_of(&st, &waiting, &unspent);
    // Direct lookup classifies the same way.
    let lookup = st
        .wallet()
        .db()
        .get_unspent_transparent_output(&unspent.outpoint, target);
    assert!(
        matches!(
            &lookup,
            Err(SqliteClientError::TransparentAuthorityUnavailable(
                AuthorityRefusal::Pending { accounts }
            )) if accounts == &vec![account]
        ),
        "{lookup:?}"
    );

    // A pass that places the receive again on the new chain admits it.
    let remined = ReceiveEvent {
        mined_height: floor + 3,
        ..unspent.clone()
    };
    cover(&mut st, account, &revision(1, true), vec![remined]);
    assert_eq!(check(&st, &input, target), Ok(()));
}

#[test]
fn a_rewound_receive_covered_without_placement_is_withdrawn() {
    let (mut st, account, _, unspent) = eligible_wallet();
    st.truncate_to_height(unspent.mined_height - 2);
    scan_new_blocks(&mut st, 4);
    // Recovery covers the replacement chain, which does not mine the receive.
    cover(&mut st, account, &revision(1, true), vec![]);
    let refusal = check(&st, &[&unspent.outpoint], next_target(&st));
    assert_eq!(refusal, refused(RefusalReason::Withdrawn));
    names_nothing_of(&st, &refusal, &unspent);
}

#[test]
fn a_withdrawn_receive_is_refused_while_recovery_catches_up() {
    let (mut st, account, received, replacement) = super::withdrawal::provisional_wallet(false);
    let input = [&received.outpoint];
    assert_eq!(check(&st, &input, next_target(&st)), Ok(()));

    // The replacement revision drops the receive. Waiting cannot restore it, even while the
    // account's recovery has yet to cover the replacement.
    qualify(&mut st, &replacement);
    assert!(
        snapshot(&st, account)
            .blockers
            .contains(&RecoveryBlocker::Recovery(
                CandidateBlocker::IncompleteCoverage
            ))
    );
    let refusal = check(&st, &input, next_target(&st));
    assert_eq!(refusal, refused(RefusalReason::Withdrawn));
    names_nothing_of(&st, &refusal, &received);

    cover(&mut st, account, &replacement, vec![]);
    assert_eq!(
        check(&st, &input, next_target(&st)),
        refused(RefusalReason::Withdrawn)
    );
}

#[test]
fn a_rewound_receive_withdrawn_before_recovery_places_it_is_refused() {
    let (mut st, account, received, replacement) = super::withdrawal::provisional_wallet(false);
    st.truncate_to_height(received.mined_height - 2);
    scan_new_blocks(&mut st, 4);
    let input = [&received.outpoint];
    assert_eq!(check(&st, &input, next_target(&st)), pending(account));
    // Withdrawal removes the unplaced receive, so nothing remains to wait for.
    qualify(&mut st, &replacement);
    assert_eq!(
        check(&st, &input, next_target(&st)),
        refused(RefusalReason::Withdrawn)
    );
}

/// Re-places `received` on the replacement chain at `floor + 3` and covers it.
fn place_again(st: &mut State, account: AccountUuid, received: &ReceiveEvent, floor: BlockHeight) {
    let remined = ReceiveEvent {
        mined_height: floor + 3,
        ..received.clone()
    };
    cover(st, account, &revision(1, true), vec![remined]);
}

#[test]
fn a_rewound_receive_waits_past_the_default_expiry() {
    let (mut st, account, _, unspent) = eligible_wallet();
    let input = [&unspent.outpoint];
    // The receive's transaction is known only from recovery, so its expiry is unknown. After a
    // rewind clears its placement, the replacement chain outgrows the default expiry guess
    // before recovery covers it.
    let floor = unspent.mined_height - 2;
    st.truncate_to_height(floor);
    scan_new_blocks(&mut st, 45);
    let target = next_target(&st);
    assert!(BlockHeight::from(target) > unspent.mined_height + DEFAULT_TX_EXPIRY_DELTA);
    assert_eq!(check(&st, &input, target), pending(account));
    let lookup = st
        .wallet()
        .db()
        .get_unspent_transparent_output(&unspent.outpoint, target);
    assert!(
        matches!(
            &lookup,
            Err(SqliteClientError::TransparentAuthorityUnavailable(
                AuthorityRefusal::Pending { accounts }
            )) if accounts == &vec![account]
        ),
        "{lookup:?}"
    );

    place_again(&mut st, account, &unspent, floor);
    assert_eq!(check(&st, &input, target), Ok(()));
}

#[test]
fn a_rewound_receive_waits_past_its_known_expiry() {
    let (mut st, account, _, unspent) = eligible_wallet();
    let input = [&unspent.outpoint];
    // Enhancement recorded the receive's transaction expiry, which the replacement chain passes
    // before recovery places the receive again.
    let expiry = unspent.mined_height + 5;
    conn(&st)
        .execute(
            "UPDATE transactions SET expiry_height = ?1 WHERE txid = ?2",
            rusqlite::params![u32::from(expiry), unspent.outpoint.hash()],
        )
        .unwrap();
    let floor = unspent.mined_height - 2;
    st.truncate_to_height(floor);
    scan_new_blocks(&mut st, 10);
    let target = next_target(&st);
    assert!(BlockHeight::from(target) > expiry);
    assert_eq!(check(&st, &input, target), pending(account));

    place_again(&mut st, account, &unspent, floor);
    assert_eq!(check(&st, &input, target), Ok(()));
}

#[test]
fn a_rewound_receive_public_history_also_holds_keeps_its_expiry() {
    let (mut st, account, _, unspent) = eligible_wallet();
    // Public discovery also found the output, whose transaction's expiry enhancement recorded.
    let expiry = unspent.mined_height + 5;
    conn(&st)
        .execute(
            "INSERT INTO tpir_output_origins (output_id, origin)
             SELECT u.id, 0 FROM transparent_received_outputs u
             JOIN transactions t ON t.id_tx = u.transaction_id
             WHERE t.txid = ?1 AND u.output_index = ?2",
            rusqlite::params![unspent.outpoint.hash(), unspent.outpoint.n()],
        )
        .unwrap();
    conn(&st)
        .execute(
            "UPDATE transactions SET expiry_height = ?1 WHERE txid = ?2",
            rusqlite::params![u32::from(expiry), unspent.outpoint.hash()],
        )
        .unwrap();
    // A rewind leaves the receive unplaced; the user then turns private queries off, which
    // keeps the ledger's events. The replacement chain passes the expiry.
    st.truncate_to_height(unspent.mined_height - 2);
    set_policy(&mut st, TransparentLedgerMode::Public);
    scan_new_blocks(&mut st, 10);
    let target = next_target(&st);
    assert!(BlockHeight::from(target) > expiry);
    // Public history is no evidence the transaction was mined: it expired, and is not spendable.
    assert_eq!(
        check(&st, &[&unspent.outpoint], target),
        refused(RefusalReason::Expired)
    );
    assert!(
        st.wallet()
            .db()
            .get_unspent_transparent_output(&unspent.outpoint, target)
            .unwrap()
            .is_none()
    );
}

/// Covers every watched address of `account` through the target from `revision`, adding
/// `spends`, and repeats while the window grows.
fn cover_spends(
    st: &mut State,
    account: AccountUuid,
    revision: &RecoveryRevision,
    spends: Vec<SpendEvent>,
) {
    let mut spends = Some(spends);
    loop {
        let ws = watch(st, account);
        let mut c = commit(&ws);
        c.revision = revision.clone();
        c.spends = spends.take().unwrap_or_default();
        c.coverage = full_coverage(&ws);
        if !apply(st, c).unwrap().window_grew {
            break;
        }
    }
}

#[test]
fn a_rewound_spend_keeps_its_output_out_until_recovery_settles_it() {
    let (mut st, account, _, spent) = ready_wallet();
    activate_recovered_ledger(&mut st, account).unwrap();
    // `ready_wallet` spends the output two blocks after receiving it. A rewind between the two
    // keeps the receive and clears the spend's placement.
    let floor = spent.mined_height + 1;
    st.truncate_to_height(floor);
    let input = [&spent.outpoint];

    // While the spender may still be mined again, it competes with any new spend.
    scan_new_blocks(&mut st, 4);
    assert_eq!(
        check(&st, &input, next_target(&st)),
        refused(RefusalReason::CompetingSpend)
    );
    // Past the default expiry guess the spender no longer counts, but recovery has yet to cover
    // the replacement chain: the output waits rather than becoming spendable.
    scan_new_blocks(&mut st, DEFAULT_TX_EXPIRY_DELTA as usize);
    assert_eq!(check(&st, &input, next_target(&st)), pending(account));

    // Recovery places the spend again on the replacement chain.
    cover_spends(
        &mut st,
        account,
        &revision(1, true),
        vec![spend(3, &spent, floor + 2)],
    );
    assert_eq!(
        check(&st, &input, next_target(&st)),
        refused(RefusalReason::CompetingSpend)
    );
}
