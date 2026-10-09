//! Coinbase maturity applies to direct input lookup and the final storage boundary too.

use transparent::{
    address::Script,
    bundle::{Bundle, TxIn, TxOut},
};
use zcash_client_backend::data_api::SentTransaction;
use zcash_primitives::transaction::{Authorized, TransactionData, TxVersion};
use zcash_protocol::consensus::BranchId;

use super::*;

/// Exercises storage authorization directly, as an externally finalized transaction would.
/// The synthetic signature is deliberately not a cryptographic validation test.
pub(super) fn store_spend(
    st: &mut State,
    account: AccountUuid,
    received: &ReceiveEvent,
) -> Result<(), SqliteClientError> {
    let target = next_target(st);
    let tx = TransactionData::<Authorized>::from_parts(
        TxVersion::V5,
        BranchId::Nu5,
        0,
        BlockHeight::from(target) + 20,
        Some(Bundle {
            vin: vec![TxIn::from_parts(
                received.outpoint.clone(),
                Script::default(),
                u32::MAX,
            )],
            vout: vec![TxOut::new(
                Zatoshis::const_from_u64(20_000),
                TransparentAddress::PublicKeyHash([7; 20]).script().into(),
            )],
            authorization: transparent::bundle::Authorized,
        }),
        None,
        None,
        None,
    )
    .freeze()
    .unwrap();
    st.wallet_mut()
        .db_mut()
        .store_transactions_to_be_sent(&[SentTransaction::new(
            &tx,
            time::OffsetDateTime::UNIX_EPOCH,
            target,
            account,
            &[],
            Zatoshis::const_from_u64(20_000),
            std::slice::from_ref(&received.outpoint),
        )])
}

fn coinbase_wallet() -> (State, AccountUuid, ReceiveEvent, RecoveryRevision) {
    let (mut st, accounts) = recovery_wallet_with(0);
    let account = accounts[0];
    let fixture = revision(1, true);
    let ws = watch(&st, account);
    let coinbase = ReceiveEvent {
        coinbase: true,
        ..receive(51, external(&ws), 40_000, below_target(&ws, 3))
    };
    cover(&mut st, account, &fixture, vec![coinbase.clone()]);
    qualify(&mut st, &fixture);
    set_policy(&mut st, PrivateRequired);
    promote(&mut st, account).unwrap();
    (st, account, coinbase, fixture)
}

#[test]
fn externally_finalized_immature_coinbase_is_rejected_without_writes() {
    let (mut st, account, coinbase, _) = coinbase_wallet();
    let before = production_dump(conn(&st));
    assert!(matches!(
        store_spend(&mut st, account, &coinbase),
        Err(SqliteClientError::TransparentAuthorityUnavailable)
    ));
    assert_eq!(production_dump(conn(&st)), before);
}

#[test]
fn maturity_boundary_governs_every_selector_and_final_storage() {
    let (mut st, account, coinbase, fixture) = coinbase_wallet();
    let confirmations = u32::from(next_target(&st)) - u32::from(coinbase.mined_height);
    scan_new_blocks(&mut st, (99 - confirmations) as usize);
    cover(&mut st, account, &fixture, vec![]);
    assert_eq!(
        u32::from(next_target(&st)) - u32::from(coinbase.mined_height),
        99
    );
    for selection in selections(
        &st,
        account,
        &[coinbase.address],
        &coinbase.outpoint,
        next_target(&st),
    ) {
        assert_eq!(selection.unwrap(), vec![]);
    }
    let before = production_dump(conn(&st));
    assert!(matches!(
        store_spend(&mut st, account, &coinbase),
        Err(SqliteClientError::TransparentAuthorityUnavailable)
    ));
    assert_eq!(production_dump(conn(&st)), before);

    assert!(
        crate::wallet::transparent::get_wallet_transparent_output(
            conn(&st),
            &coinbase.outpoint,
            None,
            &crate::wallet::transparent_ledger::InputAuthority::Public,
        )
        .unwrap()
        .is_some()
    );
    set_policy(&mut st, Public);
    for selection in selections(
        &st,
        account,
        &[coinbase.address],
        &coinbase.outpoint,
        next_target(&st),
    ) {
        assert_eq!(selection.unwrap(), vec![]);
    }
    set_policy(&mut st, PrivateRequired);
    promote(&mut st, account).unwrap();

    scan_new_blocks(&mut st, 1);
    cover(&mut st, account, &fixture, vec![]);
    assert_eq!(
        u32::from(next_target(&st)) - u32::from(coinbase.mined_height),
        100
    );
    for selection in selections(
        &st,
        account,
        &[coinbase.address],
        &coinbase.outpoint,
        next_target(&st),
    ) {
        assert_eq!(selection.unwrap(), vec![coinbase.outpoint.clone()]);
    }
    store_spend(&mut st, account, &coinbase).unwrap();
    assert_eq!(spend_count(&st, &coinbase.outpoint), 1);
}
