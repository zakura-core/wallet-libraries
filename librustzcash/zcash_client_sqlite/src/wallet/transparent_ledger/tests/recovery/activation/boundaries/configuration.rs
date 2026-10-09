use super::*;

#[test]
fn combined_handle_modes_preserve_durable_policy_and_stale_commit_checks() {
    use zcash_client_backend::data_api::{
        enhance_pir::EnhancementMode, status::TransactionStatusMode,
    };
    let (mut st, account) = recovery_wallet();
    set_policy(&mut st, Public);
    let captured = commit(&watch(&st, account));
    let db = st.wallet_mut().db_mut();
    db.set_handle_modes(crate::WalletHandleModes {
        status: TransactionStatusMode::Private,
        transparent_ledger: PrivateRequired,
        enhancement: EnhancementMode::PrivateIronwood,
    });
    // Configuring a handle alone does not persist a policy transition.
    assert_eq!(db.applied_transparent_policy().unwrap().mode, Public);
    db.apply_transparent_policy(PrivateRequired).unwrap();
    assert!(matches!(
        apply(&mut st, captured),
        Err(SqliteClientError::StaleTransparentPolicy { .. })
    ));
    st.wallet_mut()
        .db_mut()
        .set_handle_modes(crate::WalletHandleModes {
            status: TransactionStatusMode::Public,
            transparent_ledger: Public,
            enhancement: EnhancementMode::Standard,
        });
    // The weaker handle operates under the durable policy, which reading never lowers.
    assert_eq!(
        st.wallet().db().transparent_ledger_mode().unwrap(),
        PrivateRequired
    );
    assert_eq!(
        st.wallet().db().applied_transparent_policy().unwrap().mode,
        PrivateRequired
    );
}
