//! The account's transparent ledger snapshot: authority, authorized balance, last-known amount
//! and blockers, read together.

use zcash_client_backend::data_api::{
    transparent_ledger::{
        ChainPoint, LastKnownBalance, LastKnownSource, RecoveryBlocker, RecoveryCompletion,
        TransparentAuthority, TransparentLedgerBalance, TransparentLedgerMode,
        TransparentLedgerSnapshot,
    },
    wallet::{ConfirmationsPolicy, TargetHeight},
};
use zcash_protocol::{
    consensus::{self, BlockHeight},
    value::Zatoshis,
};

use crate::{AccountUuid, error::SqliteClientError, wallet::chain_tip_height};

#[cfg(feature = "transparent-inputs")]
use {
    super::recovery,
    zcash_client_backend::data_api::{AccountBalance, transparent_ledger::AccountLifecycle},
    zcash_keys::keys::transparent::gap_limits::GapLimits,
};

/// Reads the account's transparent balance, counting only ledger-projected outputs when
/// `ledger_only`. Without transparent support this build cannot read transparent state that
/// another build may have written, so it reports none rather than a zero balance.
#[cfg(feature = "transparent-inputs")]
fn transparent_balance(
    conn: &rusqlite::Connection,
    account: AccountUuid,
    target_height: TargetHeight,
    confirmations_policy: ConfirmationsPolicy,
    ledger_only: bool,
) -> Result<Option<TransparentLedgerBalance>, SqliteClientError> {
    let mut balances = std::collections::HashMap::<AccountUuid, AccountBalance>::new();
    crate::wallet::transparent::add_transparent_account_balances(
        conn,
        target_height,
        confirmations_policy,
        ledger_only,
        Some(account),
        &mut balances,
    )?;
    let balance = balances.remove(&account).unwrap_or(AccountBalance::ZERO);
    Ok(Some(TransparentLedgerBalance {
        regular: *balance.unshielded_regular_balance(),
        coinbase: *balance.unshielded_coinbase_balance(),
    }))
}

#[cfg(not(feature = "transparent-inputs"))]
fn transparent_balance(
    _: &rusqlite::Connection,
    _: AccountUuid,
    _: TargetHeight,
    _: ConfirmationsPolicy,
    _: bool,
) -> Result<Option<TransparentLedgerBalance>, SqliteClientError> {
    Ok(None)
}

/// The private ledger's part of a snapshot.
struct PrivateView {
    authority: Option<TransparentLedgerBalance>,
    last_known: Option<LastKnownBalance>,
    blockers: Vec<RecoveryBlocker>,
    covered_through: Option<ChainPoint>,
    recovered_unverified: Option<Zatoshis>,
}

/// Reads `account`'s private ledger for a `PrivateRequired` snapshot targeting the block after
/// `tip`.
#[cfg(feature = "transparent-inputs")]
fn private_view<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    gap_limits: &GapLimits,
    account: AccountUuid,
    tip: BlockHeight,
    confirmations_policy: ConfirmationsPolicy,
) -> Result<PrivateView, SqliteClientError> {
    let ledger = recovery::account_ledger(conn, params, gap_limits, account)?;
    let target = TargetHeight::from(tip + 1);
    let covered_through = match ledger.status.covered_through {
        Some(height) => {
            crate::wallet::get_block_hash(conn, height)?.map(|hash| ChainPoint { height, hash })
        }
        None => None,
    };
    let (authority, last_known, blockers) = if ledger.authorizes_after(tip) {
        (
            transparent_balance(conn, account, target, confirmations_policy, true)?,
            None,
            vec![],
        )
    } else {
        let last_known = match ledger.lifecycle {
            // An active account's own ledger is the best prior amount. It is evaluated after
            // the tip, so it is established at the covered point only when coverage reaches the
            // tip; while coverage lags, placed events above it may already count.
            AccountLifecycle::Active => {
                let at = covered_through.filter(|point| point.height == tip);
                transparent_balance(conn, account, target, confirmations_policy, true)?.map(
                    |balance| LastKnownBalance {
                        balance,
                        source: LastKnownSource::PrivateLedger,
                        at,
                    },
                )
            }
            AccountLifecycle::Candidate => {
                legacy_last_known(conn, account, target, confirmations_policy)?
            }
        };
        (
            None,
            last_known,
            recovery::ledger_blockers(conn, &ledger, Some(tip))?,
        )
    };
    Ok(PrivateView {
        authority,
        last_known,
        blockers,
        covered_through,
        recovered_unverified: ledger.status.recovered_unverified,
    })
}

/// Without transparent support there is no private ledger to read.
#[cfg(not(feature = "transparent-inputs"))]
fn private_view(
    conn: &rusqlite::Connection,
    account: AccountUuid,
    tip: BlockHeight,
    confirmations_policy: ConfirmationsPolicy,
) -> Result<PrivateView, SqliteClientError> {
    Ok(PrivateView {
        authority: None,
        last_known: legacy_last_known(
            conn,
            account,
            TargetHeight::from(tip + 1),
            confirmations_policy,
        )?,
        blockers: vec![
            RecoveryBlocker::TransparentSupportUnavailable,
            RecoveryBlocker::PrivateRecoveryUnavailable,
        ],
        covered_through: None,
        recovered_unverified: None,
    })
}

/// The account's whole transparent balance as last-known evidence, classified by provenance.
fn legacy_last_known(
    conn: &rusqlite::Connection,
    account: AccountUuid,
    target: TargetHeight,
    confirmations_policy: ConfirmationsPolicy,
) -> Result<Option<LastKnownBalance>, SqliteClientError> {
    transparent_balance(conn, account, target, confirmations_policy, false)?
        .map(|balance| {
            Ok(LastKnownBalance {
                balance,
                source: last_known_source(conn, account, target, confirmations_policy)?,
                at: None,
            })
        })
        .transpose()
}

/// Builds the snapshot for `account` from the connection's current state. The caller provides
/// the read transaction.
pub(crate) fn snapshot<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    #[cfg_attr(not(feature = "transparent-inputs"), allow(unused_variables))] params: &P,
    #[cfg(feature = "transparent-inputs")] gap_limits: &GapLimits,
    account: AccountUuid,
    mode: TransparentLedgerMode,
    confirmations_policy: ConfirmationsPolicy,
) -> Result<TransparentLedgerSnapshot<AccountUuid>, SqliteClientError> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM accounts WHERE uuid = ?1)",
        [account.0],
        |row| row.get(0),
    )?;
    if !exists {
        return Err(SqliteClientError::AccountUnknown);
    }

    let blocked = |blockers| TransparentLedgerSnapshot {
        account,
        mode,
        authority: TransparentAuthority::Unavailable,
        authorized: None,
        last_known: None,
        completion: RecoveryCompletion::Blocked,
        blockers,
        covered_through: None,
        recovered_unverified: None,
    };
    // Authority cannot be established before the chain is known.
    let Some(tip) = chain_tip_height(conn)? else {
        return Ok(blocked(vec![RecoveryBlocker::ChainUnknown]));
    };
    let target = TargetHeight::from(tip + 1);

    if mode.retains_public_authority() {
        // A build that cannot read transparent state never reports public authority.
        let Some(balance) =
            transparent_balance(conn, account, target, confirmations_policy, false)?
        else {
            return Ok(blocked(vec![
                RecoveryBlocker::TransparentSupportUnavailable,
            ]));
        };
        return Ok(TransparentLedgerSnapshot {
            account,
            mode,
            authority: TransparentAuthority::Public,
            authorized: Some(balance),
            last_known: None,
            completion: RecoveryCompletion::NotApplicable,
            blockers: vec![],
            covered_through: None,
            recovered_unverified: None,
        });
    }

    #[cfg(feature = "transparent-inputs")]
    let private = private_view(conn, params, gap_limits, account, tip, confirmations_policy)?;
    #[cfg(not(feature = "transparent-inputs"))]
    let private = private_view(conn, account, tip, confirmations_policy)?;
    let (covered_through, recovered_unverified) =
        (private.covered_through, private.recovered_unverified);
    Ok(match private.authority {
        Some(balance) => TransparentLedgerSnapshot {
            account,
            mode,
            authority: TransparentAuthority::Private,
            authorized: Some(balance),
            last_known: None,
            completion: RecoveryCompletion::Complete,
            blockers: vec![],
            covered_through,
            recovered_unverified,
        },
        None => TransparentLedgerSnapshot {
            account,
            mode,
            authority: TransparentAuthority::Unavailable,
            authorized: None,
            last_known: private.last_known,
            completion: RecoveryCompletion::Blocked,
            blockers: private.blockers,
            covered_through,
            recovered_unverified,
        },
    })
}

/// Classifies the provenance of the outputs counted in the account's transparent balance.
#[cfg(feature = "transparent-inputs")]
fn last_known_source(
    conn: &rusqlite::Connection,
    account: AccountUuid,
    target_height: TargetHeight,
    confirmations_policy: ConfirmationsPolicy,
) -> Result<LastKnownSource, SqliteClientError> {
    use crate::wallet::transparent::{BalanceProvenance, transparent_balance_provenance};
    Ok(
        match transparent_balance_provenance(conn, account, target_height, confirmations_policy)? {
            BalanceProvenance::LegacyPublic => LastKnownSource::LegacyPublic,
            BalanceProvenance::IncludesLocalOnly => LastKnownSource::LegacyPublicAndLocal,
        },
    )
}

/// Without transparent support no balance is read, so no last-known amount is classified.
#[cfg(not(feature = "transparent-inputs"))]
fn last_known_source(
    _: &rusqlite::Connection,
    _: AccountUuid,
    _: TargetHeight,
    _: ConfirmationsPolicy,
) -> Result<LastKnownSource, SqliteClientError> {
    Ok(LastKnownSource::LegacyPublic)
}
