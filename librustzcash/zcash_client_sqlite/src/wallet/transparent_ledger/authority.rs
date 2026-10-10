//! Transparent authority: whether a handle may consume transparent inputs, record publicly
//! discovered data, or report transparent funds as current.

use zcash_client_backend::data_api::transparent_ledger::TransparentLedgerMode;

use crate::{
    error::{AuthorityRefusal, RefusalReason, SqliteClientError},
    wallet::chain_tip_height,
};

use zcash_client_backend::data_api::transparent_ledger::AppliedTransparentPolicy;

use super::policy::{durable_policy, resolve_mode};

#[cfg(feature = "transparent-inputs")]
use {
    super::recovery,
    crate::{AccountRef, AccountUuid},
    zcash_client_backend::data_api::{
        transparent_ledger::{AccountLifecycle, CandidateBlocker, RecoveryBlocker},
        wallet::TargetHeight,
    },
    zcash_keys::keys::transparent::gap_limits::GapLimits,
    zcash_protocol::consensus::{self, BlockHeight},
};

/// Whether the handle may grant private authority: qualify a revision or activate an account.
///
/// That requires a handle explicitly configured `PrivateRequired` over a durable
/// `PrivateRequired` policy. A weaker handle reads under the durable policy (see
/// [`resolve_mode`]) but never grants authority under it.
pub(crate) fn grants_private_authority(
    conn: &rusqlite::Connection,
    configured: Option<TransparentLedgerMode>,
) -> Result<bool, SqliteClientError> {
    let configured = configured.ok_or(SqliteClientError::TransparentLedgerModeNotConfigured)?;
    Ok(configured == TransparentLedgerMode::PrivateRequired
        && durable_policy(conn)?.map(|policy| policy.mode)
            == Some(TransparentLedgerMode::PrivateRequired))
}

/// The error refusing transparent inputs for `reason`.
pub(crate) fn refused(reason: RefusalReason) -> SqliteClientError {
    SqliteClientError::TransparentAuthorityUnavailable(AuthorityRefusal::Refused(reason))
}

/// Checks that the handle may authorize consuming transparent inputs.
///
/// Public authority is retained only by explicitly configured `Public` handles; financial
/// authorization never defaults to public. Even then it requires the same conditions under which
/// the snapshot reports public authority: a known chain tip, and a build that can read
/// transparent state. `PrivateRequired` handles are rejected: private authority is
/// per account, and [`input_authority`] resolves it where transparent support exists.
pub(crate) fn check_transparent_authority(
    conn: &rusqlite::Connection,
    configured: Option<TransparentLedgerMode>,
) -> Result<(), SqliteClientError> {
    match resolve_mode(conn, configured)? {
        TransparentLedgerMode::PrivateRequired => Err(refused(RefusalReason::NoAuthority)),
        TransparentLedgerMode::Public => {
            if cfg!(not(feature = "transparent-inputs")) {
                Err(refused(RefusalReason::NoAuthority))
            } else if chain_tip_height(conn)?.is_none() {
                Err(refused(RefusalReason::ChainUnknown))
            } else {
                Ok(())
            }
        }
    }
}

/// Which transparent outputs the handle's transparent authority admits as inputs.
#[cfg(feature = "transparent-inputs")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InputAuthority {
    /// Public authority admits every output.
    Public,
    /// Private authority admits only ledger-projected outputs of these accounts.
    Private(Vec<AccountRef>),
}

#[cfg(feature = "transparent-inputs")]
impl InputAuthority {
    /// The `:private_authority` and `:eligible_accounts` parameters of the input-authority SQL
    /// condition.
    pub(crate) fn sql_params(&self) -> (bool, std::rc::Rc<Vec<rusqlite::types::Value>>) {
        match self {
            Self::Public => (false, std::rc::Rc::new(vec![])),
            Self::Private(accounts) => (
                true,
                std::rc::Rc::new(
                    accounts
                        .iter()
                        .map(|a| rusqlite::types::Value::Integer(a.0))
                        .collect(),
                ),
            ),
        }
    }

    /// Whether private authority admits `account`'s outputs; public authority admits all.
    pub(crate) fn admits(&self, account: AccountRef) -> bool {
        match self {
            Self::Public => true,
            Self::Private(accounts) => accounts.contains(&account),
        }
    }

    /// Whether the authority admits an output of `account`, `placed` when the private ledger
    /// places the receive it is projected from. Private authority admits only placed outputs.
    pub(crate) fn admits_output(&self, account: AccountRef, placed: bool) -> bool {
        match self {
            Self::Public => true,
            Self::Private(accounts) => placed && accounts.contains(&account),
        }
    }
}

/// Resolves which outputs may fund a transaction targeting `target`.
///
/// Public authority follows [`check_transparent_authority`]. Under `PrivateRequired`, an
/// account is eligible when it is active and not suspended, its ledger has no blockers, and
/// both its covered local target and the chain tip are `target - 1`: coverage through `H`
/// supports a transaction targeting `H + 1`, with no freshness tolerance. The caller provides
/// the read snapshot.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn input_authority<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    gap_limits: &GapLimits,
    configured: Option<TransparentLedgerMode>,
    target: TargetHeight,
) -> Result<InputAuthority, SqliteClientError> {
    if resolve_mode(conn, configured)?.retains_public_authority() {
        check_transparent_authority(conn, configured)?;
        return Ok(InputAuthority::Public);
    }
    let Some(tip) = chain_tip_height(conn)? else {
        return Err(refused(RefusalReason::ChainUnknown));
    };
    if BlockHeight::from(target) != tip + 1 {
        return Ok(InputAuthority::Private(vec![]));
    }
    let mut stmt = conn.prepare_cached(
        "SELECT a.uuid FROM tpir_active_accounts t JOIN accounts a ON a.id = t.account_id",
    )?;
    let active = stmt
        .query_map([], |row| row.get(0).map(AccountUuid))?
        .collect::<Result<Vec<_>, _>>()?;
    let mut eligible = vec![];
    for account in active {
        let ledger = recovery::account_ledger(conn, params, gap_limits, account)?;
        if ledger.authorizes_after(tip) {
            eligible.push(ledger.account_ref);
        }
    }
    Ok(InputAuthority::Private(eligible))
}

/// Why private authority, which does not admit `account`, keeps its outputs out of a
/// transaction targeting `target`, or `None` when only private recovery catching up does: see
/// [`AuthorityRefusal::Pending`]. The caller provides the read snapshot.
///
/// That requires an active account not suspended from recovery, at a target above the chain tip, whose only
/// blockers are `Recovery(IncompleteCoverage)` and `ChainBehindTip`. Any other blocker, such as
/// open pages, unresolved spends or an unknown local chain point, is
/// [`RefusalReason::NotAdmitted`]. An account blocked by nothing at the block after the tip
/// would be admitted; one that is not lacks authority for a reason no blocker names, which
/// waiting does not resolve.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn private_exclusion<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    gap_limits: &GapLimits,
    account: AccountUuid,
    target: TargetHeight,
) -> Result<Option<RefusalReason>, SqliteClientError> {
    let Some(tip) = chain_tip_height(conn)? else {
        return Ok(Some(RefusalReason::ChainUnknown));
    };
    let target = BlockHeight::from(target);
    if target <= tip {
        return Ok(Some(RefusalReason::StaleTarget));
    }
    let ledger = recovery::account_ledger(conn, params, gap_limits, account)?;
    if ledger.lifecycle != AccountLifecycle::Active || ledger.recovery_suspended {
        return Ok(Some(RefusalReason::NotAdmitted));
    }
    let blockers = recovery::ledger_blockers(conn, &ledger, Some(tip))?;
    let catching_up = blockers.iter().all(|blocker| {
        matches!(
            blocker,
            RecoveryBlocker::Recovery(CandidateBlocker::IncompleteCoverage)
                | RecoveryBlocker::ChainBehindTip
        )
    });
    if !catching_up || (target == tip + 1 && blockers.is_empty()) {
        return Ok(Some(RefusalReason::NotAdmitted));
    }
    Ok(None)
}

/// The refusal of inputs that `authority` does not admit, owned by `account` (`account_ref`):
/// [`RefusalReason::NotInLedger`] when the account holds private authority and the output is
/// not `placed`, and otherwise its [`private_exclusion`], recording a pending account in
/// `pending` once.
#[cfg(feature = "transparent-inputs")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn refuse_unadmitted_input<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    gap_limits: &GapLimits,
    authority: &InputAuthority,
    account: AccountUuid,
    account_ref: AccountRef,
    target: TargetHeight,
    pending: &mut Vec<AccountUuid>,
) -> Result<(), SqliteClientError> {
    if authority.admits(account_ref) {
        return Err(refused(RefusalReason::NotInLedger));
    }
    exclude_or_defer(conn, params, gap_limits, account, target, pending)
}

/// The refusal of an input projected only from a ledger receive that a rewind left unplaced,
/// owned by `account` (`account_ref`): [`RefusalReason::Withdrawn`] when `authority` admits
/// the account, whose recovery then covers the tip without placing the receive again, and
/// otherwise its [`private_exclusion`], recording a pending account in `pending` once. An
/// account catching up may place the receive again; a withdrawn receive has no event left, so
/// it never reaches this check.
#[cfg(feature = "transparent-inputs")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn refuse_unplaced_input<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    gap_limits: &GapLimits,
    authority: &InputAuthority,
    account: AccountUuid,
    account_ref: AccountRef,
    target: TargetHeight,
    pending: &mut Vec<AccountUuid>,
) -> Result<(), SqliteClientError> {
    if authority.admits(account_ref) {
        return Err(refused(RefusalReason::Withdrawn));
    }
    exclude_or_defer(conn, params, gap_limits, account, target, pending)
}

/// Refuses an input of `account` for its [`private_exclusion`], or records the account in
/// `pending` once when only private recovery catching up keeps the input out.
#[cfg(feature = "transparent-inputs")]
fn exclude_or_defer<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    gap_limits: &GapLimits,
    account: AccountUuid,
    target: TargetHeight,
    pending: &mut Vec<AccountUuid>,
) -> Result<(), SqliteClientError> {
    match private_exclusion(conn, params, gap_limits, account, target)? {
        Some(reason) => Err(refused(reason)),
        None => {
            if !pending.contains(&account) {
                pending.push(account);
            }
            Ok(())
        }
    }
}

/// The result of an input check that refused nothing outright: success, or
/// [`AuthorityRefusal::Pending`] for the accounts in `pending`.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn pending_result(pending: Vec<AccountUuid>) -> Result<(), SqliteClientError> {
    if pending.is_empty() {
        Ok(())
    } else {
        Err(SqliteClientError::TransparentAuthorityUnavailable(
            AuthorityRefusal::Pending { accounts: pending },
        ))
    }
}

/// Fails when private authority admits none of the accounts owning `addresses`. Selection over
/// several accounts' addresses otherwise proceeds with the eligible ones only, so the refusal
/// is pending when any owner is (see [`private_exclusion`]): its authority alone would let
/// selection proceed.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn check_address_owners<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    gap_limits: &GapLimits,
    authority: &InputAuthority,
    addresses: &[transparent::address::TransparentAddress],
    target: TargetHeight,
) -> Result<(), SqliteClientError> {
    let InputAuthority::Private(_) = authority else {
        return Ok(());
    };
    // Resolve owners as receiving does, including a legacy external receiver without a row.
    let mut owners = vec![];
    for address in addresses {
        if let Some((account, _)) =
            crate::wallet::transparent::find_account_uuid_for_transparent_address(
                conn, params, address,
            )?
        {
            owners.push((account, crate::wallet::get_account_ref(conn, account)?));
        }
    }
    if owners.is_empty() || owners.iter().any(|(_, owner)| authority.admits(*owner)) {
        return Ok(());
    }
    let mut pending = vec![];
    let mut reason = None;
    for (account, _) in owners {
        match private_exclusion(conn, params, gap_limits, account, target)? {
            None if !pending.contains(&account) => pending.push(account),
            None => {}
            Some(refusal) => {
                reason.get_or_insert(refusal);
            }
        }
    }
    match reason {
        Some(reason) if pending.is_empty() => Err(refused(reason)),
        _ => pending_result(pending),
    }
}

#[cfg(feature = "transparent-inputs")]
/// Returns whether public transparent discovery is permitted for this handle. It requires an
/// explicitly configured mode that retains public authority.
///
/// This equals [`retains_public_authority`](super::retains_public_authority) for a configured
/// handle, but fails for an unconfigured one, where that lower-level check consults the durable
/// policy alone.
pub(crate) fn public_discovery_permitted(
    conn: &rusqlite::Connection,
    configured: Option<TransparentLedgerMode>,
) -> Result<bool, SqliteClientError> {
    Ok(resolve_mode(conn, configured)?.retains_public_authority())
}

/// Rejects recording publicly discovered transparent data unless public discovery is permitted.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn check_public_discovery(
    conn: &rusqlite::Connection,
    configured: Option<TransparentLedgerMode>,
) -> Result<(), SqliteClientError> {
    if public_discovery_permitted(conn, configured)? {
        Ok(())
    } else {
        Err(SqliteClientError::PublicTransparentDiscoveryForbidden)
    }
}

/// Returns whether balance reads may report transparent funds as current.
///
/// This applies the snapshot's availability rules: no current transparent authority exists
/// under a required-private policy (configured on the handle or durably applied), before the
/// chain tip is known, or in a build that cannot read transparent state. The ledger snapshot
/// then reports the funds as last-known instead. Balance reads are display-only, so an
/// unconfigured handle on a wallet without a private policy keeps reporting them.
pub(crate) fn transparent_funds_current(
    conn: &rusqlite::Connection,
    configured: Option<TransparentLedgerMode>,
) -> Result<bool, SqliteClientError> {
    Ok(transparent_funds_refusal(conn, configured)?.is_none())
}

/// Why balance reads may not report transparent funds as current (see
/// [`transparent_funds_current`]), in the order [`check_transparent_authority`] reports them:
/// [`RefusalReason::NoAuthority`] under a required-private policy or without transparent
/// support, then [`RefusalReason::ChainUnknown`] before the chain tip is known.
pub(crate) fn transparent_funds_refusal(
    conn: &rusqlite::Connection,
    configured: Option<TransparentLedgerMode>,
) -> Result<Option<RefusalReason>, SqliteClientError> {
    let durable_private = matches!(
        durable_policy(conn)?,
        Some(AppliedTransparentPolicy {
            mode: TransparentLedgerMode::PrivateRequired,
            ..
        })
    );
    Ok(
        if cfg!(not(feature = "transparent-inputs"))
            || durable_private
            || configured == Some(TransparentLedgerMode::PrivateRequired)
        {
            Some(RefusalReason::NoAuthority)
        } else if chain_tip_height(conn)?.is_none() {
            Some(RefusalReason::ChainUnknown)
        } else {
            None
        },
    )
}

/// Returns whether `tx` consumes transparent inputs. A locally stored transaction with
/// transparent inputs spends transparent funds, whatever its caller-supplied metadata claims,
/// so it requires transparent authority. This applies in every build.
pub(crate) fn has_transparent_inputs(tx: &zcash_primitives::transaction::Transaction) -> bool {
    tx.transparent_bundle()
        .is_some_and(|bundle| !bundle.vin.is_empty())
}
