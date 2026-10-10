//! Transparent authority: whether a handle may consume transparent inputs, record publicly
//! discovered data, or report transparent funds as current.

use zcash_client_backend::data_api::transparent_ledger::TransparentLedgerMode;

use crate::{error::SqliteClientError, wallet::chain_tip_height};

use zcash_client_backend::data_api::transparent_ledger::AppliedTransparentPolicy;

use super::policy::{durable_policy, resolve_mode};

#[cfg(feature = "transparent-inputs")]
use {
    super::recovery,
    crate::{AccountRef, AccountUuid},
    zcash_client_backend::data_api::wallet::TargetHeight,
    zcash_keys::keys::transparent::gap_limits::GapLimits,
    zcash_protocol::consensus::{self, BlockHeight},
};

/// Whether the handle may grant private authority: qualify a revision or promote an account.
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
        TransparentLedgerMode::PrivateRequired => {
            Err(SqliteClientError::TransparentAuthorityUnavailable)
        }
        TransparentLedgerMode::Public => {
            if cfg!(not(feature = "transparent-inputs")) || chain_tip_height(conn)?.is_none() {
                Err(SqliteClientError::TransparentAuthorityUnavailable)
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
}

/// Resolves which outputs may fund a transaction targeting `target`.
///
/// Public authority follows [`check_transparent_authority`]. Under `PrivateRequired`, an
/// account is eligible when it is active and not quarantined, its ledger has no blockers, and
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
        return Err(SqliteClientError::TransparentAuthorityUnavailable);
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

/// Fails when private authority admits none of the accounts owning `addresses`. Selection over
/// several accounts' addresses otherwise proceeds with the eligible ones only.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn check_address_owners<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    authority: &InputAuthority,
    addresses: &[transparent::address::TransparentAddress],
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
            owners.push(crate::wallet::get_account_ref(conn, account)?);
        }
    }
    if !owners.is_empty() && !owners.iter().any(|owner| authority.admits(*owner)) {
        return Err(SqliteClientError::TransparentAuthorityUnavailable);
    }
    Ok(())
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
    let durable_private = matches!(
        durable_policy(conn)?,
        Some(AppliedTransparentPolicy {
            mode: TransparentLedgerMode::PrivateRequired,
            ..
        })
    );
    Ok(cfg!(feature = "transparent-inputs")
        && !durable_private
        && configured != Some(TransparentLedgerMode::PrivateRequired)
        && chain_tip_height(conn)?.is_some())
}

/// Returns whether `tx` consumes transparent inputs. A locally stored transaction with
/// transparent inputs spends transparent funds, whatever its caller-supplied metadata claims,
/// so it requires transparent authority. This applies in every build.
pub(crate) fn has_transparent_inputs(tx: &zcash_primitives::transaction::Transaction) -> bool {
    tx.transparent_bundle()
        .is_some_and(|bundle| !bundle.vin.is_empty())
}
