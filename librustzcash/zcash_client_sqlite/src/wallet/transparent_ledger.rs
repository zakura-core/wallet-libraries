//! SQLite storage for the transparent ledger (`tpir_*` tables).
//!
//! Projection origins record why each transparent output and spend exists in the wallet, so
//! that invalidating one source never removes a record another source still supports. Legacy
//! and local origins are provenance only; they never constitute ledger coverage.
//!
//! Handle configuration and the durable policy are enforced here. A candidate account's recovery
//! (`recovery`) is isolated from the projection. Promotion projects a complete, qualified ledger
//! (`projection`) and makes the account active; under `PrivateRequired`, only active accounts
//! whose ledger is complete through the chain tip can authorize transparent inputs.

pub(crate) mod details;
mod history;
mod policy;
#[cfg(feature = "transparent-inputs")]
mod projection;
mod recovery;

use rusqlite::OptionalExtension as _;
use zcash_client_backend::data_api::{
    transparent_ledger::{
        AppliedTransparentPolicy, ChainPoint, LastKnownBalance, LastKnownSource, RecoveryBlocker,
        RecoveryCompletion, TransparentAuthority, TransparentLedgerBalance, TransparentLedgerMode,
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
    crate::AccountRef, zcash_client_backend::data_api::transparent_ledger::AccountLifecycle,
    zcash_keys::keys::transparent::gap_limits::GapLimits,
};

#[cfg(feature = "transparent-inputs")]
use {
    crate::{TxRef, UtxoId},
    rusqlite::named_params,
    transparent::bundle::OutPoint,
    zcash_client_backend::data_api::AccountBalance,
};

pub(crate) use history::transaction_history_details;
pub(crate) use policy::{
    applied_transparent_policy, apply_transparent_policy, capture_policy_generation,
    check_transparent_policy_generation, ensure_policy_generation,
    pending_private_transparent_details, retains_public_authority,
};
#[cfg(all(feature = "transparent-inputs", feature = "transparent-key-import"))]
pub(crate) use recovery::forget_other_candidates;
#[cfg(all(
    feature = "transparent-inputs",
    any(test, feature = "test-dependencies")
))]
pub(crate) use recovery::qualify_revision;
#[cfg(feature = "transparent-inputs")]
pub(crate) use recovery::{
    CommitTrust, apply_commit, candidate_recovery, forget_reattributed_script, promote, watch_set,
};
pub(crate) use recovery::{clear_pending_pages, truncate as truncate_recovery};

fn mode_from_code(code: i64) -> Result<TransparentLedgerMode, SqliteClientError> {
    match code {
        0 => Ok(TransparentLedgerMode::Public),
        1 => Ok(TransparentLedgerMode::PrivateShadow),
        2 => Ok(TransparentLedgerMode::PrivateRequired),
        other => Err(SqliteClientError::CorruptedData(format!(
            "unknown transparent ledger mode code {other}"
        ))),
    }
}

pub(super) fn mode_code(mode: TransparentLedgerMode) -> i64 {
    match mode {
        TransparentLedgerMode::Public => 0,
        TransparentLedgerMode::PrivateShadow => 1,
        TransparentLedgerMode::PrivateRequired => 2,
    }
}

/// The highest `tpir_meta.min_reader_version` this build can interpret. A wallet requiring a
/// newer reader is refused rather than operated on with semantics this build lacks: every
/// ledger read and write fails, and so does a rewind, which would otherwise leave state this
/// build cannot maintain anchored on replaced blocks.
///
/// Version 3 maintains candidate recovery state through rewinds, policy transitions, and
/// account changes; the first candidate commit requires it. Version 5 honors activation,
/// qualification, quarantine, and retained outputs whose receive was withdrawn. Version 4
/// could admit those retained rows under public authority, so activation writes require 5.
/// Version 6 separates observed revisions from trusted replacement; revision writes require 6.
/// Version 7 maintains source-bound transaction facts through withdrawals and rewinds.
/// Version 8 retains shared derivation origins after address materialization.
pub(crate) const TPIR_READER_VERSION: i64 = SHARED_DERIVATION_READER_VERSION;

/// The reader version retained shared derivation origins require.
pub(crate) const SHARED_DERIVATION_READER_VERSION: i64 = 8;

/// Maintains source-bound transaction facts through withdrawals and rewinds.
pub(crate) const METADATA_READER_VERSION: i64 = 7;

/// Separates observed revision identities from trusted wallet-wide supersession.
pub(crate) const REVISION_READER_VERSION: i64 = 6;

/// The reader version candidate recovery state requires.
#[cfg(feature = "transparent-inputs")]
pub(crate) const RECOVERY_READER_VERSION: i64 = 3;

/// The reader version activation, qualification, and quarantine state requires.
pub(crate) const ACTIVATION_READER_VERSION: i64 = 5;

/// A SQL condition admitting an output's existence as current evidence. A ledger-only output
/// whose receive was withdrawn or unplaced is retained to preserve its spend links and locks,
/// but cannot contribute value or authorize an input under either public or private policy.
/// Independent origins retain their existing semantics. Rows missing provenance are left in
/// the counted set so the balance provenance check still reports them as corrupted data.
pub(crate) fn output_observation_condition(output: &str) -> String {
    format!(
        "NOT EXISTS (
             SELECT 1 FROM tpir_output_origins oo WHERE oo.output_id = {output}.id AND oo.origin = 2
         ) OR EXISTS (
             SELECT 1 FROM tpir_output_origins oo WHERE oo.output_id = {output}.id AND oo.origin != 2
         ) OR EXISTS (
             SELECT 1 FROM tpir_receive_events re
             JOIN transactions rt ON rt.txid = re.txid
             WHERE rt.id_tx = {output}.transaction_id AND re.output_index = {output}.output_index
             AND re.account_id = {output}.account_id AND re.mined_height IS NOT NULL
         )"
    )
}

/// Raises `tpir_meta.min_reader_version` to at least `version`, so that builds that cannot
/// interpret the state about to be written fail closed rather than ignore it.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn require_reader_version(
    conn: &rusqlite::Connection,
    version: i64,
) -> Result<(), SqliteClientError> {
    conn.execute(
        "UPDATE tpir_meta
         SET min_reader_version = MAX(min_reader_version, :version)
         WHERE id = 0",
        rusqlite::named_params![":version": version],
    )?;
    Ok(())
}

/// The policy durably applied to the wallet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DurablePolicy {
    pub(crate) mode: TransparentLedgerMode,
    pub(crate) generation: u64,
}

impl From<DurablePolicy> for AppliedTransparentPolicy {
    fn from(policy: DurablePolicy) -> Self {
        AppliedTransparentPolicy {
            mode: policy.mode,
            generation: policy.generation,
        }
    }
}

/// Runs `f` against one SQLite snapshot.
///
/// Public follow-on dispatch reads the resolved mode, the durable generation, and queued work.
/// Those must not be mixed across a concurrent `Public` → `PrivateRequired` transition: a stale
/// public-authority result combined with the new generation would emit newly queued txids as
/// public work. Callers already inside a transaction reuse that snapshot.
pub(crate) fn with_read_snapshot<T, F>(
    conn: &rusqlite::Connection,
    f: F,
) -> Result<T, SqliteClientError>
where
    F: FnOnce(&rusqlite::Connection) -> Result<T, SqliteClientError>,
{
    if conn.is_autocommit() {
        let tx = conn.unchecked_transaction()?;
        let value = f(&tx)?;
        tx.commit()?;
        Ok(value)
    } else {
        f(conn)
    }
}

/// Reads the durable policy. A wallet that predates the ledger schema has none, and so cannot
/// hold a stricter policy than any handle.
pub(crate) fn durable_policy(
    conn: &rusqlite::Connection,
) -> Result<Option<DurablePolicy>, SqliteClientError> {
    let has_meta: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'tpir_meta')",
        [],
        |row| row.get(0),
    )?;
    if !has_meta {
        // Only a wallet that never ran the ledger migration may lack the policy table. Once
        // the migration is recorded, a missing table is damage and must not read as public.
        let migrated: bool = conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM schemer_migrations WHERE id = ?1)",
            [super::init::migrations::TRANSPARENT_LEDGER_SCHEMA_ID
                .as_bytes()
                .to_vec()],
            |row| row.get(0),
        )?;
        return if migrated {
            Err(SqliteClientError::CorruptedData(
                "tpir_meta is missing after the transparent ledger migration".into(),
            ))
        } else {
            Ok(None)
        };
    }
    let (mode, generation, min_reader_version) = conn
        .query_row(
            "SELECT applied_mode, policy_generation, min_reader_version FROM tpir_meta WHERE id = 0",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?
        // Once the table exists, a missing singleton is damage, not the absence of a policy.
        .ok_or_else(|| {
            SqliteClientError::CorruptedData("tpir_meta policy row is missing".into())
        })?;
    if min_reader_version > TPIR_READER_VERSION {
        return Err(SqliteClientError::TransparentLedgerIncompatible {
            required: min_reader_version,
        });
    }
    Ok(Some(DurablePolicy {
        mode: mode_from_code(mode)?,
        generation: u64::try_from(generation).map_err(|_| {
            SqliteClientError::CorruptedData("negative policy_generation in tpir_meta".into())
        })?,
    }))
}

/// Rejects a handle whose configured mode is weaker than a durably applied private-required
/// policy. The stored policy is never changed here.
fn check_not_weaker(
    configured: Option<TransparentLedgerMode>,
    durable: Option<DurablePolicy>,
) -> Result<(), SqliteClientError> {
    match durable {
        Some(DurablePolicy {
            mode: applied @ TransparentLedgerMode::PrivateRequired,
            ..
        }) if configured != Some(TransparentLedgerMode::PrivateRequired) => {
            Err(SqliteClientError::TransparentLedgerPolicyConflict {
                configured,
                applied,
            })
        }
        _ => Ok(()),
    }
}

/// Resolves the mode a handle operates under for transparent ledger APIs, which require
/// explicit configuration even for an empty wallet.
pub(crate) fn resolve_mode(
    conn: &rusqlite::Connection,
    configured: Option<TransparentLedgerMode>,
) -> Result<TransparentLedgerMode, SqliteClientError> {
    let mode = configured.ok_or(SqliteClientError::TransparentLedgerModeNotConfigured)?;
    check_not_weaker(configured, durable_policy(conn)?)?;
    Ok(mode)
}

/// Checks that the handle may authorize consuming transparent inputs.
///
/// Public authority is retained only by explicitly configured `Public` and `PrivateShadow`
/// handles; financial authorization never defaults to public. Even then it requires the same
/// conditions under which the snapshot reports public authority: a known chain tip, and a build
/// that can read transparent state. `PrivateRequired` handles are rejected: private authority is
/// per account, and [`input_authority`] resolves it where transparent support exists.
pub(crate) fn check_transparent_authority(
    conn: &rusqlite::Connection,
    configured: Option<TransparentLedgerMode>,
) -> Result<(), SqliteClientError> {
    match resolve_mode(conn, configured)? {
        TransparentLedgerMode::PrivateRequired => {
            Err(SqliteClientError::TransparentAuthorityUnavailable)
        }
        TransparentLedgerMode::Public | TransparentLedgerMode::PrivateShadow => {
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
            super::transparent::find_account_uuid_for_transparent_address(conn, params, address)?
        {
            owners.push(super::get_account_ref(conn, account)?);
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
        Some(DurablePolicy {
            mode: TransparentLedgerMode::PrivateRequired,
            ..
        })
    );
    Ok(cfg!(feature = "transparent-inputs")
        && !durable_private
        && configured != Some(TransparentLedgerMode::PrivateRequired)
        && chain_tip_height(conn)?.is_some())
}

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
    super::transparent::add_transparent_account_balances(
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

/// Reads `account`'s private ledger for a snapshot targeting the block after `tip`.
///
/// Authority, last-known amounts and blockers are read only when `authoritative`, that is under
/// `PrivateRequired`. A shadow snapshot reports public authority and only the recovery progress,
/// so a diagnostic it would discard cannot fail the public amount.
#[cfg(feature = "transparent-inputs")]
fn private_view<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    gap_limits: &GapLimits,
    account: AccountUuid,
    tip: BlockHeight,
    confirmations_policy: ConfirmationsPolicy,
    authoritative: bool,
) -> Result<PrivateView, SqliteClientError> {
    let ledger = recovery::account_ledger(conn, params, gap_limits, account)?;
    let target = TargetHeight::from(tip + 1);
    let covered_through = match ledger.status.covered_through {
        Some(height) => {
            super::get_block_hash(conn, height)?.map(|hash| ChainPoint { height, hash })
        }
        None => None,
    };
    let (authority, last_known, blockers) = if !authoritative {
        (None, None, vec![])
    } else if ledger.authorizes_after(tip) {
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

    let private = match mode {
        TransparentLedgerMode::Public => None,
        TransparentLedgerMode::PrivateShadow | TransparentLedgerMode::PrivateRequired => {
            #[cfg(feature = "transparent-inputs")]
            let view = private_view(
                conn,
                params,
                gap_limits,
                account,
                tip,
                confirmations_policy,
                mode == TransparentLedgerMode::PrivateRequired,
            )?;
            #[cfg(not(feature = "transparent-inputs"))]
            let view = private_view(conn, account, tip, confirmations_policy)?;
            Some(view)
        }
    };
    let (covered_through, recovered_unverified) = private.as_ref().map_or((None, None), |p| {
        (p.covered_through, p.recovered_unverified)
    });

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
            covered_through,
            recovered_unverified,
        });
    }

    let private = private.expect("PrivateRequired reads the private ledger");
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
    use super::transparent::{BalanceProvenance, transparent_balance_provenance};
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

/// Why a transparent output or spend exists in the wallet's projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(feature = "transparent-inputs"), allow(dead_code))]
pub(crate) enum ProjectionOrigin {
    /// Written by public discovery, or present before the ledger schema existed.
    LegacyPublic,
    /// Written by local transaction construction.
    LocalConstruction,
    /// Projected from an active account's private ledger.
    LedgerEvent,
}

impl ProjectionOrigin {
    #[cfg_attr(not(feature = "transparent-inputs"), allow(dead_code))]
    fn code(self) -> i64 {
        match self {
            Self::LegacyPublic => 0,
            Self::LocalConstruction => 1,
            Self::LedgerEvent => 2,
        }
    }
}

/// Records `origin` for a transparent output. Idempotent.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn record_output_origin(
    conn: &rusqlite::Connection,
    output: UtxoId,
    origin: ProjectionOrigin,
) -> Result<(), SqliteClientError> {
    conn.prepare_cached(
        "INSERT INTO tpir_output_origins (output_id, origin)
         VALUES (:output_id, :origin)
         ON CONFLICT (output_id, origin) DO NOTHING",
    )?
    .execute(named_params![":output_id": output.0, ":origin": origin.code()])?;
    // Local creation evidence may already exist, recorded by an outbox before the transaction
    // was projected; the record then has a local origin whatever path projected it.
    conn.prepare_cached(
        "INSERT INTO tpir_output_origins (output_id, origin)
         SELECT o.id, 1
         FROM transparent_received_outputs o
         JOIN transactions t ON t.id_tx = o.transaction_id
         WHERE o.id = :output_id
         AND (t.created IS NOT NULL OR t.target_height IS NOT NULL)
         ON CONFLICT (output_id, origin) DO NOTHING",
    )?
    .execute(named_params![":output_id": output.0])?;
    Ok(())
}

/// Records `origin` for the spend of `outpoint` by `spent_in_tx`, whether or not the spent
/// output is known yet. Idempotent.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn record_spend_origin(
    conn: &rusqlite::Connection,
    spent_in_tx: TxRef,
    outpoint: &OutPoint,
    origin: ProjectionOrigin,
) -> Result<(), SqliteClientError> {
    conn.prepare_cached(
        "INSERT INTO tpir_spend_origins (
             spending_transaction_id, prevout_txid, prevout_output_index, origin
         )
         VALUES (:spent_in_tx, :prevout_txid, :prevout_idx, :origin)
         ON CONFLICT (spending_transaction_id, prevout_txid, prevout_output_index, origin)
         DO NOTHING",
    )?
    .execute(named_params![
        ":spent_in_tx": spent_in_tx.0,
        ":prevout_txid": outpoint.hash(),
        ":prevout_idx": outpoint.n(),
        ":origin": origin.code(),
    ])?;
    conn.prepare_cached(
        "INSERT INTO tpir_spend_origins (
             spending_transaction_id, prevout_txid, prevout_output_index, origin
         )
         SELECT id_tx, :prevout_txid, :prevout_idx, 1
         FROM transactions
         WHERE id_tx = :spent_in_tx
         AND (created IS NOT NULL OR target_height IS NOT NULL)
         ON CONFLICT (spending_transaction_id, prevout_txid, prevout_output_index, origin)
         DO NOTHING",
    )?
    .execute(named_params![
        ":spent_in_tx": spent_in_tx.0,
        ":prevout_txid": outpoint.hash(),
        ":prevout_idx": outpoint.n(),
    ])?;
    Ok(())
}

/// Adds local origins to the transparent records already projected for `txid`, when local
/// creation evidence is recorded after projection.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn record_local_origins_for_tx(
    conn: &rusqlite::Connection,
    txid: &[u8],
) -> Result<(), SqliteClientError> {
    conn.execute(
        "INSERT INTO tpir_output_origins (output_id, origin)
         SELECT o.id, 1
         FROM transparent_received_outputs o
         JOIN transactions t ON t.id_tx = o.transaction_id
         WHERE t.txid = :txid
         ON CONFLICT (output_id, origin) DO NOTHING",
        named_params![":txid": txid],
    )?;
    conn.execute(
        "INSERT INTO tpir_spend_origins (
             spending_transaction_id, prevout_txid, prevout_output_index, origin
         )
         SELECT so.spending_transaction_id, so.prevout_txid, so.prevout_output_index, 1
         FROM tpir_spend_origins so
         JOIN transactions t ON t.id_tx = so.spending_transaction_id
         WHERE t.txid = :txid
         ON CONFLICT (spending_transaction_id, prevout_txid, prevout_output_index, origin)
         DO NOTHING",
        named_params![":txid": txid],
    )?;
    Ok(())
}

#[cfg(all(test, feature = "transparent-inputs"))]
mod tests;

/// Returns whether `tx` consumes transparent inputs. A locally stored transaction with
/// transparent inputs spends transparent funds, whatever its caller-supplied metadata claims,
/// so it requires transparent authority. This applies in every build.
pub(crate) fn has_transparent_inputs(tx: &zcash_primitives::transaction::Transaction) -> bool {
    tx.transparent_bundle()
        .is_some_and(|bundle| !bundle.vin.is_empty())
}
