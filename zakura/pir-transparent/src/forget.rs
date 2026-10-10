//! Forgetting private recovery once the wallet's transparent policy is public again, with
//! feature `sqlite`.

use std::io;
use std::time::Duration;

use rusqlite::Connection;
use zcash_client_backend::data_api::transparent_ledger::{
    ForgottenTransparentLedger, TransparentLedgerMode, TransparentLedgerRead as _,
    TransparentLedgerWrite as _,
};
use zcash_client_sqlite::{WalletDb, error::SqliteClientError};
use zcash_protocol::consensus;

use crate::apply::{Interrupted, WriteGate};
use crate::companion::CompanionDir;

/// Why [`forget_private_recovery`] forgot nothing.
///
/// Messages name only the variant: the wallet's errors can quote addresses or outpoints, so
/// the nested errors are for matching, never for logs.
#[derive(Debug, thiserror::Error)]
pub enum ForgetError {
    /// The handle or the durable policy is not `Public`. Checked before anything is deleted.
    #[error("transparent PIR forget: the transparent policy is not public")]
    NotPublic,
    /// The durable policy changed after the forget began, so a companion may have been
    /// created since the companions were deleted. Companions before the change are deleted;
    /// nothing was forgotten.
    #[error("transparent PIR forget: the transparent policy changed")]
    PolicyChanged,
    /// Another handle held a companion until the wait ran out. Companions before it are
    /// deleted; nothing was forgotten.
    #[error("transparent PIR forget: a companion is in use")]
    CompanionBusy,
    /// A companion could not be listed or deleted. Nothing was forgotten.
    #[error("transparent PIR forget: companion removal failed")]
    Io(io::Error),
    /// The [`WriteGate`] declined the forget. Every companion is deleted; nothing was
    /// forgotten.
    #[error("transparent PIR forget: interrupted before the wallet write")]
    Interrupted,
    /// Any other wallet failure.
    #[error("transparent PIR forget: wallet failure")]
    Wallet(SqliteClientError),
}

impl From<SqliteClientError> for ForgetError {
    fn from(error: SqliteClientError) -> Self {
        match error {
            SqliteClientError::PublicTransparentDiscoveryForbidden => Self::NotPublic,
            SqliteClientError::StaleTransparentPolicy { .. } => Self::PolicyChanged,
            error => Self::Wallet(error),
        }
    }
}

/// Removes what private recovery alone contributed to `wallet`, and every companion in
/// `companions`, once the wallet's transparent policy is `Public` again.
///
/// `wallet` must be configured `Public` over a durable `Public` policy; otherwise this fails
/// with [`ForgetError::NotPublic`] before deleting anything, so a wallet still recovering
/// privately keeps its companions. It then deletes every companion, waiting at most `wait` in
/// all for those another handle holds, and only once all are gone runs
/// `TransparentLedgerWrite::forget_transparent_ledger` through `gate`, under the
/// application's wallet write serialization. That removes, in one wallet transaction, the
/// outputs, spends and transactions only private recovery reported and the recovery state that
/// would project them again; public discovery then rebuilds the transparent view. The same
/// transaction first confirms that the durable policy generation is still the one read before
/// the companions were deleted.
///
/// The order matters. A companion records which revisions the wallet already holds, and a
/// later private pass exports only what it does not. A companion that outlived the forgotten
/// facts would make that pass skip them, leaving the wallet without them for good. A wallet
/// whose companions are gone but whose facts remain is safe: a fresh companion exports every
/// revision again, and replaying them changes nothing the wallet holds. So a held companion
/// fails with [`ForgetError::CompanionBusy`] and forgets nothing, and so does a declined gate.
/// So does any policy change after the forget began ([`ForgetError::PolicyChanged`]): a policy
/// that went private, even one public again by the time of the write, may have let a private
/// pass create a companion recording revisions whose facts the forget would remove. Every
/// failure can be retried.
///
/// Forgetting a wallet without private ledger facts changes nothing, which
/// [`ForgottenTransparentLedger::removed_nothing`] reports.
pub fn forget_private_recovery<P: consensus::Parameters, CL, R>(
    companions: &CompanionDir,
    wallet: &mut WalletDb<Connection, P, CL, R>,
    gate: &mut impl WriteGate,
    wait: Duration,
) -> Result<ForgottenTransparentLedger, ForgetError> {
    // Read first, so any policy change from here on fails the forget below.
    let generation = wallet.applied_transparent_policy()?.generation;
    // The handle's mode resolves under the durable policy: `Public` means both are.
    if wallet.transparent_ledger_mode()? != TransparentLedgerMode::Public {
        return Err(ForgetError::NotPublic);
    }
    companions.clear(wait).map_err(|error| match error.kind() {
        io::ErrorKind::WouldBlock => ForgetError::CompanionBusy,
        _ => ForgetError::Io(error),
    })?;
    Ok(gate
        .write(|| {
            wallet.transactionally(|wallet| {
                wallet.check_transparent_policy_generation(generation)?;
                wallet.forget_transparent_ledger()
            })
        })
        .map_err(|Interrupted| ForgetError::Interrupted)??)
}
