//! The user's choice of one advertised server.
//!
//! A wallet sends every PIR product's queries to one selected server base and
//! never moves to another server on its own: not on failure, not when the
//! selected server disappears from the config. Only an explicit user choice
//! or the very first default (no prior choice in this scope) sets it.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::profile::WalletPirConfigScope;
use crate::resolve::ResolvedWalletPirConfig;
use crate::server::{AdvertisedServer, ServerBase};

/// A selected server, for the application to persist.
///
/// Identified by the normalized base, not the label, so it survives label
/// and order changes. Bound to the [`WalletPirConfigScope`] it was made in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerSelection {
    scope: WalletPirConfigScope,
    base: ServerBase,
}

impl ServerSelection {
    pub fn scope(&self) -> &WalletPirConfigScope {
        &self.scope
    }

    pub fn base(&self) -> &ServerBase {
        &self.base
    }
}

/// What a wallet should do with its server after accepting a config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerSelectionOutcome {
    /// The persisted selection is still advertised; keep using it.
    Kept(ServerSelection),
    /// There was no selection in this scope, so the first advertised server
    /// was chosen. Persist it.
    Defaulted(ServerSelection),
    /// The config advertises no server and there was no selection to lose.
    /// Send no private PIR traffic.
    NoServers,
    /// The persisted server is no longer advertised. Send no private PIR
    /// traffic and ask the user to choose; keep the persisted selection until
    /// they do, so a restart reaches this state again rather than a default.
    SelectionRequired { removed: ServerBase },
}

impl ServerSelectionOutcome {
    /// The server to query, if any.
    pub fn selection(&self) -> Option<&ServerSelection> {
        match self {
            Self::Kept(selection) | Self::Defaulted(selection) => Some(selection),
            Self::NoServers | Self::SelectionRequired { .. } => None,
        }
    }
}

/// An explicit choice the config does not allow.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SelectionError {
    #[error("server {base} is not advertised by the current config")]
    NotAdvertised { base: ServerBase },
}

impl<V> ResolvedWalletPirConfig<V> {
    /// Records the user's explicit choice of an advertised server.
    pub fn select_server(&self, base: &ServerBase) -> Result<ServerSelection, SelectionError> {
        if self.servers.iter().any(|server| server.base == *base) {
            Ok(ServerSelection {
                scope: self.scope.clone(),
                base: base.clone(),
            })
        } else {
            Err(SelectionError::NotAdvertised { base: base.clone() })
        }
    }

    /// Reconciles the persisted selection with this config.
    ///
    /// A selection from another scope is ignored, as if absent: it was made
    /// for another source, pin, network or policy. Within the scope, a
    /// selection is kept while its base is advertised and otherwise requires a
    /// new user choice; another server is never substituted.
    pub fn reconcile_selection(
        &self,
        persisted: Option<&ServerSelection>,
    ) -> ServerSelectionOutcome {
        match persisted.filter(|selection| selection.scope == self.scope) {
            Some(selection) if self.server(selection).is_some() => {
                ServerSelectionOutcome::Kept(selection.clone())
            }
            Some(selection) => ServerSelectionOutcome::SelectionRequired {
                removed: selection.base.clone(),
            },
            None => match self.servers.first() {
                Some(first) => ServerSelectionOutcome::Defaulted(ServerSelection {
                    scope: self.scope.clone(),
                    base: first.base.clone(),
                }),
                None => ServerSelectionOutcome::NoServers,
            },
        }
    }

    /// The advertised server `selection` names, with its current label, if
    /// the selection belongs to this scope and is still advertised.
    pub fn server(&self, selection: &ServerSelection) -> Option<&AdvertisedServer> {
        if selection.scope != self.scope {
            return None;
        }
        self.servers
            .iter()
            .find(|server| server.base == selection.base)
    }
}
