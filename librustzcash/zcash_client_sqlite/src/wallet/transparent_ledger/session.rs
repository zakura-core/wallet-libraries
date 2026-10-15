//! Transparent work the replies at one chain tip created, held back until the tip changes,
//! shared by the database handles of one open wallet.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;
#[cfg(feature = "transparent-inputs")]
use {crate::AccountUuid, zcash_client_backend::data_api::transparent_ledger::ChainPoint};

use crate::error::SqliteClientError;

/// The chain tip at which each transparent lookup was newly queued, for one open-wallet session.
///
/// At a given chain tip, a private reply may only change what the wallet asks at a later tip.
/// A txid lookup queued at the current tip (by a recovery reply, an Enhance reply, a status
/// reply or the scan) is therefore not listed until the tip changes, whether it rose or a reorg
/// lowered it. Likewise, the addresses an account's watch set holds at one recovery target
/// are those its first read at that target held: window growth a reply causes is watched from
/// the next target.
///
/// Keep this object alive across syncs. Handles opened for the same wallet can share it with
/// `WalletDb::with_transparent_pir_session`; serialize their wallet operations. Never share it
/// between wallets. Dropping the session and opening a new one, as on restart, releases the
/// work it held.
#[derive(Clone, Default)]
pub struct TransparentPirSession(Arc<Mutex<State>>);

#[derive(Clone, Default)]
struct State {
    /// The chain tip at which each lookup was newly queued. Only entries at one tip matter;
    /// recording at another tip drops the rest.
    queued_at: BTreeMap<TxId, BlockHeight>,
    /// Per account, the target of the first watch set read there and each window scope's
    /// watched end at that read.
    #[cfg(feature = "transparent-inputs")]
    watched: BTreeMap<AccountUuid, (ChainPoint, [u32; 3])>,
}

#[derive(Clone)]
enum Change {
    Queued(BlockHeight, Vec<TxId>),
    #[cfg(feature = "transparent-inputs")]
    Watched(AccountUuid, ChainPoint, [u32; 3]),
}

impl Change {
    fn apply(&self, state: &mut State) {
        match self {
            Self::Queued(tip, txids) => {
                state.queued_at.retain(|_, at| at == tip);
                state
                    .queued_at
                    .extend(txids.iter().map(|txid| (*txid, *tip)));
            }
            #[cfg(feature = "transparent-inputs")]
            Self::Watched(account, target, ends) => {
                state.watched.insert(*account, (*target, *ends));
            }
        }
    }
}

/// A session view whose changes follow the enclosing wallet transaction's commit.
///
/// A view inside another view's transaction (a savepoint, say) journals into a journal of its
/// own; committing it hands its changes to the enclosing journal, and dropping it discards them.
#[derive(Clone, Default)]
pub(crate) struct SessionState {
    pub(crate) session: TransparentPirSession,
    /// The journals of the enclosing transactions, outermost first, then this view's own.
    journals: Vec<Arc<Mutex<Vec<Change>>>>,
}

impl SessionState {
    /// A caller-owned SQL transaction cannot publish or roll back this session's changes.
    /// Wallet-owned transactions have an enclosing journal that delays publication until
    /// their SQL commit; reject writes without one before creating a nested journal.
    pub(crate) fn check_transaction(
        &self,
        conn: &rusqlite::Connection,
    ) -> Result<(), SqliteClientError> {
        if !conn.is_autocommit() && self.journals.is_empty() {
            Err(SqliteClientError::TransparentSessionTransactionRequired)
        } else {
            Ok(())
        }
    }

    pub(crate) fn new(session: TransparentPirSession) -> Self {
        Self {
            session,
            journals: vec![],
        }
    }

    /// A view for a transaction inside this view's (or the first, outside any), whose changes
    /// take effect when [`Self::commit`] is called.
    pub(crate) fn transaction(&self) -> Self {
        let mut journals = self.journals.clone();
        journals.push(Arc::new(Mutex::new(Vec::new())));
        Self {
            session: self.session.clone(),
            journals,
        }
    }

    /// Hands this transaction's changes to the enclosing one, or applies them to the session
    /// outside any. Call it once the transaction committed.
    pub(crate) fn commit(&self) {
        if let Some((own, outer)) = self.journals.split_last() {
            let changes = std::mem::take(&mut *own.lock().unwrap_or_else(|e| e.into_inner()));
            match outer.last() {
                Some(enclosing) => enclosing
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .extend(changes),
                None => {
                    let mut state = self.session.0.lock().unwrap_or_else(|e| e.into_inner());
                    for change in changes {
                        change.apply(&mut state);
                    }
                }
            }
        }
    }

    fn change(&self, change: Change) {
        if let Some(own) = self.journals.last() {
            own.lock().unwrap_or_else(|e| e.into_inner()).push(change);
        } else {
            change.apply(&mut self.session.0.lock().unwrap_or_else(|e| e.into_inner()));
        }
    }

    fn state(&self) -> State {
        let mut state = self
            .session
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        for journal in &self.journals {
            for change in journal.lock().unwrap_or_else(|e| e.into_inner()).iter() {
                change.apply(&mut state);
            }
        }
        state
    }

    /// Records that `txids` were newly queued at chain tip `tip`.
    pub(crate) fn queued(&self, tip: BlockHeight, txids: Vec<TxId>) {
        if !txids.is_empty() {
            self.change(Change::Queued(tip, txids));
        }
    }

    /// The lookups newly queued at chain tip `tip`, which are not listed while it is the tip.
    pub(crate) fn held(&self, tip: BlockHeight) -> Vec<TxId> {
        self.state()
            .queued_at
            .into_iter()
            .filter(|(_, at)| *at == tip)
            .map(|(txid, _)| txid)
            .collect()
    }

    /// The window ends `account`'s watch set keeps at `target`, per window scope. The first
    /// read at a target records the current `ends`; later reads there get the recorded ones.
    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn watched_ends(
        &self,
        account: AccountUuid,
        target: ChainPoint,
        ends: [u32; 3],
    ) -> [u32; 3] {
        match self.state().watched.get(&account) {
            Some((at, recorded)) if *at == target => *recorded,
            _ => {
                self.change(Change::Watched(account, target, ends));
                ends
            }
        }
    }
}
