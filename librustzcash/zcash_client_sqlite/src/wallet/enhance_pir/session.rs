//! The content-failure allowance and Enhance waits of one open wallet, shared by its database
//! handles.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use zcash_client_backend::data_api::enhance_pir::{
    EnhancePirRequest, EnhancePirSuspension, EnhancePirWork, TransactionEnhancementWork,
};
use zcash_primitives::transaction::TxId;

use super::MAX_REJECTIONS;

/// In-memory content-failure counts and Enhance waits for one open-wallet session.
///
/// Keep this object alive across syncs. Handles opened for the same wallet can share it with
/// `WalletDb::with_enhance_pir_session`; serialize their wallet operations. Never share it
/// between wallets. Dropping the session and opening a new one restores the full allowance and
/// draws each queued position's wait again.
#[derive(Clone, Default)]
pub struct EnhancePirSession(Arc<Mutex<State>>);

#[derive(Clone, Default)]
struct State {
    /// Content failures per request.
    counts: BTreeMap<EnhancePirRequest, u32>,
    /// The time before which each queued position is not queried, per commitment tree position
    /// (`docs/pir-remaining-leaks-plan.md`, change D).
    not_before: BTreeMap<u64, SystemTime>,
}

#[derive(Clone)]
enum Change {
    Failure(EnhancePirRequest),
    RearmTransaction(TxId),
    RearmPosition(u64),
    Retain(BTreeSet<EnhancePirRequest>),
    NotBefore(u64, SystemTime),
    RetainNotBefore(BTreeSet<u64>),
}

impl Change {
    fn apply(&self, state: &mut State) {
        let counts = &mut state.counts;
        match self {
            Self::Failure(request) => {
                let count = counts.entry(*request).or_default();
                *count = count.saturating_add(1).min(MAX_REJECTIONS);
            }
            Self::RearmTransaction(txid) => {
                counts.retain(|request, _| request.request_id().txid() != *txid)
            }
            Self::RearmPosition(position) => {
                counts.retain(|request, _| u64::from(request.position()) != *position)
            }
            Self::Retain(live) => counts.retain(|request, _| live.contains(request)),
            Self::NotBefore(position, time) => {
                state.not_before.entry(*position).or_insert(*time);
            }
            Self::RetainNotBefore(live) => state
                .not_before
                .retain(|position, _| live.contains(position)),
        }
    }
}

/// A session view whose changes follow the enclosing wallet transaction's commit.
#[derive(Clone, Default)]
pub(crate) struct SessionState {
    pub(crate) session: EnhancePirSession,
    pending: Option<Arc<Mutex<Vec<Change>>>>,
}

impl SessionState {
    pub(crate) fn new(session: EnhancePirSession) -> Self {
        Self {
            session,
            pending: None,
        }
    }

    pub(crate) fn transaction(&self) -> Self {
        Self {
            session: self.session.clone(),
            pending: Some(Arc::new(Mutex::new(Vec::new()))),
        }
    }

    pub(crate) fn has_transaction_journal(&self) -> bool {
        self.pending.is_some()
    }

    pub(crate) fn commit(&self) {
        if let Some(pending) = &self.pending {
            let changes = std::mem::take(&mut *pending.lock().unwrap_or_else(|e| e.into_inner()));
            let mut state = self.session.0.lock().unwrap_or_else(|e| e.into_inner());
            for change in changes {
                change.apply(&mut state);
            }
        }
    }

    fn change(&self, change: Change) {
        if let Some(pending) = &self.pending {
            pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(change);
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
        if let Some(pending) = &self.pending {
            for change in pending.lock().unwrap_or_else(|e| e.into_inner()).iter() {
                change.apply(&mut state);
            }
        }
        state
    }

    fn counts(&self) -> BTreeMap<EnhancePirRequest, u32> {
        self.state().counts
    }

    pub(crate) fn is_empty(&self) -> bool {
        let state = self.state();
        state.counts.is_empty() && state.not_before.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn waits(&self) -> usize {
        self.state().not_before.len()
    }

    /// The time before which `position` is not queried, if this session has one.
    pub(crate) fn not_before(&self, position: u64) -> Option<SystemTime> {
        self.state().not_before.get(&position).copied()
    }

    /// Sets the time before which `position` is not queried, unless it already has one.
    pub(crate) fn set_not_before(&self, position: u64, time: SystemTime) {
        if self.not_before(position).is_none() {
            self.change(Change::NotBefore(position, time));
        }
    }

    /// Forgets the wait of every position not in `live`: its work completed, or a rewind
    /// removed it, so a later requeue draws a new one.
    pub(crate) fn retain_not_before(&self, live: BTreeSet<u64>) {
        if self
            .state()
            .not_before
            .keys()
            .any(|position| !live.contains(position))
        {
            self.change(Change::RetainNotBefore(live));
        }
    }

    #[cfg(test)]
    pub(crate) fn count(&self, request: EnhancePirRequest) -> Option<u32> {
        self.counts().get(&request).copied()
    }
    pub(crate) fn failure(&self, request: EnhancePirRequest) {
        self.change(Change::Failure(request));
    }
    pub(crate) fn rearm_transaction(&self, txid: TxId) {
        if self
            .counts()
            .keys()
            .any(|request| request.request_id().txid() == txid)
        {
            self.change(Change::RearmTransaction(txid));
        }
    }
    pub(crate) fn rearm_position(&self, position: u64) {
        if self
            .counts()
            .keys()
            .any(|request| u64::from(request.position()) == position)
        {
            self.change(Change::RearmPosition(position));
        }
    }
    pub(crate) fn retain(&self, live: BTreeSet<EnhancePirRequest>) {
        if self.counts().keys().any(|request| !live.contains(request)) {
            self.change(Change::Retain(live));
        }
    }

    /// Suspends requests at the content-failure limit. With `waits`, also lists each query
    /// whose position is not yet due at `now` as waiting. A position this session has no time
    /// for waits the longest delay from `now`: wallet writes draw the times, and a read cannot.
    pub(crate) fn filter(
        &self,
        mut work: Vec<TransactionEnhancementWork>,
        waits: Option<(SystemTime, std::time::Duration)>,
    ) -> Vec<TransactionEnhancementWork> {
        let counts = self.counts();
        for item in &mut work {
            if let TransactionEnhancementWork::Private(EnhancePirWork::Query(request)) = *item
                && counts
                    .get(&request)
                    .is_some_and(|count| *count >= MAX_REJECTIONS)
            {
                *item = TransactionEnhancementWork::Private(EnhancePirWork::Suspended(
                    EnhancePirSuspension::Rejected(request),
                ));
            }
        }
        if let Some((now, max_delay)) = waits {
            for item in &mut work {
                if let TransactionEnhancementWork::Private(EnhancePirWork::Query(request)) = *item {
                    let position = u64::from(request.position());
                    self.set_not_before(position, now + max_delay);
                    let not_before = self.not_before(position).expect("set above");
                    if not_before > now {
                        *item = TransactionEnhancementWork::Private(EnhancePirWork::Waiting {
                            request,
                            not_before,
                        });
                    }
                }
            }
        }
        work
    }
}
