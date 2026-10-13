//! The content-failure allowance of one open wallet, shared by its database handles.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use zcash_client_backend::data_api::enhance_pir::{
    EnhancePirRequest, EnhancePirSuspension, EnhancePirWork, TransactionEnhancementWork,
};
use zcash_primitives::transaction::TxId;

use super::MAX_REJECTIONS;

/// In-memory content-failure counts for one open-wallet session.
///
/// Keep this object alive across syncs. Handles opened for the same wallet can share it with
/// `WalletDb::with_enhance_pir_session`; serialize their wallet operations. Never share it
/// between wallets. Dropping the session and opening a new one restores the full allowance.
#[derive(Clone, Default)]
pub struct EnhancePirSession(Arc<Mutex<BTreeMap<EnhancePirRequest, u32>>>);

#[derive(Clone)]
enum Change {
    Failure(EnhancePirRequest),
    RearmTransaction(TxId),
    RearmPosition(u64),
    Retain(BTreeSet<EnhancePirRequest>),
}

impl Change {
    fn apply(&self, counts: &mut BTreeMap<EnhancePirRequest, u32>) {
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
            let mut counts = self.session.0.lock().unwrap_or_else(|e| e.into_inner());
            for change in changes {
                change.apply(&mut counts);
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

    fn counts(&self) -> BTreeMap<EnhancePirRequest, u32> {
        let mut counts = self
            .session
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(pending) = &self.pending {
            for change in pending.lock().unwrap_or_else(|e| e.into_inner()).iter() {
                change.apply(&mut counts);
            }
        }
        counts
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.counts().is_empty()
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

    pub(crate) fn filter(
        &self,
        mut work: Vec<TransactionEnhancementWork>,
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
        work
    }
}
