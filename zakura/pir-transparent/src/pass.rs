//! One recovery pass as a wallet runs it: fresh transports over the caller's exchange,
//! one retry after a publication change, and the ready batch held for its settlement.

use transparent_wallet::ChainView;
use zcash_client_backend::data_api::transparent_ledger::TransparentAddressWatchSet;

use crate::batch::{self, BatchState, RecoveryBatch};
use crate::error::RecoveryError;
use crate::http::{HttpExchange, TransparentPirHttp};
use crate::progress::{Progress, Retry};
use crate::transparent_history_recovery::TransparentHistoryRecovery;

/// What one [`TransparentHistoryRecovery::pass`] found. It carries no commit, address or
/// revision, so it may be logged whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PassReport {
    /// Whether the batch's commits may reach the wallet. Only a
    /// [`BatchState::Ready`] batch is held for settlement.
    pub state: BatchState,
    /// How far the pass covered the watch set, and why it stopped.
    pub progress: Progress,
    /// The batch's commits.
    pub commits: usize,
    /// The batch's [`RecoveryBatch::retired_revisions`]: nonzero only for a ready
    /// batch, which only trusted settlement reconciles.
    pub retired: usize,
    /// Whether the first attempt found the publication set changed and the pass
    /// retried with the reset companion.
    pub publication_changed: bool,
}

impl PassReport {
    /// When to pass the account again: [`RecoveryBatch::retry`] of the batch.
    pub fn retry(&self) -> Retry {
        batch::retry(self.state, self.progress)
    }

    /// Whether the pass held its batch for [`TransparentHistoryRecovery::settle_latest`]:
    /// exactly when it is [`BatchState::Ready`].
    pub fn settleable(&self) -> bool {
        self.state == BatchState::Ready
    }

    fn of<A>(batch: &RecoveryBatch<A>, publication_changed: bool) -> Self {
        Self {
            state: batch.state(),
            progress: batch.progress(),
            commits: batch.commits().len(),
            retired: batch.retired_revisions().len(),
            publication_changed,
        }
    }
}

/// Why a pass returned no batch. Nothing was held, and the companion is kept.
///
/// Messages name only the variant. The strings of [`PassError::Invalid`] and
/// [`PassError::Failure`] are [`RecoveryError`]'s, which may quote the wallet's
/// transparent history or the transport's errors: match them, never log them.
#[derive(Debug, thiserror::Error)]
pub enum PassError {
    /// A request failed because the service cannot be reached or is not serving
    /// ([`TransparentPirHttp::outage`]), whatever the pass then reported. It fails
    /// every account alike: stop visiting accounts until a later run.
    #[error("transparent PIR pass: service unavailable")]
    Outage,
    /// [`RecoveryError::Invalid`]: configuration, accepted chain, context or
    /// publication content.
    #[error("transparent PIR pass: invalid")]
    Invalid(String),
    /// [`RecoveryError::Failure`]: retrieval or companion persistence. Pass the
    /// account again in a later run.
    #[error("transparent PIR pass: failure")]
    Failure(String),
    /// [`RecoveryError::PublicationChanged`] on the retry too, or on the first
    /// attempt when the caller was stopping. The companion's store was reset each
    /// time; pass again in a later run with the same companion.
    #[error("transparent PIR pass: publication set changed")]
    PublicationChanged,
}

impl TransparentHistoryRecovery {
    /// One pass over `watch` through the caller's `exchange`, accepting
    /// successful bodies of at most `limit` bytes: the entry point for wallets.
    ///
    /// Forgets the batch any earlier pass held, then runs [`Self::recover`] over
    /// a fresh [`TransparentPirHttp`], so an earlier pass's outage does not carry
    /// over. When the publication set changed ([`RecoveryError::PublicationChanged`]),
    /// the companion's store was reset and its catalog kept, and the pass retries
    /// once over the same transports unless `should_stop` returns true. The reset
    /// store is bound to no set, so the retry binds whatever set it finds; a change
    /// found again, or while stopping, is [`PassError::PublicationChanged`].
    ///
    /// A [`BatchState::Ready`] batch is held for [`Self::settle_latest`] (feature
    /// `sqlite`), or for [`Self::take_latest`]. Pending and withdrawn batches have
    /// nothing to hold. Any failure while the transports saw an outage is
    /// [`PassError::Outage`].
    ///
    /// `should_stop` only declines the retry: cancelling requests in flight is the
    /// exchange's. A caller that stopped discards whatever the pass returned.
    pub fn pass<A, C, E>(
        &mut self,
        watch: &TransparentAddressWatchSet<A>,
        chain: &C,
        exchange: E,
        limit: usize,
        should_stop: &dyn Fn() -> bool,
    ) -> Result<PassReport, PassError>
    where
        A: Copy + std::fmt::Debug + Send + 'static,
        C: ChainView,
        E: HttpExchange,
    {
        self.latest = None;
        let mut http = TransparentPirHttp::new(exchange, limit);
        let (result, changed) = retry_publication_change(
            || {
                let (mut filters, mut shards) = http.split();
                self.recover(watch, chain, &mut filters, &mut shards)
            },
            should_stop,
        );
        let batch = result.map_err(|error| pass_error(error, http.outage()))?;
        let report = PassReport::of(&batch, changed);
        if report.settleable() {
            self.latest = Some(Box::new(batch));
        }
        Ok(report)
    }

    /// The ready batch the latest [`Self::pass`] holds, for reading: `None` when
    /// it held none, when it was taken or settled, or when `A` is not the account
    /// type of that pass's watch set.
    pub fn latest<A: 'static>(&self) -> Option<&RecoveryBatch<A>> {
        self.latest.as_ref()?.downcast_ref()
    }

    /// Takes the batch [`Self::latest`] reads, for a caller that applies its
    /// commits itself and acknowledges with [`Self::acknowledge_applied`]. With
    /// feature `sqlite`, settle it with [`Self::settle_latest`] instead.
    pub fn take_latest<A: 'static>(&mut self) -> Option<RecoveryBatch<A>> {
        match self.latest.take()?.downcast() {
            Ok(batch) => Some(*batch),
            Err(other) => {
                self.latest = Some(other);
                None
            }
        }
    }
}

/// Runs `attempt`, and once more after a publication change unless `should_stop`
/// returns true. Returns the last attempt's result and whether a change was found.
fn retry_publication_change<T>(
    mut attempt: impl FnMut() -> Result<T, RecoveryError>,
    should_stop: &dyn Fn() -> bool,
) -> (Result<T, RecoveryError>, bool) {
    match attempt() {
        Err(RecoveryError::PublicationChanged) if !should_stop() => (attempt(), true),
        Err(RecoveryError::PublicationChanged) => (Err(RecoveryError::PublicationChanged), true),
        result => (result, false),
    }
}

/// The pass error for `error`, given whether the transports saw an outage.
fn pass_error(error: RecoveryError, outage: bool) -> PassError {
    match error {
        _ if outage => PassError::Outage,
        RecoveryError::Invalid(message) => PassError::Invalid(message),
        RecoveryError::Failure(message) => PassError::Failure(message),
        RecoveryError::PublicationChanged => PassError::PublicationChanged,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    fn change() -> RecoveryError {
        RecoveryError::PublicationChanged
    }

    /// Runs the retry over `results`, one per attempt, and returns the outcome
    /// and how many attempts ran.
    fn run(
        results: Vec<Result<u8, RecoveryError>>,
        stopping: bool,
    ) -> (Result<u8, RecoveryError>, bool, usize) {
        let mut results = results.into_iter();
        let attempts = Cell::new(0);
        let (result, changed) = retry_publication_change(
            || {
                attempts.set(attempts.get() + 1);
                results.next().expect("an attempt the test planned")
            },
            &|| stopping,
        );
        (result, changed, attempts.get())
    }

    #[test]
    fn a_publication_change_is_retried_once() {
        let (result, changed, attempts) = run(vec![Err(change()), Ok(7)], false);
        assert_eq!((result.ok(), changed, attempts), (Some(7), true, 2));
        // A second change surfaces.
        let (result, changed, attempts) = run(vec![Err(change()), Err(change())], false);
        assert!(matches!(result, Err(RecoveryError::PublicationChanged)));
        assert_eq!((changed, attempts), (true, 2));
        // So does any other failure of the retry.
        let (result, _, attempts) = run(
            vec![Err(change()), Err(RecoveryError::Failure("x".into()))],
            false,
        );
        assert!(matches!(result, Err(RecoveryError::Failure(_))));
        assert_eq!(attempts, 2);
    }

    #[test]
    fn a_stopping_caller_is_not_retried() {
        let (result, changed, attempts) = run(vec![Err(change())], true);
        assert!(matches!(result, Err(RecoveryError::PublicationChanged)));
        assert_eq!((changed, attempts), (true, 1));
    }

    #[test]
    fn other_outcomes_are_not_retried() {
        for first in [
            Ok(1),
            Err(RecoveryError::Invalid("x".into())),
            Err(RecoveryError::Failure("x".into())),
        ] {
            let (_, changed, attempts) = run(vec![first], false);
            assert_eq!((changed, attempts), (false, 1));
        }
    }

    #[test]
    fn an_outage_names_every_failure() {
        for outage in [false, true] {
            for (error, expected) in [
                (RecoveryError::Invalid("x".into()), "invalid"),
                (RecoveryError::Failure("x".into()), "failure"),
                (change(), "publication set changed"),
            ] {
                let expected = if outage {
                    "service unavailable"
                } else {
                    expected
                };
                assert_eq!(
                    pass_error(error, outage).to_string(),
                    format!("transparent PIR pass: {expected}")
                );
            }
        }
        // Only the variant reaches the message.
        assert_eq!(
            PassError::Failure("a quoted outpoint".into()).to_string(),
            "transparent PIR pass: failure"
        );
    }
}
