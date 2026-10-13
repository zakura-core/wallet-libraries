//! One recovery pass as a wallet runs it: fresh transports over the caller's exchange,
//! one retry after a publication change, and the ready batch held for its settlement.

use transparent_wallet::ChainView;
use zcash_client_backend::data_api::transparent_ledger::TransparentAddressWatchSet;

use crate::batch::{self, BatchState, RecoveryBatch};
use crate::error::RecoveryError;
use crate::http::{HttpExchange, TransparentPirHttp};
use crate::progress::{FailedEntries, Progress, Retry};
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
    /// The batch's [`RecoveryBatch::failed_entries`]: directory entries whose private
    /// replies failed on content, counted. Any makes the pass [`Retry::Stalled`].
    pub failed_entries: FailedEntries,
}

impl PassReport {
    /// When to pass the account again: [`RecoveryBatch::retry`] of the batch.
    pub fn retry(&self) -> Retry {
        batch::retry(self.state, self.progress, self.failed_entries)
    }

    /// Whether the pass held its batch for settlement: exactly when it is
    /// [`BatchState::Ready`].
    pub(crate) fn settleable(&self) -> bool {
        self.state == BatchState::Ready
    }

    fn of<A>(batch: &RecoveryBatch<A>, publication_changed: bool) -> Self {
        Self {
            state: batch.state(),
            progress: batch.progress(),
            commits: batch.commits().len(),
            retired: batch.retired_revisions().len(),
            publication_changed,
            failed_entries: batch.failed_entries(),
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

impl PassError {
    /// Classifies `error`, a failed pass, given whether its transport saw an outage
    /// ([`TransparentPirHttp::outage`]): any failure while it did is [`PassError::Outage`],
    /// whatever it was, since the service failed every account alike. Otherwise the variant
    /// of `error` carries over.
    fn classify(error: RecoveryError, outage: bool) -> Self {
        match error {
            _ if outage => PassError::Outage,
            RecoveryError::Invalid(message) => PassError::Invalid(message),
            RecoveryError::Failure(message) => PassError::Failure(message),
            RecoveryError::PublicationChanged => PassError::PublicationChanged,
        }
    }
}

impl TransparentHistoryRecovery {
    /// One pass over `watch` through the caller's `exchange`, accepting
    /// successful bodies of at most `limit` bytes: the entry point for wallets.
    ///
    /// Forgets the batch any earlier pass held, then recovers through a fresh
    /// [`TransparentPirHttp`], so an earlier pass's outage does not carry over. When
    /// the publication set changed ([`RecoveryError::PublicationChanged`]),
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
    ///
    /// `exchange` must reach the origin bound into this companion. Before any filter or private
    /// retrieval, in order: the watch set's target must be accepted by `chain`; the watch set and
    /// the companion's retained scripts must be within the script limit; the filters must not use
    /// the parent filter experiment; the shard map, its shards and the revisions its re-cuts
    /// declare superseded at or above the watch set's floor counted together, must be within the
    /// shard limit, its declarations at any height within
    /// [`MAX_SUPERSEDED`](transparent_filter::wire::MAX_SUPERSEDED), and it must name Zcash
    /// mainnet's network and genesis block; and the service's init must name
    /// [`SCHEMA`](crate::SCHEMA). A failed check is [`PassError::Invalid`] without further
    /// requests. A watch set with no addresses needs nothing retrieved: once its target is
    /// accepted, the pass sends no request and holds a batch with no commits,
    /// [`Outcome::Complete`](crate::Outcome::Complete) at the target.
    ///
    /// `chain` answers for every block at or above the watch set's floor, its lowest required
    /// height; below it the pass needs no wallet hashes and exports nothing. When the publication
    /// ends below the target, the pass syncs to the publication's end if `chain` accepts it and the
    /// companion holds nothing above it; completing there reports
    /// [`Outcome::Behind`](crate::Outcome::Behind). Otherwise the pass is
    /// [`Outcome::Behind`](crate::Outcome::Behind) at once. Commits keep the watch set's context
    /// either way.
    ///
    /// The batch is built from the shard map the sync finished with, which is the first one fetched
    /// unless the sync refreshed it; no further map is fetched. Its [`BatchState`] says whether the
    /// commits may be applied.
    ///
    /// When the first map's set identity no longer continues the one the companion's store is bound
    /// to, the pass resets the store, keeps the catalog, and retries as above. If that map ends
    /// below the store's anchor while `chain` still accepts the anchor, the pass instead keeps the
    /// store and waits for the map to catch up. That, and any divergence the sync itself finds (a
    /// map refreshed mid-pass that does not continue the first), is a [`BatchState::Pending`] batch
    /// with [`Outcome::Behind`](crate::Outcome::Behind) that claims no coverage, keeping companion
    /// and catalog. A map that rewrites sealed history the store holds without declaring a re-cut,
    /// where `chain` accepts both the stored range's end block and the end block of the map's
    /// sealed shard now covering it, is refused by the sync before anything is read, after it
    /// rolled back any reorg the chain alone shows. The pass reports a [`BatchState::Withdrawn`]
    /// batch with [`WithdrawnCause::ChangedSealed`](crate::WithdrawnCause::ChangedSealed), claiming
    /// no coverage, unless the map declares fewer re-cuts (a lower epoch) than one this companion
    /// recorded: such a map is taken for a replica still serving the publication from before that
    /// re-cut, and the batch is `Pending` and behind.
    ///
    /// A re-cut the map declares keeps the wallet's history: facts the store read under a sealed
    /// revision the re-cut superseded are exported under that revision's own identity, which the
    /// wallet holds, and the renumbered shards and tail keep their sources. An undeclared change of
    /// sealed content never reaches the wallet: the sync refuses it, or the catalog withdraws it,
    /// either way as [`BatchState::Withdrawn`]. A ready pass over a re-cut map records its re-cut
    /// epoch once the store holds a fact under a revision any of its re-cuts superseded, or under
    /// one the map publishes at or above its newest re-cut's first height. The epoch never stops a
    /// sync: a map at a lower epoch that rewrites nothing the store has finished reading is synced
    /// normally, and only a refused `SealedRewrite` is classified by the epoch. It tells a lagging
    /// replica's refused map from a contradiction, so a forged epoch can at most soften a real
    /// contradiction to `Pending`, and an honest map that rewrites nothing the store holds is never
    /// held back.
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
        let batch = result.map_err(|error| PassError::classify(error, http.outage()))?;
        let report = PassReport::of(&batch, changed);
        if report.settleable() {
            self.latest = Some(Box::new(batch));
        }
        Ok(report)
    }

    /// Takes the ready batch the latest [`Self::pass`] holds: `None` when it held
    /// none, when it was taken or settled, or when `A` is not the account type of
    /// that pass's watch set. For a caller that reads or discards the batch, which
    /// stays unacknowledged; with feature `sqlite`, settle it with
    /// `settle_latest` instead.
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
                    PassError::classify(error, outage).to_string(),
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
