//! One run over the wallet's due txid detail lookups: what to list, when to check the display
//! map, and what each lookup's result writes.
//!
//! The caller owns everything around it: transport, scheduling, budgets, threads,
//! cancellation and the wallet's write lock. A run holds no wallet borrow between steps, so
//! lookups run with no lock held and each write takes the lock only for itself.

use std::collections::VecDeque;
use std::time::SystemTime;

use transparent_txid_client::{TxidError, TxidLookup};
use zcash_client_backend::data_api::transparent_ledger::{
    TransparentDetailOutcome, TransparentDetailRead, TransparentDetailRequest,
    TransparentDetailWrite, TransparentDisplayFacts, TransparentDisplayStore,
    TransparentLedgerMode,
};
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;

use super::display_facts::{deferral, display_facts};
use super::service::{DisplayLookup, TxidDisplayService};
use crate::http::HttpExchange;

/// One run over the wallet's due txid detail lookups.
///
/// [`DetailRun::plan`] lists the due work under the service's display map. When nothing is due
/// but lookups are parked on the map and a re-check is due, the run's first and only step is
/// [`DetailStep::RefreshMap`]; [`DetailRun::relist`] lists again when the fetched map differs.
/// Every other step is a [`DetailStep::Lookup`], preferred transactions first.
///
/// The run's mode and policy generation come from its listing's snapshot, and stay fixed: a
/// relisting under another policy lists nothing, so the caller's check after `plan` holds for
/// the whole run.
///
/// ```no_run
/// use std::time::{Instant, SystemTime};
/// use zakura_pir_transparent::{
///     DetailAnswer, DetailRun, DetailStep, HttpExchange, TxidDisplayService, TxidError,
/// };
/// use zcash_client_backend::data_api::transparent_ledger::TransparentDetailWrite;
/// use zcash_primitives::transaction::TxId;
///
/// /// A private run: every lookup goes through the display service.
/// fn run_once<W: TransparentDetailWrite>(
///     wallet: &mut W,
///     service: &TxidDisplayService,
///     exchange: &impl HttpExchange,
///     expected_generation: u64,
///     opened_receipts: &[TxId],
///     exiting: &dyn Fn() -> bool,
///     deadline: Instant,
/// ) -> Result<(), W::Error> {
///     let now = SystemTime::now();
///     let mut run = DetailRun::plan(wallet, Some(service), now, 8, opened_receipts)?;
///     // The caller's own gate, against the listing's snapshot.
///     if run.policy_generation() != expected_generation || run.public_transport() {
///         return Ok(());
///     }
///     let out_of_time = || Instant::now() >= deadline;
///     let cancel = || exiting() || out_of_time();
///     while let Some(step) = run.next() {
///         match step {
///             // The check is already recorded; a failed fetch leaves nothing to do.
///             DetailStep::RefreshMap(check) => {
///                 let checked = check.fetch(service, exchange, &cancel);
///                 run.relist(wallet, checked, SystemTime::now())?;
///             }
///             DetailStep::Lookup(request) => {
///                 // With no wallet lock held.
///                 let found = service.lookup(
///                     exchange,
///                     *request.txid.as_ref(),
///                     u32::from(request.mined_height).into(),
///                     &cancel,
///                 );
///                 let answer = match found.found {
///                     Err(TxidError::Cancelled) if exiting() => DetailAnswer::Cancelled,
///                     // The run's budget, not the service: an attempt, deferred.
///                     Err(TxidError::Cancelled) => DetailAnswer::TimedOut,
///                     _ => DetailAnswer::Display(found),
///                 };
///                 // `()`: this caller never fetches publicly.
///                 if let Some(write) = run.record::<()>(&request, answer) {
///                     // Under the caller's write lock.
///                     write.apply(wallet, SystemTime::now())?;
///                 }
///             }
///         }
///         if cancel() {
///             break;
///         }
///     }
///     Ok(())
/// }
/// ```
pub struct DetailRun<'a> {
    service: Option<&'a TxidDisplayService>,
    now: SystemTime,
    limit: usize,
    prefer: Vec<TxId>,
    mode: TransparentLedgerMode,
    policy_generation: u64,
    /// The display map hash the work was listed under.
    listed_map: Option<[u8; 32]>,
    requests: VecDeque<TransparentDetailRequest>,
    /// Whether the next step is a map check.
    check_map: bool,
}

/// What a run asks the caller to do next.
#[derive(Debug)]
pub enum DetailStep {
    /// Look up this transaction's details, then [`DetailRun::record`] the answer.
    Lookup(TransparentDetailRequest),
    /// Fetch the display map ([`MapCheck::fetch`]), then [`DetailRun::relist`].
    RefreshMap(MapCheck),
}

/// A display map check, already recorded with the service as started.
///
/// The check counts toward the re-check interval whether it is fetched, fails or is dropped,
/// so a map that cannot be fetched is not asked for again before the interval passes.
#[derive(Debug)]
#[must_use = "a map check is recorded when created; fetch it, or drop it to skip it"]
pub struct MapCheck {
    listed_map: Option<[u8; 32]>,
}

impl MapCheck {
    /// Fetches the recent display map through `exchange` ([`TxidDisplayService::refresh_map`]).
    /// A failure, including cancellation, leaves the run with nothing more to list.
    pub fn fetch(
        self,
        service: &TxidDisplayService,
        exchange: &impl HttpExchange,
        cancel: &dyn Fn() -> bool,
    ) -> MapChecked {
        MapChecked {
            listed_map: self.listed_map,
            fetched: service.refresh_map(exchange, cancel).ok(),
        }
    }
}

/// The outcome of a [`MapCheck`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapChecked {
    listed_map: Option<[u8; 32]>,
    fetched: Option<[u8; 32]>,
}

impl MapChecked {
    /// The fetched map's hash, when it was fetched and differs from the one the work was listed
    /// under.
    pub fn changed(&self) -> Option<[u8; 32]> {
        self.fetched
            .filter(|fetched| Some(*fetched) != self.listed_map)
    }
}

/// A lookup's result, as the caller hands it to [`DetailRun::record`].
///
/// `R` is the caller's public transaction, such as a decoded lightwalletd `GetTransaction`
/// response; the run never reads it.
#[derive(Debug)]
pub enum DetailAnswer<R> {
    /// What [`TxidDisplayService::lookup`] returned for the request, with the map it used.
    Display(DisplayLookup),
    /// What a public lookup returned: the transaction, or the outcome to defer it with
    /// (`Absent` for a transaction the server does not have, `Unavailable` for an outage,
    /// `Protocol` for an unusable answer).
    Public(Result<R, TransparentDetailOutcome>),
    /// The caller's run budget stopped the lookup before it completed: its time limit ran out
    /// while the lookup was in flight, by any route, including a transport failure the budget
    /// caused. An attempt: it is deferred as
    /// [`Unavailable`](TransparentDetailOutcome::Unavailable), so the lookup backs off like an
    /// unreachable service (30 seconds, doubling up to an hour) and other due lookups come
    /// first in the next runs. A lookup that always outlasts the budget would otherwise stay
    /// due, listed first, and take every run.
    TimedOut,
    /// The caller stopped the lookup because it is exiting: shutting down, cancelled or
    /// leaving the run for a reason that says nothing about the lookup, by any route,
    /// including a transport failure its own cancellation caused. Not an attempt: nothing is
    /// written, and the lookup stays due for the next run.
    ///
    /// A [`DisplayLookup`] that failed with [`TxidError::Cancelled`] records the same; a caller
    /// whose cancellation was its run budget hands [`DetailAnswer::TimedOut`] instead.
    Cancelled,
}

/// What a lookup's result writes to the wallet.
#[derive(Debug)]
#[must_use = "the lookup's result is written only when applied"]
pub enum DetailWrite<R> {
    /// Display facts to validate and store under the listing's policy generation.
    Store {
        /// The facts.
        facts: Box<TransparentDisplayFacts>,
        /// The generation the work was listed under.
        expected_generation: u64,
    },
    /// A failed lookup to record, which schedules the next attempt.
    Defer {
        /// The transaction.
        txid: TxId,
        /// The mined height the lookup used.
        looked_up_height: BlockHeight,
        /// Why it failed.
        outcome: TransparentDetailOutcome,
        /// The display map the lookup used, when it used one.
        map_sha256: Option<[u8; 32]>,
    },
    /// A public transaction under a snapshot that retains public authority. The caller stores
    /// it through ordinary transaction ingestion, re-checking its policy in the same wallet
    /// transaction.
    Raw {
        /// The transaction.
        txid: TxId,
        /// The mined height the request named.
        looked_up_height: BlockHeight,
        /// The caller's transaction.
        transaction: R,
    },
}

/// What [`DetailWrite::apply`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum DetailApplied<R> {
    /// The facts were validated; see [`TransparentDisplayStore`].
    Stored(TransparentDisplayStore),
    /// The failure was recorded.
    Deferred(TransparentDetailOutcome),
    /// Nothing was written: the public transaction, for the caller to store.
    Raw(R),
}

impl<R> DetailWrite<R> {
    /// Writes a [`DetailWrite::Store`] or [`DetailWrite::Defer`] to `wallet` at `now`, each in
    /// its own short wallet transaction; hands a [`DetailWrite::Raw`] back unwritten.
    ///
    /// A store under a policy generation that is no longer current fails with the wallet's
    /// stale-policy error and changes nothing: the run should end.
    pub fn apply<W: TransparentDetailWrite>(
        self,
        wallet: &mut W,
        now: SystemTime,
    ) -> Result<DetailApplied<R>, W::Error> {
        match self {
            DetailWrite::Store {
                facts,
                expected_generation,
            } => wallet
                .store_transparent_display(*facts, expected_generation, now)
                .map(DetailApplied::Stored),
            DetailWrite::Defer {
                txid,
                looked_up_height,
                outcome,
                map_sha256,
            } => wallet
                .defer_transparent_detail(txid, looked_up_height, outcome, map_sha256, now)
                .map(|()| DetailApplied::Deferred(outcome)),
            DetailWrite::Raw { transaction, .. } => Ok(DetailApplied::Raw(transaction)),
        }
    }
}

impl<'a> DetailRun<'a> {
    /// Lists up to `limit` due lookups at `now` plus the due ones among `prefer`, first and in
    /// its order, under `service`'s display map; see
    /// [`TransparentDetailRead::transparent_detail_work`].
    ///
    /// When nothing is due, it asks which lookups are parked on the map: if any are and their
    /// re-check time has passed, the run's only step is a map check. `service` is `None` for a
    /// caller that fetches only publicly; such a run never checks a map.
    pub fn plan<W: TransparentDetailRead>(
        wallet: &W,
        service: Option<&'a TxidDisplayService>,
        now: SystemTime,
        limit: usize,
        prefer: &[TxId],
    ) -> Result<Self, W::Error> {
        let listed_map = service.and_then(TxidDisplayService::map_sha256);
        let work = wallet.transparent_detail_work(now, limit, prefer, listed_map)?;
        let check_map = match service {
            Some(service) if work.requests.is_empty() => {
                let parked =
                    wallet.transparent_detail_parked(now, listed_map, service.map_checked_at())?;
                parked.count > 0 && parked.refresh_at.is_some_and(|at| at <= now)
            }
            _ => false,
        };
        Ok(Self {
            service,
            now,
            limit,
            prefer: prefer.to_vec(),
            mode: work.mode,
            policy_generation: work.policy_generation,
            listed_map,
            requests: work.requests.into(),
            check_map,
        })
    }

    /// The wallet handle's resolved transparent ledger mode, from the listing's snapshot.
    pub fn mode(&self) -> TransparentLedgerMode {
        self.mode
    }

    /// The durable policy generation, from the listing's snapshot (`0` before any policy was
    /// applied). Display facts are stored only while it is still current.
    pub fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    /// Whether the listing's snapshot allows fetching over public transport; see
    /// [`TransparentDetailWork::public_transport`](zcash_client_backend::data_api::transparent_ledger::TransparentDetailWork::public_transport).
    pub fn public_transport(&self) -> bool {
        self.mode.retains_public_authority()
    }

    /// Lists the due work again under the map `checked` fetched, when it differs from the one
    /// the run listed under; otherwise does nothing.
    ///
    /// A listing under another mode or policy generation than the run's lists nothing: the
    /// next run plans under the new policy.
    pub fn relist<W: TransparentDetailRead>(
        &mut self,
        wallet: &W,
        checked: MapChecked,
        now: SystemTime,
    ) -> Result<(), W::Error> {
        let Some(map) = checked.changed() else {
            return Ok(());
        };
        let work = wallet.transparent_detail_work(now, self.limit, &self.prefer, Some(map))?;
        self.listed_map = Some(map);
        if work.mode == self.mode && work.policy_generation == self.policy_generation {
            self.requests = work.requests.into();
        }
        Ok(())
    }

    /// What `answer`, the result of looking up `request`, writes; `None` for a cancelled
    /// lookup, which writes nothing. A timed-out lookup is deferred as
    /// [`Unavailable`](TransparentDetailOutcome::Unavailable) without a map.
    ///
    /// Found display facts are translated ([`display_facts`]) and stored under the run's
    /// policy generation; facts that cannot be translated, and every other display result, are
    /// deferred ([`deferral`]) with the map the lookup used, never one a later lookup or map
    /// check left the shared service holding. A public transaction is handed
    /// back only under a snapshot allowing public transport, and deferred as `Protocol`
    /// otherwise.
    pub fn record<R>(
        &self,
        request: &TransparentDetailRequest,
        answer: DetailAnswer<R>,
    ) -> Option<DetailWrite<R>> {
        let defer = |outcome, map_sha256| DetailWrite::Defer {
            txid: request.txid,
            looked_up_height: request.mined_height,
            outcome,
            map_sha256,
        };
        match answer {
            DetailAnswer::Cancelled
            | DetailAnswer::Display(DisplayLookup {
                found: Err(TxidError::Cancelled),
                ..
            }) => None,
            DetailAnswer::Display(DisplayLookup {
                found: Ok(TxidLookup::Found { entry, provenance }),
                map_sha256,
            }) => Some(
                match display_facts(request.txid, &entry, &provenance, request.mined_height) {
                    Ok(facts) => DetailWrite::Store {
                        facts: Box::new(facts),
                        expected_generation: self.policy_generation,
                    },
                    Err(_) => defer(TransparentDetailOutcome::Protocol, map_sha256),
                },
            ),
            DetailAnswer::Display(DisplayLookup { found, map_sha256 }) => {
                deferral(&found).map(|outcome| defer(outcome, map_sha256))
            }
            DetailAnswer::Public(Ok(transaction)) if self.public_transport() => {
                Some(DetailWrite::Raw {
                    txid: request.txid,
                    looked_up_height: request.mined_height,
                    transaction,
                })
            }
            DetailAnswer::Public(Ok(_)) => Some(defer(TransparentDetailOutcome::Protocol, None)),
            DetailAnswer::Public(Err(outcome)) => Some(defer(outcome, None)),
            DetailAnswer::TimedOut => Some(defer(
                TransparentDetailOutcome::Unavailable { retry_after: None },
                None,
            )),
        }
    }
}

impl Iterator for DetailRun<'_> {
    type Item = DetailStep;

    /// The next step: the map check, at most once and only first, then each listed lookup.
    ///
    /// Handing out the map check records it with the service as started at the run's `now`.
    fn next(&mut self) -> Option<DetailStep> {
        if std::mem::take(&mut self.check_map)
            && let Some(service) = self.service
        {
            service.map_check_started(self.now);
            return Some(DetailStep::RefreshMap(MapCheck {
                listed_map: self.listed_map,
            }));
        }
        self.requests.pop_front().map(DetailStep::Lookup)
    }
}
