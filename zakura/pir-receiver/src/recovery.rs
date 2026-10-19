//! Continuous recovery of an account's one-time keys from a receiver directory's paid
//! buckets, cumulative snapshots and seen set, over the backend's coverage traits.

use std::collections::{BTreeMap, BTreeSet};

use receiver_directory::{
    Hash,
    catalog::{BucketIndex, CatalogHead},
    paid::{BUCKET_BLOCKS, PaidSet, bucket_start},
    seen::SeenSet,
};
use receiver_pir::transport::DirectoryClient;
use zakura_one_time_ivk::KeyId;
use zcash_client_backend::data_api::{
    one_time_ivk::{
        coverage::{
            CoverageOutcome, CoverageState, CoverageStep, CoverageTarget, DirectoryHistory,
            ObligationReceivers, OneTimeIvkCoverageWrite, ReceiverSet, RecoveryStatus, Snapshot,
        },
        restore::{DiscoveryWork, OneTimeIvkRestoreWrite},
    },
    transparent_ledger::ChainPoint,
};
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters};

use crate::{
    DirectoryError, Transport, checked,
    session::{
        AccountError, AccountId, Error, PARALLEL_LOOKUPS, Session, WriteLock, directory_payment,
        join_all,
    },
};

/// The most window receivers one run derives.
pub const DERIVE_PER_RUN: u32 = 1_000;
/// Window receivers derived per wallet write.
const DERIVE_CHUNK: u32 = 100;
/// The most buckets and snapshots one run downloads: ten days of buckets.
pub const OBJECTS_PER_RUN: usize = 240;
/// How long a seen check stays fresh, in seconds.
pub const SEEN_REFRESH_SECS: i64 = 24 * 60 * 60;
/// How far the directory's latest closed bucket may end below the wallet's chain tip
/// before recovery counts as behind: the open bucket, the one closing and one more.
const BEHIND_BLOCKS: u32 = 3 * BUCKET_BLOCKS;
/// Coverage writes refused as stale that a run retries before leaving the rest for later.
const STALE_RETRIES: usize = 4;
/// Rounds of coverage, lookups and paths one run makes while admitted payments keep
/// growing the receiver set.
const ROUNDS: usize = 3;
/// Rounds of window growth one seen check makes before leaving the rest for later.
const SEEN_ROUNDS: usize = 16;

/// Why recovery is held up.
#[derive(Debug)]
pub enum Delay {
    /// The directory, or an object it names, could not be fetched or failed its checks.
    Unavailable(DirectoryError),
    /// The directory's closed buckets end far below the wallet's chain tip, or it went back
    /// to an older payment-history epoch than the wallet follows.
    Behind,
    /// A bucket or snapshot ends at a block the wallet's chain does not have, as when one
    /// of them has not followed a reorg yet.
    OffChain,
}

/// What one [`recover`] or [`check_history`] run left. `E` is the wallet's error type.
#[derive(Debug)]
pub struct Recovered<E> {
    /// The account's recovery after the run, or `None` if it has no one-time keys to
    /// recover.
    pub status: Option<RecoveryStatus>,
    /// Why recovery is held up, if it is.
    pub delay: Option<Delay>,
    /// Why the seen set could not be read, when a check was due.
    pub seen: Option<DirectoryError>,
    /// Whether the run stopped at a budget with work due now, so the app runs it again
    /// soon rather than at its next timer.
    pub more: bool,
    /// Keys whose lookup or inclusion path failed in this run, with why. A failed read or a
    /// page the wallet refused backs its lookup off.
    pub failed: Vec<(KeyId, Error<E>)>,
}

/// Runs one step of `account`'s continuous recovery against the receiver directory at
/// `origin`. The app calls it on every sync and on a timer, since retries are due even
/// without new blocks, and once for each account. Every step commits on its own, so
/// dropping the future at any await is safe.
///
/// The publication must commit to `genesis` ([`MAINNET_GENESIS`](crate::MAINNET_GENESIS) on
/// mainnet) and cover history from Ironwood activation on `params`' network. A run:
///
/// 1. Derives window receivers, at most [`DERIVE_PER_RUN`].
/// 2. Reads the catalog head the manifest commits to and its bucket index. A new
///    payment-history epoch drops coverage, so the whole receiver set is bootstrapped
///    again and every lookup restarts.
/// 3. Once a day, or after a window grew, tests the window receivers against the seen set
///    and grows the windows past its hits until it holds none they were not grown for. A
///    hit never queues a lookup. Paid recovery never waits for this.
/// 4. Moves the frontier: bootstraps it from a pinned cumulative snapshot, then tests the
///    whole receiver set against each closed bucket that continues it, and bootstraps it
///    again from a newer snapshot once the buckets that continue it are no longer
///    retained. Each historical obligation tests its receivers against its own pinned
///    snapshot, then bridges with every closed bucket through the frontier it owes. A
///    pinned snapshot the directory no longer serves gives way to the current one. At
///    most [`OBJECTS_PER_RUN`] buckets and snapshots download, and a bucket or snapshot
///    ending at a block the wallet has not stored waits for its scan.
/// 5. Looks up each hit's history over PIR, turning payments ahead of the scan into exact
///    scan hints and others into late candidates. A walk completes only the target it was
///    handed.
/// 6. Fetches due inclusion paths from the publication's common witnesses.
///
/// An admitted payment can grow a window, so steps 4 to 6 repeat, a few times at most,
/// until the receiver set stops growing.
///
/// Directory failures delay recovery rather than fail the run: `Err` is for the wallet's.
/// `now` is the caller's clock in seconds.
#[allow(clippy::too_many_arguments)]
pub async fn recover<W, P, T, L>(
    wallet: &mut W,
    params: &P,
    account: AccountId<W>,
    genesis: [u8; 32],
    origin: &str,
    transport: T,
    lock: &L,
    now: i64,
) -> Result<Recovered<AccountError<W>>, Error<AccountError<W>>>
where
    W: OneTimeIvkCoverageWrite + OneTimeIvkRestoreWrite,
    P: Parameters,
    T: Transport,
    L: WriteLock,
{
    let mut run = Run::new(wallet, account, lock, now);
    if run.coverage()?.is_none() {
        return run.finish();
    }
    run.derive()?;
    let Some(mut session) = run.session(params, genesis, origin, &transport).await? else {
        return run.finish();
    };
    let mut catalog = match Catalog::fetch(&session).await {
        Ok(catalog) => {
            run.follow_history(&catalog)?;
            run.grow_from_seen(&session, &catalog.head).await?;
            Some(catalog)
        }
        Err(e) => {
            run.delay(Delay::Unavailable(e));
            None
        }
    };
    for _ in 0..ROUNDS {
        let before = run.receiver_set()?.generation;
        if let Some(catalog) = &mut catalog {
            run.cover(&session, catalog).await?;
        }
        run.look_up(&mut session).await?;
        run.witnesses(&mut session).await?;
        // An admitted payment can grow a window, owing its new receivers their history.
        if run.receiver_set()?.generation == before {
            break;
        }
    }
    run.finish()
}

/// Runs "Check swap history" for `account`, then [`recover`]: every registered key's
/// history and every window receiver's, plus `deeper` indices past each window, is read
/// again from page zero over PIR whatever the paid sets say. Each window and deeper
/// receiver is probed first, and registers for a lookup only if its history is not empty.
/// Unlike [`recover`], a directory failure fails the run, so the app can say the check did
/// not finish.
#[allow(clippy::too_many_arguments)]
pub async fn check_history<W, P, T, L>(
    wallet: &mut W,
    params: &P,
    account: AccountId<W>,
    genesis: [u8; 32],
    origin: &str,
    transport: T,
    lock: &L,
    deeper: u32,
    now: i64,
) -> Result<Recovered<AccountError<W>>, Error<AccountError<W>>>
where
    W: OneTimeIvkCoverageWrite + OneTimeIvkRestoreWrite,
    P: Parameters,
    T: Transport,
    L: WriteLock,
{
    let mut run = Run::new(wallet, account, lock, now);
    if run.coverage()?.is_none() {
        return run.finish();
    }
    while !run.derive()? {}
    run.more = false;
    let Some(coverage) = run.coverage()? else {
        return run.finish();
    };
    let activation = activation(params)?;
    let manifest = DirectoryClient::fetch_manifest(origin, &transport).await?;
    let mut session = Session::new(activation, genesis, origin, &transport, manifest)?;
    session.connect().await?;
    let set = run.receiver_set()?;
    let mut probes: Vec<DiscoveryWork> = set
        .receivers
        .into_iter()
        .filter(|r| r.key.index() < window_end(&coverage, r.key))
        .collect();
    for window in coverage.windows {
        let past = run
            .wallet
            .one_time_receivers(account, window.purpose, window.end, deeper)
            .map_err(Error::Wallet)?;
        probes.extend(past);
    }
    let mut found = Vec::new();
    for batch in probes.chunks(PARALLEL_LOOKUPS) {
        let pages = join_all(batch.iter().map(|r| session.first_page(r.receiver))).await;
        for (probe, page) in batch.iter().zip(pages) {
            if page?.is_some() {
                found.push(probe.key);
            }
        }
    }
    let cutoff = session.publication_end().height;
    run.lock
        .write("one_time_recovery.check_history", || {
            run.wallet
                .restart_one_time_lookups(account, &found, cutoff, now)
        })
        .map_err(Error::Wallet)?;
    let recovered = recover(
        wallet, params, account, genesis, origin, &transport, lock, now,
    )
    .await?;
    match recovered.delay {
        Some(Delay::Unavailable(e)) => Err(e.into()),
        _ => Ok(recovered),
    }
}

/// Ironwood's activation on `params`' network, the history a publication must cover.
fn activation<E>(params: &impl Parameters) -> Result<BlockHeight, Error<E>> {
    params
        .activation_height(NetworkUpgrade::Nu6_3)
        .ok_or(Error::Unavailable("Ironwood is not active on this network"))
}

/// The first index past `key`'s purpose's window.
fn window_end(coverage: &CoverageState, key: KeyId) -> u64 {
    coverage
        .windows
        .iter()
        .find(|w| w.purpose == key.purpose())
        .map_or(0, |w| w.end)
}

/// A paid set's last block.
fn end(set: &PaidSet) -> ChainPoint {
    ChainPoint {
        height: BlockHeight::from(set.span().end),
        hash: BlockHash(set.span().end_hash),
    }
}

/// `snapshot` as the cumulative snapshot it is.
fn snapshot(set: &PaidSet) -> Snapshot {
    Snapshot {
        cutoff: end(set),
        digest: set.digest(),
    }
}

/// `set` as a coverage step of `history`: a bucket, or a cumulative snapshot.
fn step(set: &PaidSet, history: DirectoryHistory, bucket: bool) -> CoverageStep {
    let start = bucket.then(|| ChainPoint {
        height: BlockHeight::from(set.span().start),
        hash: BlockHash(set.span().start_hash),
    });
    CoverageStep {
        start,
        end: end(set),
        digest: set.digest(),
        history,
    }
}

/// The keys of `receivers` that `set` may hold.
fn hits(set: &PaidSet, receivers: &[&DiscoveryWork]) -> Vec<KeyId> {
    let bytes: Vec<_> = receivers.iter().map(|r| r.receiver).collect();
    receivers
        .iter()
        .zip(set.matches(&bytes))
        .filter_map(|(r, hit)| hit.then_some(r.key))
        .collect()
}

/// A publication's catalog head and bucket index, with the objects a run downloaded.
struct Catalog {
    head: CatalogHead,
    index: BucketIndex,
    /// Cumulative snapshots, by digest.
    snapshots: BTreeMap<Hash, PaidSet>,
    /// Buckets, by start.
    buckets: BTreeMap<u32, PaidSet>,
}

impl Catalog {
    /// The catalog head `session`'s manifest commits to and its bucket index.
    async fn fetch<T: Transport>(session: &Session<'_, T>) -> Result<Self, DirectoryError> {
        let (origin, http) = (session.origin(), session.transport());
        let head = DirectoryClient::fetch_catalog(origin, http, session.manifest()).await?;
        let index = DirectoryClient::fetch_bucket_index(origin, http, &head).await?;
        Ok(Self {
            head,
            index,
            snapshots: BTreeMap::new(),
            buckets: BTreeMap::new(),
        })
    }

    /// The history the head's objects belong to. The catalog's identity is its network:
    /// the same payments on the same chain make the same buckets in every directory.
    fn history(&self) -> DirectoryHistory {
        DirectoryHistory {
            catalog: self.head.genesis,
            epoch: self.head.epoch,
        }
    }

    /// Objects downloaded so far.
    fn downloaded(&self) -> usize {
        self.snapshots.len() + self.buckets.len()
    }

    /// The cumulative snapshot with `digest`, the head's own if `None`.
    async fn snapshot<T: Transport>(
        &mut self,
        session: &Session<'_, T>,
        digest: Option<Hash>,
    ) -> Result<&PaidSet, DirectoryError> {
        let digest = digest.unwrap_or(self.head.paid);
        if !self.snapshots.contains_key(&digest) {
            let (origin, http) = (session.origin(), session.transport());
            let set = DirectoryClient::fetch_pinned_paid(origin, http, &self.head, &digest).await?;
            self.snapshots.insert(digest, set);
        }
        Ok(&self.snapshots[&digest])
    }

    /// The closed bucket starting at `start`.
    async fn bucket<T: Transport>(
        &mut self,
        session: &Session<'_, T>,
        start: u32,
    ) -> Result<&PaidSet, DirectoryError> {
        if !self.buckets.contains_key(&start) {
            let (origin, http) = (session.origin(), session.transport());
            let set =
                DirectoryClient::fetch_bucket(origin, http, &self.head, &self.index, start).await?;
            self.buckets.insert(start, set);
        }
        Ok(&self.buckets[&start])
    }

    /// Where coverage that reached `height` goes on: the closed bucket holding the next
    /// block, which the index still lists, or why not.
    fn next_bucket(&self, height: BlockHeight) -> Next {
        let start = bucket_start(u32::from(height) + 1).expect("above zero");
        if start < self.head.oldest_start {
            Next::Expired
        } else if start + BUCKET_BLOCKS > self.head.latest_end {
            Next::Open
        } else {
            Next::Bucket(start)
        }
    }
}

/// Where coverage goes on (see [`Catalog::next_bucket`]).
enum Next {
    /// The closed bucket starting here.
    Bucket(u32),
    /// The bucket is not closed yet.
    Open,
    /// The bucket is no longer retained.
    Expired,
}

/// The next coverage step a run takes for one target.
enum Action {
    /// Test the target's pinned snapshot, pinning the head's first if it has none.
    Snapshot(Option<Snapshot>),
    /// Test the closed bucket starting here.
    Bucket(u32),
    /// Drop the obligation's pinned snapshot: the buckets that continue it expired.
    Restart(Snapshot),
}

/// One run's wallet, clock and findings.
struct Run<'r, W: OneTimeIvkCoverageWrite, L> {
    wallet: &'r mut W,
    account: AccountId<W>,
    lock: &'r L,
    now: i64,
    delay: Option<Delay>,
    seen: Option<DirectoryError>,
    more: bool,
    failed: Vec<(KeyId, Error<AccountError<W>>)>,
}

impl<'r, W, L> Run<'r, W, L>
where
    W: OneTimeIvkCoverageWrite + OneTimeIvkRestoreWrite,
    L: WriteLock,
{
    /// A run for `account` at `now`.
    fn new(wallet: &'r mut W, account: AccountId<W>, lock: &'r L, now: i64) -> Self {
        Self {
            wallet,
            account,
            lock,
            now,
            delay: None,
            seen: None,
            more: false,
            failed: Vec::new(),
        }
    }

    /// Notes why recovery is held up, keeping the first reason.
    fn delay(&mut self, delay: Delay) {
        self.delay.get_or_insert(delay);
    }

    /// The account's coverage.
    fn coverage(&self) -> Result<Option<CoverageState>, Error<AccountError<W>>> {
        self.wallet
            .one_time_coverage(self.account)
            .map_err(Error::Wallet)
    }

    /// The account's receiver set.
    fn receiver_set(&self) -> Result<ReceiverSet, Error<AccountError<W>>> {
        self.wallet
            .one_time_receiver_set(self.account)
            .map_err(Error::Wallet)
    }

    /// Derives window receivers up to the run's budget. Returns whether every one is
    /// derived; if not, more is due.
    fn derive(&mut self) -> Result<bool, Error<AccountError<W>>> {
        for _ in 0..DERIVE_PER_RUN / DERIVE_CHUNK {
            let (wallet, account, now) = (&mut *self.wallet, self.account, self.now);
            let complete = self
                .lock
                .write("one_time_recovery.derive", || {
                    wallet.prepare_one_time_coverage(account, DERIVE_CHUNK, now)
                })
                .map_err(Error::Wallet)?;
            if complete {
                return Ok(true);
            }
        }
        self.more = true;
        Ok(false)
    }

    /// The session of the publication `origin` serves, or `None` with the delay why not.
    async fn session<'a, T: Transport>(
        &mut self,
        params: &impl Parameters,
        genesis: [u8; 32],
        origin: &'a str,
        transport: &'a T,
    ) -> Result<Option<Session<'a, T>>, Error<AccountError<W>>> {
        let activation = activation(params)?;
        let session = match DirectoryClient::fetch_manifest(origin, transport).await {
            Ok(manifest) => Session::new(activation, genesis, origin, transport, manifest),
            Err(e) => Err(e),
        };
        Ok(session.map_err(|e| self.delay(Delay::Unavailable(e))).ok())
    }

    /// Follows `catalog`'s history: a new epoch drops coverage (see [`recover`]). An older
    /// epoch than the account follows, or closed buckets far below the wallet's chain tip,
    /// delay recovery.
    fn follow_history(&mut self, catalog: &Catalog) -> Result<(), Error<AccountError<W>>> {
        let history = catalog.history();
        let followed = self.coverage()?.and_then(|c| c.history);
        if followed.is_some_and(|h| h.catalog == history.catalog && h.epoch > history.epoch) {
            self.delay(Delay::Behind);
        } else if followed != Some(history) {
            let (wallet, account) = (&mut *self.wallet, self.account);
            self.lock
                .write("one_time_recovery.history", || {
                    wallet.reset_one_time_history(account, history)
                })
                .map_err(Error::Wallet)?;
        }
        let tip = self.wallet.chain_height().map_err(Error::Wallet)?;
        if tip.is_some_and(|tip| u32::from(tip) > catalog.head.latest_end + BEHIND_BLOCKS) {
            self.delay(Delay::Behind);
        }
        Ok(())
    }

    /// Grows the windows from the seen set `head` names if a check is due (see
    /// [`recover`]).
    async fn grow_from_seen<T: Transport>(
        &mut self,
        session: &Session<'_, T>,
        head: &CatalogHead,
    ) -> Result<(), Error<AccountError<W>>> {
        let checked = self.status()?.and_then(|s| s.seen_checked_at);
        if checked.is_some_and(|at| self.now.saturating_sub(at) < SEEN_REFRESH_SECS) {
            return Ok(());
        }
        let (origin, http) = (session.origin(), session.transport());
        let seen = match DirectoryClient::fetch_seen(origin, http, head).await {
            Ok(seen) => seen,
            Err(e) => {
                self.seen = Some(e);
                return Ok(());
            }
        };
        for _ in 0..SEEN_ROUNDS {
            if self.seen_round(&seen)? {
                return Ok(());
            }
        }
        self.more = true;
        Ok(())
    }

    /// Tests the derived window receivers against `seen` and records its hits. Returns
    /// whether the check is done: it is, too, when derivation ran out of budget, and the
    /// next run checks again.
    fn seen_round(&mut self, seen: &SeenSet) -> Result<bool, Error<AccountError<W>>> {
        if !self.derive()? {
            return Ok(true);
        }
        let Some(coverage) = self.coverage()? else {
            return Ok(true);
        };
        let set = self.receiver_set()?;
        let window: Vec<_> = set
            .receivers
            .iter()
            .filter(|r| r.key.index() < window_end(&coverage, r.key))
            .collect();
        let bytes: Vec<_> = window.iter().map(|r| r.receiver).collect();
        let hits: Vec<_> = window
            .iter()
            .zip(seen.matches(&bytes))
            .filter_map(|(r, hit)| hit.then_some(r.key))
            .collect();
        let (wallet, account, now) = (&mut *self.wallet, self.account, self.now);
        self.lock
            .write("one_time_recovery.seen", || {
                wallet.record_one_time_seen(account, set.generation, &hits, now)
            })
            .map_err(Error::Wallet)
    }

    /// Moves the frontier and the obligations as far as `catalog` and the run's budget
    /// allow (see [`recover`]).
    async fn cover<T: Transport>(
        &mut self,
        session: &Session<'_, T>,
        catalog: &mut Catalog,
    ) -> Result<(), Error<AccountError<W>>> {
        let history = catalog.history();
        // Targets that wait for a later run, the frontier as `None`.
        let mut waiting = BTreeSet::new();
        let mut stale = 0;
        loop {
            if catalog.downloaded() >= OBJECTS_PER_RUN {
                self.more = true;
                return Ok(());
            }
            let Some(coverage) = self.coverage()? else {
                return Ok(());
            };
            if coverage.history != Some(history) {
                return Ok(());
            }
            let set = self.receiver_set()?;
            if !set.complete {
                if self.derive()? {
                    continue;
                }
                return Ok(());
            }
            let Some((target, action)) = next_action(&coverage, &set, catalog, &waiting) else {
                return Ok(());
            };
            let key = match target {
                CoverageTarget::Frontier { .. } => None,
                CoverageTarget::Obligation { id, .. } => Some(id),
            };
            let receivers = receivers(&coverage, &set, target);
            let (set, pinned) = match action {
                Action::Restart(pinned) => {
                    self.unpin(target, pinned)?;
                    continue;
                }
                Action::Bucket(start) => match catalog.bucket(session, start).await {
                    Ok(bucket) => (bucket, None),
                    Err(e) => {
                        self.delay(Delay::Unavailable(e));
                        waiting.insert(key);
                        continue;
                    }
                },
                Action::Snapshot(pinned) => {
                    let pinned = match pinned {
                        Some(pinned) => pinned,
                        None => {
                            let current = match catalog.snapshot(session, None).await {
                                Ok(current) => snapshot(current),
                                Err(e) => {
                                    self.delay(Delay::Unavailable(e));
                                    return Ok(());
                                }
                            };
                            match self.pin(target, current)? {
                                Some(pinned) => pinned,
                                // An established frontier takes only a snapshot past it.
                                None if key.is_none() && coverage.frontier.is_some() => {
                                    self.delay(Delay::Behind);
                                    waiting.insert(key);
                                    continue;
                                }
                                None => continue,
                            }
                        }
                    };
                    let current = catalog.head.paid;
                    match catalog.snapshot(session, Some(pinned.digest)).await {
                        Ok(set) => (set, Some(pinned)),
                        // A pinned snapshot the directory no longer serves gives way to the
                        // current one.
                        Err(_) if pinned.digest != current => {
                            self.unpin(target, pinned)?;
                            continue;
                        }
                        Err(e) => {
                            self.delay(Delay::Unavailable(e));
                            waiting.insert(key);
                            continue;
                        }
                    }
                }
            };
            let hits = hits(set, &receivers);
            let step = step(set, history, pinned.is_none());
            let (wallet, account, now) = (&mut *self.wallet, self.account, self.now);
            let outcome = self
                .lock
                .write("one_time_recovery.coverage", || {
                    wallet.record_one_time_coverage(account, target, step, &hits, now)
                })
                .map_err(Error::Wallet)?;
            match outcome {
                CoverageOutcome::Recorded => stale = 0,
                CoverageOutcome::Stale => {
                    stale += 1;
                    if stale > STALE_RETRIES {
                        self.more = true;
                        return Ok(());
                    }
                }
                CoverageOutcome::Pending => {
                    waiting.insert(key);
                }
                CoverageOutcome::OffChain => {
                    self.delay(Delay::OffChain);
                    waiting.insert(key);
                }
                // A snapshot pinned before the frontier passed it no longer continues it.
                CoverageOutcome::Discontinuous => match pinned {
                    Some(pinned) => self.unpin(target, pinned)?,
                    None => {
                        waiting.insert(key);
                    }
                },
                CoverageOutcome::HistoryChanged => return Ok(()),
            }
        }
    }

    /// Pins `snapshot` for `target` (see `OneTimeIvkCoverageWrite::pin_one_time_snapshot`).
    fn pin(
        &mut self,
        target: CoverageTarget,
        snapshot: Snapshot,
    ) -> Result<Option<Snapshot>, Error<AccountError<W>>> {
        let (wallet, account) = (&mut *self.wallet, self.account);
        self.lock
            .write("one_time_recovery.pin", || {
                wallet.pin_one_time_snapshot(account, target, snapshot)
            })
            .map_err(Error::Wallet)
    }

    /// Drops `target`'s pinned `snapshot` (see
    /// `OneTimeIvkCoverageWrite::unpin_one_time_snapshot`).
    fn unpin(
        &mut self,
        target: CoverageTarget,
        snapshot: Snapshot,
    ) -> Result<(), Error<AccountError<W>>> {
        let (wallet, account) = (&mut *self.wallet, self.account);
        self.lock
            .write("one_time_recovery.unpin", || {
                wallet.unpin_one_time_snapshot(account, target, snapshot)
            })
            .map_err(Error::Wallet)?;
        Ok(())
    }

    /// The account's recovery status.
    fn status(&self) -> Result<Option<RecoveryStatus>, Error<AccountError<W>>> {
        self.wallet
            .one_time_recovery_status(self.account)
            .map_err(Error::Wallet)
    }

    /// Looks up the lookups due now that `session`'s publication reaches, as [`recover`]
    /// describes, [`PARALLEL_LOOKUPS`] at a time, recording each walk against its ticket. A
    /// failed read, or a page the wallet refused, backs its lookup off and is listed in
    /// `failed`; a page the wallet skipped for another reason is listed without a backoff.
    /// Lookups go on after one fails unless the directory's connection failed or it revoked
    /// the session.
    async fn look_up<T: Transport>(
        &mut self,
        session: &mut Session<'_, T>,
    ) -> Result<(), Error<AccountError<W>>> {
        let (wallet, account, now) = (&mut *self.wallet, self.account, self.now);
        let tickets = self
            .lock
            .write("one_time_recovery.dispatch", || {
                wallet.dispatch_one_time_lookups(account, now)
            })
            .map_err(Error::Wallet)?;
        // A lookup whose target the publication has not reached waits for a newer one.
        let revision = session.publication_end();
        let tickets: Vec<_> = tickets
            .into_iter()
            .filter(|t| t.work.cutoff <= revision.height)
            .collect();
        if tickets.is_empty() {
            return Ok(());
        }
        if let Err(e) = session.connect().await {
            self.delay(Delay::Unavailable(e));
            return Ok(());
        }
        for batch in tickets.chunks(PARALLEL_LOOKUPS) {
            let walks = join_all(batch.iter().map(|t| session.page_through(&t.work))).await;
            let mut stop = false;
            for (ticket, walk) in batch.iter().zip(walks) {
                let key = ticket.work.work.key;
                let mut defer = false;
                self.more |= !walk.complete && walk.error.is_none();
                if !walk.records.is_empty() || walk.complete {
                    let payments = walk.records.into_iter().map(directory_payment);
                    match payments.collect::<Result<Vec<_>, _>>() {
                        Ok(payments) => {
                            let wallet = &mut *self.wallet;
                            let recorded = self
                                .lock
                                .write("one_time_recovery.lookup", || {
                                    wallet.record_one_time_lookup_page(
                                        account,
                                        ticket,
                                        revision,
                                        walk.start,
                                        &payments,
                                        walk.complete,
                                        now,
                                    )
                                })
                                .map_err(Error::Wallet)?;
                            // The wallet backs off a lookup whose page it refused, but not
                            // one whose ticket went stale.
                            if !recorded {
                                let skipped = "the wallet did not record the page";
                                self.failed.push((key, Error::Unavailable(skipped)));
                            }
                        }
                        Err(e) => {
                            self.failed.push((key, e.into()));
                            defer = true;
                        }
                    }
                }
                if let Some(e) = walk.error {
                    stop |= matches!(e, DirectoryError::Revision | DirectoryError::Transport(_));
                    self.failed.push((key, e.into()));
                    defer = true;
                }
                if defer {
                    let wallet = &mut *self.wallet;
                    self.lock
                        .write("one_time_recovery.defer", || {
                            wallet.defer_one_time_lookup(account, key, now)
                        })
                        .map_err(Error::Wallet)?;
                }
            }
            if stop {
                break;
            }
        }
        Ok(())
    }

    /// Fetches the due inclusion paths from `session`'s common witnesses. A path the
    /// witnesses cannot give is listed in `failed` and requested again later.
    async fn witnesses<T: Transport>(
        &mut self,
        session: &mut Session<'_, T>,
    ) -> Result<(), Error<AccountError<W>>> {
        let Some(status) = self.status()? else {
            return Ok(());
        };
        let publication = session.publication_end();
        // A path to a root the wallet would refuse as too old is not worth the download.
        if status.witnesses.is_empty() || publication.height < status.witness_anchor_floor {
            return Ok(());
        }
        let anchor = ChainPoint {
            height: publication.height,
            hash: BlockHash(publication.hash),
        };
        let fetched = match session.connect().await {
            Ok(()) => session.witnesses().await,
            Err(e) => Err(e),
        };
        let witnesses = match fetched {
            Ok(witnesses) => witnesses,
            Err(e) => {
                self.delay(Delay::Unavailable(e));
                return Ok(());
            }
        };
        let (account, now) = (self.account, self.now);
        for request in status.witnesses {
            // The common witnesses hold every record's position in this publication.
            match witnesses.path(request.position, request.cmx) {
                Ok(siblings) => {
                    let wallet = &mut *self.wallet;
                    self.lock
                        .write("one_time_recovery.witness", || {
                            wallet.record_one_time_witness(
                                account,
                                request.key,
                                request.position,
                                anchor,
                                siblings,
                                now,
                            )
                        })
                        .map_err(Error::Wallet)?;
                }
                Err(e) => self
                    .failed
                    .push((request.key, Error::Directory(checked(e)))),
            }
        }
        Ok(())
    }

    /// What the run left.
    fn finish(self) -> Result<Recovered<AccountError<W>>, Error<AccountError<W>>> {
        Ok(Recovered {
            status: self.status()?,
            delay: self.delay,
            seen: self.seen,
            more: self.more,
            failed: self.failed,
        })
    }
}

/// The next coverage step: the frontier's, then each obligation's in order, skipping the
/// `waiting` targets (the frontier as `None`) and those with nothing to do yet.
fn next_action(
    coverage: &CoverageState,
    set: &ReceiverSet,
    catalog: &Catalog,
    waiting: &BTreeSet<Option<u64>>,
) -> Option<(CoverageTarget, Action)> {
    let frontier = CoverageTarget::Frontier {
        generation: set.generation,
    };
    if !waiting.contains(&None) {
        // A frontier whose adjoining buckets expired bootstraps again from a newer snapshot.
        let snapshot = Action::Snapshot(coverage.bootstrap);
        match coverage.frontier {
            _ if coverage.bootstrap.is_some() => return Some((frontier, snapshot)),
            None => return Some((frontier, snapshot)),
            Some((point, _)) => match catalog.next_bucket(point.height) {
                Next::Bucket(start) => return Some((frontier, Action::Bucket(start))),
                Next::Expired => return Some((frontier, snapshot)),
                Next::Open => {}
            },
        }
    }
    coverage.obligations.iter().find_map(|o| {
        let target = CoverageTarget::Obligation {
            id: o.id,
            generation: set.generation,
        };
        if waiting.contains(&Some(o.id)) {
            return None;
        }
        let action = match (o.snapshot, o.bridged) {
            (Some(pinned), Some(bridged)) => match catalog.next_bucket(bridged) {
                Next::Bucket(start) => Action::Bucket(start),
                Next::Expired => Action::Restart(pinned),
                Next::Open => return None,
            },
            (pinned, _) => Action::Snapshot(pinned),
        };
        Some((target, action))
    })
}

/// The receivers of `set` that `target` tests: all of them for the frontier, an
/// obligation's own otherwise.
fn receivers<'s>(
    coverage: &CoverageState,
    set: &'s ReceiverSet,
    target: CoverageTarget,
) -> Vec<&'s DiscoveryWork> {
    let owed = match target {
        CoverageTarget::Frontier { .. } => None,
        CoverageTarget::Obligation { id, .. } => coverage
            .obligations
            .iter()
            .find(|o| o.id == id)
            .map(|o| o.receivers),
    };
    set.receivers
        .iter()
        .filter(|r| match owed {
            None => true,
            Some(ObligationReceivers::Key(key)) => r.key == key,
            Some(ObligationReceivers::Window {
                purpose,
                start,
                end,
            }) => r.key.purpose() == purpose && (start..end).contains(&r.key.index()),
        })
        .collect()
}
