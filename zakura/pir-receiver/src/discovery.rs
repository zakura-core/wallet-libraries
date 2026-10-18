//! Discovery of a restored account's one-time keys over a wallet's restore traits.

use std::future::Future;
use std::pin::Pin;
use std::task::Poll;

use receiver_directory::{
    RawRecord,
    filter::{Filters, PAID, RECENT},
    snapshot::{FilterSet, check_next},
};
use receiver_pir::{AcceptedCoverage, transport::DirectoryClient};
use zakura_one_time_ivk::{
    KeyId, Purpose,
    swap::{RESTORE_WATCH_SECS, provider_read_is_current},
};
use zakura_receiver_crypto::{
    Receiver,
    witness::{Publication, WitnessSnapshot},
};
use zcash_client_backend::data_api::{
    WalletRead,
    one_time_ivk::restore::{
        DirectoryPayment, DiscoveryWork, EnumerationCursor, FilterCheck, LookupWork,
        OneTimeIvkRestoreWrite, PublicationEnd,
    },
    transparent_ledger::ChainPoint,
};
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters};

use crate::{DirectoryError, Transport, checked, seen::seen_sets};

/// A wallet's account identifier.
pub(crate) type AccountId<W> = <W as WalletRead>::AccountId;
/// A wallet's error type.
pub(crate) type AccountError<W> = <W as WalletRead>::Error;

/// Keys discovery always checks, from index zero, in each purpose.
pub const FIRST_WINDOW: u64 = 100;
/// Consecutive keys in no filter after which a purpose's checks stop, past
/// [`FIRST_WINDOW`].
pub const GAP: u64 = 30;
/// The most keys one [`discover`] call checks in a purpose. The wallet keeps the cursor, so
/// the next call continues, unless the directory has published since: the search then
/// starts over and runs to its end in one call, so it finishes against the newest filters.
pub const KEYS_PER_RUN: u64 = 5_000;
/// Receivers derived per wallet read.
const CHUNK: u64 = 100;
/// Lookups in flight at once.
const PARALLEL_LOOKUPS: usize = 8;
/// Pages one lookup reads in a call; the wallet keeps the cursor for the next.
const PAGES_PER_LOOKUP: u32 = 64;

/// Why a discovery run, or one key's lookup, stopped. `E` is the wallet's error type.
#[derive(Debug, thiserror::Error)]
pub enum Error<E> {
    /// The receiver directory refused, failed or answered inconsistently.
    #[error("receiver directory: {0}")]
    Directory(#[from] DirectoryError),
    /// A wallet step refused the work, or the wallet's storage failed.
    #[error(transparent)]
    Wallet(E),
    /// A service's publication cannot be used against the wallet's chain yet.
    #[error("{0}")]
    Unavailable(&'static str),
}

/// Serializes discovery's wallet writes with the caller's other writers.
pub trait WriteLock {
    /// Runs `write` while holding the caller's wallet write lock. `label` names the
    /// step.
    fn write<T>(&self, label: &'static str, write: impl FnOnce() -> T) -> T;
}

/// What one [`discover`] run left. `E` is the wallet's error type.
#[derive(Debug)]
pub struct Discovered<E> {
    /// Whether the account's discovery is complete, including every payment it found (see
    /// `DiscoveryStatus::complete`). Until it is, the app runs discovery again.
    pub complete: bool,
    /// Lookups ready to run again now, for example after a page budget. A lookup backed off
    /// after a failure counts only once its retry is due, and one waiting for a newer
    /// publication not at all.
    pub lookups: usize,
    /// Late payments still waiting for an inclusion path.
    pub witnesses: usize,
    /// Keys whose lookup or inclusion path failed in this run, with why. A failed read or a
    /// page the wallet refused backs its lookup off. A page the wallet skipped for another
    /// reason does not, and a path the witnesses could not give is requested again.
    pub failed: Vec<(KeyId, Error<E>)>,
}

/// Runs `account`'s discovery (see `OneTimeIvkRestoreWrite`) against the receiver directory
/// at `origin`. A wallet with several accounts calls it once for each, before the restore
/// scan's first batch and again after every sync. Every step commits on its own, so
/// dropping the future at any await is safe.
///
/// The publication must commit to `genesis` ([`MAINNET_GENESIS`](crate::MAINNET_GENESIS) on
/// mainnet) and cover history from Ironwood activation on `params`' network. It is
/// provisional: the wallet judges it once its scan stores the publication's last block. A
/// run with nothing due makes no request, and keys registered after discovery finished,
/// such as a refund key recovered from a funding memo, are looked up by the first run whose
/// publication reaches the blocks the wallet scanned without them. A run starts a new pass
/// when the account has none, its pass's publication was rejected, or its pass's search is
/// unfinished and the directory has published since (see [`KEYS_PER_RUN`]). Once discovery is complete, only `recheck_one_time_key_history` in
/// the SQLite store starts another pass, so a payment to a closed key is found on request.
/// Each purpose's keys are checked against the filters from index zero: always the first
/// [`FIRST_WINDOW`], then on until [`GAP`] consecutive keys are in no seen set and not in
/// the paid filter, and then every closed key past that (see `DiscoveryStatus::closed`). A
/// provider's recent set counts only if its feed's last read began at most fifteen minutes
/// before `now` and at most a minute after it, and its window, with the feed running
/// throughout, covers [`RESTORE_WATCH_SECS`]; unless every provider has one, every key is
/// recent.
///
/// Paid keys are then looked up over PIR, several at once, each paging from the cursor the
/// wallet keeps. A late payment's inclusion path comes from the publication's common
/// witnesses. Lookups go on after one fails unless the directory's connection failed or it
/// revoked the session: then the remaining keys wait for the next run. `now` is the
/// caller's clock in seconds.
#[allow(clippy::too_many_arguments)]
pub async fn discover<W, P, T, L>(
    wallet: &mut W,
    params: &P,
    account: AccountId<W>,
    genesis: [u8; 32],
    origin: &str,
    transport: T,
    lock: &L,
    now: i64,
) -> Result<Discovered<AccountError<W>>, Error<AccountError<W>>>
where
    W: OneTimeIvkRestoreWrite,
    P: Parameters,
    T: Transport,
    L: WriteLock,
{
    let Some(status) = wallet
        .one_time_discovery(account, now)
        .map_err(Error::Wallet)?
    else {
        return Ok(nothing_due(vec![]));
    };
    if status.publication.is_some()
        && status.enumeration.is_none()
        && status.lookups.is_empty()
        && status.witnesses.is_empty()
    {
        return Ok(Discovered {
            complete: status.complete,
            lookups: 0,
            witnesses: 0,
            failed: vec![],
        });
    }
    let activation = params
        .activation_height(NetworkUpgrade::Nu6_3)
        .ok_or(Error::Unavailable("Ironwood is not active on this network"))?;
    let manifest = DirectoryClient::fetch_manifest(origin, &transport).await?;
    let mut directory = Directory::new(activation, genesis, origin, transport, manifest)?;
    let publication = directory.publication_end();

    // A newer publication's filters can mark keys an unfinished search already passed, so the
    // search starts over against them, and runs to its end so it cannot restart forever.
    let moved = status.enumeration.is_some() && status.publication != Some(publication);
    let cursors = if status.publication.is_none() || moved {
        Some([
            (Purpose::Receive, EnumerationCursor::default()),
            (Purpose::Refund, EnumerationCursor::default()),
        ])
    } else {
        status.enumeration
    };
    let budget = if moved { u64::MAX } else { KEYS_PER_RUN };
    if let Some(cursors) = cursors {
        for (purpose, cursor) in cursors {
            check_purpose(
                wallet,
                &mut directory,
                account,
                publication,
                purpose,
                cursor,
                budget,
                &status.closed,
                lock,
                now,
            )
            .await?;
        }
    }

    let mut failed = Vec::new();
    let Some(status) = wallet
        .one_time_discovery(account, now)
        .map_err(Error::Wallet)?
    else {
        return Ok(nothing_due(failed));
    };
    let lookups = readable(status.lookups, publication);
    if !lookups.is_empty() {
        directory.open_session().await?;
        look_up_due(wallet, &directory, account, lookups, lock, now, &mut failed).await?;
    }

    let Some(status) = wallet
        .one_time_discovery(account, now)
        .map_err(Error::Wallet)?
    else {
        return Ok(nothing_due(failed));
    };
    // A path to a root the wallet would refuse as too old is not worth the download.
    if !status.witnesses.is_empty() && publication.height >= status.witness_anchor_floor {
        directory.open_session().await?;
        let witnesses = directory.witnesses().await?;
        let anchor = ChainPoint {
            height: publication.height,
            hash: BlockHash(publication.hash),
        };
        for request in status.witnesses {
            // The common witnesses hold every record's position in this publication.
            match witnesses.path(request.position, request.cmx) {
                Ok(siblings) => lock
                    .write("one_time_discovery.witness", || {
                        wallet.record_one_time_witness(
                            account,
                            request.key,
                            request.position,
                            anchor,
                            siblings,
                            now,
                        )
                    })
                    .map_err(Error::Wallet)?,
                Err(e) => failed.push((request.key, Error::Directory(crate::checked(e)))),
            }
        }
    }

    let Some(status) = wallet
        .one_time_discovery(account, now)
        .map_err(Error::Wallet)?
    else {
        return Ok(nothing_due(failed));
    };
    Ok(Discovered {
        complete: status.complete,
        lookups: readable(status.lookups, publication).len(),
        witnesses: status.witnesses.len(),
        failed,
    })
}

/// The lookups `publication` can serve. One whose cutoff it has not reached, such as a key
/// registered after the scan passed the account's pass, waits for a newer publication.
fn readable(lookups: Vec<LookupWork>, publication: PublicationEnd) -> Vec<LookupWork> {
    lookups
        .into_iter()
        .filter(|lookup| lookup.cutoff <= publication.height)
        .collect()
}

/// What a run reports once the account has no discovery to run, as a fresh account has
/// none again when its last work finishes: complete, with nothing due.
fn nothing_due<E>(failed: Vec<(KeyId, Error<E>)>) -> Discovered<E> {
    Discovered {
        complete: true,
        lookups: 0,
        witnesses: 0,
        failed,
    }
}

/// Checks `purpose`'s keys from `cursor` against the filters and records each chunk, up to
/// `budget` keys. The last chunk also checks the `closed` keys past where the search
/// stopped.
#[allow(clippy::too_many_arguments)]
async fn check_purpose<W, T, L>(
    wallet: &mut W,
    directory: &mut Directory<'_, T>,
    account: AccountId<W>,
    publication: PublicationEnd,
    purpose: Purpose,
    cursor: EnumerationCursor,
    budget: u64,
    closed: &[DiscoveryWork],
    lock: &L,
    now: i64,
) -> Result<(), Error<AccountError<W>>>
where
    W: OneTimeIvkRestoreWrite,
    T: Transport,
    L: WriteLock,
{
    let (mut from, start) = (cursor.next, cursor.next);
    // Each used key moves `reach` to `GAP` keys past it.
    let mut reach = cursor.reach.max(FIRST_WINDOW);
    loop {
        let to = reach.min(from + CHUNK);
        let count = u32::try_from(to - from).expect("at most CHUNK");
        let work = wallet
            .one_time_receivers(account, purpose, from, count)
            .map_err(Error::Wallet)?;
        let mut checks = directory.check(&work, now).await?;
        for check in &checks {
            if check.seen || check.paid {
                reach = reach.max(check.key.index() + 1 + GAP);
            }
        }
        from = to;
        let finished = from >= reach;
        if finished {
            let rest: Vec<_> = closed
                .iter()
                .filter(|item| item.key.purpose() == purpose && item.key.index() >= from)
                .cloned()
                .collect();
            // The filters are already fetched, so an empty check makes no request.
            checks.extend(directory.check(&rest, now).await?);
        }
        let next = EnumerationCursor { next: from, reach };
        let took = lock
            .write("one_time_discovery.filters", || {
                wallet.record_one_time_filter_checks(
                    account,
                    publication,
                    purpose,
                    &checks,
                    next,
                    finished,
                    now,
                )
            })
            .map_err(Error::Wallet)?;
        if !took {
            return Err(Error::Unavailable(
                "the receiver directory's publication is ahead of the wallet's chain",
            ));
        }
        if finished || from - start >= budget {
            return Ok(());
        }
    }
}

/// Looks up each due key's history, [`PARALLEL_LOOKUPS`] at a time, and records what each
/// read. A failed key is backed off and listed in `failed`.
async fn look_up_due<W, T, L>(
    wallet: &mut W,
    directory: &Directory<'_, T>,
    account: AccountId<W>,
    lookups: Vec<LookupWork>,
    lock: &L,
    now: i64,
    failed: &mut Vec<(KeyId, Error<AccountError<W>>)>,
) -> Result<(), Error<AccountError<W>>>
where
    W: OneTimeIvkRestoreWrite,
    T: Transport,
    L: WriteLock,
{
    let revision = directory.publication_end();
    for batch in lookups.chunks(PARALLEL_LOOKUPS) {
        let walks = join_all(batch.iter().map(|lookup| directory.page_through(lookup))).await;
        let mut stop = false;
        for (lookup, walk) in batch.iter().zip(walks) {
            let key = lookup.work.key;
            let mut defer = false;
            if !walk.records.is_empty() || walk.complete {
                match walk
                    .records
                    .into_iter()
                    .map(directory_payment)
                    .collect::<Result<Vec<_>, _>>()
                {
                    Ok(payments) => {
                        let recorded = lock
                            .write("one_time_discovery.lookup", || {
                                wallet.record_one_time_lookup(
                                    account,
                                    key,
                                    revision,
                                    walk.start,
                                    &payments,
                                    walk.complete,
                                    now,
                                )
                            })
                            .map_err(Error::Wallet)?;
                        // The wallet backs off a lookup whose page it refused, but not one
                        // that was no longer due, moved, or read too old a revision.
                        if !recorded {
                            failed.push((
                                key,
                                Error::Unavailable("the wallet did not record the page"),
                            ));
                        }
                    }
                    Err(e) => {
                        failed.push((key, e.into()));
                        defer = true;
                    }
                }
            }
            if let Some(e) = walk.error {
                stop |= matches!(e, DirectoryError::Revision | DirectoryError::Transport(_));
                failed.push((key, e.into()));
                defer = true;
            }
            if defer {
                lock.write("one_time_discovery.defer", || {
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

/// What a walk through one key's history read.
struct Walk {
    /// The page the records start at.
    start: u32,
    /// Consecutive records from `start`, at or below the cutoff.
    records: Vec<RawRecord>,
    /// Whether the walk read every record at or below the cutoff.
    complete: bool,
    /// Why the walk stopped early, if it did.
    error: Option<DirectoryError>,
}

/// A receiver-directory publication whose coverage the client checked. Its filters are
/// fetched only once a key needs them, and its PIR session and common witnesses only once a
/// key needs a lookup or a path.
struct Directory<'a, T> {
    origin: &'a str,
    /// Moves into the session when one opens.
    transport: Option<T>,
    manifest: receiver_pir::Manifest,
    accepted: AcceptedCoverage,
    filters: Option<Filters>,
    /// The labels of the provider seen sets.
    seen: Vec<String>,
    session: Option<DirectoryClient<T>>,
    witnesses: Option<WitnessSnapshot>,
}

impl<'a, T: Transport> Directory<'a, T> {
    /// Takes `manifest`, the publication `origin` serves, if it commits to `genesis`, covers
    /// history from `activation`, and has the seen sets [`fetch_seen`](crate::fetch_seen)
    /// requires. Its own last block is provisional until the wallet judges it.
    fn new<E>(
        activation: BlockHeight,
        genesis: [u8; 32],
        origin: &'a str,
        transport: T,
        manifest: receiver_pir::Manifest,
    ) -> Result<Self, Error<E>> {
        let accepted = AcceptedCoverage {
            genesis,
            required_start: activation.into(),
            height: manifest.directory.end_height,
            hash: manifest.directory.end_hash,
        };
        accepted.check(&manifest.directory)?;
        // Discovery uses only seen-set membership; issuance checks the sets' dates as it
        // issues.
        let seen = seen_sets(&manifest.directory.filters)?
            .into_iter()
            .map(|(label, _, _)| label.to_owned())
            .collect();
        Ok(Self {
            origin,
            transport: Some(transport),
            manifest,
            accepted,
            filters: None,
            seen,
            session: None,
            witnesses: None,
        })
    }

    /// The publication's last block as its manifest declares it.
    fn publication_end(&self) -> PublicationEnd {
        let directory = &self.manifest.directory;
        PublicationEnd {
            height: BlockHeight::from(directory.end_height),
            hash: directory.end_hash,
            tree_size: directory.end_position,
        }
    }

    /// What the filters say about each item's receiver at `now`, downloading them first
    /// if needed; see [`discover`] for how the recent sets are read.
    async fn check<E>(
        &mut self,
        work: &[DiscoveryWork],
        now: i64,
    ) -> Result<Vec<FilterCheck>, Error<E>> {
        let receivers = work
            .iter()
            .map(|item| Receiver::from_bytes(item.receiver).map(|r| *r.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(checked)?;
        if self.filters.is_none() {
            let transport = match (&self.transport, &self.session) {
                (Some(transport), _) => transport,
                (None, Some(_)) => {
                    return Err(Error::Unavailable("filters are checked before lookups"));
                }
                (None, None) => unreachable!("the transport moves only into a session"),
            };
            let filters =
                DirectoryClient::fetch_filters(self.origin, transport, &self.manifest).await?;
            self.filters = Some(filters);
        }
        let key = &self.manifest.directory.salt;
        let filters = self.filters.as_ref().expect("fetched above");
        // Fetching the filters checked them against the manifest's sets.
        let matches = |label: &str| {
            filters
                .get(label)
                .expect("the manifest declares every set")
                .matches(key, &receivers)
        };
        let mut checks: Vec<_> = work
            .iter()
            .zip(matches(PAID))
            .map(|(item, paid)| FilterCheck {
                key: item.key,
                seen: false,
                paid,
                recent: false,
            })
            .collect();
        // Every provider has a seen set (see `seen_sets`), and needs a current, complete
        // recent set too, or any receiver may still be paid.
        let mut complete = true;
        for label in &self.seen {
            for (check, hit) in checks.iter_mut().zip(matches(label)) {
                check.seen |= hit;
            }
            let provider = label.split_once('/').map_or(label.as_str(), |(p, _)| p);
            let recent = format!("{provider}/{RECENT}");
            let sets = &self.manifest.directory.filters;
            match sets.iter().find(|set| set.label == recent) {
                Some(set) if covers_restore_watch(set, now) => {
                    for (check, hit) in checks.iter_mut().zip(matches(&recent)) {
                        check.recent |= hit;
                    }
                }
                _ => complete = false,
            }
        }
        if !complete {
            for check in &mut checks {
                check.recent = true;
            }
        }
        Ok(checks)
    }

    /// Opens the PIR session, after the filters are fetched, unless it is open.
    async fn open_session(&mut self) -> Result<(), DirectoryError> {
        if self.session.is_some() {
            return Ok(());
        }
        let transport = self.transport.take().expect("a session opens once");
        // The filters can be large and are no longer needed.
        self.filters = None;
        let client = DirectoryClient::connect_manifest(
            self.origin,
            transport,
            self.accepted,
            self.manifest.clone(),
        )
        .await?;
        self.session = Some(client);
        Ok(())
    }

    /// The publication's common witnesses, downloading them once.
    async fn witnesses(&mut self) -> Result<&WitnessSnapshot, DirectoryError> {
        if self.witnesses.is_none() {
            let session = self.session.as_ref().expect("opened for paths");
            let bytes = session.witnesses().await?;
            let publication = publication(session.manifest())?;
            let witnesses = WitnessSnapshot::decode(&bytes, &publication).map_err(checked)?;
            self.witnesses = Some(witnesses);
        }
        Ok(self.witnesses.as_ref().expect("fetched above"))
    }

    /// Reads `lookup`'s history from its cursor over the open session: the record before the
    /// cursor must still be the one the wallet applied, or the walk restarts from page zero.
    /// Stops at the first record above the cutoff, at the last page, or after
    /// [`PAGES_PER_LOOKUP`] pages.
    async fn page_through(&self, lookup: &LookupWork) -> Walk {
        let session = self.session.as_ref().expect("opened for lookups");
        let cutoff = u32::from(lookup.cutoff);
        let mut walk = Walk {
            start: lookup.applied,
            records: vec![],
            complete: false,
            error: None,
        };
        let receiver = match Receiver::from_bytes(lookup.work.receiver) {
            Ok(receiver) => *receiver.as_bytes(),
            Err(e) => {
                walk.error = Some(checked(e));
                return walk;
            }
        };
        let mut previous = None;
        if walk.start > 0 {
            match session.page(receiver, walk.start - 1).await {
                Ok(Some(record))
                    if Some((record.payment.position, record.payment.action_nullifier))
                        == lookup.last =>
                {
                    // The history ends at the cursor: nothing new.
                    if record.page + 1 == record.total {
                        walk.complete = true;
                        return walk;
                    }
                    previous = Some(record);
                }
                Ok(_) | Err(DirectoryError::Directory(receiver_directory::Error::MissingPage)) => {
                    walk.start = 0;
                }
                Err(e) => {
                    walk.error = Some(e);
                    return walk;
                }
            }
        }
        for page in walk.start..walk.start.saturating_add(PAGES_PER_LOOKUP) {
            let record = match session.page(receiver, page).await {
                Ok(Some(record)) => record,
                // Absence is allowed only on page zero: an empty history.
                Ok(None) => {
                    walk.complete = true;
                    return walk;
                }
                Err(e) => {
                    walk.error = Some(e);
                    return walk;
                }
            };
            if let Some(previous) = walk.records.last().or(previous.as_ref()) {
                if let Err(e) = check_next(previous, &record) {
                    walk.error = Some(e.into());
                    return walk;
                }
            }
            if record.payment.height > cutoff {
                walk.complete = true;
                return walk;
            }
            let last = record.page + 1 == record.total;
            walk.records.push(record);
            if last {
                walk.complete = true;
                return walk;
            }
        }
        walk
    }
}

/// Whether a provider's recent set can rule a receiver out at `now` (see [`discover`]).
fn covers_restore_watch(set: &FilterSet, now: i64) -> bool {
    let window = set.window_secs.and_then(|w| i64::try_from(w).ok());
    match (window, set.since_unix, set.until_unix) {
        (Some(window), Some(since), Some(until)) => {
            window >= RESTORE_WATCH_SECS
                && since <= until.saturating_sub(window)
                && provider_read_is_current(until, now)
        }
        _ => false,
    }
}

/// The fields of the session's validated manifest that its witness file binds to.
fn publication(manifest: &receiver_pir::Manifest) -> Result<Publication, DirectoryError> {
    let directory = &manifest.directory;
    directory.validate()?;
    Ok(Publication {
        genesis: directory.genesis,
        directory_revision: directory.revision()?,
        end_height: directory.end_height,
        end_hash: directory.end_hash,
        start_position: directory.start_position,
        end_position: directory.end_position,
        records: directory.records,
    })
}

/// A directory record's payment as the wallet takes it, after checking that its note
/// commitment and Action nullifier are canonical and its ephemeral key valid. The directory
/// crates parse records structurally only.
fn directory_payment(record: RawRecord) -> Result<DirectoryPayment, DirectoryError> {
    let payment = record.payment;
    zakura_receiver_crypto::Payment {
        height: payment.height,
        block_hash: payment.block_hash,
        txid: payment.txid,
        tx_index: payment.tx_index,
        action_index: payment.action_index,
        position: payment.position,
        action_nullifier: payment.action_nullifier,
        cmx: payment.cmx,
        ephemeral_key: payment.ephemeral_key,
        ciphertext_prefix: payment.ciphertext_prefix,
    }
    .check()
    .map_err(checked)?;
    Ok(DirectoryPayment {
        height: payment.height,
        block_hash: payment.block_hash,
        txid: payment.txid,
        tx_index: payment.tx_index,
        action_index: payment.action_index,
        position: payment.position,
        action_nullifier: payment.action_nullifier,
        cmx: payment.cmx,
        ephemeral_key: payment.ephemeral_key,
        ciphertext_prefix: payment.ciphertext_prefix,
    })
}

/// Runs `futures` concurrently and returns their outputs in order, without depending on a
/// particular runtime.
async fn join_all<F: Future>(futures: impl IntoIterator<Item = F>) -> Vec<F::Output> {
    let mut futures: Vec<Option<Pin<Box<F>>>> =
        futures.into_iter().map(|f| Some(Box::pin(f))).collect();
    let mut outputs: Vec<Option<F::Output>> = futures.iter().map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut pending = false;
        for (slot, output) in futures.iter_mut().zip(outputs.iter_mut()) {
            if let Some(future) = slot {
                match future.as_mut().poll(cx) {
                    Poll::Ready(value) => {
                        *output = Some(value);
                        *slot = None;
                    }
                    Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await;
    outputs
        .into_iter()
        .map(|output| output.expect("every future finished"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zakura_one_time_ivk::swap::PROVIDER_READ_MAX_AGE_SECS;

    /// A recent set of `window_secs` from a feed that started at `since_unix` and last
    /// read the provider at `until_unix`.
    fn recent(window_secs: Option<u64>, since_unix: Option<i64>, until_unix: i64) -> FilterSet {
        FilterSet {
            label: "near-intents/recent".into(),
            count: 0,
            window_secs,
            since_unix,
            until_unix: Some(until_unix),
        }
    }

    #[test]
    fn a_recent_set_rules_receivers_out_only_when_current_across_the_whole_watch() {
        let now = 10 * RESTORE_WATCH_SECS;
        let watch = RESTORE_WATCH_SECS as u64;
        let read = now - 60;
        let started = Some(read - RESTORE_WATCH_SECS);
        assert!(covers_restore_watch(
            &recent(Some(watch), started, read),
            now
        ));
        assert!(covers_restore_watch(
            &recent(Some(2 * watch), Some(0), read),
            now
        ));
        // A shorter window, or a feed younger than the window, can miss a quote.
        assert!(!covers_restore_watch(
            &recent(Some(watch - 1), started, read),
            now
        ));
        assert!(!covers_restore_watch(
            &recent(Some(watch), Some(read - 60), read),
            now
        ));
        assert!(!covers_restore_watch(&recent(None, started, read), now));
        assert!(!covers_restore_watch(&recent(Some(watch), None, read), now));
        // So can a set whose feed stalled: quotes after its last read are missing.
        let stalled = now - PROVIDER_READ_MAX_AGE_SECS - 1;
        let started = Some(stalled - RESTORE_WATCH_SECS);
        assert!(!covers_restore_watch(
            &recent(Some(watch), started, stalled),
            now
        ));
        let mut undated = recent(Some(watch), started, read);
        undated.until_unix = None;
        assert!(!covers_restore_watch(&undated, now));
        // A read up to a minute after `now` is a provider clock slightly ahead of the
        // caller's; one further ahead may miss the watch.
        let watch_start = Some(now - RESTORE_WATCH_SECS);
        assert!(covers_restore_watch(
            &recent(Some(watch), watch_start, now + 30),
            now
        ));
        assert!(!covers_restore_watch(
            &recent(Some(watch), watch_start, now + 120),
            now
        ));
        assert!(!covers_restore_watch(
            &recent(Some(watch), Some(now), now + RESTORE_WATCH_SECS),
            now
        ));
    }

    #[test]
    fn join_all_keeps_order() {
        let outputs = std::thread::scope(|_| {
            let futures = (0..5).map(|i| async move { i * 2 });
            let mut future = Box::pin(join_all(futures));
            let waker = std::task::Waker::noop();
            let mut cx = std::task::Context::from_waker(waker);
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(outputs) => outputs,
                Poll::Pending => panic!("ready futures finish at once"),
            }
        });
        assert_eq!(outputs, [0, 2, 4, 6, 8]);
    }
}
