//! Restore sweeps over a wallet's dynamic IVK traits.

use std::{collections::BTreeMap, num::NonZeroU32};

use futures_util::StreamExt;
use receiver_directory::{
    Receiver,
    filter::{Filters, PAID, RECENT, SEEN},
    snapshot::FilterSet,
    witness::WitnessSnapshot,
};
use receiver_pir::{AcceptedCoverage, transport::DirectoryClient};
use zakura_dynamic_ivk::{KeyId, lifecycle::RESTORE_WATCH_SECS};
use zakura_pir_enhance::{
    ClientError, ClientResourceLimits,
    transport::{Client, PendingClient, Transport as EnhanceTransport},
    wallet::{Acceptance, acceptance},
};
use zcash_client_backend::data_api::{
    WalletRead,
    dynamic_ivk::{
        DirectoryPayment, DiscoveryWork, DynamicIvkRead, DynamicIvkWrite, PaymentApplication,
        ProviderView, SweepDeferral,
    },
    enhance_pir::EnhancePirRead,
    transparent_ledger::ChainPoint,
};
use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters};

use crate::{DirectoryError, Transport};

/// A wallet's account identifier.
type AccountId<W> = <W as WalletRead>::AccountId;
/// A wallet's error type.
type AccountError<W> = <W as WalletRead>::Error;
/// Due sweeps, each with its account.
type Work<W> = Vec<(AccountId<W>, DiscoveryWork)>;

/// Due sweeps prepared per account at a time.
const BATCH: NonZeroU32 = NonZeroU32::new(64).unwrap();
/// Positions whose note data one request asks for. Each batch is queued as it arrives,
/// so a long history keeps its progress when a run stops partway.
const NOTE_BATCH: usize = 64;
/// How long before `now` a provider's recent set may have last read its feed and still
/// rule a receiver out. A quote made after that read is missing from the set.
const RECENT_SET_MAX_AGE_SECS: i64 = 15 * 60;

/// Why a sweep run, or one key's sweep, stopped. `E` is the wallet's error type.
#[derive(Debug, thiserror::Error)]
pub enum Error<E> {
    /// The receiver directory refused, failed or answered inconsistently.
    #[error("receiver directory: {0}")]
    Directory(#[from] DirectoryError),
    /// Enhance PIR could not supply note data.
    #[error("note data: {0}")]
    NoteData(#[from] ClientError),
    /// A wallet step refused the work, or the wallet's storage failed.
    #[error(transparent)]
    Wallet(E),
    /// A wallet step must wait for more scanning or a newer publication.
    #[error("deferred: {0:?}")]
    Deferred(SweepDeferral),
    /// A service's publication cannot be used against the wallet's chain yet.
    #[error("{0}")]
    Unavailable(&'static str),
    /// A queued payment is waiting, for example for its witness.
    #[error("payment remains queued: {0:?}")]
    Queued(PaymentApplication),
}

/// Serializes a sweep's wallet writes with the caller's other writers.
pub trait WriteLock {
    /// Runs `write` while holding the caller's wallet write lock. `label` names the
    /// step.
    fn write<T>(&self, label: &'static str, write: impl FnOnce() -> T) -> T;
}

/// Supplies the note data that payments a lookup found need.
#[allow(async_fn_in_trait)]
pub trait NoteSource<W: DynamicIvkRead> {
    /// The 528 ciphertext bytes after the directory's prefix for each of `positions`,
    /// keyed by commitment tree position. `wallet` is the wallet being swept.
    async fn note_data(
        &mut self,
        wallet: &W,
        positions: Vec<u64>,
    ) -> Result<BTreeMap<u64, [u8; 528]>, Error<AccountError<W>>>;
}

/// Note data over Enhance PIR. Its session opens on first use, accepted against the
/// wallet's scanned chain, so a run whose lookups find nothing makes no Enhance
/// request.
pub struct EnhanceNotes<'a, T, P> {
    origin: &'a str,
    transport: &'a T,
    params: &'a P,
    session: Option<Client>,
}

impl<'a, T: EnhanceTransport, P: Parameters> EnhanceNotes<'a, T, P> {
    /// Note data from the Enhance PIR service at `origin`, reached through `transport`,
    /// for a wallet on `params`' network.
    pub fn new(origin: &'a str, transport: &'a T, params: &'a P) -> Self {
        Self {
            origin,
            transport,
            params,
            session: None,
        }
    }
}

impl<T, P, W> NoteSource<W> for EnhanceNotes<'_, T, P>
where
    T: EnhanceTransport,
    P: Parameters,
    W: DynamicIvkRead + EnhancePirRead,
{
    async fn note_data(
        &mut self,
        wallet: &W,
        positions: Vec<u64>,
    ) -> Result<BTreeMap<u64, [u8; 528]>, Error<AccountError<W>>> {
        let mut note_data = BTreeMap::new();
        if positions.is_empty() {
            return Ok(note_data);
        }
        if self.session.is_none() {
            let pending = PendingClient::fetch(self.transport, self.origin).await?;
            let limits = ClientResourceLimits::with_cache(32768, 2);
            let accepted = acceptance(wallet, pending.manifest(), self.params, limits)
                .map_err(Error::Wallet)??;
            let accepted = match accepted {
                Acceptance::Accepted(accepted) => accepted,
                Acceptance::WaitingForScanning => {
                    return Err(Error::Unavailable(
                        "the Enhance PIR anchor has not been scanned",
                    ));
                }
                Acceptance::Mismatch => {
                    return Err(Error::Unavailable(
                        "the Enhance PIR anchor differs from the wallet's chain",
                    ));
                }
            };
            self.session = Some(pending.accept(&accepted)?);
        }
        let session = self.session.as_mut().expect("opened above");
        // Enhance groups these positions into shared row requests itself.
        let stream = session.query_batch(self.transport, positions)?;
        futures_util::pin_mut!(stream);
        while let Some(result) = stream.next().await {
            note_data.insert(result.position, *result.record?.enc_ciphertext_suffix());
        }
        Ok(note_data)
    }
}

/// What one [`sweep`] run did. `E` is the wallet's error type.
#[derive(Debug)]
pub struct Swept<E> {
    /// Keys whose sweep finished.
    pub finished: usize,
    /// Keys left for a later run, each already backed off, with why.
    pub deferred: Vec<(KeyId, Error<E>)>,
    /// Whether any of the accounts still has unfinished sweeps or queued payments.
    pub pending: bool,
}

/// Runs `accounts`' due restore sweeps against the receiver directory at `origin`,
/// then releases Ironwood spend evidence that no sweep needs any longer (see
/// [`DynamicIvkWrite::finish_dynamic_nullifier_recovery`]).
///
/// `through` is the wallet's fully scanned tip, and sweeps run only while it is also
/// the stored chain tip. When none is due, the run makes no request. Otherwise the
/// publication must commit to `genesis` ([`MAINNET_GENESIS`](crate::MAINNET_GENESIS)
/// on mainnet), cover history from Ironwood activation on `params`' network, and end at
/// a block the wallet accepts (see [`DynamicIvkRead::directory_publication_anchor`]).
///
/// Each key's receiver is first tested against the publication's filters, which every
/// wallet downloads alike: only a receiver in the paid set is looked up over PIR. A
/// swap provider's sets then say whether a swap may still pay the receiver, which keeps
/// its key scanning after the sweep, and whether the provider ever had it (see
/// [`ProviderView`]). A provider's recent set can rule a receiver out only if it is
/// current and complete: its feed's last read began at most fifteen minutes before
/// `now`, and its window, with the feed running throughout, covers the wallet's own
/// restore watch, [`RESTORE_WATCH_SECS`]. If any recent set falls short, a provider
/// with sets has no recent set, or the publication has no provider sets, every key
/// keeps scanning.
///
/// A run that looks nothing up opens no PIR session and fetches no witnesses. New
/// payments a lookup finds take their note data from `notes`. After each batch the
/// incoming lookahead moves past paid indices and its new keys are swept too. A key
/// that fails is backed off and listed in [`Swept::deferred`], and the others go on,
/// unless the directory's session or connection failed: then the run stops before
/// leasing more keys. `now` is the caller's clock in seconds, for retry backoff and the
/// recent sets.
#[allow(clippy::too_many_arguments)]
pub async fn sweep<W, P, T, N, L>(
    wallet: &mut W,
    params: &P,
    accounts: &[AccountId<W>],
    through: ChainPoint,
    genesis: [u8; 32],
    origin: &str,
    transport: T,
    notes: &mut N,
    lock: &L,
    now: i64,
) -> Result<Swept<AccountError<W>>, Error<AccountError<W>>>
where
    W: DynamicIvkWrite,
    P: Parameters,
    T: Transport,
    N: NoteSource<W>,
    L: WriteLock,
{
    let mut swept = Swept {
        finished: 0,
        deferred: Vec::new(),
        pending: false,
    };
    let tip = wallet.chain_height().map_err(Error::Wallet)?;
    if tip == Some(through.height) {
        let mut work = due(wallet, accounts, through, lock, now)?;
        if !work.is_empty() {
            let accepted =
                Directory::accept(wallet, params, through, genesis, origin, transport).await;
            let mut directory = match accepted {
                Ok(directory) => directory,
                Err(e) => {
                    // No key can be swept without the directory, so each backs off as
                    // if its own lookup had failed, and the next sync does not wait on
                    // the same directory again.
                    for (account, item) in &work {
                        lock.write("dynamic_sweep.attempt", || {
                            wallet.begin_dynamic_sweep_attempt(*account, item.key, now)
                        })
                        .map_err(Error::Wallet)?;
                    }
                    return Err(e);
                }
            };
            'run: loop {
                let checks = directory.check(&work, now)?;
                let lookups = work
                    .iter()
                    .zip(&checks)
                    .filter(|((_, item), check)| item.lookup.is_none() && check.paid)
                    .count();
                if let Some(session) = &mut directory.session {
                    session.client.use_file_for_work(lookups).await?;
                }
                for ((account, item), check) in work.into_iter().zip(checks) {
                    let swept_key = sweep_key(
                        wallet,
                        &mut directory,
                        account,
                        &item,
                        check,
                        lookups,
                        through,
                        notes,
                        lock,
                        now,
                    );
                    match swept_key.await {
                        Ok(()) => swept.finished += 1,
                        Err(e) => {
                            // Every later key would fail the same way and back off.
                            let unavailable = matches!(
                                e,
                                Error::Directory(
                                    DirectoryError::Revision | DirectoryError::Transport(_)
                                )
                            );
                            swept.deferred.push((item.key, e));
                            if unavailable {
                                break 'run;
                            }
                        }
                    }
                }
                lock.write("dynamic_sweep.lookahead", || {
                    accounts
                        .iter()
                        .try_for_each(|account| wallet.maintain_dynamic_ivks(*account))
                })
                .map_err(Error::Wallet)?;
                work = due(wallet, accounts, through, lock, now)?;
                if work.is_empty() {
                    break;
                }
            }
        }
    }
    for account in accounts {
        lock.write("dynamic_sweep.release", || {
            wallet.finish_dynamic_nullifier_recovery(*account, through)
        })
        .map_err(Error::Wallet)?;
        swept.pending |= wallet
            .dynamic_history_pending(*account, through.height)
            .map_err(Error::Wallet)?;
    }
    Ok(swept)
}

/// What a publication's filters say about one key's receiver.
#[derive(Clone, Copy)]
struct Check {
    /// The paid set holds it, so a lookup may find payments.
    paid: bool,
    /// What the swap provider sets say.
    provider: ProviderView,
}

/// A receiver-directory publication accepted at a block the wallet scanned, with its
/// filters. Its PIR session and common witnesses are fetched only once a key needs a
/// lookup or has payments to apply.
struct Directory<'a, T> {
    origin: &'a str,
    /// Moves into the session when one opens.
    transport: Option<T>,
    manifest: receiver_pir::Manifest,
    accepted: AcceptedCoverage,
    anchor: ChainPoint,
    filters: Filters,
    session: Option<Session<T>>,
}

/// An open PIR session and the publication's common witnesses, which every wallet
/// fetches identically.
struct Session<T> {
    client: DirectoryClient<T>,
    witnesses: WitnessSnapshot,
}

impl<'a, T: Transport> Directory<'a, T> {
    /// Accepts the publication `origin` serves, at the block of the wallet's chain it
    /// ends at, and downloads its filters.
    async fn accept<W: DynamicIvkRead, P: Parameters>(
        wallet: &W,
        params: &P,
        through: ChainPoint,
        genesis: [u8; 32],
        origin: &'a str,
        transport: T,
    ) -> Result<Self, Error<AccountError<W>>> {
        let manifest = DirectoryClient::fetch_manifest(origin, &transport).await?;
        let end = BlockHeight::from(manifest.directory.end_height);
        let anchor = wallet
            .directory_publication_anchor(end, through)
            .map_err(Error::Wallet)?
            .map_err(Error::Deferred)?;
        let activation = params
            .activation_height(NetworkUpgrade::Nu6_3)
            .ok_or(Error::Unavailable("Ironwood is not active on this network"))?;
        let accepted = AcceptedCoverage {
            genesis,
            required_start: activation.into(),
            height: anchor.height.into(),
            hash: anchor.hash.0,
        };
        accepted.check(&manifest.directory)?;
        let filters = DirectoryClient::fetch_filters(origin, &transport, &manifest).await?;
        Ok(Self {
            origin,
            transport: Some(transport),
            manifest,
            accepted,
            anchor,
            filters,
            session: None,
        })
    }

    /// What the filters say about each item's receiver at `now`; see [`sweep`] for how
    /// the provider sets are read.
    fn check<A>(
        &self,
        work: &[(A, DiscoveryWork)],
        now: i64,
    ) -> Result<Vec<Check>, DirectoryError> {
        let receivers = work
            .iter()
            .map(|(_, item)| Receiver::from_bytes(item.receiver))
            .collect::<Result<Vec<_>, _>>()?;
        let key = &self.manifest.directory.salt;
        // Fetching the filters checked them against the manifest's sets.
        let matches = |label: &str| {
            self.filters
                .get(label)
                .expect("the manifest declares every set")
                .matches(key, &receivers)
        };
        let mut checks: Vec<_> = matches(PAID)
            .into_iter()
            .map(|paid| Check {
                paid,
                provider: ProviderView::default(),
            })
            .collect();
        // Each provider with a set, and whether its recent sets, if any, are all current
        // and complete.
        let mut providers = BTreeMap::<&str, Option<bool>>::new();
        for set in &self.manifest.directory.filters {
            match set.label.split_once('/') {
                Some((provider, RECENT)) => {
                    let covers = covers_restore_watch(set, now);
                    let complete = providers.entry(provider).or_default();
                    *complete = Some(complete.unwrap_or(true) && covers);
                    if covers {
                        for (check, hit) in checks.iter_mut().zip(matches(&set.label)) {
                            check.provider.recent |= hit;
                        }
                    }
                }
                Some((provider, SEEN)) => {
                    providers.entry(provider).or_default();
                    for (check, hit) in checks.iter_mut().zip(matches(&set.label)) {
                        check.provider.seen |= hit;
                    }
                }
                _ => {}
            }
        }
        if providers.is_empty() || providers.values().any(|&complete| complete != Some(true)) {
            for check in &mut checks {
                check.provider.recent = true;
            }
        }
        Ok(checks)
    }

    /// The PIR session, opened for `lookups` lookups if none is open yet.
    async fn session<E>(&mut self, lookups: usize) -> Result<&mut Session<T>, Error<E>> {
        if self.session.is_none() {
            let transport = self
                .transport
                .take()
                .ok_or(Error::Unavailable("the receiver directory session failed"))?;
            let client = DirectoryClient::connect_manifest(
                self.origin,
                transport,
                self.accepted,
                self.manifest.clone(),
                lookups,
            )
            .await?;
            let witnesses = client.witnesses().await?;
            self.session = Some(Session { client, witnesses });
        }
        Ok(self.session.as_mut().expect("opened above"))
    }
}

/// Whether a provider's recent set can rule a receiver out at `now`: its feed's last
/// read began at most [`RECENT_SET_MAX_AGE_SECS`] before `now`, and its window, which
/// reaches back from that read through the time the feed was running, covers
/// [`RESTORE_WATCH_SECS`].
fn covers_restore_watch(set: &FilterSet, now: i64) -> bool {
    let window = set.window_secs.and_then(|w| i64::try_from(w).ok());
    match (window, set.since_unix, set.until_unix) {
        (Some(window), Some(since), Some(until)) => {
            window >= RESTORE_WATCH_SECS
                && since <= until.saturating_sub(window)
                && until >= now.saturating_sub(RECENT_SET_MAX_AGE_SECS)
        }
        _ => false,
    }
}

/// `accounts`' due sweeps at `through`, a bounded batch per account.
fn due<W: DynamicIvkWrite, L: WriteLock>(
    wallet: &mut W,
    accounts: &[AccountId<W>],
    through: ChainPoint,
    lock: &L,
    now: i64,
) -> Result<Work<W>, Error<AccountError<W>>> {
    let mut work = Vec::new();
    for &account in accounts {
        let batch = lock
            .write("dynamic_sweep.due", || {
                wallet.prepare_dynamic_sweeps(account, through, now, BATCH)
            })
            .map_err(Error::Wallet)?
            .map_err(Error::Deferred)?;
        work.extend(batch.into_iter().map(|item| (account, item)));
    }
    Ok(work)
}

/// Sweeps one key: leases an attempt, looks up its receiver if the paid set holds it
/// and no earlier lookup is queued, queues the new payments with their note data in
/// batches, and applies them with the publication's witnesses. `lookups` is the
/// batch's lookup count, which sizes a session that this key opens.
#[allow(clippy::too_many_arguments)]
async fn sweep_key<W, T, N, L>(
    wallet: &mut W,
    directory: &mut Directory<'_, T>,
    account: AccountId<W>,
    item: &DiscoveryWork,
    check: Check,
    lookups: usize,
    through: ChainPoint,
    notes: &mut N,
    lock: &L,
    now: i64,
) -> Result<(), Error<AccountError<W>>>
where
    W: DynamicIvkWrite,
    T: Transport,
    N: NoteSource<W>,
    L: WriteLock,
{
    let key = item.key;
    let anchor = directory.anchor;
    lock.write("dynamic_sweep.attempt", || {
        wallet.begin_dynamic_sweep_attempt(account, key, now)
    })
    .map_err(Error::Wallet)?;
    if item.lookup.is_none() {
        let payments: Vec<_> = if check.paid {
            let receiver = Receiver::from_bytes(item.receiver).map_err(DirectoryError::from)?;
            let accepted = directory.accepted;
            let session = directory.session(lookups).await?;
            session
                .client
                .lookup(receiver, accepted)
                .await?
                .into_iter()
                .map(directory_payment)
                .collect()
        } else {
            Vec::new()
        };
        loop {
            let batch: Vec<_> = wallet
                .directory_note_data_needed(account, key, &payments)
                .map_err(Error::Wallet)?
                .into_iter()
                .take(NOTE_BATCH)
                .collect();
            let requested = batch.len();
            let note_data = notes.note_data(wallet, batch).await?;
            let done = lock
                .write("dynamic_sweep.queue", || {
                    wallet.queue_directory_lookup(account, key, anchor, &payments, &note_data)
                })
                .map_err(Error::Wallet)?
                .map_err(Error::Deferred)?;
            if done {
                break;
            }
            if note_data.len() < requested {
                return Err(Error::Unavailable(
                    "note data is missing for a directory payment",
                ));
            }
        }
    }
    let witnesses = if check.paid || item.lookup.is_some() {
        Some(&directory.session(lookups).await?.witnesses)
    } else {
        None
    };
    let applied = lock
        .write("dynamic_sweep.apply", || {
            wallet.apply_dynamic_sweep(
                account,
                key,
                through,
                anchor,
                check.provider,
                |position, cmx| witnesses.and_then(|w| w.path(position, cmx).ok()),
            )
        })
        .map_err(Error::Wallet)?
        .map_err(Error::Deferred)?;
    match applied {
        PaymentApplication::Applied => Ok(()),
        waiting => Err(Error::Queued(waiting)),
    }
}

/// A directory payment as the wallet takes it.
fn directory_payment(payment: receiver_directory::Payment) -> DirectoryPayment {
    DirectoryPayment {
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let stalled = now - RECENT_SET_MAX_AGE_SECS - 1;
        let started = Some(stalled - RESTORE_WATCH_SECS);
        assert!(!covers_restore_watch(
            &recent(Some(watch), started, stalled),
            now
        ));
        let mut undated = recent(Some(watch), started, read);
        undated.until_unix = None;
        assert!(!covers_restore_watch(&undated, now));
    }
}
