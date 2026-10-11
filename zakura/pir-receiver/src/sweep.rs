//! Restore sweeps over a wallet's dynamic IVK traits.

use std::{collections::BTreeMap, num::NonZeroU32};

use futures_util::StreamExt;
use receiver_directory::{
    Receiver,
    filter::{Filters, PAID, RECENT},
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
        SweepDeferral,
    },
    enhance_pir::EnhancePirRead,
    transparent_ledger::ChainPoint,
};
use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters};

use crate::{DirectoryError, Transport, seen::seen_sets};

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
    /// The note source cannot serve the wallet's chain, so no key can get note data
    /// this run.
    #[error("note source: {0}")]
    NotesUnavailable(&'static str),
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
    /// `positions` is never empty when a sweep calls this. [`Error::NotesUnavailable`]
    /// stops the run before it leases more keys.
    async fn note_data(
        &mut self,
        wallet: &W,
        positions: Vec<u64>,
    ) -> Result<BTreeMap<u64, [u8; 528]>, Error<AccountError<W>>>;
}

/// Note data over Enhance PIR. Its session opens on first use, accepted against the
/// wallet's scanned chain, so a run whose lookups find nothing makes no Enhance
/// request. A later batch first accepts fresh routing if Enhance says a refresh is
/// due: thirty seconds on, or after a 409 or 410. A failed batch is not retried; the
/// next call refreshes.
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
        if self.session.as_ref().is_none_or(Client::refresh_due) {
            let pending = PendingClient::fetch(self.transport, self.origin).await?;
            let limits = ClientResourceLimits::with_cache(32768, 2);
            let accepted = acceptance(wallet, pending.manifest(), self.params, limits)
                .map_err(Error::Wallet)??;
            let accepted = match accepted {
                Acceptance::Accepted(accepted) => accepted,
                Acceptance::WaitingForScanning => {
                    return Err(Error::NotesUnavailable(
                        "the Enhance PIR anchor has not been scanned",
                    ));
                }
                Acceptance::Mismatch => {
                    return Err(Error::NotesUnavailable(
                        "the Enhance PIR anchor differs from the wallet's chain",
                    ));
                }
            };
            match &mut self.session {
                Some(session) => session.accept_routing(pending, &accepted)?,
                None => self.session = Some(pending.accept(&accepted)?),
            }
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

/// What one [`sweep`] run did. `A` is the wallet's account identifier and `E` its error
/// type.
#[derive(Debug)]
pub struct Swept<A, E> {
    /// Keys whose sweep finished.
    pub finished: usize,
    /// Keys left for a later run, each with its account, already backed off, with why.
    pub deferred: Vec<(A, KeyId, Error<E>)>,
    /// Whether any of the accounts still has unfinished sweeps or queued payments.
    pub pending: bool,
}

/// Runs `accounts`' due restore sweeps against the receiver directory at `origin`,
/// then releases Ironwood spend evidence that no sweep needs any longer (see
/// [`DynamicIvkWrite::finish_dynamic_nullifier_recovery`]).
///
/// `through` is the wallet's fully scanned tip, and sweeps and release run only while
/// it is also the stored chain tip and the block the wallet scanned there, which
/// release checks again under its write lock along with the fully scanned height.
/// When none is due, the run makes no request. Otherwise the publication must commit
/// to `genesis` ([`MAINNET_GENESIS`](crate::MAINNET_GENESIS) on mainnet), cover
/// history from Ironwood activation on `params`' network, and end at a block the
/// wallet accepts (see [`DynamicIvkRead::directory_publication_anchor`]) with the
/// wallet's Ironwood tree size there, and have a dated seen set for at least one swap
/// provider and for every provider with a set, as for [`fetch_seen`](crate::fetch_seen).
///
/// Each key's receiver is first tested against the publication's filters, which every
/// wallet downloads alike: only a receiver in the paid set is looked up over PIR, and
/// one in a swap provider's seen set is never issued again (see
/// [`DynamicIvkWrite::begin_dynamic_sweep_attempt`]). A key whose receiver a provider's
/// recent set holds keeps scanning for the wallet's restore watch, and any other closes
/// (see [`DynamicIvkWrite::apply_dynamic_sweep`]). A recent set can rule a receiver out
/// only if it is current and complete: its feed's last read began at most fifteen
/// minutes before `now`, and its window, with the feed running throughout, covers
/// [`RESTORE_WATCH_SECS`]. Unless every provider has such a set, every key keeps
/// scanning.
///
/// After releasing, the run checks closed keys with no known payment against the
/// publication's paid filter once per publication (see
/// [`DynamicIvkWrite::record_paid_filter_check`]), so a payment the publication shows
/// after such a key closed is swept on a later run. While any such key exists, every
/// run fetches the manifest; it fetches the filters only for a newer publication.
///
/// A run that looks nothing up opens no PIR session and fetches no witnesses. New
/// payments a lookup finds take their note data from `notes`. A run sweeps at most one
/// batch of due keys per account, then moves the incoming lookahead past paid and seen
/// indices; its new keys are left for a later run, and [`Swept::pending`] reports them.
/// A key that fails is backed off and listed in [`Swept::deferred`], and the others go
/// on, unless the directory's session or connection failed or `notes` cannot serve the
/// wallet's chain: then the run stops before leasing more keys. A lease the wallet fails to store stops the run with its error.
/// `now` is the caller's clock in seconds, for retry backoff and the recent sets.
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
) -> Result<Swept<AccountId<W>, AccountError<W>>, Error<AccountError<W>>>
where
    W: DynamicIvkWrite,
    P: Parameters,
    T: Transport,
    N: NoteSource<W>,
    L: WriteLock,
{
    // A repeated account would lease and back off each of its keys twice.
    let mut unique = Vec::with_capacity(accounts.len());
    for account in accounts {
        if !unique.contains(account) {
            unique.push(*account);
        }
    }
    let accounts = &unique[..];
    let mut swept = Swept {
        finished: 0,
        deferred: Vec::new(),
        pending: false,
    };
    let current = at_tip(wallet, through).map_err(Error::Wallet)?;
    let mut transport = Some(transport);
    let mut directory = None;
    if current {
        let work = due(wallet, accounts, through, lock, now)?;
        if !work.is_empty() {
            let transport = transport.take().expect("not yet used");
            let accepted =
                Directory::accept(wallet, params, through, genesis, origin, transport).await;
            let directory = directory.insert(match accepted {
                Ok(directory) => directory,
                Err(e) => {
                    // No key can be swept without the directory, so each backs off as
                    // if its own lookup had failed, and the next sync does not wait on
                    // the same directory again.
                    for (account, item) in &work {
                        lock.write("dynamic_sweep.attempt", || {
                            wallet.begin_dynamic_sweep_attempt(*account, item.key, now, false)
                        })
                        .map_err(Error::Wallet)?;
                    }
                    return Err(e);
                }
            });
            let checks = directory.check(&work, now).await?;
            let lookups = checks.iter().filter(|check| check.paid).count();
            if let Some(session) = &mut directory.session {
                session.client.use_file_for_work(lookups).await?;
            }
            for ((account, item), check) in work.into_iter().zip(checks) {
                // A key whose lease is not stored would be due again at once.
                lock.write("dynamic_sweep.attempt", || {
                    wallet.begin_dynamic_sweep_attempt(account, item.key, now, check.seen)
                })
                .map_err(Error::Wallet)?;
                let swept_key = sweep_key(
                    wallet, directory, account, &item, check, lookups, through, notes, lock,
                );
                match swept_key.await {
                    Ok(()) => swept.finished += 1,
                    Err(e) => {
                        // Every later key would fail the same way and back off. A session
                        // that failed to open took the transport without replacing it.
                        let unavailable = directory.transport.is_none()
                            && directory.session.is_none()
                            || matches!(
                                e,
                                Error::Directory(
                                    DirectoryError::Revision | DirectoryError::Transport(_)
                                ) | Error::NotesUnavailable(_)
                            );
                        swept.deferred.push((account, item.key, e));
                        if unavailable {
                            break;
                        }
                    }
                }
            }
            // New lookahead keys wait for a later run, which bounds this one.
            lock.write("dynamic_sweep.lookahead", || {
                accounts
                    .iter()
                    .try_for_each(|account| wallet.maintain_dynamic_ivks(*account))
            })
            .map_err(Error::Wallet)?;
        }
    }
    for account in accounts {
        if current {
            // Another writer may have moved the tip while the sweep held no lock, and a
            // finished key may have queued a rescan below it.
            lock.write("dynamic_sweep.release", || {
                let scanned = wallet.block_fully_scanned()?.map(|b| b.block_height());
                if at_tip(wallet, through)? && scanned == Some(through.height) {
                    wallet.finish_dynamic_nullifier_recovery(*account, through)?;
                }
                Ok(())
            })
            .map_err(Error::Wallet)?;
        }
        swept.pending |= wallet
            .dynamic_history_pending(*account, through.height)
            .map_err(Error::Wallet)?;
    }
    if let (true, Some(transport)) = (current, transport) {
        let mut closed = false;
        for account in accounts {
            let keys = wallet.dynamic_keys_to_recheck(*account, through.height + 1);
            closed |= !keys.map_err(Error::Wallet)?.is_empty();
        }
        if closed {
            let accepted = Directory::accept(wallet, params, through, genesis, origin, transport);
            directory = Some(accepted.await?);
        }
    }
    if let Some(directory) = &mut directory {
        swept.pending |= recheck(wallet, directory, accounts, lock, now).await?;
    }
    Ok(swept)
}

/// Records the publication's paid filter for `accounts`' keys whose sweep finished below
/// its anchor (see [`DynamicIvkWrite::record_paid_filter_check`]), fetching the filters
/// only if a key needs them. Returns whether any sweep was queued again.
async fn recheck<W, T, L>(
    wallet: &mut W,
    directory: &mut Directory<'_, T>,
    accounts: &[AccountId<W>],
    lock: &L,
    now: i64,
) -> Result<bool, Error<AccountError<W>>>
where
    W: DynamicIvkWrite,
    T: Transport,
    L: WriteLock,
{
    let mut queued = false;
    for &account in accounts {
        let keys = wallet
            .dynamic_keys_to_recheck(account, directory.anchor.height)
            .map_err(Error::Wallet)?;
        if keys.is_empty() {
            continue;
        }
        let work: Vec<_> = keys.into_iter().map(|item| ((), item)).collect();
        let checks = directory.check(&work, now).await?;
        let checked: Vec<_> = work
            .iter()
            .zip(checks)
            .map(|((_, item), check)| (item.key, check.paid))
            .collect();
        queued |= checked.iter().any(|&(_, paid)| paid);
        lock.write("dynamic_sweep.recheck", || {
            wallet.record_paid_filter_check(account, directory.anchor, &checked)
        })
        .map_err(Error::Wallet)?;
    }
    Ok(queued)
}

/// Whether `through` is still the wallet's stored chain tip and the block it scanned
/// there.
fn at_tip<W: WalletRead>(wallet: &W, through: ChainPoint) -> Result<bool, W::Error> {
    Ok(wallet.chain_height()? == Some(through.height)
        && wallet.get_block_hash(through.height)? == Some(through.hash))
}

/// What a publication's filters say about one key's receiver.
#[derive(Clone, Copy)]
struct Check {
    /// The paid set holds it, so a lookup may find payments.
    paid: bool,
    /// A swap may still pay it, so its key keeps scanning after its sweep.
    recent: bool,
    /// A swap provider's seen set holds it, so it is never issued again.
    seen: bool,
}

/// A receiver-directory publication accepted at a block the wallet scanned. Its filters
/// are fetched only once a key needs them, and its PIR session and common witnesses only
/// once a key needs a lookup or has payments to apply.
struct Directory<'a, T> {
    origin: &'a str,
    /// Moves into the session when one opens.
    transport: Option<T>,
    manifest: receiver_pir::Manifest,
    accepted: AcceptedCoverage,
    anchor: ChainPoint,
    filters: Option<Filters>,
    /// The labels of the provider seen sets.
    seen: Vec<String>,
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
    /// ends at.
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
        // Height and hash alone accept a publication that stops partway through the
        // anchor block, whose omitted payments no lookup or scan from `anchor + 1` finds.
        let tree_size = wallet
            .block_metadata(anchor.height)
            .map_err(Error::Wallet)?
            .and_then(|block| block.ironwood_tree_size());
        if tree_size.map(u64::from) != Some(manifest.directory.end_position) {
            return Err(Error::Unavailable(
                "the receiver directory's tree size differs from the wallet's at its anchor",
            ));
        }
        // Seen feeds start at `EARLIEST_RECEIVE_QUOTE`, before any dynamic address existed, so a
        // sweep ignores their dates; issuance enforces coverage where reuse is at stake.
        let seen = seen_sets(&manifest.directory.filters)?
            .into_iter()
            .map(|(label, _, _)| label.to_owned())
            .collect();
        Ok(Self {
            origin,
            transport: Some(transport),
            manifest,
            accepted,
            anchor,
            filters: None,
            seen,
            session: None,
        })
    }

    /// What the filters say about each item's receiver at `now`, downloading them first
    /// if needed; see [`sweep`] for how the recent sets are read.
    async fn check<A, E>(
        &mut self,
        work: &[(A, DiscoveryWork)],
        now: i64,
    ) -> Result<Vec<Check>, Error<E>> {
        let receivers = work
            .iter()
            .map(|(_, item)| Receiver::from_bytes(item.receiver))
            .collect::<Result<Vec<_>, _>>()
            .map_err(DirectoryError::from)?;
        if self.filters.is_none() {
            let transport = self
                .transport
                .as_ref()
                .ok_or(Error::Unavailable("the receiver directory session failed"))?;
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
        let mut checks: Vec<_> = matches(PAID)
            .into_iter()
            .map(|paid| Check {
                paid,
                recent: false,
                seen: false,
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

/// Sweeps one key whose attempt is leased: looks up its receiver if `check` shows the
/// paid set holds it, queues the answer, empty on a miss, with new payments' note data
/// in batches, and applies it with the publication's witnesses. `lookups` is the batch's
/// lookup count, which sizes a session that this key opens.
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
) -> Result<(), Error<AccountError<W>>>
where
    W: DynamicIvkWrite,
    T: Transport,
    N: NoteSource<W>,
    L: WriteLock,
{
    let key = item.key;
    let anchor = directory.anchor;
    let paid = check.paid;
    let payments: Vec<_> = if paid {
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
        let note_data = if batch.is_empty() {
            BTreeMap::new()
        } else {
            notes.note_data(wallet, batch.clone()).await?
        };
        let done = lock
            .write("dynamic_sweep.queue", || {
                wallet.queue_directory_lookup(account, key, anchor, &payments, &note_data)
            })
            .map_err(Error::Wallet)?
            .map_err(Error::Deferred)?;
        if done {
            break;
        }
        // A requested position left without data would be asked for again forever.
        if batch.iter().any(|p| !note_data.contains_key(p)) {
            return Err(Error::Unavailable(
                "note data is missing for a directory payment",
            ));
        }
    }
    // A miss queued nothing to apply.
    let witnesses = if paid {
        Some(&directory.session(lookups).await?.witnesses)
    } else {
        None
    };
    let applied = apply_queued(payments.len(), || {
        lock.write("dynamic_sweep.apply", || {
            wallet.apply_dynamic_sweep(account, key, through, anchor, check.recent, |p, cmx| {
                witnesses.and_then(|w| w.path(p, cmx).ok())
            })
        })
        .map_err(Error::Wallet)?
        .map_err(Error::Deferred)
    })?;
    match applied {
        PaymentApplication::Applied => Ok(()),
        waiting => Err(Error::Queued(waiting)),
    }
}

/// Runs `apply`, one `apply_dynamic_sweep` call, again after each
/// [`PaymentApplication::BeforeBirthday`], which reports a payment processed rather than
/// waiting. Each of the at most `queued` payments can report it once.
fn apply_queued<E>(
    queued: usize,
    mut apply: impl FnMut() -> Result<PaymentApplication, E>,
) -> Result<PaymentApplication, E> {
    let mut applied = apply()?;
    for _ in 0..queued {
        if applied != PaymentApplication::BeforeBirthday {
            break;
        }
        applied = apply()?;
    }
    Ok(applied)
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

    /// Runs [`apply_queued`] for `queued` payments over `results`, returning what it
    /// returned and how many results it took.
    fn run(queued: usize, results: &[PaymentApplication]) -> (PaymentApplication, usize) {
        let mut results = results.iter().copied();
        let mut calls = 0;
        let applied = apply_queued::<()>(queued, || {
            calls += 1;
            Ok(results.next().expect("called too often"))
        });
        (applied.unwrap(), calls)
    }

    /// A before-birthday payment was processed, so applying goes on to finish the
    /// sweep, but a backend reporting it more often than it has payments is waiting.
    #[test]
    fn before_birthday_payments_continue_applying() {
        use PaymentApplication::*;
        let finished = [BeforeBirthday, BeforeBirthday, Applied];
        assert_eq!(run(2, &finished), (Applied, 3));
        assert_eq!(
            run(2, &[BeforeBirthday, AwaitingWitness]),
            (AwaitingWitness, 2)
        );
        assert_eq!(run(1, &[BeforeBirthday; 3]), (BeforeBirthday, 2));
        assert_eq!(run(0, &[Applied]), (Applied, 1));
    }
}
