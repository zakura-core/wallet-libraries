//! Restore sweeps over a wallet's one-time IVK traits.

use std::num::NonZeroU32;

use receiver_directory::{
    filter::{Filters, PAID, RECENT},
    snapshot::FilterSet,
};
use receiver_pir::{AcceptedCoverage, transport::DirectoryClient};
use zakura_one_time_ivk::{KeyId, swap::RESTORE_WATCH_SECS};
use zakura_receiver_crypto::{
    Receiver,
    witness::{Publication, WitnessSnapshot},
};
use zcash_client_backend::data_api::{
    WalletRead,
    one_time_ivk::restore::{
        DirectoryPayment, DiscoveryWork, OneTimeIvkRestoreRead, OneTimeIvkRestoreWrite,
        PaymentApplication, SweepDeferral,
    },
    transparent_ledger::ChainPoint,
};
use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters};

use crate::{DirectoryError, Transport, checked, seen::seen_sets};

/// A wallet's account identifier.
pub(crate) type AccountId<W> = <W as WalletRead>::AccountId;
/// A wallet's error type.
pub(crate) type AccountError<W> = <W as WalletRead>::Error;

/// Due sweeps prepared per run.
const BATCH: NonZeroU32 = NonZeroU32::new(64).unwrap();
/// How long before `now` a provider's recent set may have last read its feed and still
/// rule a receiver out. A quote made after that read is missing from the set.
const RECENT_SET_MAX_AGE_SECS: i64 = 15 * 60;
/// How far after `now` a provider's recent set may have last read its feed, for a
/// provider clock slightly ahead of the caller's.
const RECENT_SET_CLOCK_SKEW_SECS: i64 = 60;

/// Why a sweep run, or one key's sweep, stopped. `E` is the wallet's error type.
#[derive(Debug, thiserror::Error)]
pub enum Error<E> {
    /// The receiver directory refused, failed or answered inconsistently.
    #[error("receiver directory: {0}")]
    Directory(#[from] DirectoryError),
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

/// What one [`sweep`] run did. `E` is the wallet's error type.
#[derive(Debug)]
pub struct Swept<E> {
    /// Keys whose sweep finished.
    pub finished: usize,
    /// Keys left for a later run, already backed off, with why.
    pub deferred: Vec<(KeyId, Error<E>)>,
    /// Whether the account still has unfinished sweeps or queued payments.
    pub pending: bool,
}

/// Runs `account`'s due restore sweeps (see [`OneTimeIvkRestoreWrite`]) against the
/// receiver directory at `origin`, releases the spend evidence they no longer need (see
/// [`OneTimeIvkRestoreWrite::finish_one_time_nullifier_recovery`]), and checks closed keys
/// against each newer publication's paid filter (see
/// [`OneTimeIvkRestoreWrite::record_paid_filter_check`]). A wallet with several accounts
/// calls it once for each.
///
/// Sweeps and release happen only while `through` is the wallet's fully scanned chain tip,
/// which the wallet checks under its write lock (see
/// [`OneTimeIvkRestoreWrite::prepare_one_time_sweeps`] and
/// [`OneTimeIvkRestoreWrite::finish_one_time_nullifier_recovery`]). A run with nothing due
/// or to check makes no request. Otherwise the publication must commit to `genesis`
/// ([`MAINNET_GENESIS`](crate::MAINNET_GENESIS) on mainnet), cover history from Ironwood
/// activation on `params`' network, end at an anchor the wallet accepts (see
/// [`OneTimeIvkRestoreRead::directory_publication_anchor`]) with the wallet's Ironwood
/// tree size there, and have the seen sets [`fetch_seen`](crate::fetch_seen) requires.
///
/// Only receivers in the paid filter are looked up over PIR. The seen and recent sets give
/// each key's `seen` and `recent` (see
/// [`OneTimeIvkRestoreWrite::begin_one_time_sweep_attempt`] and
/// [`OneTimeIvkRestoreWrite::apply_one_time_sweep`]). A provider's recent set counts only
/// if its feed's last read began at most fifteen minutes before `now` and at most a minute
/// after it, and its window, with the feed running throughout, covers
/// [`RESTORE_WATCH_SECS`]; unless every provider has one, every key is recent.
///
/// A run sweeps at most one batch of due keys, then moves the incoming lookahead, leaving
/// its new keys to a later run ([`Swept::pending`]). A publication the wallet cannot use
/// or a PIR session that fails to open fails the run before any key is leased. Each key is
/// leased just before its lookup; one that fails is backed off and listed in
/// [`Swept::deferred`] while the others go on, unless the directory's connection failed
/// or revoked the session, or the publication's anchor left the wallet's chain: then the
/// run stops leasing keys. A paid key's payments apply
/// only at the fully scanned tip, which a finished key's rescan can lower (see
/// [`OneTimeIvkRestoreWrite::apply_one_time_sweep`]), so the run also stops before
/// leasing a paid key while `through` is off it, leaving the rest due. A failed wallet
/// write stops the run with its error. `now` is the caller's clock in seconds.
#[allow(clippy::too_many_arguments)]
pub async fn sweep<W, P, T, L>(
    wallet: &mut W,
    params: &P,
    account: AccountId<W>,
    through: ChainPoint,
    genesis: [u8; 32],
    origin: &str,
    transport: T,
    lock: &L,
    now: i64,
) -> Result<Swept<AccountError<W>>, Error<AccountError<W>>>
where
    W: OneTimeIvkRestoreWrite,
    P: Parameters,
    T: Transport,
    L: WriteLock,
{
    let mut finished = 0;
    let mut deferred = Vec::new();
    let work = lock
        .write("one_time_sweep.due", || {
            wallet.prepare_one_time_sweeps(account, through, now, BATCH)
        })
        .map_err(Error::Wallet)?
        .map_err(Error::Deferred)?;
    let mut transport = Some(transport);
    let mut directory = None;
    if !work.is_empty() {
        let transport = transport.take().expect("not yet used");
        let accepted = Directory::accept(wallet, params, through, genesis, origin, transport);
        let (directory, anchor) = directory.insert(accepted.await?);
        let checks = directory.check(&work, now).await?;
        let lookups = checks.iter().filter(|check| check.paid).count();
        if lookups > 0 {
            directory.open_session(lookups).await?;
        }
        for (item, check) in work.into_iter().zip(checks) {
            // A key whose lease is not stored would be due again at once.
            let leased = lock
                .write("one_time_sweep.attempt", || {
                    let tip = Some(through.height);
                    let scanned = wallet.block_fully_scanned()?.map(|b| b.block_height());
                    if check.paid && (scanned != tip || wallet.chain_height()? != tip) {
                        return Ok(false);
                    }
                    wallet.begin_one_time_sweep_attempt(account, item.key, now, check.seen)?;
                    Ok(true)
                })
                .map_err(Error::Wallet)?;
            if !leased {
                break;
            }
            let swept = sweep_key(
                wallet, directory, *anchor, account, &item, check, through, lock,
            );
            match swept.await {
                Ok(()) => finished += 1,
                Err(e @ Error::Wallet(_)) => return Err(e),
                Err(e) => {
                    // Every later key would fail the same way and back off.
                    let run_wide = matches!(
                        e,
                        Error::Directory(DirectoryError::Revision | DirectoryError::Transport(_))
                            | Error::Deferred(SweepDeferral::UnknownAnchor)
                    );
                    deferred.push((item.key, e));
                    if run_wide {
                        break;
                    }
                }
            }
        }
        // New lookahead keys wait for a later run, which bounds this one.
        lock.write("one_time_sweep.lookahead", || {
            wallet.maintain_one_time_ivks(account)
        })
        .map_err(Error::Wallet)?;
    }
    lock.write("one_time_sweep.release", || {
        wallet.finish_one_time_nullifier_recovery(account, through)
    })
    .map_err(Error::Wallet)?;
    if let Some(transport) = transport {
        // Closed keys with no known payment need each newer publication's paid filter. No
        // publication ends above `through`, so keys checked there need none.
        let closed = wallet.one_time_keys_to_recheck(account, through.height);
        if !closed.map_err(Error::Wallet)?.is_empty() {
            let accepted = Directory::accept(wallet, params, through, genesis, origin, transport);
            directory = Some(accepted.await?);
        }
    }
    if let Some((directory, anchor)) = &mut directory {
        // Only keys this publication has not checked, so the filters are fetched only for
        // a newer one.
        let keys = wallet
            .one_time_keys_to_recheck(account, anchor.height)
            .map_err(Error::Wallet)?;
        if !keys.is_empty() {
            let checks = directory.check(&keys, now).await?;
            let checked: Vec<_> = keys
                .iter()
                .zip(checks)
                .map(|(item, check)| (item.key, check.paid))
                .collect();
            lock.write("one_time_sweep.recheck", || {
                wallet.record_paid_filter_check(account, *anchor, &checked)
            })
            .map_err(Error::Wallet)?;
        }
    }
    // Read last, since a paid filter hit queues its key's sweep again.
    let pending = wallet
        .one_time_history_pending(account, through.height)
        .map_err(Error::Wallet)?;
    Ok(Swept {
        finished,
        deferred,
        pending,
    })
}

/// What a publication's filters say about one key's receiver.
#[derive(Clone, Copy)]
pub(crate) struct Check {
    /// The paid set holds it, so a lookup may find payments.
    pub(crate) paid: bool,
    /// A swap may still pay it, so its key keeps scanning after its sweep.
    pub(crate) recent: bool,
    /// A swap provider's seen set holds it, so it is never issued again.
    pub(crate) seen: bool,
}

/// A receiver-directory publication whose coverage the client checked. Its filters are
/// fetched only once a key needs them, and its PIR session and common witnesses only
/// once a key needs a lookup.
pub(crate) struct Directory<'a, T> {
    origin: &'a str,
    /// Moves into the session when one opens.
    transport: Option<T>,
    manifest: receiver_pir::Manifest,
    accepted: AcceptedCoverage,
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
    /// Takes `manifest`, the publication `origin` serves, if it commits to `genesis`, covers
    /// history from `activation` (see [`ironwood_activation`]), ends at block `height` with
    /// hash `hash`, and has the seen sets [`fetch_seen`](crate::fetch_seen) requires.
    pub(crate) fn new<E>(
        activation: BlockHeight,
        genesis: [u8; 32],
        origin: &'a str,
        transport: T,
        manifest: receiver_pir::Manifest,
        height: u32,
        hash: [u8; 32],
    ) -> Result<Self, Error<E>> {
        let accepted = AcceptedCoverage {
            genesis,
            required_start: activation.into(),
            height,
            hash,
        };
        accepted.check(&manifest.directory)?;
        // Restores use only seen-set membership; issuance checks the sets' dates as it
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
        })
    }

    /// Accepts the publication `origin` serves at the block of the wallet's chain it ends
    /// at, which it returns with it.
    async fn accept<W: OneTimeIvkRestoreRead, P: Parameters>(
        wallet: &W,
        params: &P,
        through: ChainPoint,
        genesis: [u8; 32],
        origin: &'a str,
        transport: T,
    ) -> Result<(Self, ChainPoint), Error<AccountError<W>>> {
        let manifest = DirectoryClient::fetch_manifest(origin, &transport).await?;
        let end = BlockHeight::from(manifest.directory.end_height);
        let anchor = wallet
            .directory_publication_anchor(end, through)
            .map_err(Error::Wallet)?
            .map_err(Error::Deferred)?;
        let activation = ironwood_activation(params)?;
        let (height, hash) = (anchor.height.into(), anchor.hash.0);
        let directory = Self::new(
            activation, genesis, origin, transport, manifest, height, hash,
        )?;
        // Height and hash alone accept a publication that stops partway through the
        // anchor block, whose omitted payments no lookup or scan from `anchor + 1` finds.
        let tree_size = wallet
            .block_metadata(anchor.height)
            .map_err(Error::Wallet)?
            .and_then(|block| block.ironwood_tree_size());
        if tree_size.map(u64::from) != Some(directory.manifest.directory.end_position) {
            return Err(Error::Unavailable(
                "the receiver directory's tree size differs from the wallet's at its anchor",
            ));
        }
        Ok((directory, anchor))
    }

    /// What the filters say about each item's receiver at `now`, downloading them first
    /// if needed; see [`sweep`] for how the recent sets are read.
    pub(crate) async fn check<E>(
        &mut self,
        work: &[DiscoveryWork],
        now: i64,
    ) -> Result<Vec<Check>, Error<E>> {
        let receivers = work
            .iter()
            .map(|item| Receiver::from_bytes(item.receiver).map(|r| *r.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(checked)?;
        if self.filters.is_none() {
            // Filters are fetched before a session takes the transport.
            let transport = self.transport.as_ref().expect("no session yet");
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

    /// Drops the filters, which [`Self::check`] fetches again if it needs them.
    pub(crate) fn release_filters(&mut self) {
        self.filters = None;
    }

    /// Opens the PIR session for `lookups` lookups, after the filters are fetched.
    pub(crate) async fn open_session<E>(&mut self, lookups: usize) -> Result<(), Error<E>> {
        let transport = self.transport.take().expect("a session opens once");
        let client = DirectoryClient::connect_manifest(
            self.origin,
            transport,
            self.accepted,
            self.manifest.clone(),
            lookups,
        )
        .await?;
        let witnesses = client.witnesses().await?;
        let publication = publication(client.manifest())?;
        let witnesses = WitnessSnapshot::decode(&witnesses, &publication).map_err(checked)?;
        self.session = Some(Session { client, witnesses });
        Ok(())
    }

    /// Looks up `item`'s receiver over the open session.
    pub(crate) async fn look_up(
        &mut self,
        item: &DiscoveryWork,
    ) -> Result<Vec<DirectoryPayment>, DirectoryError> {
        let receiver = Receiver::from_bytes(item.receiver).map_err(checked)?;
        let session = self.session.as_mut().expect("opened for paid keys");
        let payments = session
            .client
            .lookup(*receiver.as_bytes(), self.accepted)
            .await?;
        payments.into_iter().map(directory_payment).collect()
    }

    /// The inclusion path of the note commitment `cmx` at `position` in the session's
    /// common witnesses, if a session is open and they hold it.
    pub(crate) fn witness(&self, position: u32, cmx: [u8; 32]) -> Option<[[u8; 32]; 32]> {
        let session = self.session.as_ref()?;
        session.witnesses.path(position, cmx).ok()
    }
}

/// Ironwood activation on `params`' network, the history every publication must cover.
pub(crate) fn ironwood_activation<E>(params: &impl Parameters) -> Result<BlockHeight, Error<E>> {
    params
        .activation_height(NetworkUpgrade::Nu6_3)
        .ok_or(Error::Unavailable("Ironwood is not active on this network"))
}

/// Whether a provider's recent set can rule a receiver out at `now` (see [`sweep`]).
fn covers_restore_watch(set: &FilterSet, now: i64) -> bool {
    let window = set.window_secs.and_then(|w| i64::try_from(w).ok());
    match (window, set.since_unix, set.until_unix) {
        (Some(window), Some(since), Some(until)) => {
            window >= RESTORE_WATCH_SECS
                && since <= until.saturating_sub(window)
                && (now.saturating_sub(RECENT_SET_MAX_AGE_SECS)
                    ..=now.saturating_add(RECENT_SET_CLOCK_SKEW_SECS))
                    .contains(&until)
        }
        _ => false,
    }
}

/// Sweeps one key whose attempt is leased: looks up its receiver if `check` shows the
/// paid set holds it, queues the answer, empty on a miss, and applies it with the
/// witnesses of the publication accepted at `anchor`.
#[allow(clippy::too_many_arguments)]
async fn sweep_key<W, T, L>(
    wallet: &mut W,
    directory: &mut Directory<'_, T>,
    anchor: ChainPoint,
    account: AccountId<W>,
    item: &DiscoveryWork,
    check: Check,
    through: ChainPoint,
    lock: &L,
) -> Result<(), Error<AccountError<W>>>
where
    W: OneTimeIvkRestoreWrite,
    T: Transport,
    L: WriteLock,
{
    let key = item.key;
    let paid = check.paid;
    let payments = if paid {
        directory.look_up(item).await?
    } else {
        Vec::new()
    };
    lock.write("one_time_sweep.queue", || {
        wallet.queue_directory_lookup(account, key, anchor, &payments)
    })
    .map_err(Error::Wallet)?
    .map_err(Error::Deferred)?;
    let applied = lock
        .write("one_time_sweep.apply", || {
            wallet.apply_one_time_sweep(account, key, through, anchor, check.recent, |p, cmx| {
                // A miss queued nothing to apply.
                directory.witness(p, cmx).filter(|_| paid)
            })
        })
        .map_err(Error::Wallet)?
        .map_err(Error::Deferred)?;
    match applied {
        PaymentApplication::Applied => Ok(()),
        waiting => Err(Error::Queued(waiting)),
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

/// A directory payment as the wallet takes it, after checking that its note
/// commitment and Action nullifier are canonical and its ephemeral key valid. The
/// directory crates parse records structurally only.
fn directory_payment(
    payment: receiver_directory::Payment,
) -> Result<DirectoryPayment, DirectoryError> {
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
}
