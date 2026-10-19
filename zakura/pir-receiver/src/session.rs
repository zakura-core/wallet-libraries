//! A receiver directory publication's PIR session, shared by discovery and recovery: paging
//! through a key's history and fetching late payments' inclusion paths.

use std::future::Future;
use std::pin::Pin;
use std::task::Poll;

use receiver_directory::{RawRecord, snapshot::check_next};
use receiver_pir::{AcceptedCoverage, transport::DirectoryClient};
use zakura_one_time_ivk::KeyId;
use zakura_receiver_crypto::{
    Receiver,
    witness::{Publication, WitnessSnapshot},
};
use zcash_client_backend::data_api::{
    WalletRead,
    one_time_ivk::restore::{DirectoryPayment, LookupWork, OneTimeIvkRestoreWrite, PublicationEnd},
    transparent_ledger::ChainPoint,
};
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::BlockHeight;

use crate::{DirectoryError, Transport, checked};

/// A wallet's account identifier.
pub(crate) type AccountId<W> = <W as WalletRead>::AccountId;
/// A wallet's error type.
pub(crate) type AccountError<W> = <W as WalletRead>::Error;

/// Lookups in flight at once.
pub(crate) const PARALLEL_LOOKUPS: usize = 8;
/// Pages one lookup reads in a call; the wallet keeps the cursor for the next.
const PAGES_PER_LOOKUP: u32 = 64;

/// Why a run, or one key's lookup, stopped. `E` is the wallet's error type.
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

/// Serializes wallet writes with the caller's other writers.
pub trait WriteLock {
    /// Runs `write` while holding the caller's wallet write lock. `label` names the
    /// step.
    fn write<T>(&self, label: &'static str, write: impl FnOnce() -> T) -> T;
}

/// What a walk through one key's history read.
pub(crate) struct Walk {
    /// The page the records start at.
    start: u32,
    /// Consecutive records from `start`, at or below the cutoff.
    records: Vec<RawRecord>,
    /// Whether the walk read every record at or below the cutoff.
    complete: bool,
    /// Why the walk stopped early, if it did.
    error: Option<DirectoryError>,
}

/// A receiver-directory publication whose coverage the client checked. Its PIR session and
/// common witnesses are fetched only once a key needs a lookup or a path.
pub(crate) struct Session<'a, T> {
    origin: &'a str,
    transport: &'a T,
    manifest: receiver_pir::Manifest,
    accepted: AcceptedCoverage,
    client: Option<DirectoryClient<&'a T>>,
    witnesses: Option<WitnessSnapshot>,
}

impl<'a, T: Transport> Session<'a, T> {
    /// Takes `manifest`, the publication `origin` serves, if it commits to `genesis` and
    /// covers history from `activation`. Its own last block is provisional until the wallet
    /// judges it.
    pub(crate) fn new(
        activation: BlockHeight,
        genesis: [u8; 32],
        origin: &'a str,
        transport: &'a T,
        manifest: receiver_pir::Manifest,
    ) -> Result<Self, DirectoryError> {
        let accepted = AcceptedCoverage {
            genesis,
            required_start: activation.into(),
            height: manifest.directory.end_height,
            hash: manifest.directory.end_hash,
        };
        accepted.check(&manifest.directory)?;
        Ok(Self {
            origin,
            transport,
            manifest,
            accepted,
            client: None,
            witnesses: None,
        })
    }

    /// The directory's origin.
    pub(crate) fn origin(&self) -> &'a str {
        self.origin
    }

    /// The transport, for requests outside the PIR session.
    pub(crate) fn transport(&self) -> &'a T {
        self.transport
    }

    /// The publication's manifest.
    pub(crate) fn manifest(&self) -> &receiver_pir::Manifest {
        &self.manifest
    }

    /// The publication's last block as its manifest declares it.
    pub(crate) fn publication_end(&self) -> PublicationEnd {
        let directory = &self.manifest.directory;
        PublicationEnd {
            height: BlockHeight::from(directory.end_height),
            hash: directory.end_hash,
            tree_size: directory.end_position,
        }
    }

    /// Opens the PIR session unless it is open.
    pub(crate) async fn connect(&mut self) -> Result<(), DirectoryError> {
        if self.client.is_none() {
            let client = DirectoryClient::connect_manifest(
                self.origin,
                self.transport,
                self.accepted,
                self.manifest.clone(),
            )
            .await?;
            self.client = Some(client);
        }
        Ok(())
    }

    /// The open session's client.
    fn client(&self) -> &DirectoryClient<&'a T> {
        self.client.as_ref().expect("connected before use")
    }

    /// Page zero of `receiver`'s history, or `None` for an empty one, over the open session.
    pub(crate) async fn first_page(
        &self,
        receiver: [u8; 43],
    ) -> Result<Option<RawRecord>, DirectoryError> {
        let receiver = *Receiver::from_bytes(receiver).map_err(checked)?.as_bytes();
        self.client().page(receiver, 0).await
    }

    /// The publication's common witnesses, downloading them once over the open session.
    async fn witnesses(&mut self) -> Result<&WitnessSnapshot, DirectoryError> {
        if self.witnesses.is_none() {
            let client = self.client();
            let bytes = client.witnesses().await?;
            let publication = publication(client.manifest())?;
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
        let session = self.client();
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
            if let Some(previous) = walk.records.last().or(previous.as_ref())
                && let Err(e) = check_next(previous, &record)
            {
                walk.error = Some(e.into());
                return walk;
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

/// How a caller records one walk's page: its revision, its first page, its payments and
/// whether it completed. Returns whether the wallet took it.
pub(crate) type RecordPage<'r, W, I> = dyn FnMut(
        &mut W,
        &I,
        PublicationEnd,
        u32,
        &[DirectoryPayment],
        bool,
    ) -> Result<bool, AccountError<W>>
    + 'r;

/// Looks up each of `lookups`' histories over the open session, [`PARALLEL_LOOKUPS`] at a
/// time, `work` giving each one's key and cursor, and records each walk with `record` under
/// `lock`'s `label`. A failed read, or a page the wallet refused, backs its lookup off and is
/// listed in `failed`; a page the wallet skipped for another reason is listed without a
/// backoff. Lookups go on after one fails unless the directory's connection failed or it
/// revoked the session. Returns whether a walk stopped at its page budget, leaving more due.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn look_up<W, T, L, I>(
    wallet: &mut W,
    session: &Session<'_, T>,
    account: AccountId<W>,
    lookups: &[I],
    work: impl Fn(&I) -> &LookupWork,
    record: &mut RecordPage<'_, W, I>,
    (lock, label): (&L, &'static str),
    now: i64,
    failed: &mut Vec<(KeyId, Error<AccountError<W>>)>,
) -> Result<bool, Error<AccountError<W>>>
where
    W: OneTimeIvkRestoreWrite,
    T: Transport,
    L: WriteLock,
{
    let revision = session.publication_end();
    let mut more = false;
    for batch in lookups.chunks(PARALLEL_LOOKUPS) {
        let walks = join_all(batch.iter().map(|item| session.page_through(work(item)))).await;
        let mut stop = false;
        for (item, walk) in batch.iter().zip(walks) {
            let key = work(item).work.key;
            let mut defer = false;
            more |= !walk.complete && walk.error.is_none();
            if !walk.records.is_empty() || walk.complete {
                match walk
                    .records
                    .into_iter()
                    .map(directory_payment)
                    .collect::<Result<Vec<_>, _>>()
                {
                    Ok(payments) => {
                        let recorded = lock
                            .write(label, || {
                                record(wallet, item, revision, walk.start, &payments, walk.complete)
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
                lock.write(label, || wallet.defer_one_time_lookup(account, key, now))
                    .map_err(Error::Wallet)?;
            }
        }
        if stop {
            break;
        }
    }
    Ok(more)
}

/// Fetches each of `requests`' inclusion paths from the open session's common witnesses
/// and records it under `lock`'s `label`, as `(key, position, cmx)`. A path the witnesses
/// cannot give is listed in `failed` and requested again later.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn record_witnesses<W, T, L>(
    wallet: &mut W,
    session: &mut Session<'_, T>,
    account: AccountId<W>,
    requests: impl IntoIterator<Item = (KeyId, u32, [u8; 32])>,
    (lock, label): (&L, &'static str),
    now: i64,
    failed: &mut Vec<(KeyId, Error<AccountError<W>>)>,
) -> Result<(), Error<AccountError<W>>>
where
    W: OneTimeIvkRestoreWrite,
    T: Transport,
    L: WriteLock,
{
    session.connect().await?;
    let publication = session.publication_end();
    let anchor = ChainPoint {
        height: publication.height,
        hash: BlockHash(publication.hash),
    };
    let witnesses = session.witnesses().await?;
    for (key, position, cmx) in requests {
        // The common witnesses hold every record's position in this publication.
        match witnesses.path(position, cmx) {
            Ok(siblings) => lock
                .write(label, || {
                    wallet.record_one_time_witness(account, key, position, anchor, siblings, now)
                })
                .map_err(Error::Wallet)?,
            Err(e) => failed.push((key, Error::Directory(checked(e)))),
        }
    }
    Ok(())
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
pub(crate) async fn join_all<F: Future>(futures: impl IntoIterator<Item = F>) -> Vec<F::Output> {
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
