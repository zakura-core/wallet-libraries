//! Restore sweeps of swap receiving keys through a receiver directory over PIR.
//!
//! A restored wallet cannot rescan public history for every key its seed may have
//! used, so each swap key recovered from the seed (see
//! [`WalletDb::maintain_swap_receiving`]) is looked up once in a receiver directory:
//! a public index of Ironwood payments sent with the zero outgoing viewing key, keyed
//! by receiver. Lookups use PIR, so the directory does not learn which receivers the
//! wallet holds. A publication is used only at a block the wallet scanned, and the
//! wallet authenticates every payment with its derived key and its own chain before
//! crediting it (see [`WalletDb::apply_swap_sweep`]).
//!
//! The caller supplies transports, which carry its route policy, cancellation and
//! timeouts, and a [`WriteLock`] that serializes wallet writes with its other
//! writers. Dropping a [`sweep`] future at any await is safe: each wallet write is
//! its own transaction, and every begun attempt is already backed off.

use std::{
    borrow::{Borrow, BorrowMut},
    collections::BTreeMap,
    num::NonZeroU32,
};

use futures_util::StreamExt;
use receiver_directory::{Receiver, filter::Filters, witness::WitnessSnapshot};
use receiver_pir::{AcceptedCoverage, transport::DirectoryClient};
use rusqlite::Connection;
use zakura_pir_enhance::{
    ClientError, ClientResourceLimits,
    transport::{Client, PendingClient, Transport as EnhanceTransport},
    wallet::{Acceptance, acceptance},
};
use zcash_client_backend::data_api::{WalletRead, transparent_ledger::ChainPoint};
use zcash_client_sqlite::{
    AccountUuid, WalletDb,
    error::SqliteClientError,
    util::Clock,
    wallet::swap_receiving::{
        DirectoryPayment, DiscoveryWork, Error as WalletError, KeyId, PaymentApplication,
        ProviderView,
    },
};
use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters};

pub use receiver_pir::{Error as DirectoryError, transport::Transport};
/// The directory format and client underneath, for callers that need them directly.
pub use {receiver_directory, receiver_pir};

/// Zcash mainnet's genesis block hash, in internal byte order, which its directory
/// publications commit to.
pub const MAINNET_GENESIS: [u8; 32] = [
    0x08, 0xce, 0x3d, 0x97, 0x31, 0xb0, 0x00, 0xc0, 0x83, 0x38, 0x45, 0x5c, 0x8a, 0x4a, 0x6b, 0xd0,
    0x5d, 0xa1, 0x6e, 0x26, 0xb1, 0x1d, 0xaa, 0x1b, 0x91, 0x71, 0x84, 0xec, 0xe8, 0x0f, 0x04, 0x00,
];

/// Due sweeps prepared per account at a time.
const BATCH: NonZeroU32 = NonZeroU32::new(64).unwrap();
/// Positions whose note data one request asks for. Each batch is queued as it arrives,
/// so a long history keeps its progress when a run stops partway.
const NOTE_BATCH: usize = 64;

/// Why a sweep run, or one key's sweep, stopped.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The receiver directory refused, failed or answered inconsistently.
    #[error("receiver directory: {0}")]
    Directory(#[from] DirectoryError),
    /// Enhance PIR could not supply note data.
    #[error("note data: {0}")]
    NoteData(#[from] ClientError),
    /// A wallet step refused or deferred the work.
    #[error(transparent)]
    Wallet(#[from] WalletError),
    /// The wallet database failed.
    #[error("wallet storage: {0}")]
    Storage(#[from] SqliteClientError),
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
pub trait NoteSource<W> {
    /// The 528 ciphertext bytes after the directory's prefix for each of `positions`,
    /// keyed by commitment tree position. `wallet` is the wallet being swept.
    async fn note_data(
        &mut self,
        wallet: &W,
        positions: Vec<u64>,
    ) -> Result<BTreeMap<u64, [u8; 528]>, Error>;
}

/// Note data over Enhance PIR. Its session opens on first use, accepted against the
/// wallet's scanned chain, so a run whose lookups find nothing makes no Enhance
/// request.
pub struct EnhanceNotes<'a, T> {
    origin: &'a str,
    transport: &'a T,
    session: Option<Client>,
}

impl<'a, T: EnhanceTransport> EnhanceNotes<'a, T> {
    /// Note data from the Enhance PIR service at `origin`, reached through `transport`.
    pub fn new(origin: &'a str, transport: &'a T) -> Self {
        Self {
            origin,
            transport,
            session: None,
        }
    }
}

impl<T: EnhanceTransport, C: Borrow<Connection>, P: Parameters, CL, R>
    NoteSource<WalletDb<C, P, CL, R>> for EnhanceNotes<'_, T>
{
    async fn note_data(
        &mut self,
        wallet: &WalletDb<C, P, CL, R>,
        positions: Vec<u64>,
    ) -> Result<BTreeMap<u64, [u8; 528]>, Error> {
        let mut note_data = BTreeMap::new();
        if positions.is_empty() {
            return Ok(note_data);
        }
        if self.session.is_none() {
            let pending = PendingClient::fetch(self.transport, self.origin).await?;
            let limits = ClientResourceLimits::with_cache(32768, 2);
            let accepted = match acceptance(wallet, pending.manifest(), wallet.params(), limits)?? {
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

/// What one [`sweep`] run did.
#[derive(Debug, Default)]
pub struct Swept {
    /// Keys whose sweep finished.
    pub finished: usize,
    /// Keys left for a later run, each already backed off, with why.
    pub deferred: Vec<(KeyId, Error)>,
    /// Whether any of the accounts still has unfinished sweeps or queued payments.
    pub pending: bool,
}

/// Runs `accounts`' due restore sweeps against the receiver directory at `origin`,
/// then releases Ironwood spend evidence that no sweep needs any longer (see
/// [`WalletDb::finish_swap_nullifier_recovery`]).
///
/// `through` is the wallet's fully scanned tip, and sweeps run only while it is also
/// the stored chain tip. When none is due, the run makes no request. Otherwise the
/// publication must commit to `genesis` ([`MAINNET_GENESIS`] on mainnet), cover
/// history from Ironwood activation, and end at a block the wallet scanned at most
/// [`MAX_PUBLICATION_LAG`](zcash_client_sqlite::wallet::swap_receiving::MAX_PUBLICATION_LAG)
/// blocks below `through`. Each key's receiver is first tested against the
/// publication's filters, which every wallet downloads alike: only a receiver in the
/// paid filter is looked up over PIR, and only one in the recent filter keeps
/// scanning after its sweep (see [`WalletDb::apply_swap_sweep`]). A run that looks
/// nothing up opens no PIR session and fetches no witnesses. New payments a lookup
/// finds take their note data from `notes`. After each batch the incoming lookahead
/// moves past paid indices and its new keys are swept too. A key that fails is backed
/// off and listed in [`Swept::deferred`], and the others go on, unless the directory's
/// session or connection failed: then the run stops before leasing more keys. `now` is
/// the caller's clock in seconds, for retry backoff.
#[allow(clippy::too_many_arguments)]
pub async fn sweep<C, P, CL, R, T, N, L>(
    wallet: &mut WalletDb<C, P, CL, R>,
    accounts: &[AccountUuid],
    through: ChainPoint,
    genesis: [u8; 32],
    origin: &str,
    transport: T,
    notes: &mut N,
    lock: &L,
    now: i64,
) -> Result<Swept, Error>
where
    C: BorrowMut<Connection>,
    P: Parameters,
    CL: Clock,
    T: Transport,
    N: NoteSource<WalletDb<C, P, CL, R>>,
    L: WriteLock,
{
    let mut swept = Swept::default();
    if wallet.chain_height()? == Some(through.height) {
        let mut work = due(wallet, accounts, through, lock, now)?;
        if !work.is_empty() {
            let mut directory =
                Directory::accept(wallet, through, genesis, origin, transport).await?;
            'run: loop {
                let checks = directory.check(&work)?;
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
                lock.write("swap_sweep.lookahead", || {
                    accounts
                        .iter()
                        .try_for_each(|account| wallet.maintain_swap_receiving(*account))
                })?;
                work = due(wallet, accounts, through, lock, now)?;
                if work.is_empty() {
                    break;
                }
            }
        }
    }
    for account in accounts {
        lock.write("swap_sweep.release", || {
            wallet.finish_swap_nullifier_recovery(*account, through)
        })?;
        swept.pending |= wallet.swap_history_pending(*account, through.height)?;
    }
    Ok(swept)
}

/// What a publication's filters say about one key's receiver.
#[derive(Clone, Copy)]
struct Check {
    /// The paid filter holds it, so a lookup may find payments.
    paid: bool,
    /// What the swap provider filters say.
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
    async fn accept<C, P, CL, R>(
        wallet: &WalletDb<C, P, CL, R>,
        through: ChainPoint,
        genesis: [u8; 32],
        origin: &'a str,
        transport: T,
    ) -> Result<Self, Error>
    where
        C: Borrow<Connection>,
        P: Parameters,
    {
        let manifest = DirectoryClient::fetch_manifest(origin, &transport).await?;
        let end = BlockHeight::from(manifest.directory.end_height);
        let anchor = wallet.swap_publication_anchor(end, through)?;
        let activation = wallet
            .params()
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

    /// What the filters say about each item's receiver.
    fn check(&self, work: &[(AccountUuid, DiscoveryWork)]) -> Result<Vec<Check>, Error> {
        let receivers = work
            .iter()
            .map(|(_, item)| Receiver::from_bytes(item.receiver))
            .collect::<Result<Vec<_>, _>>()
            .map_err(DirectoryError::from)?;
        let key = &self.manifest.directory.salt;
        let paid = self.filters.paid.matches(key, &receivers);
        let recent = self.filters.recent.matches(key, &receivers);
        let seen = self.filters.seen.matches(key, &receivers);
        Ok((0..receivers.len())
            .map(|i| Check {
                paid: paid[i],
                provider: ProviderView {
                    recent: recent[i],
                    seen: seen[i],
                },
            })
            .collect())
    }

    /// The PIR session, opened for `lookups` lookups if none is open yet.
    async fn session(&mut self, lookups: usize) -> Result<&mut Session<T>, Error> {
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

/// `accounts`' due sweeps at `through`, a bounded batch per account.
fn due<C, P, CL, R, L>(
    wallet: &mut WalletDb<C, P, CL, R>,
    accounts: &[AccountUuid],
    through: ChainPoint,
    lock: &L,
    now: i64,
) -> Result<Vec<(AccountUuid, DiscoveryWork)>, Error>
where
    C: BorrowMut<Connection>,
    P: Parameters,
    L: WriteLock,
{
    let mut work = Vec::new();
    for &account in accounts {
        let batch = lock.write("swap_sweep.due", || {
            wallet.prepare_swap_discovery_batch(account, through, now, BATCH)
        })?;
        work.extend(batch.into_iter().map(|item| (account, item)));
    }
    Ok(work)
}

/// Sweeps one key: leases an attempt, looks up its receiver if the paid filter holds
/// it and no earlier lookup is queued, queues the new payments with their note data
/// in batches, and applies them with the publication's witnesses. `lookups` is the
/// batch's lookup count, which sizes a session that this key opens.
#[allow(clippy::too_many_arguments)]
async fn sweep_key<C, P, CL, R, T, N, L>(
    wallet: &mut WalletDb<C, P, CL, R>,
    directory: &mut Directory<'_, T>,
    account: AccountUuid,
    item: &DiscoveryWork,
    check: Check,
    lookups: usize,
    through: ChainPoint,
    notes: &mut N,
    lock: &L,
    now: i64,
) -> Result<(), Error>
where
    C: BorrowMut<Connection>,
    P: Parameters,
    T: Transport,
    N: NoteSource<WalletDb<C, P, CL, R>>,
    L: WriteLock,
{
    let key = item.key;
    let anchor = directory.anchor;
    lock.write("swap_sweep.attempt", || {
        wallet.begin_swap_discovery_attempt(account, key, now)
    })?;
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
                .swap_note_data_needed(account, key, &payments)?
                .into_iter()
                .take(NOTE_BATCH)
                .collect();
            let requested = batch.len();
            let note_data = notes.note_data(wallet, batch).await?;
            let done = lock.write("swap_sweep.queue", || {
                wallet.queue_swap_directory_lookup(account, key, anchor, &payments, &note_data)
            })?;
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
    let applied = lock.write("swap_sweep.apply", || {
        wallet.apply_swap_sweep(
            account,
            key,
            through,
            anchor,
            check.provider,
            |position, cmx| witnesses.and_then(|w| w.path(position, cmx).ok()),
        )
    })?;
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
