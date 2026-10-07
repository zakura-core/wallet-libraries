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
use receiver_directory::{Receiver, witness::WitnessSnapshot};
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
/// blocks below `through`. New payments a lookup finds take
/// their note data from `notes`. After each batch the incoming lookahead moves past
/// paid indices and its new keys are swept too. A key that fails is backed off and
/// listed in [`Swept::deferred`], and the others go on, unless the directory's session
/// or connection failed: then the run stops before leasing more keys. `now` is the
/// caller's clock in seconds, for retry backoff.
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
        let (mut work, remaining) = due(wallet, accounts, through, lock, now)?;
        if !work.is_empty() {
            let mut directory =
                connect(wallet, through, genesis, origin, transport, remaining).await?;
            'run: loop {
                for (account, item) in work {
                    let swept_key = sweep_key(
                        wallet,
                        &mut directory,
                        account,
                        &item,
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
                let (next, remaining) = due(wallet, accounts, through, lock, now)?;
                if next.is_empty() {
                    break;
                }
                directory.client.use_file_for_work(remaining).await?;
                work = next;
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

/// A receiver-directory publication accepted at a block the wallet scanned.
struct Directory<T> {
    client: DirectoryClient<T>,
    accepted: AcceptedCoverage,
    anchor: ChainPoint,
    witnesses: WitnessSnapshot,
}

/// `accounts`' due sweeps at `through`, a bounded batch per account, with the whole
/// job's remaining lookup count, which decides between PIR and the full row file.
fn due<C, P, CL, R, L>(
    wallet: &mut WalletDb<C, P, CL, R>,
    accounts: &[AccountUuid],
    through: ChainPoint,
    lock: &L,
    now: i64,
) -> Result<(Vec<(AccountUuid, DiscoveryWork)>, usize), Error>
where
    C: BorrowMut<Connection>,
    P: Parameters,
    L: WriteLock,
{
    let mut work = Vec::new();
    let mut remaining = 0;
    for &account in accounts {
        let batch = lock.write("swap_sweep.due", || {
            wallet.prepare_swap_discovery_batch(account, through, now, BATCH)
        })?;
        remaining += batch.remaining_lookups;
        work.extend(batch.work.into_iter().map(|item| (account, item)));
    }
    Ok((work, remaining))
}

/// Connects to the publication `origin` serves, accepted at the block of the wallet's
/// chain it ends at, and downloads its common witnesses, which every wallet fetches
/// identically.
async fn connect<C, P, CL, R, T>(
    wallet: &WalletDb<C, P, CL, R>,
    through: ChainPoint,
    genesis: [u8; 32],
    origin: &str,
    transport: T,
    remaining: usize,
) -> Result<Directory<T>, Error>
where
    C: Borrow<Connection>,
    P: Parameters,
    T: Transport,
{
    let advertised = DirectoryClient::fetch_manifest(origin, &transport).await?;
    let end = BlockHeight::from(advertised.directory.end_height);
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
    let client =
        DirectoryClient::connect_manifest(origin, transport, accepted, advertised, remaining)
            .await?;
    let witnesses = client.witnesses().await?;
    Ok(Directory {
        client,
        accepted,
        anchor,
        witnesses,
    })
}

/// Sweeps one key: leases an attempt, looks up its receiver unless an earlier
/// lookup is already queued, queues the new payments with their note data in
/// batches, and applies them with the publication's witnesses.
#[allow(clippy::too_many_arguments)]
async fn sweep_key<C, P, CL, R, T, N, L>(
    wallet: &mut WalletDb<C, P, CL, R>,
    directory: &mut Directory<T>,
    account: AccountUuid,
    item: &DiscoveryWork,
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
    lock.write("swap_sweep.attempt", || {
        wallet.begin_swap_discovery_attempt(account, key, now)
    })?;
    if item.lookup.is_none() {
        let receiver = Receiver::from_bytes(item.receiver).map_err(DirectoryError::from)?;
        let accepted = directory.accepted;
        let payments: Vec<_> = directory
            .client
            .lookup(receiver, accepted)
            .await?
            .into_iter()
            .map(directory_payment)
            .collect();
        loop {
            let batch: Vec<_> = wallet
                .swap_note_data_needed(account, key, &payments)?
                .into_iter()
                .take(NOTE_BATCH)
                .collect();
            let requested = batch.len();
            let note_data = notes.note_data(wallet, batch).await?;
            let done = lock.write("swap_sweep.queue", || {
                wallet.queue_swap_directory_lookup(
                    account,
                    key,
                    directory.anchor,
                    &payments,
                    &note_data,
                )
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
    let applied = lock.write("swap_sweep.apply", || {
        wallet.apply_swap_sweep(account, key, through, directory.anchor, |position, cmx| {
            directory.witnesses.path(position, cmx).ok()
        })
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
