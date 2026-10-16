//! Early restore of an account's one-time keys from a receiver directory's public
//! filters (see the backend's `OneTimeIvkRestoreWrite::begin_one_time_early_restore`).

use receiver_pir::transport::DirectoryClient;
use zakura_one_time_ivk::{KeyId, Purpose};
use zcash_client_backend::data_api::{
    WalletRead,
    one_time_ivk::restore::{
        DiscoveryWork, EarlyRestoreKey, OneTimeIvkRestoreWrite, PublicationEnd,
    },
};
use zcash_protocol::consensus::{BlockHeight, Parameters};

use crate::{
    DirectoryError, Transport,
    sweep::{AccountError, AccountId, Directory, Error, WriteLock, ironwood_activation},
};

/// Keys an early restore always checks, from index zero, in each purpose.
pub const FIRST_WINDOW: u64 = 100;
/// Consecutive keys in no filter after which an early restore's lookahead stops, past
/// [`FIRST_WINDOW`].
pub const GAP: u64 = 30;
/// The most keys an early restore checks in one purpose. A purpose that reaches it is
/// left to restore sweeps beyond it.
pub const MAX_KEYS: u64 = 5_000;
/// Receivers derived per wallet read.
const CHUNK: u64 = 100;

/// One account's early restore that registered its keys, with the paid ones still to look
/// up (see [`EarlyRestore::look_up`]).
pub struct EarlyRestore<'a, T, A> {
    directory: Directory<'a, T>,
    /// The account the restore began for, which its lookups are recorded for.
    account: A,
    /// Paid keys with their receivers.
    paid: Vec<DiscoveryWork>,
}

/// What [`EarlyRestore::look_up`] did. `E` is the wallet's error type.
#[derive(Debug)]
pub struct LookedUp<E> {
    /// Paid keys left to restore sweeps, with why.
    pub failed: Vec<(KeyId, Error<E>)>,
}

/// Starts `account`'s early restore against the publication `origin` serves, if the
/// wallet allows one (see `OneTimeIvkRestoreRead::one_time_early_restore_start`). Call
/// it before the restore scan stores any of the account's history, with a time budget:
/// once the scan stores a block from the restore start on, the wallet refuses to begin.
///
/// The publication must commit to `genesis` and cover history from Ironwood activation on
/// `params`' network. It is provisional: the wallet accepts it only once its scan stores
/// the publication's last block with the declared hash and tree size. Only the public
/// filters are read here, so this makes no private query. Each purpose's keys are checked
/// from index zero: always the first [`FIRST_WINDOW`], then on until [`GAP`] consecutive
/// keys are in no seen set and not in the paid filter, up to [`MAX_KEYS`]. Every incoming
/// key checked is registered, and refund keys only when seen or paid, since refund
/// issuance skips registered indices. Recent keys follow [`crate::sweep`]'s rule.
///
/// Returns `None` when the wallet has no early restore to run.
#[allow(clippy::too_many_arguments)]
pub async fn begin_early_restore<'a, W, P, T, L>(
    wallet: &mut W,
    params: &P,
    account: AccountId<W>,
    genesis: [u8; 32],
    origin: &'a str,
    transport: T,
    lock: &L,
    now: i64,
) -> Result<Option<EarlyRestore<'a, T, AccountId<W>>>, Error<AccountError<W>>>
where
    W: OneTimeIvkRestoreWrite,
    P: Parameters,
    T: Transport,
    L: WriteLock,
{
    if wallet
        .one_time_early_restore_start(account)
        .map_err(Error::Wallet)?
        .is_none()
    {
        return Ok(None);
    }
    let activation = ironwood_activation(params)?;
    let manifest = DirectoryClient::fetch_manifest(origin, &transport).await?;
    let end = PublicationEnd {
        height: BlockHeight::from(manifest.directory.end_height),
        hash: manifest.directory.end_hash,
        tree_size: manifest.directory.end_position,
    };
    let (height, hash) = (end.height.into(), end.hash);
    let mut directory = Directory::new(
        activation, genesis, origin, transport, manifest, height, hash,
    )?;
    let mut keys = Vec::new();
    let mut paid = Vec::new();
    for purpose in [Purpose::Receive, Purpose::Refund] {
        let mut from = 0;
        // Each used key moves `reach` to `GAP` keys past it.
        let mut reach = FIRST_WINDOW;
        while from < reach.min(MAX_KEYS) {
            let to = reach.min(MAX_KEYS).min(from + CHUNK);
            let count = u32::try_from(to - from).expect("at most CHUNK");
            let work = wallet
                .one_time_receivers(account, purpose, from, count)
                .map_err(Error::Wallet)?;
            let checks = directory.check(&work, now).await?;
            for (item, check) in work.into_iter().zip(checks) {
                let used = check.seen || check.paid;
                if used {
                    reach = reach.max(item.key.index() + 1 + GAP);
                }
                if purpose == Purpose::Receive || used {
                    keys.push(EarlyRestoreKey {
                        key: item.key,
                        seen: check.seen,
                        paid: check.paid,
                        recent: check.recent,
                    });
                }
                if check.paid {
                    paid.push(item);
                }
            }
            from = to;
        }
    }
    // The filters can be large, and the lookups run alongside the scan.
    directory.release_filters();
    let begun = lock
        .write("one_time_early_restore.begin", || {
            wallet.begin_one_time_early_restore(account, end, &keys)
        })
        .map_err(Error::Wallet)?;
    Ok(begun.then_some(EarlyRestore {
        directory,
        account,
        paid,
    }))
}

impl<T: Transport, A: Copy> EarlyRestore<'_, T, A> {
    /// Looks up every paid key over PIR and records each answer for the restore's account,
    /// with the publication's witnesses (see
    /// `OneTimeIvkRestoreWrite::record_one_time_early_lookup`). Runs alongside the restore
    /// scan. The keys looked up come only from the public filters.
    /// A key whose lookup fails is listed in [`LookedUp::failed`] and left to restore
    /// sweeps, while the others go on, unless the directory's connection failed or it
    /// revoked the session: then the remaining keys are left too.
    pub async fn look_up<W, L>(
        mut self,
        wallet: &mut W,
        lock: &L,
    ) -> Result<LookedUp<AccountError<W>>, Error<AccountError<W>>>
    where
        W: OneTimeIvkRestoreWrite + WalletRead<AccountId = A>,
        L: WriteLock,
    {
        let (account, mut failed) = (self.account, Vec::new());
        if !self.paid.is_empty() {
            self.directory.open_session(self.paid.len()).await?;
        }
        let mut keys = self.paid.into_iter();
        for item in keys.by_ref() {
            let payments = match self.directory.look_up(&item).await {
                Ok(payments) => payments,
                Err(e) => {
                    let run_wide =
                        matches!(e, DirectoryError::Revision | DirectoryError::Transport(_));
                    failed.push((item.key, e.into()));
                    if run_wide {
                        break;
                    }
                    continue;
                }
            };
            let directory = &self.directory;
            lock.write("one_time_early_restore.lookup", || {
                wallet.record_one_time_early_lookup(account, item.key, &payments, |p, cmx| {
                    directory.witness(p, cmx)
                })
            })
            .map_err(Error::Wallet)?;
        }
        for item in keys {
            failed.push((item.key, Error::Unavailable("the directory session ended")));
        }
        Ok(LookedUp { failed })
    }
}
