//! Bounded public filter work. A request owns its captured wallet fence, not a wallet
//! connection or scan lock, so network waits cannot hold ordinary scanning open.
use crate::{DirectoryError, Error, Transport};
use receiver_directory::{
    archive::{Head, PAGE_BLOCKS},
    blocks::BlockId,
};
use receiver_pir::archive::ArchiveClient;
use zcash_client_backend::data_api::{
    WalletRead,
    one_time_ivk::recovery::{FilterJudgment, FilterWork, History, OneTimeRecoveryWrite},
    transparent_ledger::ChainPoint,
};
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::BlockHeight;

/// A captured public range request. Construct it only after anchoring and accepting
/// the head with `accept_filter_head`. It can be moved to an independent network task.
pub struct FilterRequest<A> {
    head: Head,
    work: FilterWork<A>,
}

/// Verified judgments awaiting an atomic, generation-fenced wallet commit.
pub struct FilterResponse<A> {
    head: Head,
    work: FilterWork<A>,
    judgments: Vec<FilterJudgment>,
}

/// Accepts the archive only when its frontier is already on the wallet's connected
/// chain. Missing chain context leaves recovery pending and never delays ordinary sync.
/// The caller serializes this short operation with its other wallet writes.
pub fn accept_filter_head<W: OneTimeRecoveryWrite>(
    wallet: &mut W,
    account: <W as WalletRead>::AccountId,
    head: &Head,
    genesis: [u8; 32],
    activation: BlockHeight,
) -> Result<bool, Error<<W as WalletRead>::Error>> {
    if head.first_height > u32::from(activation) {
        return Err(Error::Unavailable("archive omits supported history"));
    }
    if !wallet
        .one_time_recovery_state(account)
        .map_err(Error::Wallet)?
        .is_some_and(|s| s.enabled)
    {
        return Ok(false);
    }
    if !anchored(wallet, head, genesis)? {
        return Ok(false);
    }
    wallet
        .accept_one_time_history(
            account,
            History {
                genesis: head.genesis,
                archive: head.archive,
                epoch: head.epoch,
            },
        )
        .map_err(Error::Wallet)
}

/// Checks the exact frontier without requiring a stored hash for every historical filter.
fn anchored<W: WalletRead>(
    wallet: &W,
    head: &Head,
    genesis: [u8; 32],
) -> Result<bool, Error<<W as WalletRead>::Error>> {
    let Some(block) = wallet
        .block_metadata(BlockHeight::from(head.frontier.height))
        .map_err(Error::Wallet)?
    else {
        return Ok(false);
    };
    head.check_anchor(
        &genesis,
        BlockId {
            height: u32::from(block.block_height()),
            hash: block.block_hash().0,
        },
    )
    .map_err(DirectoryError::from)?;
    Ok(true)
}

impl<A> FilterRequest<A> {
    /// Captures at most one archive page for an already prepared receiver group. No
    /// request is needed when its cursor is beyond this head. Historical gaps remain due.
    pub fn new(head: Head, work: FilterWork<A>) -> Result<Option<Self>, DirectoryError> {
        head.validate()?;
        if work.fence.history
            != (History {
                genesis: head.genesis,
                archive: head.archive,
                epoch: head.epoch,
            })
            || work.receivers.is_empty()
            || work.receivers.len() > 1024
            || u32::from(work.next_height) < head.first_height
        {
            return Err(DirectoryError::Revision);
        }
        if u32::from(work.next_height) > head.frontier.height {
            return Ok(None);
        }
        Ok(Some(Self { head, work }))
    }

    /// Fetches a complete immutable page and checks membership locally. There is no
    /// wallet handle or lock in this future, and positive matches do not make PIR calls.
    pub async fn fetch(
        self,
        origin: &str,
        http: &impl Transport,
    ) -> Result<FilterResponse<A>, DirectoryError> {
        let from = u32::from(self.work.next_height);
        let page = ArchiveClient::page(origin, http, &self.head, from / PAGE_BLOCKS).await?;
        let receivers: Vec<_> = self.work.receivers.iter().map(|r| r.receiver).collect();
        let judgments = page
            .filters()
            .iter()
            .filter(|filter| filter.block().height >= from)
            .map(|filter| {
                let hits = self
                    .work
                    .receivers
                    .iter()
                    .zip(filter.matches(&receivers))
                    .filter_map(|(receiver, hit)| hit.then_some(receiver.key))
                    .collect();
                let block = filter.block();
                FilterJudgment {
                    block: ChainPoint {
                        height: BlockHeight::from(block.height),
                        hash: BlockHash(block.hash),
                    },
                    hits,
                }
            })
            .collect();
        Ok(FilterResponse {
            head: self.head,
            work: self.work,
            judgments,
        })
    }
}

impl<A: Copy + Eq> FilterResponse<A> {
    /// Exposes the authenticated hints for local cache scheduling. These do not prove
    /// ownership or settle an obligation until a wallet write accepts the captured fence.
    pub fn judgments(&self) -> &[FilterJudgment] {
        &self.judgments
    }

    /// Rechecks chain anchoring and atomically commits only the originally captured
    /// receiver group. Toggles, correction epochs and rewinds reject stale responses.
    /// The caller holds its ordinary short wallet write lock, never a network wait.
    pub fn commit<W: OneTimeRecoveryWrite + WalletRead<AccountId = A>>(
        self,
        wallet: &mut W,
    ) -> Result<bool, Error<<W as WalletRead>::Error>> {
        if !anchored(wallet, &self.head, self.work.fence.history.genesis)? {
            return Ok(false);
        }
        wallet
            .record_one_time_filters(self.work.account, &self.work, &self.judgments)
            .map_err(Error::Wallet)
    }
}
