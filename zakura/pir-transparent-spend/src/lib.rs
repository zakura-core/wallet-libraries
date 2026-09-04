//! Client and wallet adapters for private transparent-outpoint spend lookup.

pub mod client;
pub mod types;

use transparent::bundle::OutPoint;
use zcash_client_backend::data_api::{
    WalletRead, WalletWrite, enhance_pir::EnhancePirSnapshotAnchor,
};
use zcash_primitives::block::BlockHash;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::{BlockHeight, TxIndex};

pub use client::{ClientError, TransparentSpendPirClient};
pub use types::{
    SpendLookup, TransparentSpendEntry, TransparentSpendGeneration, TransparentSpendSession,
    TransparentSpendTableSession, WARM_BLOCKS,
};

#[derive(Debug, thiserror::Error)]
pub enum ApplyError<E: std::error::Error + 'static> {
    #[error("lookup result does not match the requested outpoint")]
    MismatchedOutpoint,
    #[error("lookup height exceeds the wallet height representation")]
    HeightOverflow,
    #[error("wallet error: {0}")]
    Wallet(#[source] E),
}

/// Converts the session identity into the existing wallet snapshot check.
/// Call `EnhancePirRead::enhance_pir_snapshot_status` and proceed only on
/// `Accepted`; a mismatch must not trigger a direct lightwalletd fallback.
pub fn snapshot_anchor(
    session: &TransparentSpendSession,
) -> Result<EnhancePirSnapshotAnchor, ClientError> {
    let hash: [u8; 32] = hex::decode(&session.tip_block_hash)
        .map_err(|_| ClientError::Session("invalid tip block hash".to_string()))?
        .try_into()
        .map_err(|_| ClientError::Session("invalid tip block hash".to_string()))?;
    Ok(EnhancePirSnapshotAnchor {
        height: BlockHeight::from(
            u32::try_from(session.tip_height)
                .map_err(|_| ClientError::Session("tip height exceeds u32".to_string()))?,
        ),
        block_hash: BlockHash(hash),
        ironwood_tree_size: session.ironwood_tree_size,
    })
}

/// Applies a successful two-tier PIR lookup to the ordinary wallet spend
/// index. Callers must first accept the session's exact tip height, block hash,
/// and Ironwood tree size against their fully-scanned chain state.
pub fn apply_lookup<DbT: WalletWrite>(
    db: &mut DbT,
    outpoint: OutPoint,
    lookup: SpendLookup,
) -> Result<(), ApplyError<<DbT as WalletRead>::Error>>
where
    <DbT as WalletRead>::Error: std::error::Error + 'static,
{
    match lookup {
        SpendLookup::Spent(entry) => {
            if *outpoint.hash() != entry.outpoint_txid || outpoint.n() != entry.outpoint_index {
                return Err(ApplyError::MismatchedOutpoint);
            }
            db.notify_output_spent(
                outpoint,
                TxId::from_bytes(entry.spending_txid),
                BlockHeight::from(entry.spend_height),
                TxIndex::from(entry.transaction_index),
            )
            .map_err(ApplyError::Wallet)
        }
        SpendLookup::Unspent { as_of_height } => {
            let height = u32::try_from(as_of_height).map_err(|_| ApplyError::HeightOverflow)?;
            db.notify_output_verified_unspent(outpoint, BlockHeight::from(height))
                .map_err(ApplyError::Wallet)
        }
    }
}
