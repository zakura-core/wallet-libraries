//! Binding a published shard set to the chain this wallet accepted.
//!
//! A shard names two block hashes: the block before its first height, and the
//! block at its last. A recovered event names a height and no hash at all —
//! deliberately, because an event carrying a server-supplied block hash could
//! be placed on a branch the wallet never accepted, and there would be nothing
//! in the event to notice it with.
//!
//! So the binding happens once per shard, against the wallet's own `blocks`
//! table, before a single private query is spent on it. A shard whose
//! boundaries the wallet cannot confirm is not read from, and coverage stops
//! below it rather than skipping past it: the map is gapless, so a shard that
//! cannot be confirmed makes every later shard unreachable too.

use transparent_filter::{BlockHash, ShardMap};
use zcash_protocol::consensus::BlockHeight;

use crate::Error;

/// The wallet's view of the chain, for checking a shard map against.
pub trait AcceptedBlocks {
    /// The hash the wallet accepted at `height`, if it has scanned it.
    fn accepted(&self, height: u64) -> Result<Option<[u8; 32]>, Error>;
}

impl AcceptedBlocks for zakura_wallet_store::WalletDb {
    fn accepted(&self, height: u64) -> Result<Option<[u8; 32]>, Error> {
        let Ok(height) = u32::try_from(height) else {
            return Ok(None);
        };
        Ok(self
            .accepted_block_hash(BlockHeight::from_u32(height))?
            .map(|hash| hash.0))
    }
}

/// Truncates `map` to the shards whose boundaries this wallet has accepted.
///
/// Returns the number of shards kept. Zero means nothing can be read yet, which
/// is the ordinary state of a wallet that has not scanned down to the range the
/// shards cover.
///
/// A mismatch is not the same as an absence and is not treated as one. A height
/// the wallet has not scanned yet simply stops the prefix; a height it *has*
/// scanned, whose hash is not the one the map claims, means the map describes a
/// different chain, and is refused outright rather than truncated around,
/// because every later shard in that map is then suspect as well.
pub fn accepted_prefix(map: &mut ShardMap, chain: &impl AcceptedBlocks) -> Result<usize, Error> {
    map.check_shape()
        .map_err(|why| Error::Invalid(format!("shard map is malformed: {why}")))?;

    let mut kept = 0;
    for shard in &map.shards {
        let parent = shard.start_height.saturating_sub(1);
        if !confirms(chain, parent, &shard.parent_block_hash)?
            || !confirms(chain, shard.end_height, &shard.terminal_block_hash)?
        {
            break;
        }
        kept += 1;
    }

    map.shards.truncate(kept);
    Ok(kept)
}

/// Whether the wallet's accepted chain agrees with a hash the map states.
///
/// `false` when the wallet has not scanned the height. An error when it has and
/// they differ.
fn confirms(
    chain: &impl AcceptedBlocks,
    height: u64,
    claimed: &str,
) -> Result<bool, Error> {
    // The block before shard zero is below the covered range, and a wallet is
    // not required to have scanned it in order to read shard zero.
    if height < crate::START_HEIGHT.saturating_sub(1) {
        return Ok(true);
    }
    let Some(accepted) = chain.accepted(height)? else {
        return Ok(false);
    };
    let claimed = BlockHash::from_display_hex(claimed)
        .map_err(|e| Error::Invalid(format!("a shard names a malformed block hash: {e}")))?;
    if claimed.internal_bytes() != &accepted {
        return Err(Error::Invalid(format!(
            "the shard map claims block {claimed:?} at height {height}, and this \
             wallet accepted a different block there; the map describes a chain \
             this wallet is not on"
        )));
    }
    Ok(true)
}
