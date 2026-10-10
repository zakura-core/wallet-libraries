//! What a pass hands the reference client's sync besides the store: the filter source
//! that keeps the map the sync finished with, the chain view below the floor, and the
//! anchor to sync to.

use transparent_filter::ShardMap;
use transparent_wallet::transport::{BoxError, FilterSource};
use transparent_wallet::{Acceptance, Anchor, ChainView, WalletStore};

/// A filter source that keeps the bytes of the last shard map it served.
///
/// A pass normalizes against that map, the one its sync finished with, and
/// never fetches another: a second fetch can see a newer publication than the
/// one whose facts the sync stored. It caches no filter: prefetching, and
/// dropping what an earlier prefetch left unused when the next one starts or
/// the map is fetched, as [`FilterSource`] requires, stay with the inner source.
pub(super) struct RecordingFilterSource<'a, F> {
    inner: &'a mut F,
    map: Vec<u8>,
}

impl<'a, F: FilterSource> RecordingFilterSource<'a, F> {
    /// Fetches the map a pass starts from, with what it cost.
    pub(super) fn fetch(inner: &'a mut F) -> Result<(Self, u64), BoxError> {
        let (map, cost) = inner.shard_map()?;
        Ok((Self { inner, map }, cost))
    }

    /// The last map served.
    pub(super) fn map(&self) -> &[u8] {
        &self.map
    }
}

impl<F: FilterSource> FilterSource for RecordingFilterSource<'_, F> {
    fn uses_parents(&self) -> bool {
        self.inner.uses_parents()
    }

    fn shard_map(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        let (map, cost) = self.inner.shard_map()?;
        self.map.clone_from(&map);
        Ok((map, cost))
    }

    fn filter(&mut self, shard_id: u64) -> Result<(Vec<u8>, u64), BoxError> {
        self.inner.filter(shard_id)
    }

    fn prefetch(&mut self, shard_ids: &[u64]) {
        self.inner.prefetch(shard_ids)
    }

    fn prepare_parents(
        &mut self,
        map: &ShardMap,
        uncached: &[u64],
        store: &mut dyn WalletStore,
    ) -> Result<u64, BoxError> {
        self.inner.prepare_parents(map, uncached, store)
    }

    fn parent_negative(
        &mut self,
        map: &ShardMap,
        shard_id: u64,
        scripts: &[Vec<u8>],
        store: &mut dyn WalletStore,
    ) -> Result<(bool, u64), BoxError> {
        self.inner.parent_negative(map, shard_id, scripts, store)
    }
}

/// The caller's chain, accepting every block below the watch set's floor. Passed
/// to `sync_into` only.
///
/// A wallet holds no blocks below its birthday, while a publication may start far
/// below it (the live map starts at genesis). Leniency there is sound because, at
/// wallet-pir 06a972db, `sync_into` asks below the floor only for rollback
/// anchors and, in one case below, the end of a replacement shard:
///
/// - It plans only shards meeting `[required_from, target]` (`sync.rs:949-972`),
///   so every coverage endpoint it checks (`sync.rs:1471-1472`, `:2323-2324`,
///   `sync_ahead.rs:255-258`), every stored coverage end its reorg scan and
///   sealed-rewrite judgment ask about (`sync.rs:650-700`, `:702-749`, `:1284`),
///   and the earlier target unfinished page work was read for (`:1337-1339`)
///   is at or above the floor. Required heights only move earlier and targets
///   only rise, so no script the companion retains starts below the floor.
/// - The block a rollback rewinds to may lie below it: the reorg fallback
///   `map.start_height - 1` (`:669`, rolled back at `:686`), a replaced
///   revision (`:808-821`) or a revision withdrawn mid-sync (`:1110-1114`), each
///   just below a shard's start and each resolved by `accepted_at`
///   (`:2661-2681`), which takes the hash from the map when the view has none.
///   Only block 0 has no map entry, so [`Self::hash_at`] answers it with the
///   map's genesis hash.
/// - Judging an undeclared rewrite of a stored sealed range whose own end the
///   chain accepts, it asks about the end of the map's sealed shard now
///   covering that range's start (`:1288-1292`), which can lie below the floor
///   when the range starts below it. There the view accepts it, so such a
///   rewrite is refused as a contradiction (`SealedRewrite`, a withdrawn batch)
///   rather than left unsettled (`ChainUnknown`, a stalled pass). Either way
///   nothing is read, rolled back or exported, and a reorg the publisher
///   followed ahead of the wallet lies near the tip, far above any floor.
///
/// Nothing below the floor is exported or cataloged (see `normalize`), and the
/// target and every shard anchor are checked against the caller's chain alone.
/// Re-verify these call sites on every wallet-pir pin bump.
pub(super) struct FloorAcceptingChain<'a, C> {
    pub(super) chain: &'a C,
    /// The floor: every block below it is accepted.
    pub(super) floor: u64,
    /// The map's genesis hash, already checked to be mainnet's.
    pub(super) genesis_hash: &'a str,
}

impl<C: ChainView> ChainView for FloorAcceptingChain<'_, C> {
    fn is_accepted(&self, height: u64, hash_display_hex: &str) -> Acceptance {
        if height < self.floor {
            Acceptance::Accepted
        } else {
            self.chain.is_accepted(height, hash_display_hex)
        }
    }

    fn tip(&self) -> Option<Anchor> {
        self.chain.tip()
    }

    fn hash_at(&self, height: u64) -> Option<String> {
        if height < self.floor {
            (height == 0).then(|| self.genesis_hash.to_owned())
        } else {
            self.chain.hash_at(height)
        }
    }
}

/// The anchor a pass syncs to, and whether it was clamped below `target`.
///
/// When the publication ends at `t` below the wallet's target, a pass to the
/// target can only report the publication behind. It syncs to the map's last end
/// instead, and so covers everything published, only when all of these hold:
/// `t` is at or above the `floor`; neither the companion's `stored` anchor nor a
/// `retained` event lies above `t`, so the client neither refuses a regressed
/// anchor nor a target below retained events (a lagging replica); and `chain`
/// accepts the map's terminal block at `t`. Otherwise it passes the target
/// unchanged.
pub(super) fn sync_target(
    map: &ShardMap,
    target: &Anchor,
    floor: u64,
    stored: Option<&Anchor>,
    retained: u64,
    chain: &impl ChainView,
) -> (Anchor, bool) {
    let Some(last) = map.shards.last() else {
        return (target.clone(), false);
    };
    let t = last.end_height;
    if t < target.height
        && t >= floor
        && stored.is_none_or(|anchor| t >= anchor.height)
        && t >= retained
        && chain.is_accepted(t, &last.terminal_block_hash) == Acceptance::Accepted
    {
        let clamped = Anchor {
            height: t,
            hash: last.terminal_block_hash.clone(),
        };
        (clamped, true)
    } else {
        (target.clone(), false)
    }
}
