use super::SyncError;
use crate::engine::adapters::{Acceptance, ChainView};
use crate::engine::client::classify_transport;
use crate::engine::store::{Anchor, CoverageRange};
use crate::engine::transport::{ByteCharges, FilterSource, ShardTransport};
use std::collections::BTreeMap;
use zakura_transparent_private_shared::filter::{BlockHash, ShardMap};
use zakura_transparent_private_shared::shard::manifest::ShardManifest;

/// Whether the map still vouches for a settled range the store holds.
///
/// The range is looked up by the height it starts at, not by its shard id: a
/// re-cut renumbers shards, so the id it was read under may now name another
/// range. The map vouches for it when it still publishes that revision there,
/// or when one of its re-cuts declares exactly that revision superseded: the
/// same digest, shard id and start height, sealed, ending on the same block.
/// That keeps a wallet's history across the re-cut without re-reading it.
///
/// The publication a range is matched by is its source anchor, the endpoint
/// it was published with, when the store kept one, which every store since
/// schema 2 does: a range cut short of its shard's end by a target or a
/// rollback still names the whole publication it was read from, and is
/// vouched for only while the map or a declaration names that same one. A
/// range without one matches a declaration when it ends inside the declared
/// range, or at its end on the declared block. Anything the map's sealed
/// shards do not cover is left to the chain checks.
pub(super) fn vouches_for(
    map: &ShardMap,
    declared: &BTreeMap<&str, &zakura_transparent_private_shared::filter::SupersededShard>,
    range: &CoverageRange,
) -> bool {
    let Some(entry) = map.shard_for_height(range.start_height) else {
        return true;
    };
    if !entry.sealed {
        return true;
    }
    if entry.start_height == range.start_height
        && entry.manifest_digest == range.revision_digest
        && range.source_anchor.as_ref().is_none_or(|source| {
            source.height == entry.end_height && source.hash == entry.terminal_block_hash
        })
    {
        return true;
    }
    declared
        .get(range.revision_digest.as_str())
        .is_some_and(|declared| {
            let ends_as_declared = match &range.source_anchor {
                Some(source) => {
                    declared.end_height == source.height
                        && declared.terminal_block_hash == source.hash
                }
                // Without a recorded endpoint a range may have been cut short
                // of its shard by a target or a rollback, as one with an
                // endpoint is above: inside the declared range it matches,
                // and at the declared end it must rest on the declared block.
                None => {
                    range.end_height < declared.end_height
                        || (range.end_height == declared.end_height
                            && range.terminal_block_hash == declared.terminal_block_hash)
                }
            };
            declared.sealed
                && declared.shard_id == range.shard_id
                && declared.start_height == range.start_height
                && ends_as_declared
        })
}

/// What a settled range the map no longer vouches for means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Rewrite {
    /// The wallet's chain rejects the block the range rests on: a reorg,
    /// rolled back like any other.
    Reorg,
    /// The wallet's chain rejects the block the range's publication ended on
    /// but not the block its coverage, cut short by a target or a rollback,
    /// rests on: a reorg above what the wallet covered, which the publisher
    /// followed. The covered part came from a publication of a branch the
    /// chain left, so it is read again from the one now covering it.
    Rederive,
    /// The wallet's chain accepts both the block the range rests on and the
    /// one the shard now covering its start ends on: the publisher
    /// contradicts itself on the chain the wallet follows. Retrying does not
    /// change that while it serves this history.
    Contradiction,
    /// The chain cannot settle it yet; the height is the block it would need
    /// to confirm. A publisher that followed a shallow reorg across a shard it
    /// had just sealed, before the wallet's chain did, looks like this, and
    /// becomes an ordinary reorg once the chain moves.
    Unsettled(u64),
}

/// Judges a settled range `vouches_for` refused, by what the wallet's chain
/// says about the block its publication ended on and about the block the
/// map's shard now covering its start ends on.
///
/// The publication's end, the range's source anchor, is what is judged, not
/// the block the range's coverage rests on: a range cut short by a target
/// rests on a block of the wallet's own chain whatever happened above it, so
/// judging that would call a publisher that followed a reorg above the old
/// target a contradiction.
///
/// Sealing is not delayed for finality, so a publisher can follow a reorg
/// through a just-sealed shard before the wallet's chain does. Only when the
/// chain accepts the replacement's end too, at or below the target, is the
/// change the publisher's alone.
pub(super) fn judge_rewrite(
    map: &ShardMap,
    range: &CoverageRange,
    target: &Anchor,
    chain: &impl ChainView,
) -> Rewrite {
    let (source_height, source_hash) = match &range.source_anchor {
        Some(source) => (source.height, &source.hash),
        None => (range.end_height, &range.terminal_block_hash),
    };
    match chain.is_accepted(source_height, source_hash) {
        Acceptance::Rejected => {
            if (source_height, source_hash) == (range.end_height, &range.terminal_block_hash)
                || chain.is_accepted(range.end_height, &range.terminal_block_hash)
                    == Acceptance::Rejected
            {
                Rewrite::Reorg
            } else {
                Rewrite::Rederive
            }
        }
        Acceptance::Unknown => Rewrite::Unsettled(source_height),
        Acceptance::Accepted => match map.shard_for_height(range.start_height) {
            Some(entry)
                if entry.sealed
                    && entry.end_height <= target.height
                    && chain.is_accepted(entry.end_height, &entry.terminal_block_hash)
                        == Acceptance::Accepted =>
            {
                Rewrite::Contradiction
            }
            Some(entry) => Rewrite::Unsettled(entry.end_height),
            // `vouches_for` refuses only ranges a sealed shard covers, so
            // this and the unsealed case above are not reached; both would
            // be the publisher ahead of or apart from the chain, not settled.
            None => Rewrite::Unsettled(range.end_height),
        },
    }
}

/// Fetches a matched shard's manifest and verifies it against the map.
pub(super) fn fetch_manifest(
    entry: &zakura_transparent_private_shared::filter::ShardMapEntry,
    previous_digest: &str,
    map: &ShardMap,
    transport: &mut impl ShardTransport,
    charges: &mut ByteCharges,
) -> Result<ShardManifest, SyncError> {
    let prepaid = transport.manifest_prepaid(entry.shard_id, &entry.manifest_digest);
    let (raw, cost) = transport
        .manifest(entry.shard_id, &entry.manifest_digest)
        .map_err(|error| SyncError::from(classify_transport(error)))?;
    if prepaid {
        charges.add_manifest_download(cost);
    } else {
        charges.add_manifest(cost);
    }
    verify_manifest(&raw, entry, previous_digest, map)
}

/// Checks a manifest against the map entry that named it, the entry before
/// it, and this build's registry.
///
/// The digest first: the bytes must hash to the digest the map names, or
/// nothing else in them is worth reading. Then every field a retrieval relies
/// on. The parent link ties the manifest to the map's previous entry, so a
/// manifest that is individually well formed but belongs to a different
/// sequence of shards is refused too. Segment shapes are checked against the
/// registry entry the manifest names, which is what makes the geometry a
/// property of the verified manifest rather than of the map alone.
///
/// None of this is an independence proof. The map, the manifest and the
/// tables come from one publisher; agreement among them rules out corruption,
/// stale data and mixed publications, not omission.
pub(super) fn verify_manifest(
    raw: &[u8],
    entry: &zakura_transparent_private_shared::filter::ShardMapEntry,
    previous_digest: &str,
    map: &ShardMap,
) -> Result<ShardManifest, SyncError> {
    let shard_id = entry.shard_id;
    let mismatch = |field: &'static str| SyncError::ManifestMismatch { shard_id, field };
    let manifest: ShardManifest = serde_json::from_slice(raw)
        .map_err(|error| SyncError::Invalid(format!("shard {shard_id} manifest: {error}")))?;
    if manifest.digest() != entry.manifest_digest {
        return Err(mismatch("digest"));
    }
    if !zakura_transparent_private_shared::shard::manifest::supported_schema(&manifest.schema) {
        return Err(SyncError::Schema {
            served: manifest.schema.clone(),
            expected: zakura_transparent_private_shared::shard::SCHEMA,
        });
    }
    if manifest.layout != zakura_transparent_private_shared::shard::ManifestLayout::current() {
        return Err(mismatch("layout"));
    }
    if manifest.tag_salt_counter
        > zakura_transparent_private_shared::shard::tag::MAX_TAG_SALT_COUNTER
    {
        return Err(mismatch("tag_salt_counter"));
    }
    if manifest.network != map.network {
        return Err(mismatch("network"));
    }
    if manifest.genesis_hash != map.genesis_hash {
        return Err(mismatch("genesis_hash"));
    }
    if manifest.profile != map.profile {
        return Err(mismatch("profile"));
    }
    if manifest.shard_id != entry.shard_id {
        return Err(mismatch("shard_id"));
    }
    if manifest.geometry != entry.geometry {
        return Err(mismatch("geometry"));
    }
    if manifest.start_height != entry.start_height || manifest.end_height != entry.end_height {
        return Err(mismatch("range"));
    }
    if manifest.parent_block_hash != entry.parent_block_hash {
        return Err(mismatch("parent_block_hash"));
    }
    if manifest.terminal_block_hash != entry.terminal_block_hash {
        return Err(mismatch("terminal_block_hash"));
    }
    if manifest.filter_hash != entry.filter_hash {
        return Err(mismatch("filter_hash"));
    }
    if manifest.sealed != entry.sealed {
        return Err(mismatch("sealed"));
    }
    if manifest.revision != entry.revision {
        return Err(mismatch("revision"));
    }
    if manifest.parent_manifest_digest != previous_digest {
        return Err(mismatch("parent_manifest_digest"));
    }
    // The map's `page_segments` counts the directory shard's page shards.
    if manifest.directory_segments.len() as u32 != entry.directory_segments
        || manifest.page_children.len() as u32 != entry.page_segments
    {
        return Err(mismatch("segment_count"));
    }
    let geometry = zakura_transparent_private_shared::shard::layout::by_name(&manifest.geometry)
        .ok_or_else(|| SyncError::UnknownGeometry(manifest.geometry.clone()))?;
    for segment in &manifest.directory_segments {
        if segment.rows != geometry.directory_rows
            || segment.row_bytes != geometry.directory_row_bytes as u32
        {
            return Err(mismatch("directory_segment_shape"));
        }
    }
    // Every page shard: contiguous, in order, sealed but for an open last one
    // of a tail, ending on the shard's terminal, segments of the registry's
    // shape. A walk relies on each of these.
    manifest
        .check_children(geometry.page_rows, geometry.page_row_bytes as u32)
        .map_err(|_| mismatch("page_children"))?;
    for child in &manifest.page_children {
        BlockHash::from_display_hex(&child.terminal_block_hash)
            .map_err(|_| mismatch("page_children"))?;
    }
    if let Some(seal) = map.seal.get(&manifest.geometry) {
        if manifest.seal.scripts_target != seal.max_scripts
            || manifest.seal.page_rows_target != seal.max_page_rows
        {
            return Err(mismatch("seal"));
        }
    }
    directory_choice(&manifest)?;
    Ok(manifest)
}

/// The manifest's directory choice table, if it publishes one.
///
/// A table that does not decode, or that indexes a different number of
/// scripts than the shard places, stops the sync. Falling back to two queries
/// would be safe for this shard, but it would hide a malformed publication
/// behind a working one.
pub(super) fn directory_choice(
    manifest: &ShardManifest,
) -> Result<Option<zakura_transparent_private_shared::shard::ChoiceTable>, SyncError> {
    manifest.directory_choice().map_err(|error| {
        SyncError::Invalid(format!("shard {} manifest: {error}", manifest.shard_id))
    })
}

/// Refetches the map after a withdrawn revision, and checks it continues the
/// one in hand.
///
/// Returns the map and the digest of the bytes it came from, so a later refusal
/// naming that same digest can be recognised as unresolvable rather than
/// spending another refresh on it.
pub(super) fn refresh_map(
    started_from: &ShardMap,
    covered_through: u64,
    filters: &mut impl FilterSource,
    charges: &mut ByteCharges,
) -> Result<(ShardMap, String), SyncError> {
    let (bytes, cost) = filters.shard_map().map_err(|error| {
        SyncError::Transport(crate::engine::transport::describe_error(error.as_ref()))
    })?;
    charges.map_bytes += cost;
    let fresh: ShardMap = serde_json::from_slice(&bytes).map_err(|error| {
        SyncError::Invalid(format!("refreshed shard map is malformed: {error}"))
    })?;
    fresh.validate_supported().map_err(|error| {
        SyncError::Invalid(format!("refreshed shard map is malformed: {error}"))
    })?;
    check_continuation(started_from, &fresh, covered_through).map_err(SyncError::MapDiverged)?;
    let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&bytes));
    Ok((fresh, digest))
}

/// Checks a refreshed map is the same shard set, continued.
///
/// A map fetched mid-sync is not independently trusted. The caller validated
/// the map this sync started from against the wallet's accepted chain, and a
/// refresh inherits that validation only over the range the two agree on. So
/// the set's identity must be unchanged, and every shard whose range is already
/// covered must be the *same entry* — sealed content is immutable, so a
/// disagreement there means a different set rather than a longer one.
///
/// Everything this function rules out is what makes the recovery sound: once it
/// passes, the shard the sync resumes at begins exactly where coverage stopped,
/// so no range can be skipped and none can need retracting.
pub(super) fn check_continuation(
    started_from: &ShardMap,
    fresh: &ShardMap,
    covered_through: u64,
) -> Result<(), String> {
    if fresh.genesis_hash != started_from.genesis_hash {
        return Err("it names a different genesis block".into());
    }
    if fresh.network != started_from.network {
        return Err("it names a different network".into());
    }
    if fresh.profile != started_from.profile {
        return Err("it names a different filter profile".into());
    }
    if fresh.range_envelope_version != started_from.range_envelope_version {
        return Err("it names a different range envelope version".into());
    }
    if fresh.start_height != started_from.start_height {
        return Err("its coverage begins at a different height".into());
    }
    // A re-cut redraws the boundaries this walk was planned over and gives
    // shard ids to other ranges, even where it lies above everything covered
    // so far. This sync ends; the next starts from the re-cut map, whose
    // declaration lets it keep what the store holds.
    if fresh.recut_epoch() != started_from.recut_epoch() {
        return Err(format!(
            "it is re-cut epoch {}, this sync started from epoch {}",
            fresh.recut_epoch(),
            started_from.recut_epoch()
        ));
    }
    // New geometries may appear as a set grows into another tier; the seal
    // parameters of a geometry already in use may not change, because they are
    // what the boundaries were derived from.
    for (name, seal) in &started_from.seal {
        if let Some(refreshed) = fresh.seal.get(name) {
            if refreshed != seal {
                return Err(format!("it reseals geometry {name}"));
            }
        }
    }
    for (index, before) in started_from.shards.iter().enumerate() {
        if before.end_height > covered_through {
            break;
        }
        match fresh.shards.get(index) {
            Some(after) if after == before => {}
            Some(_) => {
                return Err(format!(
                    "shard {} covers height {} but is not the shard this sync read",
                    before.shard_id, before.end_height
                ));
            }
            None => {
                return Err(format!(
                    "it withdraws shard {}, whose range this sync already covered",
                    before.shard_id
                ));
            }
        }
    }
    // A map that ends below what is already covered withdraws history the
    // wallet has read, which is the same disagreement as a re-cut shard.
    if let Some(last) = fresh.shards.last() {
        if last.end_height < covered_through {
            return Err(format!(
                "its coverage ends at {}, below the {covered_through} this sync already read",
                last.end_height
            ));
        }
    } else if covered_through >= started_from.start_height {
        return Err("it publishes no shards at all".into());
    }
    Ok(())
}

/// Checks the shard the walk resumes at after a refresh.
///
/// The walk resumes by shard id, which is sound only while the id still names
/// a range starting where the withdrawn one did. `check_continuation` already
/// refuses a refreshed map that changes covered history or its re-cut epoch,
/// so with a well-formed map this holds; it is checked again here because
/// resuming anywhere else would skip or repeat heights.
pub(super) fn check_resume(
    resumed: &zakura_transparent_private_shared::filter::ShardMapEntry,
    withdrawn: &zakura_transparent_private_shared::filter::ShardMapEntry,
) -> Result<(), String> {
    if resumed.start_height != withdrawn.start_height {
        return Err(format!(
            "it moves shard {} from height {} to {}",
            withdrawn.shard_id, withdrawn.start_height, resumed.start_height
        ));
    }
    Ok(())
}

/// Salt the wallet derives from a verified manifest. Records are accepted
/// only under this salt.
pub(super) fn tag_salt_of(manifest: &ShardManifest) -> Result<[u8; 32], SyncError> {
    let terminal = BlockHash::from_display_hex(&manifest.terminal_block_hash).map_err(|error| {
        SyncError::Invalid(format!(
            "shard {} terminal block hash: {error}",
            manifest.shard_id
        ))
    })?;
    Ok(zakura_transparent_private_shared::shard::tag_salt(
        manifest.shard_id,
        &terminal,
        manifest.tag_salt_counter,
    ))
}
