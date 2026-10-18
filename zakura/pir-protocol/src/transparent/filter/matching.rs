//! Local matching of wallet scripts against a validated filter.
//!
//! Matching is entirely local. The wallet's script list is never sent to the
//! server, and a range request never carries script, address or match
//! information.

use crate::transparent::filter::error::FilterError;
use crate::transparent::filter::hash::{BlockHash, FilterKeys, ShardKey};
use crate::transparent::filter::script::ScriptBytes;
use crate::transparent::filter::validate::ValidatedFilter;
use bitcoin_hashes::siphash24;

/// Maps a SipHash output into `[0, nm)` by taking the high 64 bits of the
/// 128-bit product, as BIP 158 specifies.
fn map_to_range(hash: u64, nm: u64) -> u64 {
    ((u128::from(hash) * u128::from(nm)) >> 64) as u64
}

/// Returns the indices of **every** wallet script that matches the filter.
///
/// A boolean would be insufficient: the caller needs the identities of the
/// matching scripts to decide which private lookups to run.
///
/// A match is not proof of activity. BIP 158 filters have false positives by
/// construction, so a match means "fetch and check exactly", and a script that
/// is absent from the block can still match. Callers must resolve every match
/// against real data; a false positive may only ever cost extra work, never
/// fabricate a payment or a balance change.
///
/// An empty wallet list returns an empty result — after the filter has been
/// validated, so a malformed filter is still reported as an error rather than
/// silently passing as "nothing matched".
pub fn match_scripts(
    filter: &ValidatedFilter,
    block_hash: BlockHash,
    wallet_scripts: &[ScriptBytes],
) -> Result<Vec<usize>, FilterError> {
    match_keyed(filter, block_hash.filter_keys(), wallet_scripts)
}

/// [`match_scripts`] for a shard filter, under the range profile's keying.
pub fn match_range_scripts(
    filter: &ValidatedFilter,
    shard_key: ShardKey,
    wallet_scripts: &[ScriptBytes],
) -> Result<Vec<usize>, FilterError> {
    match_keyed(filter, shard_key.filter_keys(), wallet_scripts)
}

/// Matching under keys the caller has already derived.
///
/// The keying is the only thing that differs between profiles, so both public
/// entry points land here. Taking [`FilterKeys`] rather than a hash keeps it
/// impossible to match a filter under keys that no profile produces.
pub fn match_keyed(
    filter: &ValidatedFilter,
    keys: FilterKeys,
    wallet_scripts: &[ScriptBytes],
) -> Result<Vec<usize>, FilterError> {
    match_mapped(
        filter,
        &map_wallet_scripts_keyed(filter, keys, wallet_scripts),
    )
}

/// The wallet's scripts mapped into this filter's range, paired with their
/// original indices.
///
/// Exposed so a caller syncing many blocks can hash its script set once per
/// block instead of once per script per block.
pub fn map_wallet_scripts(
    filter: &ValidatedFilter,
    block_hash: BlockHash,
    wallet_scripts: &[ScriptBytes],
) -> Vec<(u64, usize)> {
    map_wallet_scripts_keyed(filter, block_hash.filter_keys(), wallet_scripts)
}

/// [`map_wallet_scripts`] under keys the caller has already derived.
///
/// A wallet syncing many shards hashes its script set once per shard, which is
/// where the saving is: the per-shard cost is one pass over the wallet's
/// scripts, not one pass per block in the shard's range.
pub fn map_wallet_scripts_keyed(
    filter: &ValidatedFilter,
    keys: FilterKeys,
    wallet_scripts: &[ScriptBytes],
) -> Vec<(u64, usize)> {
    let FilterKeys { k0, k1 } = keys;
    let range = filter.range();
    let mut mapped: Vec<(u64, usize)> = wallet_scripts
        .iter()
        .enumerate()
        .filter(|(_, script)| !script.is_empty())
        .map(|(index, script)| {
            let hash = siphash24::Hash::hash_to_u64_with_keys(k0, k1, script.as_slice());
            (map_to_range(hash, range), index)
        })
        .collect();
    mapped.sort_unstable();
    mapped
}

/// Merges pre-mapped wallet values against the filter's sorted value set.
pub fn match_mapped(
    filter: &ValidatedFilter,
    mapped: &[(u64, usize)],
) -> Result<Vec<usize>, FilterError> {
    let values = filter.values();
    let mut matches = Vec::new();
    let mut cursor = 0usize;
    for (value, index) in mapped {
        while cursor < values.len() && values[cursor] < *value {
            cursor += 1;
        }
        // Do not advance past an equal value: several wallet scripts may map to
        // the same filter value, and each of them matches.
        if cursor < values.len() && values[cursor] == *value {
            matches.push(*index);
        }
    }
    matches.sort_unstable();
    Ok(matches)
}
