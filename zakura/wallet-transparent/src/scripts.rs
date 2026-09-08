//! Which scripts to ask about, and where each has already been read to.
//!
//! Filter elements are raw locking scripts. Not addresses, not address text,
//! not hashes of either: the exact `scriptPubKey` bytes as they appear in the
//! block, which is also the key a recovered event is stored under. The wallet
//! stores that form already, so nothing is re-derived or re-encoded here — the
//! two sides agreeing on an encoding is a class of bug this avoids by not
//! having two sides.
//!
//! Coverage is per script, and the grouping below is why. A script the wallet
//! derived yesterday has no coverage over the chain before yesterday. An
//! account-wide start height would either re-read everything whenever the
//! address window widened, or hand a new script the coverage its siblings
//! earned — and the second is invisible, because a script with no history and a
//! script that was never looked for return the same empty answer.

use std::collections::BTreeMap;

use transparent_filter::ScriptBytes;
use zakura_wallet_core::AccountId;
use zcash_protocol::consensus::BlockHeight;

use crate::Error;

/// The scripts of one account, grouped by where reading must start.
#[derive(Debug, Clone, Default)]
pub struct WatchedScripts {
    /// Groups of scripts that share a start height, keyed by that height.
    pub groups: BTreeMap<u64, Vec<ScriptBytes>>,
    /// Scripts longer than the private tables index.
    ///
    /// Carried rather than dropped. Such a script can still match a filter and
    /// will still have no directory entry, and reading that miss as "no
    /// history" would be wrong in the direction that hides funds.
    pub outside_coverage: Vec<ScriptBytes>,
}

impl WatchedScripts {
    /// Whether there is nothing to ask about.
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// How many scripts are covered by the private tables.
    pub fn covered(&self) -> usize {
        self.groups.values().map(Vec::len).sum()
    }
}

/// Reads one account's watched scripts and groups them by start height.
///
/// The start height for a script is one above where its coverage reaches, and
/// coverage for a script never read is one below the account's birthday, so a
/// fresh account produces a single group at its birthday.
pub fn watched_scripts(
    db: &zakura_wallet_store::WalletDb,
    account: AccountId,
    birthday: BlockHeight,
) -> Result<WatchedScripts, Error> {
    let mut out = WatchedScripts::default();

    for coverage in db.transparent_coverage(account, birthday)? {
        let script = ScriptBytes::new(coverage.script);
        if script.as_slice().len() > transparent_shard::MAX_SCRIPT_BYTES {
            out.outside_coverage.push(script);
            continue;
        }
        // An empty or `OP_RETURN` script is not in any filter, so asking about
        // one costs a query that can never match.
        if !script.is_filter_element() {
            continue;
        }
        let start = u64::from(u32::from(coverage.covered_through)) + 1;
        // Never below where coverage begins: a start under it would make the
        // run report coverage over a range no shard describes.
        let start = start.max(crate::START_HEIGHT);
        out.groups.entry(start).or_default().push(script);
    }

    Ok(out)
}
