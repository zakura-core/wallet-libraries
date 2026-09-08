//! Which scripts to ask about, and from which height each.
//!
//! Filter elements are raw locking scripts. Not addresses, not address text,
//! not hashes of either: the exact `scriptPubKey` bytes as they appear in the
//! block, which is also the key a recovered event is stored under. The wallet
//! stores that form already, so nothing is re-derived or re-encoded here — the
//! two sides agreeing on an encoding is a class of bug this avoids by not
//! having two sides.
//!
//! Each script carries the first height the wallet needs it covered from: its
//! account's birthday, or the first height the published set covers if that is
//! later.
//! The library keeps that height per script and never raises it, which is what
//! lets a script the gap limit only just reached be read over the whole range
//! its siblings were, rather than inheriting coverage it never earned.

use std::collections::BTreeMap;

use transparent_filter::ScriptBytes;
use transparent_wallet::{ScriptEntry, ScriptOrigin};
use zakura_wallet_core::AccountId;
use zakura_wallet_store::WalletDb;
use zcash_protocol::consensus::Parameters;

use crate::Error;

/// The wallet's scripts, as the library wants them.
#[derive(Debug, Clone, Default)]
pub struct WatchedScripts {
    /// Every script the ledger is asked about, with its required height.
    pub entries: Vec<ScriptEntry>,
    /// Which account each of them belongs to.
    pub owners: BTreeMap<Vec<u8>, AccountId>,
    /// How many scripts are longer than the private tables index.
    ///
    /// Counted rather than dropped silently. Such a script can still match a
    /// filter and will still have no directory entry, and reading that miss as
    /// "no history" would be wrong in the direction that hides funds. The
    /// interface says they exist; it does not say they are empty.
    pub outside_coverage: usize,
}

impl WatchedScripts {
    /// Whether there is nothing to ask about.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Reads every account's watched scripts with the height each needs.
///
/// Every account at once, because the store is one ledger over one set and
/// the library's coverage is per script rather than per account; which account
/// a recovered output belongs to is settled when it is projected, by the
/// address it was paid to. `set_start` is the first height the published set
/// covers: a birthday below it is clamped there, because a run that started
/// lower would report coverage over a range no shard describes.
pub fn watched_scripts<P: Parameters>(
    db: &WalletDb,
    params: &P,
    set_start: u64,
) -> Result<WatchedScripts, Error> {
    let birthdays: BTreeMap<AccountId, u64> = db
        .accounts(params)?
        .into_iter()
        .map(|account| (account.id, u64::from(u32::from(account.birthday))))
        .collect();

    let mut out = WatchedScripts::default();
    for watched in db.transparent_watch()?.addresses {
        let script = ScriptBytes::new(watched.script);
        if script.as_slice().len() > transparent_shard::MAX_SCRIPT_BYTES {
            out.outside_coverage += 1;
            continue;
        }
        // An empty or `OP_RETURN` script is not in any filter, so asking about
        // one costs a query that can never match.
        if !script.is_filter_element() {
            continue;
        }
        let Some(birthday) = birthdays.get(&watched.account) else {
            // An address whose account is gone is not the ledger's to ask
            // about; the address row is stale, and the balance it could feed
            // has no owner to be shown to.
            continue;
        };
        let bytes = script.as_slice().to_vec();
        out.owners.insert(bytes.clone(), watched.account);
        out.entries.push(ScriptEntry {
            script: bytes,
            origin: ScriptOrigin::Derived,
            required_from: (*birthday).max(set_start),
        });
    }
    Ok(out)
}
