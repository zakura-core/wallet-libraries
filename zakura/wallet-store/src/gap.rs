//! Transparent address discovery, and the gap limit that bounds it.
//!
//! A wallet cannot ask a light server "which of my addresses were used" without
//! naming them, so it watches a window of addresses ahead of the ones it has
//! handed out, and widens the window as they get used. The width of that window
//! is the gap limit.
//!
//! The limits here are **below BIP 44's twenty**, deliberately. A light server
//! sees every address a wallet asks about together, and can cluster them into
//! one wallet on that basis alone. Every extra address in the window is another
//! address in that cluster, so the window is kept as narrow as discovery
//! tolerates rather than as wide as convention suggests. The fork documents the
//! same reasoning for the same numbers.

use rusqlite::named_params;
use zakura_wallet_core::{AccountId, KeyScope};

use crate::{error::Error, schema::CACHE_SCHEMA};

/// How many unused addresses the wallet keeps ahead of the used ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GapLimits {
    /// For addresses handed out to other people.
    pub external: u32,
    /// For addresses the wallet pays itself.
    ///
    /// Narrower than external, because only the wallet ever uses them: nobody
    /// else can pay an address they were never given.
    pub internal: u32,
    /// For the single-use addresses of a ZIP 320 payment.
    pub ephemeral: u32,
}

impl Default for GapLimits {
    fn default() -> Self {
        // Not BIP 44's twenty. See the module documentation: every address in
        // the window is one more address a server can cluster into this wallet.
        Self {
            external: 10,
            internal: 5,
            ephemeral: 10,
        }
    }
}

impl GapLimits {
    /// Returns the limit for a scope.
    pub fn for_scope(&self, scope: KeyScope) -> u32 {
        match scope {
            KeyScope::External => self.external,
            KeyScope::Internal => self.internal,
        }
    }
}

/// The `key_scope` code of a transparent script the user imported.
///
/// Not a derivation scope: nothing derives an imported script, no gap limit
/// applies to it, and no key of this wallet can spend from it. It lives in the
/// address table so a recovered output at it resolves to an account, under a
/// code the gap-limit queries never select. Codes 0 and 1 are the derivation
/// scopes and 2 is reserved for ZIP 320 ephemeral addresses.
pub const IMPORTED_SCOPE_CODE: u8 = 3;

/// Where an account's addresses currently stand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GapState {
    /// The highest index that has actually received something.
    pub highest_used: Option<u32>,
    /// The highest index the wallet is watching.
    pub highest_known: Option<u32>,
    /// How many unused addresses remain ahead of the used ones.
    pub remaining: u32,
}

impl GapState {
    /// Returns whether the window has been consumed and must be widened.
    ///
    /// If it has, the wallet is watching a range that no longer extends far
    /// enough past its used addresses, and a payment to one it has not
    /// generated would go unseen.
    pub fn needs_widening(&self, limit: u32) -> bool {
        self.remaining < limit
    }
}

/// Returns where an account's addresses stand in a scope.
pub(crate) fn state(
    conn: &rusqlite::Connection,
    account: AccountId,
    scope: KeyScope,
) -> Result<GapState, Error> {
    // "Used" means an output was actually received at the address, not that the
    // wallet generated it. Generating an address costs nothing and reveals
    // nothing; being paid at one is what obliges the wallet to look further.
    let (highest_used, highest_known): (Option<u32>, Option<u32>) = conn.query_row(
        &format!(
            "SELECT
                (SELECT MAX(a.transparent_child_index)
                 FROM {CACHE_SCHEMA}.addresses a
                 JOIN {CACHE_SCHEMA}.transparent_received_outputs o
                    ON o.address_id = a.id
                 JOIN {CACHE_SCHEMA}.transactions t ON t.id = o.transaction_id
                 WHERE a.account_id = :account AND a.key_scope = :scope
                   -- Mined, not merely seen. A transaction in the mempool may
                   -- never be mined, and letting one advance the window would
                   -- let anybody who can put a payment in the mempool push the
                   -- wallet's addresses forward.
                   AND t.mined_height IS NOT NULL),
                (SELECT MAX(transparent_child_index) FROM {CACHE_SCHEMA}.addresses
                 WHERE account_id = :account AND key_scope = :scope)"
        ),
        named_params![":account": account.0, ":scope": scope.code()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;

    let remaining = match (highest_used, highest_known) {
        (_, None) => 0,
        (None, Some(known)) => known + 1,
        (Some(used), Some(known)) => known.saturating_sub(used),
    };

    Ok(GapState {
        highest_used,
        highest_known,
        remaining,
    })
}

/// Returns the address indices that must be generated to restore the gap.
///
/// Returned rather than generated here, because deriving an address needs the
/// account's viewing key and this module owns only the bookkeeping. An empty
/// result means the window is already wide enough.
pub(crate) fn indices_to_generate(
    conn: &rusqlite::Connection,
    account: AccountId,
    scope: KeyScope,
    limits: &GapLimits,
) -> Result<Vec<u32>, Error> {
    let limit = limits.for_scope(scope);
    let state = state(conn, account, scope)?;

    if !state.needs_widening(limit) {
        return Ok(Vec::new());
    }

    let first = state.highest_known.map_or(0, |k| k + 1);
    let last = state.highest_used.map_or(limit - 1, |used| used + limit);

    Ok((first..=last).collect())
}

/// Records that an address at `index` is being watched.
pub(crate) fn record_address(
    conn: &rusqlite::Transaction<'_>,
    account: AccountId,
    scope: KeyScope,
    index: u32,
    address: &str,
    script: &[u8],
) -> Result<(), Error> {
    record_address_in_scope(conn, account, scope.code(), index, address, script)
}

/// Records an imported script at the next free index of the imported scope.
///
/// The index has no meaning beyond keeping the row unique; nothing derives
/// from it and no window is measured against it.
pub(crate) fn record_imported(
    conn: &rusqlite::Transaction<'_>,
    account: AccountId,
    address: &str,
    script: &[u8],
) -> Result<(), Error> {
    let next: u32 = conn.query_row(
        &format!(
            "SELECT COALESCE(MAX(transparent_child_index) + 1, 0)
             FROM {CACHE_SCHEMA}.addresses
             WHERE account_id = :account AND key_scope = :scope"
        ),
        named_params![":account": account.0, ":scope": IMPORTED_SCOPE_CODE],
        |row| row.get(0),
    )?;
    record_address_in_scope(conn, account, IMPORTED_SCOPE_CODE, next, address, script)
}

fn record_address_in_scope(
    conn: &rusqlite::Transaction<'_>,
    account: AccountId,
    scope: u8,
    index: u32,
    address: &str,
    script: &[u8],
) -> Result<(), Error> {
    conn.execute(
        &format!(
            "INSERT INTO {CACHE_SCHEMA}.addresses
                (account_id, key_scope, diversifier_index_be, transparent_child_index,
                 transparent_address, transparent_script)
             VALUES (:account, :scope, :index_be, :index, :address, :script)
             ON CONFLICT (account_id, key_scope, diversifier_index_be) DO UPDATE SET
                transparent_child_index = :index,
                transparent_address = :address,
                transparent_script = :script"
        ),
        named_params![
            ":account": account.0,
            ":scope": scope,
            // The same eleven-byte big-endian encoding accounts.rs uses. These
            // two writers share a uniqueness constraint, so encoding the same
            // index differently — which they did — makes the unified address
            // and its transparent receiver two rows that can never be joined.
            ":index_be": crate::accounts::encode_diversifier_index(
                zip32::DiversifierIndex::from(index),
            ),
            ":index": index,
            ":address": address,
            ":script": script,
        ],
    )?;
    Ok(())
}

/// Records that an address was used on chain at `height`.
///
/// Lowers `exposed_at_height` rather than setting it, because a reorg can
/// re-mine the same transaction lower and the earliest height an address was
/// visible is the one that matters. Overwriting would quietly move an address's
/// exposure later than it really was.
pub(crate) fn observe_use(
    conn: &rusqlite::Transaction<'_>,
    address_id: i64,
    height: zcash_protocol::consensus::BlockHeight,
) -> Result<(), Error> {
    conn.execute(
        &format!(
            "UPDATE {CACHE_SCHEMA}.addresses
             SET exposed_at_height = MIN(IFNULL(exposed_at_height, :height), :height)
             WHERE id = :id"
        ),
        named_params![":id": address_id, ":height": u32::from(height)],
    )?;
    Ok(())
}
