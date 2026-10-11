//! Production ownership wins over unprojected candidate derivation.
use super::*;
use crate::wallet::transparent::store_address_range;
use std::ops::Range;
use zcash_keys::keys::transparent::gap_limits::generate_address_list;

/// Whether an account other than `account` has a production address row for `address`.
fn owned_elsewhere<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account: AccountRef,
    address: &TransparentAddress,
) -> Result<bool, SqliteClientError> {
    let mut stmt = conn.prepare_cached(
        "SELECT EXISTS(SELECT 1 FROM addresses WHERE cached_transparent_receiver_address = ?1 AND account_id != ?2)",
    )?;
    Ok(stmt.query_row(
        rusqlite::params![Address::Transparent(*address).encode(params), account.0],
        |row| row.get::<_, bool>(0),
    )?)
}

/// Filter a derived watch without changing production address ownership or financial rows.
pub(super) fn retain_owned<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account: AccountRef,
    addresses: &mut BTreeMap<TransparentAddress, WatchOrigin>,
) -> Result<(), SqliteClientError> {
    let mut excluded = vec![];
    for address in addresses.keys() {
        if owned_elsewhere(conn, params, account, address)? {
            excluded.push(*address);
        }
    }
    for address in excluded {
        addresses.remove(&address);
    }
    Ok(())
}

/// Writes `account`'s derived addresses in `range` to the address table, except receivers another
/// account owns. The watch set excluded those receivers, so the account has no coverage for them,
/// and transferring one here would make activation refuse itself on every retry. The wallet's own
/// address generation, including gap-limit generation after a receive is projected, may still
/// transfer one under the existing rules; recovery then schedules it for its new owner.
pub(super) fn generate_unowned_range<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account: &Account,
    key_scope: TransparentKeyScope,
    range: Range<NonHardenedChildIndex>,
) -> Result<(), SqliteClientError> {
    let account_ref = account.internal_id();
    let mut unowned = vec![];
    for entry in generate_address_list(
        &account.uivk(),
        account.ufvk(),
        key_scope,
        UnifiedAddressRequest::unsafe_custom(Allow, Allow, Require),
        range,
        false,
    )? {
        if owned_elsewhere(conn, params, account_ref, &entry.1)? {
            // Materialization can move production_end beyond this receiver. Keep its origin
            // independently of ownership, so later activity still expands the deriving window.
            conn.execute(
                "INSERT OR IGNORE INTO tpir_shared_derivations (account_id, key_scope, child_index)
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![
                    account_ref.0,
                    KeyScope::try_from(key_scope)?.encode(),
                    entry.2.index()
                ],
            )?;
            super::super::require_reader_version(
                conn,
                super::super::SHARED_DERIVATION_READER_VERSION,
            )?;
        } else {
            unowned.push(entry);
        }
    }
    store_address_range(conn, params, account_ref, key_scope, unowned)
}

/// Adds recovered addresses to the wallet under production ownership rules. Shared derivations
/// remain discovery metadata; an ownerless retained receiver can become this account's address again.
/// Runs inside activation or an active commit's transaction, never during candidate recovery.
pub(super) fn materialize_recovery_addresses<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    recovery_addresses: &AccountRecoveryAddresses,
) -> Result<(), SqliteClientError> {
    for (slot, scope) in WINDOW_SCOPES.into_iter().enumerate() {
        let (start, end) = (
            recovery_addresses.production_end[slot],
            recovery_addresses.candidate_end[slot],
        );
        if start < end {
            let end = NonHardenedChildIndex::from_index(end).ok_or_else(|| {
                SqliteClientError::TransparentActivationBlocked(vec![RecoveryBlocker::Recovery(
                    CandidateBlocker::WindowUnderivable,
                )])
            })?;
            generate_unowned_range(
                conn,
                params,
                &recovery_addresses.account,
                scope,
                NonHardenedChildIndex::from_index(start).expect("start below end")..end,
            )?;
        }
    }
    // Retained shared receivers below production_end can lose their other owner (for example,
    // on account deletion). Make them projectable only once they are in this account's watch.
    for origin in recovery_addresses.addresses.values() {
        if let WatchOrigin::CandidateWindow { scope, index } = origin
            && index.index()
                < recovery_addresses.production_end[WINDOW_SCOPES
                    .iter()
                    .position(|s| s == scope)
                    .expect("window scope")]
            && let Some(end) = index
                .index()
                .checked_add(1)
                .and_then(NonHardenedChildIndex::from_index)
        {
            generate_unowned_range(
                conn,
                params,
                &recovery_addresses.account,
                *scope,
                *index..end,
            )?;
        }
    }
    if let Some((_, index)) =
        get_legacy_transparent_address(params, conn, recovery_addresses.account.id())?
        && let Some(end) = index
            .index()
            .checked_add(1)
            .and_then(NonHardenedChildIndex::from_index)
    {
        generate_unowned_range(
            conn,
            params,
            &recovery_addresses.account,
            TransparentKeyScope::EXTERNAL,
            index..end,
        )?;
    }
    Ok(())
}

/// A standalone import is a production ownership change. Remove only competing candidate
/// facts in the same transaction; active receivers already have production address rows.
#[cfg(feature = "transparent-key-import")]
pub(crate) fn forget_other_candidates(
    conn: &rusqlite::Connection,
    owner: AccountRef,
    address: &TransparentAddress,
) -> Result<(), SqliteClientError> {
    let installed: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'tpir_active_accounts')", [], |row| row.get(0))?;
    if !installed {
        return Ok(());
    }
    let mut stmt = conn.prepare_cached("SELECT id FROM accounts WHERE id != ?1 AND NOT EXISTS (SELECT 1 FROM tpir_active_accounts a WHERE a.account_id = accounts.id)")?;
    let accounts = stmt
        .query_map([owner.0], |row| row.get::<_, i64>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    for account in accounts {
        lifecycle::forget_reattributed_script(conn, AccountRef(account), address)?;
    }
    Ok(())
}
