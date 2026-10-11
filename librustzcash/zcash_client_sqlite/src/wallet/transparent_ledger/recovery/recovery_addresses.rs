//! Select the transparent addresses an account must recover, extending derivation
//! windows from recorded activity and respecting production address ownership.
//! Build the recovery watch set with its captured wallet context and pending pages.

use super::*;

/// The derived scopes candidate windows extend, indexed by their `key_scope` code.
#[cfg(feature = "transparent-inputs")]
pub(super) const WINDOW_SCOPES: [TransparentKeyScope; 3] = [
    TransparentKeyScope::EXTERNAL,
    TransparentKeyScope::INTERNAL,
    TransparentKeyScope::EPHEMERAL,
];

/// One past the highest non-hardened child index.
#[cfg(feature = "transparent-inputs")]
pub(super) const WINDOW_LIMIT: u32 = 1 << 31;

#[cfg(feature = "transparent-inputs")]
fn scope_slot(scope: TransparentKeyScope) -> Option<usize> {
    WINDOW_SCOPES.iter().position(|s| *s == scope)
}

/// An account's addresses requiring history recovery, together with the
/// derivation-window bounds used to expand discovery.
#[cfg(feature = "transparent-inputs")]
pub(super) struct AccountRecoveryAddresses {
    pub(super) account: Account,
    pub(super) required_from: BlockHeight,
    pub(super) addresses: BTreeMap<TransparentAddress, WatchOrigin>,
    /// Derivation origins before ownership filtering, used only for gap expansion. A receiver
    /// owned by another account still supplies activity for its deriving key's window.
    window_origins: BTreeMap<TransparentAddress, WatchOrigin>,
    /// One past the highest index in the wallet's own address table, per window scope.
    pub(super) production_end: [u32; 3],
    /// The effective candidate window end, including activity recorded by other accounts.
    pub(super) candidate_end: [u32; 3],
    /// Whether the account's keys can derive further addresses, per window scope.
    pub(super) derivable: [bool; 3],
}

#[cfg(feature = "transparent-inputs")]
impl AccountRecoveryAddresses {
    /// Loads the addresses `account_uuid` must have recovered; `None` for an unknown account.
    ///
    /// The recovery address selection holds every address the wallet's address table assigns the account, its
    /// legacy external address, and the candidate window's addresses beyond them. The window
    /// is extended, without writing, until the account's mined candidate activity needs no
    /// further gap. Addresses another account owns in production stay in the window that
    /// drives gap expansion but are left out of the recovery address selection.
    pub(super) fn load<P: consensus::Parameters>(
        conn: &rusqlite::Connection,
        params: &P,
        gap_limits: &GapLimits,
        account_uuid: AccountUuid,
    ) -> Result<Option<Self>, SqliteClientError> {
        let Some(account) = get_account(conn, params, account_uuid)? else {
            return Ok(None);
        };
        let account_ref = account.internal_id();
        let mut addresses = BTreeMap::new();
        let mut production_end = [0u32; 3];
        let mut note_derived = |addresses: &mut BTreeMap<TransparentAddress, WatchOrigin>,
                                address: TransparentAddress,
                                scope: TransparentKeyScope,
                                index: NonHardenedChildIndex| {
            if let Some(slot) = scope_slot(scope) {
                production_end[slot] = production_end[slot].max(index.index() + 1);
            }
            note_origin(addresses, address, WatchOrigin::Derived { scope, index });
        };

        let mut stmt = conn.prepare_cached(
            "SELECT cached_transparent_receiver_address, key_scope, transparent_child_index
             FROM addresses
             WHERE account_id = :account_id
             AND cached_transparent_receiver_address IS NOT NULL",
        )?;
        let mut rows = stmt.query(named_params![":account_id": account_ref.0])?;
        while let Some(row) = rows.next()? {
            let encoded: String = row.get(0)?;
            let address = Address::decode(params, &encoded)
                .and_then(|a| a.to_transparent_address())
                .ok_or_else(|| {
                    SqliteClientError::CorruptedData(format!(
                        "invalid transparent receiver {encoded}"
                    ))
                })?;
            match KeyScope::decode(row.get(1)?)?.as_transparent() {
                Some(scope) => {
                    let index = row
                        .get::<_, Option<u32>>(2)?
                        .and_then(NonHardenedChildIndex::from_index)
                        .ok_or_else(|| {
                            SqliteClientError::CorruptedData(
                                "derived address without a valid child index".into(),
                            )
                        })?;
                    note_derived(&mut addresses, address, scope, index);
                }
                None => note_origin(&mut addresses, address, WatchOrigin::Standalone),
            }
        }
        // The legacy external address may have no address row.
        if let Some((address, index)) = get_legacy_transparent_address(params, conn, account_uuid)?
        {
            note_derived(
                &mut addresses,
                address,
                TransparentKeyScope::EXTERNAL,
                index,
            );
        }

        let mut candidate_end = [0u32; 3];
        let mut stmt = conn.prepare_cached(
            "SELECT key_scope, end_index FROM tpir_candidate_windows WHERE account_id = :account_id",
        )?;
        let mut rows = stmt.query(named_params![":account_id": account_ref.0])?;
        while let Some(row) = rows.next()? {
            let slot = usize::try_from(row.get::<_, i64>(0)?)
                .ok()
                .filter(|slot| *slot < WINDOW_SCOPES.len())
                .ok_or_else(|| {
                    SqliteClientError::CorruptedData("invalid candidate window scope".into())
                })?;
            candidate_end[slot] = u32::try_from(row.get::<_, i64>(1)?)
                .ok()
                .filter(|end| *end <= WINDOW_LIMIT)
                .ok_or_else(|| {
                    SqliteClientError::CorruptedData("invalid candidate window end".into())
                })?;
        }

        let derivable = WINDOW_SCOPES.map(|scope| derive(&account, scope, None).is_some());
        for (slot, scope) in WINDOW_SCOPES.into_iter().enumerate() {
            for index in production_end[slot]..candidate_end[slot] {
                let index = NonHardenedChildIndex::from_index(index).expect("below WINDOW_LIMIT");
                if let Some(address) = derive(&account, scope, Some(index)) {
                    addresses
                        .entry(address)
                        .or_insert(WatchOrigin::CandidateWindow { scope, index });
                }
            }
        }

        let required_from = account.birthday();
        let mut recovery_addresses = AccountRecoveryAddresses {
            account,
            required_from,
            window_origins: addresses.clone(),
            addresses,
            production_end,
            candidate_end,
            derivable,
        };
        // Activation retains only the indices it skipped, rather than re-deriving every address
        // below a possibly distant production_end. These origins confer no financial ownership.
        let mut stmt = conn.prepare_cached(
            "SELECT key_scope, child_index FROM tpir_shared_derivations WHERE account_id = ?1",
        )?;
        let mut rows = stmt.query([account_ref.0])?;
        while let Some(row) = rows.next()? {
            let scope = KeyScope::decode(row.get(0)?)?
                .as_transparent()
                .ok_or_else(|| {
                    SqliteClientError::CorruptedData("invalid shared derivation scope".into())
                })?;
            let index =
                NonHardenedChildIndex::from_index(row.get::<_, u32>(1)?).ok_or_else(|| {
                    SqliteClientError::CorruptedData("invalid shared derivation index".into())
                })?;
            let address =
                derive(&recovery_addresses.account, scope, Some(index)).ok_or_else(|| {
                    SqliteClientError::CorruptedData("underivable shared receiver".into())
                })?;
            note_origin(
                &mut recovery_addresses.window_origins,
                address,
                WatchOrigin::CandidateWindow { scope, index },
            );
        }
        // Activity at a receiver owned by another account can extend this account's discovery
        // window between commits. Derive the effective window before scheduling or checking
        // completeness; reads must not need an otherwise unnecessary commit to expose gaps.
        loop {
            let needs = recovery_addresses.window_needs(conn, gap_limits)?;
            let mut grew = false;
            for (slot, needed) in needs.into_iter().enumerate() {
                if let Some(end) = needed.filter(|_| recovery_addresses.derivable[slot]) {
                    let scope = WINDOW_SCOPES[slot];
                    let start = recovery_addresses.production_end[slot]
                        .max(recovery_addresses.candidate_end[slot]);
                    for index in start..end {
                        let index =
                            NonHardenedChildIndex::from_index(index).expect("below WINDOW_LIMIT");
                        if let Some(address) =
                            derive(&recovery_addresses.account, scope, Some(index))
                        {
                            recovery_addresses
                                .window_origins
                                .entry(address)
                                .or_insert(WatchOrigin::CandidateWindow { scope, index });
                        }
                    }
                    recovery_addresses.candidate_end[slot] = end;
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }
        recovery_addresses.addresses = recovery_addresses.window_origins.clone();
        ownership::retain_owned(conn, params, account_ref, &mut recovery_addresses.addresses)?;
        Ok(Some(recovery_addresses))
    }

    fn watched_addresses(&self) -> Vec<WatchedAddress> {
        self.addresses
            .iter()
            .map(|(address, origin)| WatchedAddress {
                address: *address,
                origin: *origin,
                required_from: self.required_from,
            })
            .collect()
    }

    /// The window end each scope needs for the account's mined candidate activity: one gap
    /// beyond the highest index with activity, where that exceeds the current window.
    pub(super) fn window_needs(
        &self,
        conn: &rusqlite::Connection,
        gap_limits: &GapLimits,
    ) -> Result<[Option<u32>; 3], SqliteClientError> {
        let mut stmt = conn.prepare_cached(
            "SELECT script FROM tpir_receive_events WHERE mined_height IS NOT NULL
             UNION
             SELECT prevout_script FROM tpir_spend_events WHERE mined_height IS NOT NULL",
        )?;
        let used = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<Result<BTreeSet<_>, _>>()?;
        let mut max_used: [Option<u32>; 3] = [None; 3];
        for (address, origin) in &self.window_origins {
            let (WatchOrigin::Derived { scope, index }
            | WatchOrigin::CandidateWindow { scope, index }) = origin
            else {
                continue;
            };
            if let Some(slot) = scope_slot(*scope)
                && used.contains(&script_bytes(address))
            {
                max_used[slot] =
                    Some(max_used[slot].map_or(index.index(), |m| m.max(index.index())));
            }
        }
        let mut needs = [None; 3];
        for (slot, scope) in WINDOW_SCOPES.into_iter().enumerate() {
            let (Some(used), Some(gap)) = (max_used[slot], gap_limits.limit_for(scope)) else {
                continue;
            };
            let needed = used.saturating_add(1).saturating_add(gap).min(WINDOW_LIMIT);
            if needed > self.production_end[slot].max(self.candidate_end[slot]) {
                needs[slot] = Some(needed);
            }
        }
        Ok(needs)
    }
}

/// Records why `address` is watched. A derivation outranks a standalone import of the same
/// receiver, so activity there still extends the derived window.
#[cfg(feature = "transparent-inputs")]
pub(super) fn note_origin(
    addresses: &mut BTreeMap<TransparentAddress, WatchOrigin>,
    address: TransparentAddress,
    origin: WatchOrigin,
) {
    let entry = addresses.entry(address).or_insert(origin);
    if *entry == WatchOrigin::Standalone {
        *entry = origin;
    }
}

/// Derives the address at `index` in `scope`, or with `index` absent, reports whether the
/// account's keys can derive the scope at all.
#[cfg(feature = "transparent-inputs")]
fn derive(
    account: &Account,
    scope: TransparentKeyScope,
    index: Option<NonHardenedChildIndex>,
) -> Option<TransparentAddress> {
    let probe = index.unwrap_or(NonHardenedChildIndex::ZERO);
    let pubkey = account.ufvk().and_then(|ufvk| ufvk.transparent());
    match scope {
        TransparentKeyScope::EXTERNAL => match pubkey {
            Some(pubkey) => pubkey
                .derive_external_ivk()
                .ok()?
                .derive_address(probe)
                .ok(),
            None => account
                .uivk()
                .transparent()
                .as_ref()?
                .derive_address(probe)
                .ok(),
        },
        TransparentKeyScope::INTERNAL => pubkey?
            .derive_internal_ivk()
            .ok()?
            .derive_address(probe)
            .ok(),
        TransparentKeyScope::EPHEMERAL => pubkey?
            .derive_ephemeral_ivk()
            .ok()?
            .derive_ephemeral_address(probe)
            .ok(),
        _ => None,
    }
}

#[cfg(feature = "transparent-inputs")]
fn pending_pages(
    conn: &rusqlite::Connection,
    account_ref: AccountRef,
) -> Result<Vec<PendingPage>, SqliteClientError> {
    let mut pages = conn.prepare_cached(
        "SELECT p.id, p.page, p.from_height, p.through_height, p.target_height, p.target_hash,
                r.source, r.revision, r.lineage, r.sealed, r.publication_height,
                r.publication_hash
         FROM tpir_pending_pages p
         JOIN tpir_revisions r ON r.id = p.revision_id
         WHERE p.account_id = :account_id
         ORDER BY p.id",
    )?;
    let mut scripts = conn.prepare_cached(
        "SELECT script FROM tpir_pending_page_scripts WHERE page_id = :page_id ORDER BY script",
    )?;
    let mut rows = pages.query(named_params![":account_id": account_ref.0])?;
    let mut result = vec![];
    while let Some(row) = rows.next()? {
        let page_id: i64 = row.get(0)?;
        let addresses = scripts
            .query_map(named_params![":page_id": page_id], |row| {
                row.get::<_, Vec<u8>>(0)
            })?
            .map(|script| address_from_script(script?))
            .collect::<Result<_, _>>()?;
        result.push(PendingPage {
            request: PageRequest {
                page: row.get(1)?,
                addresses,
                from: height(row.get(2)?),
                through: height(row.get(3)?),
            },
            target: ChainPoint {
                height: height(row.get(4)?),
                hash: read_hash(row.get(5)?)?,
            },
            revision: read_revision(row, 6)?,
        });
    }
    Ok(result)
}

/// Returns `account`'s watched addresses, capture context, and pending pages. The caller
/// provides the read snapshot.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn watch_set<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    gap_limits: &GapLimits,
    configured: Option<TransparentLedgerMode>,
    account: AccountUuid,
) -> Result<TransparentAddressWatchSet<AccountUuid>, SqliteClientError> {
    resolve_mode(conn, configured)?;
    let recovery_addresses = AccountRecoveryAddresses::load(conn, params, gap_limits, account)?
        .ok_or(SqliteClientError::AccountUnknown)?;
    Ok(TransparentAddressWatchSet {
        account,
        lifecycle: account_lifecycle(conn, recovery_addresses.account.internal_id())?,
        policy_generation: capture_policy_generation(conn)?,
        target: local_target(conn)?,
        addresses: recovery_addresses.watched_addresses(),
        pending_pages: pending_pages(conn, recovery_addresses.account.internal_id())?,
    })
}
