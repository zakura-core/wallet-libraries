//! Exact-block key selection and commit-time admission fences for ordinary scanning.
use super::{
    Discovery, KeyId, account_key, block_recovery, invalid, key_by_id, register, stored_key_id,
};
use crate::{AccountUuid, SqlTransaction, SqliteClientError, WalletDb, util::Clock};
use rand_core::Rng;
use rusqlite::{OptionalExtension, Transaction, params};
use std::{borrow::BorrowMut, collections::HashMap};
use zcash_client_backend::data_api::{
    ScannedBlock,
    chain::ChainState,
    one_time_ivk::recovery::{BlockScan, OneTimeBlockScan, ScanPermit},
    transparent_ledger::ChainPoint,
};
use zcash_protocol::consensus::Parameters;

/// Selects discovery separately from known-note repair, preserving the setting's generation.
pub(crate) fn prepare<P: Parameters>(
    conn: &Transaction<'_>,
    params: &P,
    block: ChainPoint,
    ready: &[(AccountUuid, KeyId)],
    now: i64,
) -> Result<BlockScan<AccountUuid>, SqliteClientError> {
    if now < 0 || ready.len() > 1024 {
        return Err(invalid("invalid block scan work"));
    }
    let mut selected = HashMap::<(AccountUuid, KeyId), bool>::new();
    for (account, ufvk) in super::super::get_unified_full_viewing_keys(conn, params)? {
        if ufvk.orchard().is_none() {
            continue;
        }
        let (owner, _) = account_key(conn, params, account)?;
        let state = block_recovery::state(conn, params, account)?;
        // Re-mining and restoring retained witnesses remain ordinary wallet maintenance.
        let known=conn.prepare("SELECT DISTINCT k.purpose,k.key_index FROM ironwood_one_time_keys k JOIN ironwood_received_notes n ON n.one_time_key_id=k.id JOIN transactions t ON t.id_tx=n.transaction_id WHERE k.account_id=?1 AND (t.mined_height IS NULL OR t.mined_height=?2)")?.query_and_then(params![owner.0,u32::from(block.height)],stored_key_id)?.collect::<Result<Vec<_>,_>>()?;
        for key in known {
            selected.insert((account, key), false);
        }
        if !state.is_some_and(|s| s.enabled) {
            continue;
        }
        let watched = conn
            .prepare(&format!(
                "SELECT k.purpose,k.key_index FROM ironwood_one_time_keys k
             WHERE k.account_id=?1 AND {}",
                block_recovery::LOCAL_WATCH,
            ))?
            .query_and_then(
                params![owner.0, u32::from(block.height), now],
                stored_key_id,
            )?
            .collect::<Result<Vec<_>, _>>()?;
        for key in watched {
            selected.insert((account, key), true);
        }
        let pending=conn.prepare("SELECT purpose,key_index FROM ironwood_block_matches WHERE account_id=?1 AND height=?2 AND hash=?3 ORDER BY purpose,key_index LIMIT 1024")?
            .query_and_then(params![owner.0,u32::from(block.height),block.hash.0],stored_key_id)?.collect::<Result<Vec<_>,_>>()?;
        for key in pending.into_iter().chain(
            ready
                .iter()
                .filter_map(|(a, key)| (*a == account).then_some(*key)),
        ) {
            let receiver:Option<Vec<u8>>=conn.query_row("SELECT receiver FROM ironwood_block_receivers WHERE account_id=?1 AND purpose=?2 AND key_index=?3",params![owner.0,super::purpose_code(key.purpose())?,key.index().to_be_bytes()],|r|r.get(0)).optional()?;
            if receiver.is_none() {
                return Err(invalid("scan hint outside prepared receivers"));
            }
            register(
                conn,
                params,
                account,
                key,
                block.height,
                false,
                Discovery::Filter,
                now,
            )?;
            selected.insert((account, key), true);
        }
    }
    let mut keys = Vec::with_capacity(selected.len());
    let mut permits = Vec::new();
    for ((account, key), discovery) in selected {
        let id = super::key_ref(conn, account, key)?;
        keys.push(key_by_id(conn, params, account, id)?.scanning_key);
        if discovery {
            let state =
                block_recovery::state(conn, params, account)?.expect("enabled selection has state");
            permits.push(ScanPermit {
                account,
                key,
                work: state.work,
            });
        }
    }
    Ok(BlockScan {
        block,
        keys,
        permits,
    })
}

/// Commits ordinary scanning while rejecting discoveries whose captured permit expired.
impl<C: BorrowMut<rusqlite::Connection>, P: Parameters, CL: Clock, R: Rng> OneTimeBlockScan
    for WalletDb<C, P, CL, R>
{
    /// Captures exact-block keys in a short storage transaction without any network wait.
    fn prepare_one_time_block_scan(
        &mut self,
        block: ChainPoint,
        ready: &[(AccountUuid, KeyId)],
    ) -> Result<BlockScan<AccountUuid>, SqliteClientError> {
        self.transactionally(|db| {
            prepare(
                db.conn.0,
                &db.params,
                block,
                ready,
                super::unix_now(&db.clock),
            )
        })
    }
    /// Keeps ordinary scan progress atomic with filtered receipts and accepted scan evidence.
    fn put_blocks_with_recovery(
        &mut self,
        from_state: &ChainState,
        blocks: Vec<ScannedBlock<AccountUuid>>,
        scanned: &[BlockScan<AccountUuid>],
    ) -> Result<(), SqliteClientError> {
        self.transactionally(|db| {
            db.store_scanned_blocks_impl(from_state, blocks, Some(&[]), Some(scanned))
        })
    }
}

/// Applies current per-key permits and preserves known authenticated notes when they are stale.
pub(crate) fn fence<P: Parameters, CL, R>(
    db: &WalletDb<SqlTransaction<'_>, P, CL, R>,
    blocks: &mut [ScannedBlock<AccountUuid>],
    scanned: &[BlockScan<AccountUuid>],
) -> Result<Vec<Vec<(AccountUuid, KeyId)>>, SqliteClientError> {
    if blocks.len() != scanned.len() {
        return Err(invalid("scan plan block count differs"));
    }
    let mut accepted = Vec::with_capacity(blocks.len());
    let mut refused_nullifiers = std::collections::HashSet::new();
    for (block, scan) in blocks.iter_mut().zip(scanned) {
        if block.height() != scan.block.height || block.block_hash() != scan.block.hash {
            return Err(invalid("scan plan block identity differs"));
        }
        let mut valid = Vec::new();
        for permit in &scan.permits {
            if !scan
                .keys
                .iter()
                .any(|key| *key.account_id() == permit.account && key.key_id() == permit.key)
            {
                return Err(invalid("scan permit lacks selected key"));
            }
            if block_recovery::state(db.conn.0, &db.params, permit.account)?
                .is_some_and(|state| state.enabled && state.work == permit.work)
            {
                valid.push((permit.account, permit.key));
            }
        }
        block.retain_one_time_receipts(|_txid, output| -> Result<bool, SqliteClientError> {
            let key = output.one_time_key_id().expect("one-time receipt");
            if valid.contains(&(*output.account_id(), key)) {
                return Ok(true);
            }
            let known = known_receipt(
                db.conn.0,
                *output.account_id(),
                key,
                output.nf().map(|nf| nf.to_bytes()),
                &output.note().0,
            )?;
            if !known && let Some(nf) = output.nf() {
                refused_nullifiers.insert((*output.account_id(), nf.to_bytes()));
            }
            Ok(known)
        })?;
        accepted.push(valid);
    }
    for block in blocks {
        block.retain_ironwood_spends(|spend| {
            !refused_nullifiers.contains(&(*spend.account_id(), spend.nf().to_bytes()))
        });
    }
    Ok(accepted)
}

/// Matches authenticated note identity, never directory transaction labels. Full-transaction
/// receipts may lack a nullifier until compact scanning, so compare their plaintext too.
pub(crate) fn known_receipt(
    conn: &rusqlite::Connection,
    account: AccountUuid,
    key: KeyId,
    nf: Option<[u8; 32]>,
    note: &orchard::Note,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_received_notes n
        JOIN ironwood_one_time_keys k ON k.id=n.one_time_key_id AND k.account_id=n.account_id
        JOIN accounts a ON a.id=k.account_id
        WHERE a.uuid=?2 AND k.purpose=?3 AND k.key_index=?4
        AND (n.nf=?1 OR (n.nf IS NULL AND n.rho=?5 AND n.rseed=?6 AND n.value=?7
            AND n.diversifier=?8 AND n.note_version=3)))",
        params![
            nf,
            account.0,
            super::purpose_code(key.purpose())?,
            key.index().to_be_bytes(),
            note.rho().to_bytes(),
            note.rseed().as_bytes(),
            note.value().inner(),
            note.recipient().diversifier().as_array(),
        ],
        |r| r.get::<_, bool>(0),
    )?)
}
