//! Full-transaction discovery selection and storage fences.
use super::{account_key, block_recovery, block_scan, key_by_id, key_ref, stored_key_id};
use crate::{AccountUuid, SqliteClientError, WalletDb, util::Clock};
use rand_core::Rng;
use rusqlite::{OptionalExtension, Transaction, params};
use std::borrow::BorrowMut;
use zcash_client_backend::data_api::{
    DecryptedTransaction,
    one_time_ivk::recovery::{OneTimeTransactionScan, ScanPermit, TransactionScan},
    transparent_ledger::ChainPoint,
};
use zcash_primitives::{block::BlockHash, transaction::Transaction as ZcashTransaction};
use zcash_protocol::{
    TxId,
    consensus::{BlockHeight, Parameters},
};

/// Captures exact mined-block hints or current local watches, plus known receipt repair.
pub(crate) fn prepare<P: Parameters>(
    conn: &Transaction<'_>,
    params: &P,
    txid: TxId,
    height: Option<BlockHeight>,
    now: i64,
) -> Result<TransactionScan<AccountUuid>, SqliteClientError> {
    let block = height
        .map(|height| -> Result<_, SqliteClientError> {
            conn.query_row(
                "SELECT hash FROM blocks WHERE height=?1",
                [u32::from(height)],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|hash| -> Result<_, SqliteClientError> {
                Ok(ChainPoint {
                    height,
                    hash: BlockHash(
                        hash.try_into()
                            .map_err(|_| super::corrupt("invalid stored block hash"))?,
                    ),
                })
            })
            .transpose()
        })
        .transpose()?
        .flatten();
    let mut scan = if let Some(block) = block {
        let selected = block_scan::prepare(conn, params, block, &[], now)?;
        TransactionScan {
            keys: selected.keys,
            permits: selected.permits,
        }
    } else {
        TransactionScan {
            keys: Vec::new(),
            permits: Vec::new(),
        }
    };
    let watch_height = height.or(super::super::chain_tip_height(conn)?
        .map(|h| BlockHeight::from(u32::from(h).saturating_add(1))));
    for (account, ufvk) in super::super::get_unified_full_viewing_keys(conn, params)? {
        if ufvk.orchard().is_none() {
            continue;
        }
        let (owner, _) = account_key(conn, params, account)?;
        let known = conn.prepare("SELECT DISTINCT k.purpose,k.key_index FROM ironwood_one_time_keys k JOIN ironwood_received_notes n ON n.one_time_key_id=k.id JOIN transactions t ON t.id_tx=n.transaction_id WHERE k.account_id=?1 AND t.txid=?2")?
            .query_and_then(params![owner.0,txid.as_ref()], stored_key_id)?.collect::<Result<Vec<_>,_>>()?;
        let mut selected = known.into_iter().map(|key| (key, None)).collect::<Vec<_>>();
        if block.is_none()
            && let Some(height) = watch_height
            && let Some(state) = block_recovery::state(conn, params, account)?.filter(|s| s.enabled)
        {
            let watched = conn.prepare(&format!("SELECT k.purpose,k.key_index FROM ironwood_one_time_keys k WHERE k.account_id=?1 AND {}",block_recovery::LOCAL_WATCH))?
                .query_and_then(params![owner.0,u32::from(height),now],stored_key_id)?.collect::<Result<Vec<_>,_>>()?;
            selected.extend(watched.into_iter().map(|key| (key, Some(state.work))));
        }
        for (key, work) in selected {
            if !scan
                .keys
                .iter()
                .any(|k| *k.account_id() == account && k.key_id() == key)
            {
                scan.keys.push(
                    key_by_id(conn, params, account, key_ref(conn, account, key)?)?.scanning_key,
                );
            }
            if let Some(work) = work {
                scan.permits.push(ScanPermit { account, key, work });
            }
        }
    }
    Ok(scan)
}

impl<C: BorrowMut<rusqlite::Connection>, P: Parameters, CL: Clock, R: Rng> OneTimeTransactionScan
    for WalletDb<C, P, CL, R>
{
    /// Captures permissions atomically before synchronous full-transaction decryption.
    fn prepare_one_time_transaction_scan(
        &mut self,
        txid: TxId,
        height: Option<BlockHeight>,
    ) -> Result<TransactionScan<AccountUuid>, SqliteClientError> {
        self.transactionally(|db| {
            prepare(
                db.conn.0,
                &db.params,
                txid,
                height,
                super::unix_now(&db.clock),
            )
        })
    }
}

/// Strips discoveries with stale generations while preserving authenticated known receipts.
pub(crate) fn fence<P: Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    d_tx: &mut DecryptedTransaction<'_, ZcashTransaction, AccountUuid>,
) -> Result<(), SqliteClientError> {
    let mut valid = Vec::new();
    for permit in d_tx.one_time_permits() {
        if block_recovery::state(conn, params, permit.account)?
            .is_some_and(|s| s.enabled && s.work == permit.work)
        {
            valid.push((permit.account, permit.key));
        }
    }
    d_tx.retain_ironwood_outputs(|output| {
        let Some(key) = output.one_time_key_id() else {
            return Ok(true);
        };
        let account = *output.account();
        if valid.contains(&(account, key)) {
            return Ok(true);
        }
        let registered = key_by_id(conn, params, account, key_ref(conn, account, key)?)?;
        let nf = output
            .note()
            .0
            .nullifier(registered.scanning_key.full_viewing_key())
            .to_bytes();
        block_scan::known_receipt(conn, account, key, Some(nf), &output.note().0)
    })
}
