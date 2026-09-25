//! Recovery from authenticated wallet data, independent of the discovery transport.

use std::borrow::BorrowMut;

use rusqlite::{Connection, params};
use zakura_swap_receiving::RefundMemo;
use zcash_protocol::consensus::{BlockHeight, Parameters};

use super::{Error, KeyId, Purpose, account_key, decode_index, register};
use crate::{AccountUuid, SqlTransaction, WalletDb};

/// A confirmed funding record recovered from an ordinary internal Ironwood note.
/// The deposit address restores the application's provider-status lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveredRefund {
    /// Refund sequence index.
    pub index: u64,
    /// Exact deposit address authenticated by the memo.
    pub deposit_address: String,
    /// Earliest block to scan with the recovered refund key.
    pub funding_height: BlockHeight,
}

impl<C: BorrowMut<Connection>, P: Parameters, CL, R> WalletDb<C, P, CL, R> {
    /// Registers refund keys from confirmed, authenticated internal funding memos.
    ///
    /// Run after scanning and memo enhancement, including during restore. Own-send
    /// evidence must include an input belonging to the same account. Records whose
    /// inputs or memos are not yet available remain eligible on subsequent calls.
    /// Spent and zero-value marker notes are included. Unsupported records return
    /// an error and remain stored, rather than silently completing recovery.
    pub fn recover_swap_refund_memos(
        &mut self,
        account: AccountUuid,
    ) -> Result<Vec<RecoveredRefund>, Error> {
        self.transactionally(|db| db.recover_swap_refund_memos(account))
    }

    /// Ensures `count` incoming keys beyond the highest reserved or paid index.
    ///
    /// Call before scanning and after storing payments. New keys queue replay
    /// from `scan_from`, so a payment found at the edge can reveal earlier payments
    /// to the next window. This is bounded-gap recovery, not a completeness proof.
    pub fn maintain_swap_receive_lookahead(
        &mut self,
        account: AccountUuid,
        count: u32,
        scan_from: BlockHeight,
    ) -> Result<(), Error> {
        self.transactionally(|db| db.maintain_swap_receive_lookahead(account, count, scan_from))
    }
}

impl<P: Parameters, CL, R> WalletDb<SqlTransaction<'_>, P, CL, R> {
    /// See [`WalletDb::recover_swap_refund_memos`] on a connection-backed handle.
    pub fn recover_swap_refund_memos(
        &mut self,
        account: AccountUuid,
    ) -> Result<Vec<RecoveredRefund>, Error> {
        let (account_ref, _) = account_key(self.conn.0, &self.params, account)?;
        let records = {
            let mut stmt = self.conn.0.prepare_cached(
                "SELECT n.memo, t.mined_height
                 FROM ironwood_received_notes n
                 JOIN transactions t ON t.id_tx = n.transaction_id
                 WHERE n.account_id = ?1 AND n.recipient_key_scope = 1
                   AND n.receiving_key_id IS NULL AND t.mined_height IS NOT NULL
                   AND substr(n.memo, 1, 5) = X'FF5A535750'
                   AND EXISTS (SELECT 1 FROM v_received_output_spends s
                               WHERE s.transaction_id = n.transaction_id
                                 AND s.account_id = n.account_id)",
            )?;
            stmt.query_map([account_ref.0], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, u32>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
        };
        let mut recovered = Vec::new();
        for (bytes, height) in records {
            // SQLite omits trailing zero padding when storing MemoBytes.
            let bytes = zcash_protocol::memo::MemoBytes::from_bytes(&bytes)
                .map_err(|_| super::corrupt("invalid stored swap memo length"))?;
            let memo = RefundMemo::decode(self.params.network_type(), bytes.as_array())
                .map_err(|e| super::corrupt(&e.to_string()))?
                .ok_or_else(|| super::corrupt("missing swap memo discriminator"))?;
            let key_id = KeyId::new(Purpose::Refund, memo.index());
            let needs_registration: bool = self.conn.0.query_row(
                "SELECT NOT EXISTS (SELECT 1 FROM ironwood_receiving_keys
                 WHERE account_id = ?1 AND purpose = 0 AND derivation_version = 1
                   AND key_index = ?2 AND scan_from <= ?3 AND advances_allocation = 1)",
                params![account_ref.0, key_id.index().to_be_bytes(), height],
                |row| row.get(0),
            )?;
            if needs_registration {
                register(
                    self.conn.0,
                    &self.params,
                    account,
                    key_id,
                    height.into(),
                    true,
                )?;
            }
            recovered.push(RecoveredRefund {
                index: memo.index(),
                deposit_address: memo.deposit_address().to_owned(),
                funding_height: height.into(),
            });
        }
        Ok(recovered)
    }

    /// See [`WalletDb::maintain_swap_receive_lookahead`] on a connection-backed handle.
    pub fn maintain_swap_receive_lookahead(
        &mut self,
        account: AccountUuid,
        count: u32,
        scan_from: BlockHeight,
    ) -> Result<(), Error> {
        let (account_ref, _) = account_key(self.conn.0, &self.params, account)?;
        let last: Option<Vec<u8>> = self.conn.0.query_row(
            "SELECT MAX(key_index) FROM ironwood_receiving_keys
             WHERE account_id = ?1 AND purpose = 1 AND derivation_version = 1
               AND advances_allocation = 1",
            [account_ref.0],
            |row| row.get(0),
        )?;
        let start = last
            .map(decode_index)
            .transpose()?
            .map(|i| i.checked_add(1).ok_or(Error::IndexExhausted))
            .transpose()?
            .unwrap_or(0);
        for offset in 0..u64::from(count) {
            let index = start.checked_add(offset).ok_or(Error::IndexExhausted)?;
            let exists: bool = self.conn.0.query_row(
                "SELECT EXISTS (SELECT 1 FROM ironwood_receiving_keys
                 WHERE account_id = ?1 AND purpose = 1 AND derivation_version = 1
                   AND key_index = ?2 AND scan_from <= ?3)",
                params![account_ref.0, index.to_be_bytes(), u32::from(scan_from)],
                |row| row.get(0),
            )?;
            if !exists {
                self.watch_swap_receive_key(account, index, scan_from)?;
            }
        }
        Ok(())
    }
}
