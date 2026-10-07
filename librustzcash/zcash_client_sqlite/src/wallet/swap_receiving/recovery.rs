//! Recovery from authenticated wallet data, independent of the discovery transport.

use std::borrow::BorrowMut;

use crate::{util::Clock, wallet};
use rusqlite::{Connection, OptionalExtension, params};
use zakura_swap_receiving::RefundMemo;
use zcash_protocol::consensus::{BlockHeight, Parameters};

use super::{
    Discovery, Error, KeyId, Purpose, RESTORED_INCOMING, account_key, decode_index, register,
    reservations::RECEIVE_LOOKAHEAD, restore_start, retention::retain_spend_history, unix_now,
};
use crate::{AccountUuid, SqlTransaction, WalletDb};
use zcash_protocol::consensus::NetworkUpgrade;

impl<C: BorrowMut<Connection>, P: Parameters, CL: Clock, R> WalletDb<C, P, CL, R> {
    /// Queues one receiver-directory sweep for each of `account`'s closed swap keys, as
    /// a seed restore does, and returns how many were queued.
    ///
    /// A key stops scanning once its swap settles, so a rare later payment, such as a
    /// second refund, is found only by a sweep. Call this when the user asks to recheck
    /// swap history. A finished sweep reopens its key from the sweep's anchor until it
    /// closes again, and new incoming reservations wait for these sweeps as they do
    /// after a restore.
    pub fn recheck_swap_history(&mut self, account: AccountUuid) -> Result<usize, Error> {
        self.transactionally(|db| {
            let (owner, _) = account_key(db.conn.0, &db.params, account)?;
            Ok(db.conn.0.execute(
                "INSERT INTO ironwood_swap_sweeps (receiving_key_id)
                 SELECT id FROM ironwood_receiving_keys
                 WHERE account_id = ?1 AND closed_at IS NOT NULL
                 ON CONFLICT (receiving_key_id) DO UPDATE SET
                     lookup_height = NULL, lookup_hash = NULL, attempts = 0,
                     next_attempt_at = 0, done_height = NULL
                 WHERE done_height IS NOT NULL",
                [owner.0],
            )?)
        })
    }

    /// Keeps `account`'s swap recovery current. Call under the wallet write lock when
    /// each sync starts, before planning scan work, and again once it reaches the tip.
    ///
    /// Retains Ironwood spend evidence from the account's birthday until
    /// [`WalletDb::finish_swap_nullifier_recovery`] releases it; evidence pruned
    /// before the first call cannot be recovered without a rescan. Once scanning
    /// reaches the chain tip at or above Ironwood activation, it also registers refund
    /// keys from confirmed funding memos and keeps
    /// [`RECEIVE_GAP_LIMIT`](super::RECEIVE_GAP_LIMIT) incoming lookahead keys above
    /// the highest restored index, each queued for one receiver-directory sweep.
    pub fn maintain_swap_receiving(&mut self, account: AccountUuid) -> Result<(), Error> {
        self.transactionally(|db| {
            retain_spend_history(db.conn.0, &db.params, account)?;
            db.maintain_restore_discovery(account, RECEIVE_LOOKAHEAD)
        })
    }
}

impl<P: Parameters, CL: Clock, R> WalletDb<SqlTransaction<'_>, P, CL, R> {
    /// Registers refund keys from confirmed, authenticated internal funding memos, and
    /// returns how many funding records this version cannot read.
    ///
    /// Run after scanning and memo enhancement, including during restore. A key that
    /// already covers the funding block, by scanning from it or by a sweep, needs
    /// nothing more. Any other key is restored: it is queued for a receiver-directory
    /// sweep and then scans until the completion limit after the funding block, with no
    /// provider lookups. Own-send evidence must include an input belonging to the same
    /// account. Spent and zero-value marker notes are included. A record whose inputs
    /// or memo are not available yet is left for a later call (see
    /// [`WalletDb::swap_refund_memos_pending`]).
    ///
    /// A marker that still lacks own-send evidence once every block from the birthday
    /// through it is scanned was funded from notes received before the birthday, or is
    /// not this wallet's. Its key is registered and swept without advancing allocation,
    /// which skips the index instead, so a forged record cannot exhaust the index space,
    /// and an unreadable one never blocks issuance.
    pub(super) fn recover_refund_memos(&mut self, account: AccountUuid) -> Result<usize, Error> {
        let (account_ref, _) = account_key(self.conn.0, &self.params, account)?;
        let scanned = wallet::fully_scanned_height(self.conn.0)?.map(u32::from);
        let records = {
            let mut stmt = self.conn.0.prepare_cached(
                "SELECT n.memo, t.mined_height, EXISTS (SELECT 1 FROM v_received_output_spends s
                     WHERE s.transaction_id = n.transaction_id AND s.account_id = n.account_id)
                 FROM ironwood_received_notes n
                 JOIN transactions t ON t.id_tx = n.transaction_id
                 WHERE n.account_id = ?1 AND n.recipient_key_scope = 1
                   AND n.receiving_key_id IS NULL AND t.mined_height IS NOT NULL
                   AND substr(n.memo, 1, 5) = X'FF5A535750'",
            )?;
            stmt.query_map([account_ref.0], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, bool>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
        };
        let mut unreadable = 0;
        for (bytes, height, authenticated) in records {
            // SQLite omits trailing zero padding when storing MemoBytes.
            let memo = zcash_protocol::memo::MemoBytes::from_bytes(&bytes)
                .ok()
                .and_then(|bytes| RefundMemo::decode(bytes.as_array()));
            match memo {
                None if authenticated => unreadable += 1,
                Some(memo) if authenticated => {
                    self.register_refund_memo(account, account_ref.0, memo.index(), height, true)?
                }
                Some(memo) if scanned.is_some_and(|scanned| height <= scanned) => {
                    self.register_refund_memo(account, account_ref.0, memo.index(), height, false)?
                }
                _ => {}
            }
        }
        Ok(unreadable)
    }

    /// Registers the refund key at `index` that a funding memo mined at `height` names,
    /// unless a key already covers the funding block, advancing allocation past it only
    /// if `authenticated` (see [`Self::recover_refund_memos`]).
    fn register_refund_memo(
        &mut self,
        account: AccountUuid,
        account_ref: i64,
        index: u64,
        height: u32,
        authenticated: bool,
    ) -> Result<(), Error> {
        let key_id = KeyId::new(Purpose::Refund, index);
        // Storing the funding transaction already started a key scanned here (see
        // `start_funded_refund_keys`), and an earlier call queued any other.
        let covered: bool = self.conn.0.query_row(
            "SELECT EXISTS(SELECT 1 FROM ironwood_receiving_keys k
             WHERE k.account_id = ?1 AND k.purpose = 0 AND k.key_index = ?2
               AND k.scan_from <= ?3 AND (k.active_from <= ?3 OR EXISTS(
                 SELECT 1 FROM ironwood_swap_sweeps s WHERE s.receiving_key_id = k.id)))",
            params![account_ref, key_id.index().to_be_bytes(), height],
            |row| row.get(0),
        )?;
        if covered {
            return Ok(());
        }
        // Registering at the funding block's time makes the completion limit count from
        // the swap, so an old swap's key closes after its sweep.
        let funded_at = self
            .conn
            .0
            .query_row(
                "SELECT time FROM blocks WHERE height = ?1",
                [height],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .unwrap_or_else(|| unix_now(&self.clock));
        register(
            self.conn.0,
            &self.params,
            account,
            key_id,
            height.into(),
            authenticated,
            Discovery::Sweep,
            funded_at,
        )?;
        Ok(())
    }

    /// See [`WalletDb::maintain_swap_receiving`], keeping `lookahead` incoming keys.
    /// Does nothing until scanning reaches a chain tip at or above Ironwood activation.
    pub(crate) fn maintain_restore_discovery(
        &mut self,
        account: AccountUuid,
        lookahead: u32,
    ) -> Result<(), Error> {
        let tip = wallet::chain_tip_height(self.conn.0)?;
        let ready = match (tip, self.params.activation_height(NetworkUpgrade::Nu6_3)) {
            (Some(tip), Some(activation)) => {
                tip >= activation && wallet::fully_scanned_height(self.conn.0)? == Some(tip)
            }
            _ => false,
        };
        if !ready {
            return Ok(());
        }
        self.recover_refund_memos(account)?;
        self.extend_receive_lookahead(account, lookahead)
    }

    /// Keeps `count` incoming lookahead keys, scanned from the account's restore start.
    pub(crate) fn extend_receive_lookahead(
        &mut self,
        account: AccountUuid,
        count: u32,
    ) -> Result<(), Error> {
        let (account_ref, _) = account_key(self.conn.0, &self.params, account)?;
        let start = restore_start(self.conn.0, &self.params, account_ref)?;
        self.maintain_swap_receive_lookahead(account, count, start)
    }

    /// Ensures `count` incoming keys beyond the highest reserved or paid index, queued
    /// for a receiver-directory sweep.
    ///
    /// Call after scanning and after storing payments. The first window, and any
    /// window above a paid key found by restore and never reserved, extends restore
    /// recovery. Indices above a key this wallet issued were never handed out by it,
    /// so they need no sweep. This is bounded-gap recovery, not a completeness proof.
    pub(crate) fn maintain_swap_receive_lookahead(
        &mut self,
        account: AccountUuid,
        count: u32,
        scan_from: BlockHeight,
    ) -> Result<(), Error> {
        let (account_ref, _) = account_key(self.conn.0, &self.params, account)?;
        let top: Option<(Vec<u8>, bool)> = self
            .conn
            .0
            .query_row(
                &format!(
                    "SELECT k.key_index, ({RESTORED_INCOMING}) FROM ironwood_receiving_keys k
                     WHERE k.account_id = ?1 AND k.purpose = 1 AND k.advances_allocation = 1
                     ORDER BY k.key_index DESC LIMIT 1"
                ),
                [account_ref.0],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if top.as_ref().is_some_and(|(_, restored)| !restored) {
            return Ok(());
        }
        let last = top.map(|(index, _)| index);
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
                 WHERE account_id = ?1 AND purpose = 1 AND key_index = ?2
                   AND scan_from <= ?3)",
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
