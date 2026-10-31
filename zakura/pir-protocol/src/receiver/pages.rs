//! The page rules every receiver's records follow, across a segment and across a
//! wallet's steps.
use super::{Error, Hash, RawRecord};
use crate::receiver::ReceiverBytes;
use std::collections::BTreeSet;

/// Leaves in a full depth-32 note commitment tree, the largest valid note position
/// end. The last leaf's position is one less.
pub const TREE_SIZE: u64 = 1 << 32;

/// The fields of a [`RawRecord`] that [`check_pages`] reads, so validating a publication
/// need not hold its records whole.
#[derive(Clone, Copy)]
pub(super) struct PageMeta {
    receiver: ReceiverBytes,
    page: u32,
    total: u32,
    position: u64,
    txid: Hash,
    action_index: u32,
    height: u32,
    tx_index: u32,
    block_hash: Hash,
}

impl From<&RawRecord> for PageMeta {
    /// Projects `r` onto the fields page checks read.
    fn from(r: &RawRecord) -> Self {
        Self {
            receiver: r.receiver,
            page: r.page,
            total: r.total,
            position: r.payment.position,
            txid: r.payment.txid,
            action_index: r.payment.action_index,
            height: r.payment.height,
            tx_index: r.payment.tx_index,
            block_hash: r.payment.block_hash,
        }
    }
}

impl PageMeta {
    /// Whether `next` can follow `self`; see [`check_next`].
    fn continues(&self, next: &Self) -> bool {
        let same_block = next.height == self.height;
        next.receiver == self.receiver
            && self.page.checked_add(1) == Some(next.page)
            && next.total == self.total
            && next.position > self.position
            && (next.height, next.tx_index, next.action_index)
                > (self.height, self.tx_index, self.action_index)
            && (!same_block || next.block_hash == self.block_hash)
            && (!same_block || next.tx_index != self.tx_index || next.txid == self.txid)
    }
}

/// Checks that `next` can follow `previous` as the same receiver's next page: the
/// same receiver and total, the next page number, a later note position, a later
/// output by height, transaction index and action index, the same block hash at the
/// same height, and the same txid in the same transaction.
pub fn check_next(previous: &RawRecord, next: &RawRecord) -> Result<(), Error> {
    if !PageMeta::from(previous).continues(&PageMeta::from(next)) {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// Checks records sorted by receiver and page: every receiver has pages zero to its
/// total, each continuing the last as [`check_next`] requires, and no two records
/// share an output or note position. Beyond that uniqueness, different receivers'
/// records are not checked against each other: a wallet reads only its own pages.
pub(super) fn check_pages(sorted: impl IntoIterator<Item = PageMeta>) -> Result<(), Error> {
    let mut previous: Option<PageMeta> = None;
    let mut outputs = BTreeSet::new();
    let mut positions = BTreeSet::new();
    for record in sorted {
        // Every advertised page must exist in this revision, in chain order.
        match previous {
            Some(p) if p.receiver == record.receiver => {
                if !p.continues(&record) {
                    return Err(Error::Malformed);
                }
            }
            p => {
                if record.page != 0 || p.is_some_and(|r| r.page + 1 != r.total) {
                    return Err(Error::Malformed);
                }
            }
        }
        previous = Some(record);
        if !outputs.insert((record.txid, record.action_index)) || !positions.insert(record.position)
        {
            return Err(Error::Malformed);
        }
    }
    if previous.is_some_and(|r| r.page + 1 != r.total) {
        return Err(Error::Malformed);
    }
    Ok(())
}
