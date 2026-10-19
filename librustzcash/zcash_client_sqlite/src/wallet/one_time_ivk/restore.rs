//! The lookups and late payments of one-time key recovery: paging through hits' histories,
//! turning payments into scan hints or late candidates, and recovering refund keys from
//! funding memos.

pub(crate) mod apply;
pub(crate) mod discovery;
pub(super) mod payments;
pub(crate) mod recovery;

use payments::PendingPayment;

#[cfg(test)]
pub(super) mod tests;
