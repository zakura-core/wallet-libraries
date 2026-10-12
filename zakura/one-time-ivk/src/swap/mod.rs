//! Swap conventions built on one-time keys: the refund memo a funding transaction
//! carries, and the completion policy and provider-neutral lifecycle types that
//! schedule scanning.

mod lifecycle;
mod memo;

pub use lifecycle::{
    COMPLETION_LIMIT_SECS, Observation, OperationStatus, RESTORE_WATCH_SECS, ReceiptExpectation,
};
pub use memo::{REFUND_MEMO_MAGIC, RefundMemo};
