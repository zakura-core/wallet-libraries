//! Swap conventions built on one-time keys: the refund memo a funding transaction
//! carries, the completion policy and provider-neutral lifecycle types that
//! schedule scanning, and when a provider's set of given receivers is current.

mod lifecycle;
mod memo;
mod provider_read;

pub use lifecycle::{
    COMPLETION_LIMIT_SECS, Observation, OperationStatus, REFUND_WATCH_SECS, RESTORE_WATCH_SECS,
    ReceiptExpectation,
};
pub use memo::{REFUND_MEMO_MAGIC, RefundMemo};
pub use provider_read::{
    PROVIDER_READ_CLOCK_SKEW_SECS, PROVIDER_READ_MAX_AGE_SECS, provider_read_is_current,
};
