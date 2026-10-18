//! Errors for filter construction, validation, matching and transport.

/// A failure that must never be reported to a caller as "no match".
///
/// Every variant means the filter's coverage claim is unusable: an exceeded
/// application cap is an unsupported or incomplete update, not a negative
/// answer about wallet activity. Callers advance durable coverage only on
/// `Ok`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FilterError {
    #[error("block hash error: {0}")]
    BlockHash(String),
    #[error("filter encoding error: {0}")]
    Encoding(String),
    #[error("filter is truncated: {0}")]
    Truncated(String),
    #[error("filter is not canonically encoded: {0}")]
    NotCanonical(String),
    #[error("filter exceeds an application limit: {0}")]
    LimitExceeded(String),
    #[error("filter has {0} trailing bytes after the coded stream")]
    TrailingBytes(usize),
    #[error("filter padding is not zero")]
    NonZeroPadding,
    #[error("previous output script is unavailable for {0}")]
    MissingPreviousOutput(String),
    #[error("envelope error: {0}")]
    Envelope(String),
    #[error("range response is invalid: {0}")]
    Response(String),
}
