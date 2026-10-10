//! Codes persisted in the detail tables: lookup outcomes and display address kinds.

/// Outcome codes of `transparent_detail_work.last_outcome`, one per
/// `TransparentDetailOutcome` variant.
pub(super) const UNAVAILABLE: i64 = 0;
pub(super) const ABSENT: i64 = 1;
pub(super) const NOT_COVERED: i64 = 2;
pub(super) const UNSUPPORTED: i64 = 3;
pub(super) const PROTOCOL: i64 = 4;
pub(super) const CONTRADICTION: i64 = 5;
pub(super) const NOT_YET_PUBLISHED: i64 = 6;

/// Address kind codes of `transparent_tx_display.sender_kind` and
/// `transparent_tx_display_outputs.address_kind`, as the display publisher encodes them.
pub(super) const KIND_ABSENT: i64 = 0;
pub(super) const KIND_P2PKH: i64 = 1;
pub(super) const KIND_P2SH: i64 = 2;
pub(super) const KIND_NON_STANDARD: i64 = 3;
