//! The payload a page row leaves for events, which the publisher packs and the
//! wallet checks fragments against.
use crate::shard::layout::{PAGE_ENTRY_HEADER_BYTES, PAGE_ROW_BYTES, PAGE_ROW_HEADER_BYTES};

pub const ROW_PAYLOAD: usize = PAGE_ROW_BYTES - PAGE_ROW_HEADER_BYTES;
pub const FRAGMENT_PAYLOAD: usize = ROW_PAYLOAD - PAGE_ENTRY_HEADER_BYTES;
