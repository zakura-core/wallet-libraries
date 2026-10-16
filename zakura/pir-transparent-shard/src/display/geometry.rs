//! Display table shapes, kept apart from the history registry.
//!
//! History shards name `layout::PROFILES` entries; display shards name these.
//! A history consumer therefore refuses a display geometry name rather than
//! decoding it, and display tables are not forced to the history archive's
//! 32,768 rows, whose selection alone is 200 KB of upload per query.
//!
//! A display table uses only the directory fields: its rows and row width.
//! The page fields restate them so the shape passes the generic checks.

use crate::layout::{Geometry, INLINE_EVENTS};

/// The native minimum row count. At the 8-bit profile a row is four
/// 2,048-byte blocks holding 72 entries: 21,000 B of dithered upload and
/// 10,256 B of download per query.
pub const TXID_2K8: Geometry = Geometry {
    name: "txid-2k8",
    directory_rows: 2_048,
    directory_row_bytes: 8_192,
    page_rows: 2_048,
    page_row_bytes: 8_192,
    inline_events: INLINE_EVENTS,
};

/// Twice the rows of `txid-2k8` at the same row: 72 entries a row, about
/// 180,000 entries a table at 61% fill. 28,168 B of dithered upload and the
/// same 10,256 B of download per query.
pub const TXID_4K8: Geometry = Geometry {
    name: "txid-4k8",
    directory_rows: 4_096,
    directory_row_bytes: 8_192,
    page_rows: 4_096,
    page_row_bytes: 8_192,
    inline_events: INLINE_EVENTS,
};

pub const DISPLAY_PROFILES: &[Geometry] = &[TXID_2K8, TXID_4K8];

/// The display geometry named `name`; `None` must be treated as a hard error.
pub fn display_by_name(name: &str) -> Option<&'static Geometry> {
    DISPLAY_PROFILES.iter().find(|g| g.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::txid::{slots_per_row, ENTRY_BYTES};

    #[test]
    fn display_profiles_are_native_shapes_disjoint_from_history() {
        for geometry in DISPLAY_PROFILES {
            geometry.validate().unwrap();
            assert_eq!(geometry.page_rows, geometry.directory_rows);
            assert_eq!(geometry.page_row_bytes, geometry.directory_row_bytes);
            assert!(crate::layout::by_name(geometry.name).is_none());
            assert_eq!(display_by_name(geometry.name), Some(geometry));
        }
        for geometry in crate::layout::PROFILES {
            assert!(display_by_name(geometry.name).is_none());
        }
        for geometry in [TXID_2K8, TXID_4K8] {
            assert_eq!(slots_per_row(geometry.directory_row_bytes), 72);
            assert_eq!(geometry.directory_row_bytes - 72 * ENTRY_BYTES, 56);
        }
    }
}
