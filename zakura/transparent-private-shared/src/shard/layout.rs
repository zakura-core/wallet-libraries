//! Named, pinned table geometries with a shared compact row codec.
//!
//! Uniformity is the whole point. The native ReinspiRING profile's public query
//! setup is a pure function of the geometry and table, so shards that share a
//! geometry share one set of scheme parameters — a client validates parameters and derives its
//! query setup once for every shard it will ever query, instead of once per
//! shard. The registry fixes each geometry; sealing bounds ordinary shard
//! demand and adds segments for an indivisible oversized block.
//!
//! Both tables use the scheme's single-instance width, 4,096 bytes: one
//! 2,048-coefficient polynomial of 16-bit plaintexts. The
//! directory carries two inline events per entry; the page row is sized for
//! storage rather than for the query count of the longest history, which is
//! what [`PAGE_ROW_BYTES`] explains.
//!
//! A geometry names two independent dimensions: the directory shard's rows
//! and the rows of each of its page shards. A directory shard holds up to
//! [`MAX_PAGE_CHILDREN`] page shards, each its own table of `page_rows` rows,
//! so the directory is sized for the scripts a range holds and the pages for
//! the history those scripts push out of it.
//!
//! # Segments
//!
//! Row *counts* are pinned per segment, not per shard. A shard normally has one
//! segment of each table and nothing below is visible; a shard whose content
//! does not fit one segment gets another of the same geometry, so the parameter
//! set stays shared. A shard's logical row space is its segments concatenated,
//! and a row index is taken over that whole space — which is why placement
//! stays even instead of spilling into a last segment, and why a page extent
//! that crosses a segment is ordinary addressing.

use crate::shard::compact::{RECEIVE_BYTES, SPEND_BYTES};

pub const DIRECTORY_ROW_BYTES: usize = 4_096;
pub const PAGE_ROW_BYTES: usize = 4_096;
pub const DIRECTORY_ROWS: usize = 2_048;
pub const PAGE_ROWS: usize = 8_192;
pub const INLINE_EVENTS: u32 = 2;
pub const PAGE_ROW_HEADER_BYTES: usize = 4;
/// Tag 14, ordinal 4, fragment count 4, event count 4, height bounds 8, and
/// the chain fields `prev_child u8 | prev_row u32 | older_runs u8`.
pub const PAGE_ENTRY_HEADER_BYTES: usize = 40;
/// Decoder bound, not the event count of a full fragment. Forty-three local
/// receive/spend pairs use 4,042 of a fragment's 4,052 bytes; an 87th event
/// cannot fit.
pub const EVENTS_PER_PAGE: u32 = 86;
pub const MAX_ENTRIES_PER_ROW: usize =
    (PAGE_ROW_BYTES - PAGE_ROW_HEADER_BYTES) / (PAGE_ENTRY_HEADER_BYTES + RECEIVE_BYTES);

/// A table geometry to score a candidate against.
///
/// The constants above are the geometry that is *built*. This is how a census
/// asks what a different one would have cost, without a rebuild and without any
/// builder being able to reach it: [`Default`] is the compiled set, so a run
/// that overrides nothing measures exactly what ships.
///
/// # What the scheme allows
///
/// Neither dimension is free. The native profile requires a row count that is a
/// multiple of `POLY_LEN` = 2,048 and refuses fewer, and it quantises the row
/// width into instances of 2,048 x 16 bits = 4,096 bytes. So the smallest legal
/// table is 2,048 rows of 4,096 bytes. Script capacity depends on encoded
/// directory-entry bytes as well as two-choice placement. [`Geometry::validate`] is where that is enforced, so a
/// sweep cannot quietly score a shape the scheme would never serve.
///
/// The two dimensions do not cost the same. Row count is charged on the query
/// upload alone, and mildly: 2,048 rows cost 40,200 bytes a query and 4,096
/// cost 52,744, +31.2%. Row width is charged on the response *and* the
/// published setup, and in whole instances, so the next legal width doubles
/// both. Widening to buy directory slots is therefore the expensive way to buy
/// them and doubling the row count is the cheap one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    /// The registry name this shape is published under.
    ///
    /// A shard names its geometry rather than restating its dimensions, so a
    /// consumer selects one validated parameter set by name instead of
    /// inferring it from numbers it would have to trust. The dimensions are
    /// still published per segment and still checked against the named entry;
    /// the name is what decides, and an unknown one is refused.
    pub name: &'static str,
    pub directory_rows: u64,
    pub directory_row_bytes: usize,
    pub page_rows: u64,
    pub page_row_bytes: usize,
    /// Events carried in a directory entry, which decides both how wide an
    /// entry is and whether a history touches the page table at all.
    pub inline_events: u32,
}

/// The recent tier: a small directory over its own 8,192-row page shards.
///
/// The directory is the table a tip catch-up queries every time, so it is the
/// native minimum of 2,048 rows; the page shards are sized for storage and
/// seal on page rows inside the directory shard.
pub const DECOUPLED_2K_8K: Geometry = Geometry {
    name: "decoupled-2k-8k",
    directory_rows: 2_048,
    directory_row_bytes: INSTANCE_BYTES,
    page_rows: 8_192,
    page_row_bytes: INSTANCE_BYTES,
    inline_events: 2,
};

/// The archive tier: 32,768-row directory shards whose page shards are also
/// 32,768 rows, at most [`MAX_PAGE_CHILDREN`] of them per directory shard.
pub const DECOUPLED_32K_32K: Geometry = Geometry {
    name: "decoupled-32k-32k",
    directory_rows: 32_768,
    page_rows: 32_768,
    ..DECOUPLED_2K_8K
};

/// Page shards one directory shard may hold.
///
/// Bounds a history's chain length (one round trip per run), the manifest's
/// child list, the publisher's replay of the open directory shard and the
/// catch-up walk. It does not affect entry size: the five bits of a
/// directory entry's `flags_child` name the child, so 32 is also the most the
/// encoding can address.
pub const MAX_PAGE_CHILDREN: u32 = 32;

/// Every geometry a published shard may name.
///
/// A closed set rather than server-chosen parameters. Each entry is a shape the
/// scheme serves, whose parameters a client validates once and reuses for every
/// shard of that geometry; an arbitrary shape would cost a parameter set per
/// shard and give a wallet nothing to check the server's choice against. One
/// entry names both dimensions, so native seeds stay keyed by geometry and table.
pub const PROFILES: &[Geometry] = &[DECOUPLED_2K_8K, DECOUPLED_32K_32K];

/// The registry entry named `name`, or `None` if there is no such geometry.
///
/// Callers must treat `None` as a hard error. A shard whose geometry this build
/// does not know cannot be decoded, and skipping it would advance coverage over
/// history that was never retrieved.
pub fn by_name(name: &str) -> Option<&'static Geometry> {
    PROFILES.iter().find(|geometry| geometry.name == name)
}

impl Default for Geometry {
    fn default() -> Self {
        DECOUPLED_2K_8K
    }
}

impl Geometry {
    /// Maximum bytes one directory entry may occupy at this inline allowance.
    pub const fn directory_entry_bytes(&self) -> usize {
        crate::shard::records::DIRECTORY_ENTRY_HEADER_BYTES
            + self.inline_events as usize * SPEND_BYTES
    }

    /// Maximum entry count, attained only with minimum-sized histories.
    /// This is a decoder/count bound; sealing separately limits actual bytes.
    pub const fn directory_slots(&self) -> u64 {
        ((self.directory_row_bytes - crate::shard::records::DIRECTORY_ROW_HEADER_BYTES)
            / (crate::shard::records::DIRECTORY_ENTRY_HEADER_BYTES
                + if self.inline_events == 0 {
                    0
                } else {
                    RECEIVE_BYTES
                })) as u64
    }

    /// Absolute script-count bound; encoded bytes and placement also constrain it.
    pub const fn directory_capacity(&self) -> u64 {
        self.directory_rows * self.directory_slots()
    }

    /// Residual bytes when a row is filled with minimum-sized entries.
    /// This is not fixed padding: mixed entry sizes may consume these bytes.
    pub const fn directory_row_slack(&self) -> usize {
        self.directory_row_bytes
            - crate::shard::records::DIRECTORY_ROW_HEADER_BYTES
            - self.directory_slots() as usize
                * (crate::shard::records::DIRECTORY_ENTRY_HEADER_BYTES
                    + if self.inline_events == 0 {
                        0
                    } else {
                        RECEIVE_BYTES
                    })
    }

    pub const fn directory_bytes_per_segment(&self) -> u64 {
        self.directory_rows * self.directory_row_bytes as u64
    }

    pub const fn page_bytes_per_segment(&self) -> u64 {
        self.page_rows * self.page_row_bytes as u64
    }

    /// Rejects a shape the PIR scheme would not serve.
    ///
    /// Checked rather than assumed because the whole point of a scoring
    /// geometry is that it is reachable from a command line, and a candidate
    /// the scheme rounds up is a candidate whose reported cost is not its cost.
    pub fn validate(&self) -> Result<(), String> {
        if self.directory_rows < POLY_LEN || !self.directory_rows.is_multiple_of(POLY_LEN) {
            return Err(format!(
                "{} directory rows: the scheme pads to a multiple of {POLY_LEN} and refuses fewer",
                self.directory_rows
            ));
        }
        if self.page_rows < POLY_LEN || !self.page_rows.is_multiple_of(POLY_LEN) {
            return Err(format!(
                "{} page rows: the scheme pads to a multiple of {POLY_LEN} and refuses fewer",
                self.page_rows
            ));
        }
        if self.directory_row_bytes < INSTANCE_BYTES
            || !self.directory_row_bytes.is_multiple_of(INSTANCE_BYTES)
        {
            return Err(format!(
                "{} directory row bytes: the scheme charges in whole instances of {INSTANCE_BYTES}",
                self.directory_row_bytes
            ));
        }
        if self.page_row_bytes < INSTANCE_BYTES
            || !self.page_row_bytes.is_multiple_of(INSTANCE_BYTES)
        {
            return Err(format!(
                "{} page row bytes: the scheme charges in whole instances of {INSTANCE_BYTES}",
                self.page_row_bytes
            ));
        }
        if self.directory_slots() == 0
            || self.directory_entry_bytes()
                > self.directory_row_bytes - crate::shard::records::DIRECTORY_ROW_HEADER_BYTES
        {
            return Err(format!(
                "a {}-byte entry does not fit a {}-byte row",
                self.directory_entry_bytes(),
                self.directory_row_bytes
            ));
        }
        Ok(())
    }

    /// Rejects a shape this build could not *encode*, as distinct from one the
    /// scheme could not serve.
    ///
    /// [`Geometry::validate`] answers whether the PIR scheme would serve a
    /// shape, which is the question a census asks of a candidate it will only
    /// score. Publishing requires both codecs' 4,096-byte rows and two inline
    /// events. The registry varies row counts only. Widening a row or changing
    /// inline capacity requires a schema bump and republication.
    pub fn validate_publishable(&self) -> Result<(), String> {
        self.validate()?;
        if self.directory_row_bytes != DIRECTORY_ROW_BYTES {
            return Err(format!(
                "{} directory row bytes: this build encodes {DIRECTORY_ROW_BYTES}-byte rows",
                self.directory_row_bytes
            ));
        }
        if self.page_row_bytes != PAGE_ROW_BYTES {
            return Err(format!(
                "{} page row bytes: this build encodes {PAGE_ROW_BYTES}-byte rows",
                self.page_row_bytes
            ));
        }
        if self.inline_events != INLINE_EVENTS {
            return Err(format!(
                "{} inline events: this build encodes {INLINE_EVENTS}",
                self.inline_events
            ));
        }
        Ok(())
    }
}

/// The scheme's RLWE degree, which is also its minimum and quantum of rows.
const POLY_LEN: u64 = 2_048;

/// Bytes of one scheme instance, which is the quantum of row width.
const INSTANCE_BYTES: usize = 4_096;

const _: () = assert!(DIRECTORY_ROW_BYTES.is_multiple_of(INSTANCE_BYTES));
const _: () = assert!(PAGE_ROW_BYTES.is_multiple_of(INSTANCE_BYTES));

/// Segments needed to hold `rows` rows, at `per_segment` rows each.
///
/// Never zero: a shard with no events still publishes an empty segment, because
/// a wallet must be able to establish absence by querying rather than by being
/// told there is nothing to query.
pub const fn segments_for(rows: u64, per_segment: u64) -> u32 {
    let needed = rows.div_ceil(per_segment);
    if needed == 0 {
        1
    } else {
        needed as u32
    }
}

/// Splits a row index over a shard's logical row space into its segment and the
/// row within that segment.
///
/// The row within the segment is what a query names. It is the same index in
/// every segment, because every segment is asked: naming the segment would
/// disclose which one holds the script, and the script is what chose it.
pub const fn split_row(row: u64, per_segment: u64) -> (u32, u64) {
    ((row / per_segment) as u32, row % per_segment)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every registry entry must be servable by the scheme *and* encodable by
    /// this build. A shape that failed either would be published as a name no
    /// consumer could act on.
    #[test]
    fn every_registry_entry_is_publishable() {
        for geometry in PROFILES {
            geometry
                .validate_publishable()
                .unwrap_or_else(|error| panic!("{}: {error}", geometry.name));
        }
    }

    /// Names are the addressing, so two entries sharing one would make the
    /// registry ambiguous and `by_name` silently pick the first.
    #[test]
    fn registry_names_are_distinct_and_resolvable() {
        for geometry in PROFILES {
            assert_eq!(by_name(geometry.name), Some(geometry), "{}", geometry.name);
        }
        let names: std::collections::BTreeSet<&str> =
            PROFILES.iter().map(|geometry| geometry.name).collect();
        assert_eq!(names.len(), PROFILES.len(), "duplicate registry name");
        assert_eq!(by_name("recent-16k"), None);
        assert_eq!(by_name(""), None);
    }

    /// The registry varies row counts and nothing else. If this ever fails, the
    /// record codec and `ManifestLayout` are part of the change — see
    /// [`Geometry::validate_publishable`].
    #[test]
    fn the_registry_varies_row_counts_only() {
        for geometry in PROFILES {
            assert_eq!(geometry.directory_row_bytes, 4_096, "{}", geometry.name);
            assert_eq!(geometry.page_row_bytes, 4_096, "{}", geometry.name);
            assert_eq!(geometry.inline_events, 2, "{}", geometry.name);
            assert_eq!(geometry.directory_slots(), 58, "{}", geometry.name);
        }
    }

    /// The two tiers' capacities are pinned rather than left to be recomputed
    /// by hand. Script-count bounds are independent of the separate byte and
    /// placement constraints; page rows are what one page shard holds.
    #[test]
    fn the_decoupled_tiers_hold_what_they_claim() {
        assert_eq!(DECOUPLED_32K_32K.directory_capacity(), 1_900_544);
        assert_eq!(DECOUPLED_32K_32K.page_rows, 32_768);
        assert_eq!(DECOUPLED_2K_8K.directory_capacity(), 118_784);
        assert_eq!(DECOUPLED_2K_8K.page_rows, 8_192);
        // The directory and its page shards are sized independently, which is
        // the point of having a pair rather than one number.
        assert_eq!(DECOUPLED_2K_8K.directory_bytes_per_segment(), 8_388_608);
        assert_eq!(DECOUPLED_2K_8K.page_bytes_per_segment(), 33_554_432);
        assert_eq!(DECOUPLED_32K_32K.directory_bytes_per_segment(), 134_217_728);
        assert_eq!(DECOUPLED_32K_32K.page_bytes_per_segment(), 134_217_728);
        // The child index has five bits in a directory entry; records.rs
        // checks that at compile time.
        assert_eq!(MAX_PAGE_CHILDREN, 32);
    }

    /// A width the scheme *would* serve is still refused for publication,
    /// because the record codec is compiled against one. Keeping the two
    /// questions apart is what lets a census score a shape it must not build.
    #[test]
    fn a_servable_width_is_not_automatically_a_publishable_one() {
        let wide = Geometry {
            directory_row_bytes: 8_192,
            ..Default::default()
        };
        wide.validate().expect("two instances is a legal width");
        assert!(wide.validate_publishable().is_err());
    }

    /// The compiled geometry is what `Default` reports. Everything a sweep says
    /// about a candidate is relative to this, so a drift here would silently
    /// rebase every comparison.
    #[test]
    fn the_default_geometry_is_the_one_that_ships() {
        let g = Geometry::default();
        assert_eq!(g, DECOUPLED_2K_8K);
        assert_eq!(g.directory_entry_bytes(), 177);
        assert_eq!(g.directory_slots(), 58);
        assert_eq!(g.directory_capacity(), 118_784);
        assert_eq!(g.directory_row_slack(), 32);
        assert_eq!(g.directory_bytes_per_segment(), 8_388_608);
        assert_eq!(g.page_bytes_per_segment(), 33_554_432);
        g.validate().expect("what ships must be servable");
    }

    /// With variable entries, the script-count bound depends on the smallest
    /// nonempty history, not the maximum inline allowance. Byte limits account
    /// for wider histories separately.
    #[test]
    fn minimum_history_size_defines_the_script_count_bound() {
        for (inline, slots, capacity) in [
            (0u32, 215u64, 440_320u64),
            (1, 58, 118_784),
            (2, 58, 118_784),
            (3, 58, 118_784),
        ] {
            let g = Geometry {
                inline_events: inline,
                ..Default::default()
            };
            assert_eq!(g.directory_slots(), slots, "inline {inline}");
            assert_eq!(g.directory_capacity(), capacity, "inline {inline}");
        }
    }

    /// Doubling the row count is the other way to the same capacity, and the
    /// one that leaves the inline allowance alone.
    #[test]
    fn doubling_the_rows_doubles_the_capacity() {
        let g = Geometry {
            directory_rows: 4_096,
            ..Default::default()
        };
        assert_eq!(
            g.directory_capacity(),
            2 * Geometry::default().directory_capacity()
        );
        assert_eq!(g.directory_bytes_per_segment(), 16_777_216);
        g.validate()
            .expect("a multiple of the poly length is servable");
    }

    /// A shape the scheme would round up is a shape whose reported cost is not
    /// its cost, so scoring it is worse than refusing it.
    #[test]
    fn a_geometry_the_scheme_would_not_serve_is_refused() {
        for bad in [
            Geometry {
                directory_rows: 1_024,
                ..Default::default()
            },
            Geometry {
                directory_rows: 3_000,
                ..Default::default()
            },
            Geometry {
                page_rows: 5_000,
                ..Default::default()
            },
            Geometry {
                directory_row_bytes: 3_584,
                ..Default::default()
            },
            // 52 maximum-sized inline events exceed one row.
            Geometry {
                inline_events: 52,
                ..Default::default()
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?} should be refused");
        }
        // The next legal width up is servable, and it buys 116 minimum entries for a
        // doubled response and setup.
        let wide = Geometry {
            directory_row_bytes: 8_192,
            ..Default::default()
        };
        wide.validate().expect("two instances is a legal width");
        assert_eq!(wide.directory_slots(), 116);
    }

    /// The inline allowance decides whether a history is paged at all, so the
    /// scoring functions must move with it and the compiled wrappers must not.

    #[test]
    fn a_shard_always_has_at_least_one_segment_of_each_table() {
        assert_eq!(segments_for(0, PAGE_ROWS as u64), 1);
        assert_eq!(segments_for(1, PAGE_ROWS as u64), 1);
        assert_eq!(segments_for(PAGE_ROWS as u64, PAGE_ROWS as u64), 1);
        assert_eq!(segments_for(PAGE_ROWS as u64 + 1, PAGE_ROWS as u64), 2);
    }

    /// A page extent that runs past a segment boundary is ordinary addressing,
    /// not a special case: the shard's page space is its segments concatenated.
    #[test]
    fn a_row_splits_into_its_segment_and_its_row_within_it() {
        let per = PAGE_ROWS as u64;
        assert_eq!(split_row(0, per), (0, 0));
        assert_eq!(split_row(per - 1, per), (0, per - 1));
        assert_eq!(split_row(per, per), (1, 0));
        assert_eq!(split_row(2 * per + 7, per), (2, 7));
    }
}
