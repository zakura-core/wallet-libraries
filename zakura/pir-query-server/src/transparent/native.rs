//! Transparent operations for this role.
pub use crate::native::*;
pub use zakura_pir_protocol::transparent::native::*;
/// Operations owned by this role.
pub trait TableQueryExt {
    /// Parses an upload of either scheme into its key and lifted selection.
    /// The width is the one the exact length names; any other length is
    /// refused.
    fn parse(&self, bytes: &[u8]) -> Result<(NativeKeys, Vec<u64>), String>;
    /// Parses an upload of either scheme over every row or over only the
    /// first `query_rows`, whichever its exact length names, zero-filled back
    /// to every row.
    fn parse_selection(
        &self,
        bytes: &[u8],
        query_rows: usize,
    ) -> Result<(NativeKeys, Vec<u64>), String>;
}
impl TableQueryExt for TableProfile {
    /// Parses an upload of either scheme into its key and lifted selection.
    /// The width is the one the exact length names; any other length is
    /// refused.
    fn parse(&self, bytes: &[u8]) -> Result<(NativeKeys, Vec<u64>), String> {
        self.native.parse_accepted(&self.setup, bytes, self.rows)
    }

    /// Parses an upload of either scheme over every row or over only the
    /// first `query_rows`, whichever its exact length names, zero-filled back
    /// to every row.
    fn parse_selection(
        &self,
        bytes: &[u8],
        query_rows: usize,
    ) -> Result<(NativeKeys, Vec<u64>), String> {
        self.native
            .parse_selection(&self.setup, bytes, query_rows, self.rows)
    }
}
