//! The wallet's half of Transparent's native profiles: preparing a query to a
//! table and decoding the answer. The profile itself, which both sides derive
//! the same way, is [`TableProfile`].

pub use zakura_pir_native::NativeSecret;
use zakura_pir_native::P16;
use zakura_transparent_private_shared::native::TableProfile;

/// Queries to a table and the decoding of their answers.
pub trait TableQuery {
    /// Fresh secret and upload selecting row `target` under [`TableProfile::scheme`]:
    /// 49 bits to nearest for a 16-bit table, 28 dithered bits for an 8-bit
    /// one.
    fn prepare(&self, target: usize) -> Result<(NativeSecret, Vec<u8>), String>;

    /// Fresh secret and dithered upload selecting row `target`: under
    /// [`TableProfile::dithered_scheme`] for a 16-bit table, and the same as
    /// [`Self::prepare`] for an 8-bit one.
    fn prepare_dithered(&self, target: usize) -> Result<(NativeSecret, Vec<u8>), String>;

    /// [`Self::prepare`] selecting among only the first `query_rows`, under
    /// the leading full-shape masks. `query_rows` must be public and the same
    /// for every query to the table.
    fn prepare_prefix(
        &self,
        query_rows: usize,
        target: usize,
    ) -> Result<(NativeSecret, Vec<u8>), String>;

    /// [`Self::prepare_dithered`] selecting among only the first `query_rows`;
    /// see [`Self::prepare_prefix`].
    fn prepare_dithered_prefix(
        &self,
        query_rows: usize,
        target: usize,
    ) -> Result<(NativeSecret, Vec<u8>), String>;

    /// Decodes one segment's body under that segment's published masks,
    /// truncated to the row width.
    fn decode(&self, secret: &NativeSecret, public: &[u8], body: &[u8]) -> Result<Vec<u8>, String>;
}

impl TableQuery for TableProfile {
    fn prepare(&self, target: usize) -> Result<(NativeSecret, Vec<u8>), String> {
        self.native
            .prepare(&self.setup, &self.masks, self.rows, target)
    }

    fn prepare_dithered(&self, target: usize) -> Result<(NativeSecret, Vec<u8>), String> {
        self.prepare_dithered_prefix(self.rows, target)
    }

    fn prepare_prefix(
        &self,
        query_rows: usize,
        target: usize,
    ) -> Result<(NativeSecret, Vec<u8>), String> {
        if query_rows > self.rows {
            return Err("native query shape".into());
        }
        self.native
            .prepare(&self.setup, &self.masks, query_rows, target)
    }

    fn prepare_dithered_prefix(
        &self,
        query_rows: usize,
        target: usize,
    ) -> Result<(NativeSecret, Vec<u8>), String> {
        if query_rows > self.rows {
            return Err("native query shape".into());
        }
        self.native
            .prepare_dithered(&self.setup, &self.masks, query_rows, target)
    }

    fn decode(&self, secret: &NativeSecret, public: &[u8], body: &[u8]) -> Result<Vec<u8>, String> {
        let mut row = self.native.decode_cols(secret, public, body, self.cols)?;
        row.truncate(self.row_bytes);
        Ok(row)
    }
}

/// Decodes `cols` 16-bit coefficients of one [`P16`] response. Every shape
/// [`zakura_pir_native::Profile::decode_cols`] refuses is an error here,
/// including no columns at all, unlike `zakura_pir_native`'s function of the
/// same name, which accepts an empty response for zero columns.
pub fn decode_cols(
    secret: &NativeSecret,
    public: &[u8],
    body: &[u8],
    cols: usize,
) -> Result<Vec<u8>, String> {
    P16.decode_cols(secret, public, body, cols)
}
