//! Private retrieval of directory rows and pages from a shard set.
//!
//! One `TableClient` per geometry per table, reused across every shard naming
//! that geometry. That reuse is the point of naming geometries from a closed
//! registry rather than letting each shard choose: the expensive part of a
//! session — the parameter re-derivation and the public query setup — is done
//! once per geometry rather than once per shard. Both are the native
//! ReinspiRING two-mask profile of `transparent-native`. A sync spanning an archive
//! tier and a recent tier pays it twice, not once per shard in either.
//!
//! What *is* per segment is the published pair of masks, because it is derived
//! from that segment's own database. So a shard *revision* is "opened" by fetching the
//! setup of each of its segments, and those bytes are charged once per segment
//! per sync. A shard normally has one segment; one whose content did not fit
//! its geometry has more, and every one of them answers each query, so the
//! segment holding a script is never named in a request.
//!
//! Setup is cached against the **manifest digest**, not the shard id. A growing
//! tail is republished as a new revision with different bytes, so setup cached
//! under the id would be reused against a database it was not derived from —
//! which does not error, it decodes to plausible nonsense.
//!
//! Everything the server sends is re-derived rather than trusted. A client that
//! adopted the server's parameters would decode against whatever geometry the
//! server chose, including one that leaks the selection.
//!
//! The directory and pages use the 8-bit profile, whose one scheme is a
//! 28-bit dithered query. A 16-bit table publishes a 49-bit scheme and may
//! advertise a 44-bit dithered one beside it; the query uses the 44 bits only
//! when that scheme reproduces exactly, and otherwise the 49 bits, which are
//! still checked whole.

use crate::transport::{BoxError, ByteCharges, Overloaded, ShardTransport, StaleRevision};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use transparent_native::{NativeScheme, NativeSecret, TableProfile};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("session: {0}")]
    Session(String),
    #[error("response: {0}")]
    Response(String),
    #[error("transport: {0}")]
    Transport(String),
    #[error("pir: {0}")]
    Pir(String),
    /// The service no longer serves the revision this query named.
    ///
    /// Kept as a type rather than folded into `Transport`: it is recoverable by
    /// refreshing the map and re-deriving the shard, and a string cannot be
    /// matched on. Every query goes through here, so collapsing it here would
    /// lose the refusal for all of them.
    #[error(transparent)]
    Stale(#[from] StaleRevision),
    /// The service had no cache capacity for this query. Retryable as it
    /// stands, without refreshing anything.
    #[error(transparent)]
    Overloaded(#[from] Overloaded),
    /// A reply was made under other published parameters than the setup the
    /// wallet holds for that segment. The held setup is stale: the caller
    /// drops it, so the next attempt fetches the published one again.
    #[error("revision {revision} table {} segment {segment}: the reply was made under other parameters than the setup held", .table.name())]
    SetupMismatch {
        revision: String,
        table: Table,
        segment: u32,
    },
}

/// Which table a query addresses.
///
/// A directory shard has one directory table and up to
/// [`MAX_PAGE_CHILDREN`](transparent_shard::MAX_PAGE_CHILDREN) page tables,
/// one per page shard, named `pages-<j>` on the wire. Native parameters are
/// per table *kind*: every `pages-<j>` of a geometry shares one scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Table {
    Directory,
    /// The pages table of page shard `j`.
    Pages(u32),
}

impl Table {
    /// The table kind native parameters are derived for.
    pub fn kind(self) -> &'static str {
        match self {
            Table::Directory => "directory",
            Table::Pages(_) => "pages",
        }
    }

    /// The table's name on the wire: `directory` or `pages-<j>`.
    pub fn name(self) -> String {
        match self {
            Table::Directory => "directory".to_string(),
            Table::Pages(child) => transparent_shard::manifest::pages_table(child),
        }
    }

    /// The table a wire name addresses, or `None` for any other name.
    pub fn parse(name: &str) -> Option<Self> {
        if name == "directory" {
            return Some(Table::Directory);
        }
        transparent_shard::manifest::parse_pages_table(name).map(Table::Pages)
    }
}

/// A prepared query and the secret needed to decode its response.
pub struct PreparedQuery {
    pub body: Vec<u8>,
    secret: NativeSecret,
}

/// One segment's published setup for one table: its two rounded masks, as
/// downloaded, and the epoch they imply.
struct SegmentSetup {
    public: Vec<u8>,
    epoch: [u8; 8],
}

/// A client for one table kind of one geometry, across every shard.
///
/// One pages client serves every `pages-<j>` table: the scheme is per kind,
/// while each table's published setup, binding and stash are per table name.
pub struct TableClient {
    schema: String,
    /// The kind this client was derived for; see [`Table::kind`].
    kind: &'static str,
    profile: TableProfile,
    /// Whether queries go at 44 dithered bits, which the service advertised
    /// and this client reproduced, rather than 49.
    dithered: bool,
    /// Per segment, because the published masks come from each segment's own
    /// database. Keyed by manifest digest, table name and segment index, so a
    /// superseded revision's setup is never reused for the revision that
    /// replaced it, and one page shard's never for another's.
    segments: HashMap<(String, String, u32), SegmentSetup>,
    /// Queries a batch already sent, per revision and table, in the order the
    /// walk will ask for their rows. See [`TableClient::stash`].
    stashed: HashMap<(String, String), VecDeque<Stashed>>,
}

/// A query sent ahead of the walk, with its outcome.
struct Stashed {
    row: usize,
    query: PreparedQuery,
    reply: Result<Vec<u8>, BoxError>,
}

impl TableClient {
    /// Builds a client for one table kind of `geometry`, re-deriving the
    /// native parameters — bit widths, query masks and packing setup — rather
    /// than adopting what the service published.
    ///
    /// `table` names the kind; any `Table::Pages(_)` builds the client every
    /// page table of the geometry shares. `served` is the 49-bit scheme,
    /// which must reproduce. `served_dithered` is the 44-bit dithered scheme,
    /// if the service advertised one: queries use it only when it reproduces
    /// too, and otherwise fall back to 49 bits.
    pub fn new(
        table: Table,
        geometry: &str,
        rows: u64,
        row_bytes: u32,
        served: &NativeScheme,
        served_dithered: Option<&NativeScheme>,
    ) -> Result<Self, ClientError> {
        Self::new_with_schema(
            transparent_shard::SCHEMA,
            table,
            geometry,
            rows,
            row_bytes,
            served,
            served_dithered,
        )
    }

    pub fn new_with_schema(
        schema: &str,
        table: Table,
        geometry: &str,
        rows: u64,
        row_bytes: u32,
        served: &NativeScheme,
        served_dithered: Option<&NativeScheme>,
    ) -> Result<Self, ClientError> {
        if !transparent_shard::manifest::supported_schema(schema) {
            return Err(ClientError::Session("unsupported schema".into()));
        }
        let kind = table.kind();
        let profile =
            TableProfile::new(schema, geometry, kind, rows, row_bytes).map_err(ClientError::Pir)?;
        if served != &profile.scheme {
            return Err(ClientError::Session(format!(
                "{kind} scheme does not match the pinned geometry"
            )));
        }
        // Compared whole, like the 49-bit scheme. One that does not reproduce
        // is not adopted; the query falls back to the 49 bits checked above.
        let dithered = profile
            .dithered_scheme
            .as_ref()
            .is_some_and(|scheme| served_dithered == Some(scheme));
        Ok(Self {
            schema: schema.to_string(),
            kind,
            profile,
            dithered,
            segments: HashMap::new(),
            stashed: HashMap::new(),
        })
    }

    pub fn rows(&self) -> usize {
        self.profile.rows
    }

    /// Bits each selection coefficient is sent at: the scheme's own (28 for
    /// the 8-bit tables, 49 for a 16-bit one), or 44 when a 16-bit table's
    /// service advertised the dithered scheme and it reproduced.
    pub fn query_bits(&self) -> usize {
        match &self.profile.dithered_scheme {
            Some(scheme) if self.dithered => scheme.query_bits,
            _ => self.profile.scheme.query_bits,
        }
    }

    fn check_kind(&self, table: Table) -> Result<(), ClientError> {
        if table.kind() != self.kind {
            return Err(ClientError::Session(format!(
                "a {} client cannot address table {}",
                self.kind,
                table.name()
            )));
        }
        Ok(())
    }

    /// Records one segment's published setup after checking it against its
    /// digest.
    pub fn open_segment(
        &mut self,
        revision: &str,
        table: Table,
        segment: u32,
        public_params_base64: &str,
        public_params_sha256: &str,
    ) -> Result<(), ClientError> {
        self.check_kind(table)?;
        let public_params = BASE64_STANDARD
            .decode(public_params_base64.as_bytes())
            .map_err(|error| ClientError::Session(error.to_string()))?;
        let digest = Sha256::digest(&public_params);
        if hex::encode(digest) != public_params_sha256 {
            return Err(ClientError::Session(format!(
                "revision {revision} published parameter digest mismatch"
            )));
        }
        if public_params.len() != self.profile.scheme.public_bytes {
            return Err(ClientError::Session(format!(
                "revision {revision} published parameter length mismatch"
            )));
        }
        let mut epoch = [0u8; 8];
        epoch.copy_from_slice(&digest[..8]);
        self.segments.insert(
            (revision.to_string(), table.name(), segment),
            SegmentSetup {
                public: public_params,
                epoch,
            },
        );
        Ok(())
    }

    /// Drops one segment's setup, so it is opened again before the next query.
    pub(crate) fn forget(&mut self, revision: &str, table: Table, segment: u32) {
        self.segments
            .remove(&(revision.to_string(), table.name(), segment));
    }

    pub fn is_open(&self, revision: &str, table: Table, segment: u32) -> bool {
        self.segments
            .contains_key(&(revision.to_string(), table.name(), segment))
    }

    /// Prepares one query against a named revision and table.
    ///
    /// The body opens with the revision-and-table binding, which the service
    /// re-derives and checks and the response repeats. It is a fixed-width
    /// public value — the revision is already in the request path and in the
    /// published map — so it discloses nothing while making a query answered by
    /// the wrong runtime fail rather than decode. A fresh secret is sampled for
    /// every query and never leaves the returned value.
    pub fn prepare(
        &self,
        revision: &str,
        table: Table,
        row: usize,
    ) -> Result<PreparedQuery, ClientError> {
        self.prepare_prefix(revision, table, self.profile.rows, row)
    }

    /// Prepares one query that selects among only the first `query_rows`,
    /// which the revision's verified manifest fixes for every query to the
    /// table (see [`PageChild::query_rows`]). Never derived from `row`: the
    /// upload's length is all the service learns from it.
    ///
    /// [`PageChild::query_rows`]: transparent_shard::manifest::PageChild::query_rows
    pub fn prepare_prefix(
        &self,
        revision: &str,
        table: Table,
        query_rows: usize,
        row: usize,
    ) -> Result<PreparedQuery, ClientError> {
        self.check_kind(table)?;
        if row >= query_rows || query_rows > self.profile.rows {
            return Err(ClientError::Session("row outside table".into()));
        }
        let (secret, upload) = if self.dithered {
            self.profile.prepare_dithered_prefix(query_rows, row)
        } else {
            self.profile.prepare_prefix(query_rows, row)
        }
        .map_err(ClientError::Pir)?;
        let mut body = transparent_shard::manifest::query_binding_for_schema(
            &self.schema,
            revision,
            &table.name(),
        )
        .to_vec();
        body.extend(upload);
        Ok(PreparedQuery { body, secret })
    }

    /// Decodes one answer: one row per segment, in segment order.
    ///
    /// Every segment answered the same query, so the response carries as many
    /// bodies as the table has segments and the caller decides which row it
    /// was looking for — by the exact script tag, never by position.
    pub fn decode(
        &self,
        revision: &str,
        table: Table,
        segments: u32,
        query: PreparedQuery,
        response: &[u8],
    ) -> Result<Vec<Vec<u8>>, ClientError> {
        self.check_kind(table)?;
        let name = table.name();
        let binding =
            transparent_shard::manifest::query_binding_for_schema(&self.schema, revision, &name);
        let each = 16 + self.profile.scheme.response_bytes;
        // A fixed length per segment, and a fixed segment count from the
        // verified manifest: a response of any other size is not this table's.
        if response.len() != each * segments as usize {
            return Err(ClientError::Response("response length mismatch".into()));
        }

        let mut rows = Vec::with_capacity(segments as usize);
        for segment in 0..segments {
            let part = &response[segment as usize * each..(segment as usize + 1) * each];
            let setup = self
                .segments
                .get(&(revision.to_string(), name.clone(), segment))
                .ok_or_else(|| {
                    ClientError::Session(format!(
                        "revision {revision} table {name} segment {segment} is not open"
                    ))
                })?;
            // The prefix binds the response to the revision and table the query
            // named, so an answer produced from another revision's bytes fails
            // here rather than decoding to plausible rows for a range the
            // wallet did not ask about. The epoch does the same for the
            // segment, since each segment publishes its own masks.
            if part.get(..8) != Some(binding.as_slice()) {
                return Err(ClientError::Response("revision or table mismatch".into()));
            }
            if part.get(8..16) != Some(setup.epoch.as_slice()) {
                return Err(ClientError::SetupMismatch {
                    revision: revision.to_string(),
                    table,
                    segment,
                });
            }
            let row = self
                .profile
                .decode(&query.secret, &setup.public, &part[16..])
                .map_err(ClientError::Response)?;
            if row.len() != self.profile.row_bytes {
                return Err(ClientError::Response("decoded row is too short".into()));
            }
            rows.push(row);
        }
        Ok(rows)
    }

    /// Keeps a query that was sent ahead of the walk, with its outcome, for
    /// the walk's next [`fetch_row`](Self::fetch_row) of that revision and
    /// table.
    ///
    /// Stashed queries are handed out once, in order, and only for the row
    /// they were prepared for: the first request that does not match drops
    /// the stash and goes to the network. A stashed refusal or failure is
    /// returned as if the query had just been sent, and drops the rest of the
    /// stash, so whatever the walk does next — a retry, a refresh — is a
    /// fresh request.
    pub(crate) fn stash(
        &mut self,
        revision: &str,
        table: Table,
        row: usize,
        query: PreparedQuery,
        reply: Result<Vec<u8>, BoxError>,
    ) {
        self.stashed
            .entry((revision.to_string(), table.name()))
            .or_default()
            .push_back(Stashed { row, query, reply });
    }

    /// Drops every stashed query.
    pub(crate) fn clear_stash(&mut self) {
        self.stashed.clear();
    }

    /// Fetches one row from every segment of a table, charging what it cost.
    ///
    /// The query selects among the first `query_rows`; see
    /// [`prepare_prefix`](Self::prepare_prefix). Uses a query a batch already
    /// sent for this row when one is stashed; the charge is the same either way.
    #[allow(clippy::too_many_arguments)]
    pub fn fetch_row(
        &mut self,
        transport: &mut impl ShardTransport,
        shard_id: u64,
        revision: &str,
        table: Table,
        segments: u32,
        query_rows: usize,
        row: usize,
        charges: &mut ByteCharges,
    ) -> Result<Vec<Vec<u8>>, ClientError> {
        let key = (revision.to_string(), table.name());
        if let Some(queue) = self.stashed.get_mut(&key) {
            let next = queue.pop_front();
            if queue.is_empty() {
                self.stashed.remove(&key);
            }
            match next {
                Some(stashed)
                    if stashed.row == row
                        && stashed.query.body.len()
                            == 8 + self
                                .profile
                                .native
                                .request_len_bits(query_rows, self.query_bits()) =>
                {
                    let response = match stashed.reply {
                        Ok(response) => response,
                        Err(error) => {
                            self.stashed.remove(&key);
                            return Err(classify_transport(error));
                        }
                    };
                    charges.add_query(
                        table,
                        stashed.query.body.len() as u64,
                        response.len() as u64,
                    );
                    return self.decode(revision, table, segments, stashed.query, &response);
                }
                // Out of step with the walk: nothing further is trusted to
                // line up, so the rest of this table goes to the network.
                _ => {
                    self.stashed.remove(&key);
                }
            }
        }
        let query = self.prepare_prefix(revision, table, query_rows, row)?;
        let uploaded = query.body.len() as u64;
        let response = transport
            .query(shard_id, revision, table, &query.body)
            .map_err(classify_transport)?;
        charges.add_query(table, uploaded, response.len() as u64);
        self.decode(revision, table, segments, query, &response)
    }
}

/// Sorts a boxed transport error into the refusals a caller can act on.
///
/// The refusals are recovered before the fallback, because both are boxed into
/// the same `BoxError` as an ordinary failure and stringifying first would
/// throw away the only thing that distinguishes them.
pub(crate) fn classify_transport(error: crate::transport::BoxError) -> ClientError {
    if let Some(stale) = StaleRevision::found_in(&error) {
        return ClientError::Stale(stale.clone());
    }
    if let Some(overloaded) = Overloaded::found_in(&error) {
        return ClientError::Overloaded(overloaded.clone());
    }
    ClientError::Transport(crate::transport::describe_error(error.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(table: Table) -> TableProfile {
        TableProfile::new(
            transparent_shard::SCHEMA,
            "recent-4k",
            table.kind(),
            4_096,
            4_096,
        )
        .unwrap()
    }

    fn client(table: Table, dithered: Option<&NativeScheme>) -> TableClient {
        let profile = profile(table);
        TableClient::new(table, "recent-4k", 4_096, 4_096, &profile.scheme, dithered).unwrap()
    }

    fn body_len(client: &TableClient, table: Table) -> usize {
        client.prepare("revision", table, 17).unwrap().body.len()
    }

    /// The directory and pages are queried at the 8-bit profile's 28 bits,
    /// with its one-digit packing key.
    #[test]
    fn history_tables_send_the_28_bit_query() {
        for table in [Table::Directory, Table::Pages(0)] {
            let profile = profile(table);
            let client = client(table, None);
            assert_eq!(client.query_bits(), 28);
            assert_eq!(body_len(&client, table), 8 + profile.scheme.request_bytes);
            assert_eq!(body_len(&client, table), 8 + 13_824 + 4_096 * 28 / 8);
        }
    }

    /// An 8-bit table has no second width: a dithered scheme a service
    /// advertises beside it is ignored, here another table's.
    #[test]
    fn an_advertised_second_scheme_is_ignored() {
        let pages = profile(Table::Pages(0));
        let client = client(Table::Directory, Some(&pages.scheme));
        assert_eq!(client.query_bits(), 28);
    }

    /// The served scheme must reproduce whatever else the service advertises.
    #[test]
    fn the_scheme_must_reproduce() {
        let profile = profile(Table::Directory);
        let mut moved = profile.scheme.clone();
        moved.rows = 8_192;
        let refused = TableClient::new(
            Table::Directory,
            "recent-4k",
            4_096,
            4_096,
            &moved,
            Some(&profile.scheme),
        );
        assert!(matches!(refused, Err(ClientError::Session(_))));
    }
}
