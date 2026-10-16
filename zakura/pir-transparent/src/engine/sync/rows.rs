use super::{IncompleteReason, SyncError, WorkLimits, budget_stopped};
use crate::engine::client::{ClientError, Table, TableClient, classify_transport};
use crate::engine::store::{SetupBlob, SetupKey, WalletStore};
use crate::engine::transport::ShardRequest;
use crate::engine::transport::{ByteCharges, ShardTransport};
use transparent_shard::manifest::ShardManifest;

/// One page row a walk asks for: page shard `child`, and a row over its
/// logical row space, which is its segments concatenated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RowRequest {
    pub(super) child: u32,
    pub(super) row: u64,
}

/// One private reply: the row from every table segment.
///
/// A reply that does not verify as a whole (its length, its revision binding,
/// the parameter epoch it was made under) fails its request, not an entry:
/// the service produces those without knowing which row the query selects,
/// so they cannot be aimed at one. Only the rows' own content, decoded and
/// checked, can fail an entry.
pub(super) type Reply = Vec<Vec<u8>>;

/// Where a walk's page rows come from: privately, or in tests, directly.
pub(super) trait RowSource {
    /// Why the walk must stop before another round, if it must.
    fn stopped(&self) -> Option<IncompleteReason>;
    /// Replies for a prefix of the requests, in order. A budget may stop
    /// dispatch between requests; each reply contains every table segment.
    fn fetch<S: WalletStore>(
        &mut self,
        store: &mut S,
        requests: &[RowRequest],
    ) -> Result<Vec<Reply>, SyncError>;
    /// A query whose reply is not read: row 0 of page shard `child`. Every
    /// query to a table selects among the same rows, so it is the length of
    /// any other query to that table, and the service cannot tell it apart.
    fn dummy(&self, child: u32) -> RowRequest {
        RowRequest { child, row: 0 }
    }
}

/// Page rows by private query against one directory shard revision.
pub(super) struct PirRows<'a, T: ShardTransport> {
    pub(super) entry: &'a transparent_filter::ShardMapEntry,
    pub(super) manifest: &'a ShardManifest,
    pub(super) client: &'a mut TableClient,
    pub(super) transport: &'a mut T,
    pub(super) charges: &'a mut ByteCharges,
    pub(super) limits: &'a WorkLimits,
    /// The budget the caller's transport declined a request for, once it has.
    pub(super) stop: Option<IncompleteReason>,
}

/// `result`, or `None` once the caller's transport declined the request for
/// its budget, which `stop` records: the round keeps the replies before it.
fn unless_budget<T>(
    stop: &mut Option<IncompleteReason>,
    result: Result<T, SyncError>,
) -> Result<Option<T>, SyncError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(SyncError::Client(ClientError::BudgetStop(budget))) => {
            *stop = Some(budget.reason());
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

impl<T: ShardTransport> RowSource for PirRows<'_, T> {
    fn stopped(&self) -> Option<IncompleteReason> {
        budget_stopped(self.charges, self.limits).or_else(|| self.stop.clone())
    }

    /// Sends a round's queries together when the transport overlaps
    /// requests, one at a time otherwise. Which queries are sent is the
    /// walk's alone; a batch changes only when.
    fn fetch<S: WalletStore>(
        &mut self,
        store: &mut S,
        requests: &[RowRequest],
    ) -> Result<Vec<Reply>, SyncError> {
        let shard_id = self.entry.shard_id;
        let revision = self.entry.manifest_digest.as_str();
        let geometry = transparent_shard::layout::by_name(&self.entry.geometry)
            .ok_or_else(|| SyncError::UnknownGeometry(self.entry.geometry.clone()))?;
        let set_digest = store
            .set_identity()?
            .map(|identity| identity.digest())
            .unwrap_or_default();
        if self.limits.max_private_bytes.is_none() && self.transport.concurrency() > 1 {
            let remaining = self
                .limits
                .max_queries
                .map(|limit| limit.saturating_sub(self.charges.queries()) as usize)
                .unwrap_or(requests.len());
            let requests = &requests[..requests.len().min(remaining)];
            // Each request: its table, segment count, query rows and row within.
            let mut planned = Vec::with_capacity(requests.len());
            for request in requests {
                let child = self
                    .manifest
                    .child(request.child)
                    .ok_or_else(|| SyncError::Invalid("a walk left the page shards".into()))?;
                let table = Table::Pages(request.child);
                let segments = child.page_segments.len() as u32;
                let opened = open_table(
                    store,
                    &set_digest,
                    shard_id,
                    revision,
                    table,
                    segments,
                    self.client,
                    self.transport,
                    self.charges,
                    None,
                );
                if unless_budget(&mut self.stop, opened)?.is_none() {
                    break;
                }
                let (_, within) =
                    transparent_shard::layout::split_row(request.row, geometry.page_rows);
                planned.push((
                    table,
                    segments,
                    child.query_rows() as usize,
                    within as usize,
                ));
            }
            let mut answers = Vec::with_capacity(planned.len());
            if self.transport.concurrency() <= 1 || planned.len() <= 1 {
                for (table, segments, query_rows, within) in planned {
                    let answer = self.client.fetch_row(
                        self.transport,
                        shard_id,
                        revision,
                        table,
                        segments,
                        query_rows,
                        within,
                        self.charges,
                    );
                    match unless_budget(&mut self.stop, answer.map_err(SyncError::from))? {
                        Some(answer) => answers.push(answer),
                        None => break,
                    }
                }
                return Ok(answers);
            }
            let mut queries = Vec::with_capacity(planned.len());
            for (table, _, query_rows, within) in &planned {
                queries.push(
                    self.client
                        .prepare_prefix(revision, *table, *query_rows, *within)?,
                );
            }
            let batch: Vec<ShardRequest<'_>> = planned
                .iter()
                .zip(&queries)
                .map(|((table, ..), query)| ShardRequest::Query {
                    shard_id,
                    revision,
                    table: *table,
                    body: &query.body,
                })
                .collect();
            let replies = self.transport.batch(&batch);
            drop(batch);
            // Charge the whole dispatched batch before any refusal or decoding
            // error can stop consumption of later replies.
            for ((table, ..), (query, reply)) in planned.iter().zip(queries.iter().zip(&replies)) {
                if let Some(reply) = reply {
                    self.charges
                        .add_query_reply(*table, query.body.len() as u64, reply);
                }
            }
            for (((table, segments, query_rows, within), query), reply) in
                planned.into_iter().zip(queries).zip(replies)
            {
                match reply {
                    Some(Ok((response, _))) => {
                        answers.push(
                            self.client
                                .decode(revision, table, segments, query, &response)?,
                        );
                    }
                    Some(Err(error)) => {
                        let failed: Result<(), _> =
                            Err(SyncError::Client(classify_transport(error)));
                        unless_budget(&mut self.stop, failed)?;
                        break;
                    }
                    None => {
                        let answer = self.client.fetch_row(
                            self.transport,
                            shard_id,
                            revision,
                            table,
                            segments,
                            query_rows,
                            within,
                            self.charges,
                        );
                        match unless_budget(&mut self.stop, answer.map_err(SyncError::from))? {
                            Some(answer) => answers.push(answer),
                            None => break,
                        }
                    }
                }
            }
            return Ok(answers);
        }
        let mut answers = Vec::with_capacity(requests.len());
        // A finite byte allowance is checked after each atomic response. Opening
        // all setups or dispatching a whole batch first would exceed that contract.
        for request in requests {
            if self.stopped().is_some() {
                break;
            }
            let child = self
                .manifest
                .child(request.child)
                .ok_or_else(|| SyncError::Invalid("a walk left the page shards".into()))?;
            let table = Table::Pages(request.child);
            let segments = child.page_segments.len() as u32;
            let opened = open_table(
                store,
                &set_digest,
                shard_id,
                revision,
                table,
                segments,
                self.client,
                self.transport,
                self.charges,
                Some(self.limits),
            );
            if unless_budget(&mut self.stop, opened)? != Some(true) {
                break;
            }
            if self.stopped().is_some() {
                break;
            }
            let (_, within) = transparent_shard::layout::split_row(request.row, geometry.page_rows);
            let answer = self.client.fetch_row(
                self.transport,
                shard_id,
                revision,
                table,
                segments,
                child.query_rows() as usize,
                within as usize,
                self.charges,
            );
            match unless_budget(&mut self.stop, answer.map_err(SyncError::from))? {
                Some(answer) => answers.push(answer),
                None => break,
            }
        }
        Ok(answers)
    }
}

/// Fetches the published setup for every segment of a shard's table, once,
/// reusing what the store holds under the exact set, revision and segment.
///
/// Each segment publishes its own `c1`, so each is opened separately; a shard
/// with one segment — the ordinary case — costs exactly one setup per table.
#[allow(clippy::too_many_arguments)]
pub(super) fn open_table<S: WalletStore>(
    store: &mut S,
    set_digest: &str,
    shard_id: u64,
    revision: &str,
    table: Table,
    segments: u32,
    client: &mut TableClient,
    transport: &mut impl ShardTransport,
    charges: &mut ByteCharges,
    limits: Option<&WorkLimits>,
) -> Result<bool, SyncError> {
    if segments == 0 {
        return Err(SyncError::Invalid(format!(
            "shard {shard_id} declares no {} segments",
            table.name()
        )));
    }
    for segment in 0..segments {
        if client.is_open(revision, table, segment) {
            continue;
        }
        let key = SetupKey {
            set_digest: set_digest.to_string(),
            revision_digest: revision.to_string(),
            table,
            segment,
        };
        let (params, digest) = match store.setup(&key)? {
            Some(blob) => (blob.public_params_base64, blob.public_params_sha256),
            None => {
                if limits
                    .and_then(|limits| budget_stopped(charges, limits))
                    .is_some()
                {
                    return Ok(false);
                }
                let reply = transport.setup(shard_id, revision, table, segment);
                if let Err(error) = &reply {
                    charges.add_failed_setup(table, error);
                }
                let (raw, cost) =
                    reply.map_err(|error| SyncError::from(classify_transport(error)))?;
                charges.add_setup(table, cost);
                let parsed: serde_json::Value = serde_json::from_slice(&raw)
                    .map_err(|error| SyncError::Transport(error.to_string()))?;
                let params = parsed["public_params"]
                    .as_str()
                    .ok_or_else(|| SyncError::Invalid("setup has no public_params".into()))?
                    .to_string();
                let digest = parsed["public_params_sha256"]
                    .as_str()
                    .ok_or_else(|| SyncError::Invalid("setup has no digest".into()))?
                    .to_string();
                (params, digest)
            }
        };
        client.open_segment(revision, table, segment, &params, &digest)?;
        // Kept only after the client verified it against its digest.
        store.put_setup(
            &key,
            &SetupBlob {
                public_params_base64: params,
                public_params_sha256: digest,
            },
        )?;
    }
    Ok(true)
}
