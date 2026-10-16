//! Work admission through actual directory PIR and durable page resumption.
use super::*;
use crate::engine::client::TableClient;
use crate::engine::transport::{BoxError, ShardTransport};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use transparent_native::TableProfile;

#[path = "../../testing/native.rs"]
mod native;

struct TableData {
    profile: Arc<TableProfile>,
    segment: native::Segment,
    query_rows: usize,
}
struct Fixture {
    directory: Directory,
    blocks: Vec<Block>,
    tables: BTreeMap<Table, TableData>,
}
fn small_fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let blocks: Vec<_> = (1..=8)
            .map(|height| {
                (
                    height,
                    (1..=2)
                        .map(|tag| {
                            (
                                ScriptBytes::new(script(tag)),
                                receive(height as u32, height as u32 * 10 + tag),
                            )
                        })
                        .collect(),
                )
            })
            .collect();
        let mut directories = build(&blocks);
        assert_eq!(directories.len(), 1);
        let directory = directories.remove(0);
        for tag in 1..=2 {
            assert!(
                directory_entry(&directory, &script(tag))
                    .unwrap()
                    .head()
                    .is_some()
            );
        }
        let g = directory.built.geometry;
        let mut tables = BTreeMap::new();
        let profile = Arc::new(
            TableProfile::new(
                transparent_shard::SCHEMA,
                g.name,
                "directory",
                g.directory_rows,
                g.directory_row_bytes as u32,
            )
            .unwrap(),
        );
        tables.insert(
            Table::Directory,
            TableData {
                segment: native::Segment::build(profile.clone(), &directory.built.directory[0])
                    .unwrap(),
                profile,
                query_rows: g.directory_rows as usize,
            },
        );
        let manifest = manifest_of(&directory);
        for child in &directory.children {
            let profile = Arc::new(
                TableProfile::new(
                    transparent_shard::SCHEMA,
                    g.name,
                    "pages",
                    g.page_rows,
                    g.page_row_bytes as u32,
                )
                .unwrap(),
            );
            assert_eq!(child.segments, 1);
            tables.insert(
                Table::Pages(child.index),
                TableData {
                    segment: native::Segment::build(profile.clone(), &child.pages).unwrap(),
                    profile,
                    query_rows: manifest.child(child.index).unwrap().query_rows() as usize,
                },
            );
        }
        Fixture {
            directory,
            blocks,
            tables,
        }
    })
}
struct Transport {
    setup: Vec<(Table, u32)>,
    queries: Vec<Table>,
    malformed_first: bool,
    refuse_first: bool,
}
impl Transport {
    fn new() -> Self {
        Self {
            setup: Vec::new(),
            queries: Vec::new(),
            malformed_first: false,
            refuse_first: false,
        }
    }
}
impl ShardTransport for Transport {
    fn init(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        unreachable!()
    }
    fn manifest(&mut self, _: u64, _: &str) -> Result<(Vec<u8>, u64), BoxError> {
        unreachable!()
    }
    fn setup(
        &mut self,
        _: u64,
        _: &str,
        table: Table,
        segment: u32,
    ) -> Result<(Vec<u8>, u64), BoxError> {
        self.setup.push((table, segment));
        let data = &small_fixture().tables[&table];
        Ok((
            serde_json::to_vec(
                &serde_json::json!({"public_params":STANDARD.encode(data.segment.public()),
            "public_params_sha256":data.segment.public_sha256()}),
            )?,
            1,
        ))
    }
    fn query(
        &mut self,
        _: u64,
        revision: &str,
        table: Table,
        body: &[u8],
    ) -> Result<Vec<u8>, BoxError> {
        self.queries.push(table);
        if self.refuse_first && self.queries.len() == 1 {
            return Err("synthetic transport refusal".into());
        }
        if self.malformed_first && self.queries.len() == 1 {
            return Ok(Vec::new());
        }
        let data = &small_fixture().tables[&table];
        let binding = transparent_shard::manifest::query_binding_for_schema(
            transparent_shard::SCHEMA,
            revision,
            &table.name(),
        );
        let (keys, query) = native::parse(&data.profile, binding, body, data.query_rows)?;
        data.segment
            .answer(binding, &keys, &query)
            .map_err(Into::into)
    }
}
fn clients() -> GeometryClients {
    let tables = &small_fixture().tables;
    let make = |table: Table| {
        let p = &tables[&table].profile;
        TableClient::new(
            table,
            small_fixture().directory.built.geometry.name,
            p.rows as u64,
            p.row_bytes as u32,
            &p.scheme,
            p.dithered_scheme.as_ref(),
        )
        .unwrap()
    };
    GeometryClients {
        directory: make(Table::Directory),
        pages: make(Table::Pages(0)),
    }
}
fn retrieve(
    store: &mut MemoryStore,
    scripts: &[Vec<u8>],
    transport: &mut Transport,
    limits: WorkLimits,
    segments: u32,
    choice: bool,
) -> Result<Option<Completion>, SyncError> {
    let fixture = small_fixture();
    let manifest = manifest_of(&fixture.directory);
    let mut entry = entry_of(&manifest);
    entry.directory_segments = segments;
    let salt = transparent_shard::tag_salt(
        entry.shard_id,
        &hash_at(entry.end_height),
        manifest.tag_salt_counter,
    );
    let chain = crate::engine::adapters::StaticChain {
        hashes: [(entry.end_height, entry.terminal_block_hash.clone())].into(),
    };
    let mut charges = ByteCharges::default();
    let mut failures = Failures::default();
    let result = super::super::shard::retrieve_shard_into(
        store,
        &entry,
        &manifest,
        scripts,
        &[],
        if choice {
            fixture.directory.built.choice.as_ref()
        } else {
            None
        },
        &salt,
        &mut clients(),
        transport,
        &mut charges,
        &limits,
        &target_of(&manifest),
        &chain,
        &mut failures,
    );
    assert!(failures.entries.is_empty());
    result
}
#[test]
fn directory_budget_admits_one_whole_pair_for_hits_misses_and_malformed_replies() {
    for (script, malformed, refusal) in [
        (script(1), false, false),
        (script(999), false, false),
        (script(1), true, false),
        (script(1), false, true),
    ] {
        let mut transport = Transport::new();
        transport.malformed_first = malformed;
        transport.refuse_first = refusal;
        let result = retrieve(
            &mut MemoryStore::new(),
            &[script, super::script(2)],
            &mut transport,
            WorkLimits {
                max_queries: Some(1),
                max_private_bytes: None,
            },
            1,
            false,
        );
        assert_eq!(transport.queries, vec![Table::Directory, Table::Directory]);
        if malformed || refusal {
            assert!(result.is_err());
        } else {
            assert!(matches!(
                result.unwrap(),
                Some(Completion::Incomplete {
                    reason: IncompleteReason::QueryBudget,
                    ..
                })
            ));
        }
    }
}
#[test]
fn choice_directory_budget_admits_one_fixed_query_per_group() {
    assert!(small_fixture().directory.built.choice.is_some());
    for (script, malformed, refusal) in [
        (script(1), false, false),
        (script(999), false, false),
        (script(1), true, false),
        (script(1), false, true),
    ] {
        let mut transport = Transport::new();
        transport.malformed_first = malformed;
        transport.refuse_first = refusal;
        let result = retrieve(
            &mut MemoryStore::new(),
            &[script, super::script(2)],
            &mut transport,
            WorkLimits {
                max_queries: Some(1),
                max_private_bytes: None,
            },
            1,
            true,
        );
        assert_eq!(transport.queries, vec![Table::Directory]);
        if malformed || refusal {
            assert!(result.is_err());
        } else {
            assert!(matches!(
                result.unwrap(),
                Some(Completion::Incomplete {
                    reason: IncompleteReason::QueryBudget,
                    ..
                })
            ));
        }
    }
}

#[test]
fn directory_setups_obey_byte_limits_before_opening_another_segment() {
    let mut transport = Transport::new();
    let result = retrieve(
        &mut MemoryStore::new(),
        &[script(1)],
        &mut transport,
        WorkLimits {
            max_queries: None,
            max_private_bytes: Some(1),
        },
        2,
        false,
    )
    .unwrap();
    assert!(matches!(
        result,
        Some(Completion::Incomplete {
            reason: IncompleteReason::ByteBudget,
            ..
        })
    ));
    assert_eq!(transport.setup, vec![(Table::Directory, 0)]);
    assert!(transport.queries.is_empty());
}
#[test]
fn capacity_one_and_one_query_passes_recover_two_paged_scripts_exactly() {
    let scripts = [script(1), script(2)];
    let mut unlimited = MemoryStore::new();
    assert!(
        retrieve(
            &mut unlimited,
            &scripts,
            &mut Transport::new(),
            WorkLimits::UNLIMITED,
            1,
            false
        )
        .unwrap()
        .is_none()
    );
    let mut bounded = MemoryStore::with_pending_limit(1);
    let mut completed = false;
    for _ in 0..32 {
        let remaining: Vec<_> = scripts
            .iter()
            .filter(|s| bounded.coverage(s).unwrap().is_empty())
            .cloned()
            .collect();
        if remaining.is_empty() {
            completed = true;
            break;
        }
        let mut transport = Transport::new();
        let result = retrieve(
            &mut bounded,
            &remaining,
            &mut transport,
            WorkLimits {
                max_queries: Some(1),
                max_private_bytes: None,
            },
            1,
            false,
        )
        .unwrap();
        assert!(
            result.is_none()
                || matches!(
                    result,
                    Some(Completion::Incomplete {
                        reason: IncompleteReason::QueryBudget,
                        ..
                    })
                )
        );
        assert!(bounded.pending().unwrap().len() <= 1);
        assert!(transport.queries.len() <= 2);
        let directory_queries = transport
            .queries
            .iter()
            .filter(|t| **t == Table::Directory)
            .count();
        assert!(directory_queries == 0 || directory_queries == 2);
    }
    assert!(
        completed,
        "bounded calls must progress, not repeat an oversized pending commit"
    );
    assert!(bounded.pending().unwrap().is_empty());
    for script in &scripts {
        assert_eq!(stored(&bounded, script), stored(&unlimited, script));
        assert_eq!(
            stored(&bounded, script),
            history(&small_fixture().blocks, &small_fixture().directory, script)
        );
        assert_eq!(
            bounded.coverage(script).unwrap(),
            unlimited.coverage(script).unwrap()
        );
    }
    assert_eq!(
        bounded.ledger().unwrap().confirmed_balance(),
        unlimited.ledger().unwrap().confirmed_balance()
    );
}
#[test]
fn zero_pending_capacity_stops_before_setup_queries_or_partial_events() {
    let mut store = MemoryStore::with_pending_limit(0);
    let mut transport = Transport::new();
    assert!(matches!(
        retrieve(
            &mut store,
            &[script(1), script(2)],
            &mut transport,
            WorkLimits::UNLIMITED,
            1,
            false
        )
        .unwrap(),
        Some(Completion::Incomplete {
            reason: IncompleteReason::PendingLimit,
            pending: 0
        })
    ));
    assert!(transport.setup.is_empty());
    assert!(transport.queries.is_empty());
    assert!(store.events().unwrap().is_empty());
    assert!(store.pending().unwrap().is_empty());
    assert!(store.coverage(&script(1)).unwrap().is_empty());
}

#[test]
fn a_failed_page_batch_charges_every_dispatched_query_before_returning() {
    struct ConcurrentRefusal(Transport);
    impl ShardTransport for ConcurrentRefusal {
        fn concurrency(&self) -> usize {
            2
        }
        fn init(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
            unreachable!()
        }
        fn manifest(&mut self, _: u64, _: &str) -> Result<(Vec<u8>, u64), BoxError> {
            unreachable!()
        }
        fn setup(
            &mut self,
            id: u64,
            revision: &str,
            table: Table,
            segment: u32,
        ) -> Result<(Vec<u8>, u64), BoxError> {
            self.0.setup(id, revision, table, segment)
        }
        fn query(&mut self, _: u64, _: &str, table: Table, _: &[u8]) -> Result<Vec<u8>, BoxError> {
            self.0.queries.push(table);
            if self.0.queries.len() == 1 {
                Err(crate::engine::transport::TransferFailure::boxed(
                    17,
                    crate::engine::transport::Overloaded { retry_after: None }.boxed(),
                ))
            } else {
                Ok(vec![0; 23])
            }
        }
        fn batch(
            &mut self,
            requests: &[crate::engine::transport::ShardRequest<'_>],
        ) -> Vec<Option<crate::engine::transport::ShardReply>> {
            requests
                .iter()
                .map(|request| {
                    let crate::engine::transport::ShardRequest::Query {
                        shard_id,
                        revision,
                        table,
                        body,
                    } = *request
                    else {
                        unreachable!()
                    };
                    Some(self.query(shard_id, revision, table, body).map(|bytes| {
                        let cost = bytes.len() as u64;
                        (bytes, cost)
                    }))
                })
                .collect()
        }
    }
    let fixture = small_fixture();
    let manifest = manifest_of(&fixture.directory);
    let entry = entry_of(&manifest);
    let child = manifest.page_children[0].index;
    let table = Table::Pages(child);
    let mut clients = clients();
    let query_rows = manifest.child(child).unwrap().query_rows() as usize;
    let upload = clients
        .pages
        .prepare_prefix(&entry.manifest_digest, table, query_rows, 0)
        .unwrap()
        .body
        .len() as u64;
    let mut transport = ConcurrentRefusal(Transport::new());
    let mut charges = ByteCharges::default();
    let mut rows = PirRows {
        entry: &entry,
        manifest: &manifest,
        client: &mut clients.pages,
        transport: &mut transport,
        charges: &mut charges,
        limits: &WorkLimits::UNLIMITED,
        stop: None,
    };
    assert!(matches!(
        rows.fetch(
            &mut MemoryStore::new(),
            &[RowRequest { child, row: 0 }, RowRequest { child, row: 0 }]
        ),
        Err(SyncError::Client(ClientError::Overloaded(_)))
    ));
    assert_eq!(transport.0.queries, vec![table, table]);
    assert_eq!(charges.queries(), 2);
    assert_eq!(charges.query_upload(), 2 * upload);
    assert_eq!(charges.query_download(), 17 + 23);
}

#[test]
fn failed_setup_response_bytes_stop_the_next_attempt_at_the_byte_allowance() {
    struct RefusingSetup {
        calls: u32,
    }
    impl ShardTransport for RefusingSetup {
        fn init(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
            unreachable!()
        }
        fn manifest(&mut self, _: u64, _: &str) -> Result<(Vec<u8>, u64), BoxError> {
            unreachable!()
        }
        fn setup(&mut self, _: u64, _: &str, _: Table, _: u32) -> Result<(Vec<u8>, u64), BoxError> {
            self.calls += 1;
            Err(crate::engine::transport::TransferFailure::boxed(
                17,
                crate::engine::transport::Overloaded { retry_after: None }.boxed(),
            ))
        }
        fn query(&mut self, _: u64, _: &str, _: Table, _: &[u8]) -> Result<Vec<u8>, BoxError> {
            unreachable!()
        }
    }
    let mut transport = RefusingSetup { calls: 0 };
    let mut store = MemoryStore::new();
    let mut clients = clients();
    let mut charges = ByteCharges::default();
    let limits = WorkLimits {
        max_queries: None,
        max_private_bytes: Some(17),
    };
    assert!(matches!(
        open_table(
            &mut store,
            "set",
            7,
            "revision",
            Table::Directory,
            1,
            &mut clients.directory,
            &mut transport,
            &mut charges,
            Some(&limits)
        ),
        Err(SyncError::Client(ClientError::Overloaded(_)))
    ));
    assert_eq!(charges.setup_bytes(), 17);
    assert_eq!(charges.shards_opened(), 0);
    assert!(
        !open_table(
            &mut store,
            "set",
            7,
            "revision",
            Table::Directory,
            1,
            &mut clients.directory,
            &mut transport,
            &mut charges,
            Some(&limits)
        )
        .unwrap()
    );
    assert_eq!(transport.calls, 1);
}
