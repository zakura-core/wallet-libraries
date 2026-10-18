//! A standalone consumer: opens and reopens a companion with no wallet backend.
//! An empty watch set needs no publication I/O and grants no financial authority.
use zakura_pir_client::transparent::{
    BatchState, HttpExchange, HttpFailure, HttpReply, HttpRequest, Outcome,
    TransparentHistoryRecovery, TransparentHistoryRecoveryConfig,
    engine::{Acceptance, Anchor, ChainView},
    recovery_types::{AccountLifecycle, ChainPoint, RecoveryBlockHash, TransparentAddressWatchSet},
};

struct LocalChain;
impl ChainView for LocalChain {
    fn is_accepted(&self, height: u64, hash: &str) -> Acceptance {
        if height == 1 && hash == RecoveryBlockHash([7; 32]).to_string() {
            Acceptance::Accepted
        } else {
            Acceptance::Unknown
        }
    }
    fn tip(&self) -> Option<Anchor> {
        Some(Anchor {
            height: 1,
            hash: RecoveryBlockHash([7; 32]).to_string(),
        })
    }
}

struct NoRequests;
impl HttpExchange for NoRequests {
    fn send(&self, _: &HttpRequest) -> Result<HttpReply, HttpFailure> {
        panic!("an empty watch set must not send a network request")
    }
}

#[test]
fn previous_companion_reopens_and_replays_unacknowledged_work()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("companion.sqlite");
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute_batch(include_str!("fixtures/pre-packaging-companion.sql"))?;
    let schema_before = schema(&connection)?;
    drop(connection);
    let config = TransparentHistoryRecoveryConfig {
        source: b"standalone-example".to_vec(),
        account_binding: vec![1],
        origin: "https://example.invalid".into(),
        scripts: 1,
        shards: 1,
        events: 1,
        queries: 1,
        private_bytes: 1024,
    };
    let watch = TransparentAddressWatchSet {
        account: 1u32,
        lifecycle: AccountLifecycle::Candidate,
        policy_generation: 0,
        target: Some(ChainPoint {
            height: 1u32.into(),
            hash: RecoveryBlockHash([7; 32]),
        }),
        addresses: vec![],
        pending_pages: vec![],
    };
    // Dropping a batch does not acknowledge it. Reopening retains the same companion.
    for _ in 0..2 {
        let mut recovery = TransparentHistoryRecovery::open(&path, config.clone())?;
        let report = recovery.pass(&watch, &LocalChain, NoRequests, 1024, &|| false)?;
        assert_eq!(report.state, BatchState::Ready);
        let batch = recovery
            .take_latest::<u32>()
            .expect("the ready batch is retained");
        assert!(batch.commits().is_empty());
        assert_eq!(batch.progress().outcome, Outcome::Complete);
    }
    let connection = rusqlite::Connection::open(&path)?;
    assert_eq!(
        schema(&connection)?,
        schema_before,
        "reopening must not change stored formats"
    );
    Ok(())
}

fn schema(connection: &rusqlite::Connection) -> rusqlite::Result<Vec<(String, String)>> {
    connection
        .prepare("SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect()
}
