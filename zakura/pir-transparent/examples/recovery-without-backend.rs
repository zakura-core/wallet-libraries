//! A standalone consumer: opens and reopens a companion with no wallet backend.
//! An empty watch set needs no publication I/O and grants no financial authority.
use zakura_pir_transparent::{
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let directory =
        std::env::temp_dir().join(format!("pir-recovery-contract-{}", std::process::id()));
    std::fs::create_dir(&directory)?;
    let path = directory.join("companion.sqlite");
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
    std::fs::remove_dir_all(directory)?;
    Ok(())
}
