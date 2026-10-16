//! The current crates against the baseline release itself, built from its
//! pinned commit, in both directions: the two publishers write the same
//! bytes, a current wallet recovers from the baseline's shard service and a
//! baseline wallet from the current one, each exactly as the baseline wallet
//! recovered from the baseline service when the fixtures were frozen.

use std::path::Path;

use zakura_transparent_private_compat::dump;

mod baseline_api {
    pub use base_backend as backend;
    pub use base_events as events;
    pub use base_native as native;
    pub use base_recovery as recovery;
    pub use base_shard as shard;
    pub use base_sqlite as sqlite;
    pub mod filter {
        pub use base_filter::*;
    }
    pub mod filter_build {
        pub use base_filter::{build_filter, build_range_filter_for};
    }
    pub mod shard_build {
        pub use base_shard::display::build_shard as display_build_shard;
    }
    pub mod fixture {
        pub use base_recovery::testing::{native, service};
    }
    pub mod traits {}
}

mod current_api {
    include!("common/current_api.rs");
}

mod baseline_publisher {
    use super::baseline_api as api;
    include!("../src/vectors.rs");
}

mod current_publisher {
    use super::current_api as api;
    include!("../src/vectors.rs");
}

/// A current wallet and its wallet crates; the baseline publisher and service.
#[allow(dead_code)]
mod current_wallet_baseline_service {
    mod api {
        pub use crate::baseline_api::{events, filter, fixture};
        pub use crate::current_api::{backend, recovery, sqlite};
    }
    use super::dump;
    include!("../src/scenario.rs");
}

/// A baseline wallet and its wallet crates; the current publisher and service.
#[allow(dead_code)]
mod baseline_wallet_current_service {
    mod api {
        pub use crate::baseline_api::{backend, recovery, sqlite};
        pub use crate::current_api::{events, filter, fixture};
    }
    use super::dump;
    include!("../src/scenario.rs");
}

/// The baseline throughout, to show the frozen files are reproducible.
#[allow(dead_code)]
mod baseline_throughout {
    use super::{baseline_api as api, dump};
    include!("../src/scenario.rs");
}

fn baseline(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("baseline")
        .join(name)
}

fn frozen_notes() -> String {
    std::fs::read_to_string(baseline("interrupted/notes.txt")).unwrap()
}

#[test]
fn both_publishers_write_the_same_bytes() {
    let work = tempfile::tempdir().unwrap();
    let old = baseline_publisher::vectors(&work.path().join("baseline"));
    let new = current_publisher::vectors(&work.path().join("current"));
    let differing: Vec<_> = old
        .iter()
        .filter(|(name, value)| new.get(*name) != Some(value))
        .map(|(name, _)| name.clone())
        .collect();
    assert!(differing.is_empty(), "differ: {differing:?}");
    assert_eq!(old.len(), new.len());
}

#[test]
fn a_current_wallet_recovers_from_the_baseline_service() {
    let work = tempfile::tempdir().unwrap();
    let run = current_wallet_baseline_service::interrupted(work.path());
    assert_eq!(run.notes.join("\n") + "\n", frozen_notes());
}

#[test]
fn a_baseline_wallet_recovers_from_the_current_service() {
    let work = tempfile::tempdir().unwrap();
    let run = baseline_wallet_current_service::interrupted(work.path());
    assert_eq!(run.notes.join("\n") + "\n", frozen_notes());
}

#[test]
fn the_baseline_reproduces_its_frozen_resumption() {
    for (source, frozen) in [("interrupted", "baseline"), ("interrupted-rc1", "rc1")] {
        let dir = baseline(source);
        let from = baseline_throughout::Interrupted {
            account: std::fs::read_to_string(dir.join("account")).unwrap(),
            owned: std::fs::read_to_string(dir.join("owned"))
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect(),
            wallet_sql: std::fs::read_to_string(dir.join("wallet.sql")).unwrap(),
            companion_sql: std::fs::read_to_string(dir.join("companion.sql")).unwrap(),
            notes: Vec::new(),
        };
        let work = tempfile::tempdir().unwrap();
        let (snapshots, notes) = baseline_throughout::resume(&from, work.path());
        let expected: baseline_throughout::Resumed = serde_json::from_str(
            &std::fs::read_to_string(baseline(&format!("resumed-{frozen}.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(snapshots, expected, "{source}");
        assert_eq!(
            notes.join("\n") + "\n",
            std::fs::read_to_string(baseline(&format!("resumed-{frozen}.txt"))).unwrap()
        );
    }
}
