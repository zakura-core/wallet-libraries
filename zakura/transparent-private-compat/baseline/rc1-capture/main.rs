//! `cargo run -- <output dir>`: an interrupted wallet written by 0.0.1-rc1.
use std::path::PathBuf;

#[path = "../../../src/dump.rs"]
mod dump;

mod api {
    pub use base_backend as backend;
    pub use base_recovery as recovery;
    pub use base_recovery::testing::transparent_events as events;
    pub use base_sqlite as sqlite;
    pub mod filter {
        pub use base_recovery::testing::transparent_filter::*;
    }
    pub mod fixture {
        pub use base_recovery::testing::service;
    }
}

#[allow(dead_code)]
mod scenario {
    use super::{api, dump};
    include!("../../../src/scenario.rs");
}

fn main() {
    let out = PathBuf::from(std::env::args().nth(1).expect("an output directory"));
    let work = tempfile::tempdir().unwrap();
    let interrupted = scenario::interrupted(work.path());
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("wallet.sql"), &interrupted.wallet_sql).unwrap();
    std::fs::write(out.join("companion.sql"), &interrupted.companion_sql).unwrap();
    std::fs::write(out.join("account"), &interrupted.account).unwrap();
    std::fs::write(out.join("owned"), interrupted.owned.join("\n") + "\n").unwrap();
    std::fs::write(out.join("notes.txt"), interrupted.notes.join("\n") + "\n").unwrap();
}
