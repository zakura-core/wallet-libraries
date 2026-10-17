//! Writes the frozen baseline under `baseline/` from the baseline release.
//!
//! `cargo run --features live-baseline --bin capture -- <output dir> [<interrupted dir>...]`
//! writes `vectors.json` and an interrupted wallet, then resumes that wallet and
//! every other interrupted wallet named (such as one written by an older
//! release) with the baseline, recording what each step leaves.

use std::path::{Path, PathBuf};

use zakura_transparent_private_compat::dump;

mod api {
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

include!("../vectors.rs");

mod scenario {
    use super::{api, dump};
    include!("../scenario.rs");
}

fn write_interrupted(dir: &Path, interrupted: &scenario::Interrupted) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("wallet.sql"), &interrupted.wallet_sql).unwrap();
    std::fs::write(dir.join("companion.sql"), &interrupted.companion_sql).unwrap();
    std::fs::write(dir.join("account"), &interrupted.account).unwrap();
    std::fs::write(dir.join("owned"), interrupted.owned.join("\n") + "\n").unwrap();
    std::fs::write(dir.join("notes.txt"), interrupted.notes.join("\n") + "\n").unwrap();
}

fn read_interrupted(dir: &Path) -> scenario::Interrupted {
    scenario::Interrupted {
        account: std::fs::read_to_string(dir.join("account")).unwrap(),
        owned: std::fs::read_to_string(dir.join("owned"))
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect(),
        wallet_sql: std::fs::read_to_string(dir.join("wallet.sql")).unwrap(),
        companion_sql: std::fs::read_to_string(dir.join("companion.sql")).unwrap(),
        notes: Vec::new(),
    }
}

fn main() {
    let mut args = std::env::args().skip(1).map(PathBuf::from);
    let out = args.next().expect("an output directory");
    std::fs::create_dir_all(&out).unwrap();
    let work = tempfile::tempdir().unwrap();

    let vectors = vectors(&work.path().join("vectors"));
    std::fs::write(
        out.join("vectors.json"),
        serde_json::to_string_pretty(&vectors).unwrap() + "\n",
    )
    .unwrap();

    let interrupted = scenario::interrupted(&work.path().join("interrupted"));
    let own = out.join("interrupted");
    write_interrupted(&own, &interrupted);

    let mut sources = vec![("baseline".to_string(), own)];
    sources.extend(args.map(|dir| (dir.file_name().unwrap().to_string_lossy().into_owned(), dir)));
    for (name, dir) in sources {
        let from = read_interrupted(&dir);
        let (snapshots, notes) =
            scenario::resume(&from, &work.path().join(format!("resume-{name}")));
        std::fs::write(
            out.join(format!("resumed-{name}.json")),
            serde_json::to_string_pretty(&snapshots).unwrap() + "\n",
        )
        .unwrap();
        std::fs::write(
            out.join(format!("resumed-{name}.txt")),
            notes.join("\n") + "\n",
        )
        .unwrap();
    }
}
