//! Compares a shadow validation profile with an independent reconstruction.
//!
//! ```sh
//! cargo run -p zakura-wallet-transparent --release --example shadow_compare -- \
//!   --profile <dir> --expected <snapshot.json> --report <sanitized.json> \
//!   [--detail <local-only.json>] [--untouched <recovery profile dir>]...
//! ```
//!
//! Refuses anything but a shadow profile before opening a file, opens the
//! profile read-only, takes no network address, and writes only the report.
//! Every file under the profile and under each `--untouched` directory is
//! digested before and after; a change fails the run. Exit status: 0 equal,
//! 1 differs, 3 not a shadow profile, 4 the profile is in use, 5 a file
//! changed, 2 any other error.

use std::path::PathBuf;

fn main() {
    let mut args = std::env::args().skip(1);
    let mut profile = None;
    let mut expected = None;
    let mut report = None;
    let mut detail = None;
    let mut untouched = Vec::new();
    while let Some(flag) = args.next() {
        let value = || args.next().unwrap_or_else(|| usage(&flag));
        match flag.as_str() {
            "--profile" => profile = Some(PathBuf::from(value())),
            "--expected" => expected = Some(PathBuf::from(value())),
            "--report" => report = Some(PathBuf::from(value())),
            "--detail" => detail = Some(PathBuf::from(value())),
            "--untouched" => untouched.push(PathBuf::from(value())),
            other => usage(other),
        }
    }
    let (Some(profile), Some(expected), Some(report)) = (profile, expected, report) else {
        usage("--profile, --expected and --report are required");
    };
    match zakura_wallet_transparent::shadow::run_compare(
        &profile,
        &expected,
        &report,
        detail.as_deref(),
        &untouched,
    ) {
        Ok(code) => {
            eprintln!(
                "{}",
                match code {
                    0 => "equal",
                    1 => "differs",
                    5 => "a file changed during the comparison; the report was not written",
                    _ => "unexpected",
                }
            );
            std::process::exit(code);
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(error.exit_code());
        }
    }
}

fn usage(what: &str) -> ! {
    eprintln!("shadow_compare: {what}");
    eprintln!(
        "usage: shadow_compare --profile <dir> --expected <snapshot.json> --report <out.json> \
         [--detail <out.json>] [--untouched <dir>]..."
    );
    std::process::exit(2);
}
