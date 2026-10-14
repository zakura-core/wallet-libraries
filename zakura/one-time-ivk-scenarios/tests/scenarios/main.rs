//! The one-time IVK scenario suite. Runs every scenario in the catalog against a
//! simulated chain, NEAR and receiver directory, then writes `report.json` and
//! `report.md`. See the crate README for options.

mod catalog;
mod harness;

use std::{
    cell::RefCell,
    panic::{self, AssertUnwindSafe},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use zakura_one_time_ivk_scenarios::{Meta, Outcome, Report, ScenarioResult, render_markdown};

use catalog::Scenario;
use harness::Ctx;

/// Command-line options. Unknown flags, such as the ones `cargo test` forwards, are
/// ignored.
struct Args {
    filter: Option<String>,
    exact: bool,
    list: bool,
    slow: bool,
    jobs: usize,
    report: PathBuf,
}

impl Args {
    fn parse() -> Self {
        let default_jobs = std::thread::available_parallelism()
            .map_or(4, |n| n.get() / 2)
            .max(1);
        let mut args = Self {
            filter: None,
            exact: false,
            list: false,
            slow: std::env::var_os("ONE_TIME_IVK_SLOW").is_some(),
            jobs: default_jobs,
            report: std::env::var_os("ONE_TIME_IVK_REPORT_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    Path::new(env!("CARGO_TARGET_TMPDIR")).join("one-time-ivk-scenarios")
                }),
        };
        let mut it = std::env::args().skip(1);
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--list" => args.list = true,
                "--exact" => args.exact = true,
                "--slow" => args.slow = true,
                "--jobs" => {
                    args.jobs = it
                        .next()
                        .and_then(|n| n.parse().ok())
                        .expect("--jobs takes a number")
                }
                "--report" => {
                    args.report = PathBuf::from(it.next().expect("--report takes a directory"))
                }
                flag if flag.starts_with('-') => {}
                filter => args.filter = Some(filter.into()),
            }
        }
        args
    }

    fn selects(&self, scenario: &Scenario) -> bool {
        let named = match &self.filter {
            Some(f) if self.exact => scenario.id == *f,
            Some(f) => scenario.id.contains(f.as_str()),
            None => true,
        };
        // A filter that names a slow scenario runs it.
        named && (self.slow || !scenario.slow || self.filter.is_some())
    }
}

fn main() {
    let args = Args::parse();
    let scenarios: Vec<Scenario> = catalog::all()
        .into_iter()
        .filter(|s| args.selects(s))
        .collect();
    if args.list {
        for scenario in &scenarios {
            println!("{}: test", scenario.id);
        }
        return;
    }
    let started = Instant::now();
    let started_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    // Read before running, so a commit made during a long run doesn't relabel it.
    let revisions = revisions();
    println!(
        "running {} one-time IVK scenarios on {} threads",
        scenarios.len(),
        args.jobs
    );
    let results = run_all(&scenarios, args.jobs);
    let report = Report {
        meta: Meta {
            started_unix,
            duration_ms: started.elapsed().as_millis() as u64,
            revisions,
            filter: args.filter.clone(),
            jobs: args.jobs,
        },
        scenarios: results,
    };
    std::fs::create_dir_all(&args.report).expect("the report directory");
    let json = serde_json::to_string_pretty(&report).expect("the report serializes");
    std::fs::write(args.report.join("report.json"), json).expect("report.json");
    std::fs::write(args.report.join("report.md"), render_markdown(&report)).expect("report.md");
    let totals = report.totals();
    println!(
        "\n{} passed, {} failed, {} errors in {:.1} s",
        totals.passed,
        totals.failed,
        totals.errors,
        report.meta.duration_ms as f64 / 1000.0
    );
    println!("report: {}", args.report.join("report.md").display());
    if totals.failed + totals.errors > 0 {
        std::process::exit(1);
    }
}

/// Runs `scenarios` on `jobs` threads, keeping catalog order. Cost scenarios measure
/// time, so they run afterwards, one at a time.
fn run_all(scenarios: &[Scenario], jobs: usize) -> Vec<ScenarioResult> {
    let alone = |s: &Scenario| s.group == catalog::COST;
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<Option<ScenarioResult>>> =
        Mutex::new((0..scenarios.len()).map(|_| None).collect());
    // Panics become scenario errors carrying their message and location.
    let default = panic::take_hook();
    panic::set_hook(Box::new(|info| {
        LAST_PANIC.with(|last| *last.borrow_mut() = Some(info.to_string()));
    }));
    let report = |i: usize, result: ScenarioResult| {
        let mark = match result.outcome {
            Outcome::Pass => "ok",
            Outcome::Fail => "FAIL",
            Outcome::Error => "ERROR",
        };
        println!(
            "{mark:>5}  {}  ({} ms)",
            scenarios[i].id, result.duration_ms
        );
        results.lock().unwrap()[i] = Some(result);
    };
    std::thread::scope(|scope| {
        for _ in 0..jobs.max(1) {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(scenario) = scenarios.get(i) else {
                        break;
                    };
                    if alone(scenario) {
                        continue;
                    }
                    let result = run_one(scenario);
                    report(i, result);
                }
            });
        }
    });
    for (i, scenario) in scenarios.iter().enumerate() {
        if alone(scenario) {
            report(i, run_one(scenario));
        }
    }
    panic::set_hook(default);
    results
        .into_inner()
        .unwrap()
        .into_iter()
        .map(|r| r.expect("every scenario ran"))
        .collect()
}

thread_local! {
    /// The message and location of this thread's latest panic.
    static LAST_PANIC: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// This thread's latest panic, for a scenario error.
fn last_panic() -> String {
    LAST_PANIC
        .with(|last| last.borrow_mut().take())
        .unwrap_or_else(|| "the scenario panicked".into())
}

/// Runs one scenario, turning a panic in any phase into an error outcome.
fn run_one(scenario: &Scenario) -> ScenarioResult {
    let started = Instant::now();
    let mut error = None;
    let (timeline, payments, checks, metrics) = match panic::catch_unwind(Ctx::new) {
        Err(_) => {
            error = Some(format!("setting up the world: {}", last_panic()));
            Default::default()
        }
        Ok(mut ctx) => {
            let ran = panic::catch_unwind(AssertUnwindSafe(|| {
                (scenario.run)(&mut ctx);
                ctx.log("suite", "every wallet keeps syncing until quiet");
                ctx.settle();
            }));
            if ran.is_err() {
                error = Some(last_panic());
            }
            match panic::catch_unwind(AssertUnwindSafe(|| ctx.finish())) {
                Ok(findings) => findings,
                Err(_) => {
                    error.get_or_insert_with(|| format!("collecting results: {}", last_panic()));
                    Default::default()
                }
            }
        }
    };
    let mut result = ScenarioResult {
        id: scenario.id.clone(),
        group: scenario.group.into(),
        title: scenario.title.clone(),
        summary: scenario.summary.clone(),
        params: scenario.params.clone(),
        outcome: Outcome::Pass,
        error,
        duration_ms: started.elapsed().as_millis() as u64,
        timeline,
        payments,
        checks,
        metrics,
    };
    result.outcome = if result.error.is_some() {
        Outcome::Error
    } else if result.mismatches().next().is_some() || result.checks.iter().any(|c| !c.ok) {
        Outcome::Fail
    } else {
        Outcome::Pass
    };
    result
}

/// The revisions under test: this checkout, and the wallet-pir receiver crates its lock
/// file pins.
fn revisions() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let git = |args: &[&str]| {
        Command::new("git")
            .args(args)
            .current_dir(&root)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    };
    let mut revisions = Vec::new();
    if let Some(head) = git(&["rev-parse", "HEAD"]) {
        let dirty = git(&["status", "--porcelain"]).is_some_and(|s| !s.is_empty());
        let value = if dirty {
            format!("{head} (with local changes)")
        } else {
            head
        };
        revisions.push(("wallet-libraries".into(), value));
    }
    if let Ok(lock) = std::fs::read_to_string(root.join("Cargo.lock")) {
        let pin = lock
            .split("[[package]]")
            .find(|p| p.contains("name = \"receiver-directory\""))
            .and_then(|p| p.lines().find(|l| l.starts_with("source = ")))
            .and_then(|l| l.rsplit('#').next())
            .map(|s| s.trim_end_matches('"').to_string());
        if let Some(pin) = pin {
            revisions.push(("wallet-pir receiver crates".into(), pin));
        }
    }
    revisions
}
