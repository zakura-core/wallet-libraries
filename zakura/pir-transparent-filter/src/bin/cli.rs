//! Reference client: a dummy wallet, and a batched adapter for the research
//! harness.
//!
//! The `sync` subcommand is a **test double**, not a wallet. In particular it
//! can be told to take its accepted chain from the same service that serves the
//! filters, which a real wallet must never do. It exists to exercise the fetch,
//! validate and match path end to end against a live service.

use clap::{Parser, Subcommand};
use std::io::{BufRead, Write};
use transparent_filter::{
    build_filter, filter_hash, http::HttpTransport, sync_range, validate_filter, BlockHash,
    ChainMap, FilterLimits, RangeRequest, ScriptBytes,
};

#[derive(Parser)]
#[command(
    name = "transparent-filter-cli",
    about = "Transparent activity filter client"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Fetch, validate and match a range against a running filter service.
    Sync {
        #[arg(long)]
        server: String,
        /// File of hex-encoded wallet scripts, one per line.
        #[arg(long)]
        scripts: std::path::PathBuf,
        /// First height to cover. Defaults to the service's start height.
        #[arg(long)]
        start_height: Option<u64>,
        /// Last height to cover. Defaults to the service's coverage tip.
        #[arg(long)]
        stop_height: Option<u64>,
        /// Take the accepted chain from the service being tested.
        ///
        /// A real wallet supplies its own. Required here because this client
        /// has no chain of its own, and named so the compromise is visible in
        /// every command line that relies on it.
        #[arg(long)]
        accept_server_chain: bool,
    },
    /// Report what the service says about itself.
    Info {
        #[arg(long)]
        server: String,
    },
    /// Build filters from element sets. One JSON object per input line:
    /// `{"block_hash_display": "...", "elements": ["<hex>", ...]}`.
    ///
    /// Batched on purpose: the harness makes one call for a whole generation
    /// rather than one process per script.
    BatchBuild,
    /// Match scripts against filters. One JSON object per input line:
    /// `{"block_hash_display": "...", "filter": "<hex>", "scripts": ["<hex>", ...]}`.
    BatchMatch,
}

fn read_scripts(path: &std::path::Path) -> Result<Vec<ScriptBytes>, String> {
    let text = std::fs::read_to_string(path).map_err(|error| format!("{path:?}: {error}"))?;
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            hex::decode(line)
                .map(ScriptBytes::new)
                .map_err(|error| format!("bad script hex {line:?}: {error}"))
        })
        .collect()
}

fn run() -> Result<(), String> {
    match Cli::parse().command {
        Command::Info { server } => {
            let transport = HttpTransport::new(&server).map_err(|e| e.to_string())?;
            let info = transport.info().map_err(|e| e.to_string())?;
            let health = transport.health().map_err(|e| e.to_string())?;
            println!("{}", serde_json::json!({"info": info, "health": health}));
            Ok(())
        }
        Command::Sync {
            server,
            scripts,
            start_height,
            stop_height,
            accept_server_chain,
        } => {
            let wallet_scripts = read_scripts(&scripts)?;
            let mut transport = HttpTransport::new(&server).map_err(|e| e.to_string())?;
            let info = transport.info().map_err(|e| e.to_string())?;
            if !accept_server_chain {
                return Err("this reference client has no accepted chain of its own; \
                            pass --accept-server-chain to let it use the service's, \
                            which a real wallet must not do"
                    .to_string());
            }
            let start = start_height.unwrap_or(info.start_height);
            let stop = stop_height
                .or(info.covered_through)
                .ok_or("service has no coverage yet and no --stop-height was given")?;
            if stop < start {
                return Err(format!("stop height {stop} is below start height {start}"));
            }

            let mut chain = ChainMap::new();
            let mut at = start;
            while at <= stop {
                let count = (stop - at + 1).min(10_000);
                for entry in transport.chain(at, count).map_err(|e| e.to_string())? {
                    chain.insert(
                        entry.height,
                        BlockHash::from_display_hex(&entry.block_hash)
                            .map_err(|e| e.to_string())?,
                    );
                }
                at += count;
            }
            let (_, stop_hash) = chain.tip().ok_or("service returned no chain entries")?;

            let request = RangeRequest {
                genesis: BlockHash::from_display_hex(&info.genesis_hash)
                    .map_err(|e| e.to_string())?,
                profile: info.profile.clone(),
                start_height: start,
                stop_block_hash: stop_hash,
            };
            let started = std::time::Instant::now();
            let outcome = sync_range(
                &mut transport,
                &request,
                &chain,
                &wallet_scripts,
                FilterLimits::default(),
            )
            .map_err(|e| e.to_string())?;
            let elapsed = started.elapsed();

            println!(
                "{}",
                serde_json::json!({
                    "start_height": start,
                    "covered_through": outcome.covered_through,
                    "covered_block_hash": outcome.covered_block_hash.to_display_hex(),
                    "filters_checked": outcome.filters_checked,
                    "wallet_scripts": wallet_scripts.len(),
                    "matched_blocks": outcome.matches.len(),
                    "matches": outcome.matches.iter().map(|m| serde_json::json!({
                        "height": m.height,
                        "block_hash": m.block_hash.to_display_hex(),
                        "script_indices": m.script_indices,
                    })).collect::<Vec<_>>(),
                    "bytes_received": outcome.charges.received,
                    "bytes_sent": outcome.charges.sent,
                    "requests": outcome.charges.requests,
                    "elapsed_ms": elapsed.as_millis() as u64,
                })
            );
            Ok(())
        }
        Command::BatchBuild => {
            let stdin = std::io::stdin();
            let mut stdout = std::io::BufWriter::new(std::io::stdout());
            for line in stdin.lock().lines() {
                let line = line.map_err(|e| e.to_string())?;
                if line.trim().is_empty() {
                    continue;
                }
                let input: serde_json::Value =
                    serde_json::from_str(&line).map_err(|e| e.to_string())?;
                let hash = BlockHash::from_display_hex(
                    input["block_hash_display"]
                        .as_str()
                        .ok_or("block_hash_display")?,
                )
                .map_err(|e| e.to_string())?;
                let elements: Vec<ScriptBytes> = input["elements"]
                    .as_array()
                    .ok_or("elements")?
                    .iter()
                    .map(|value| {
                        hex::decode(value.as_str().unwrap_or_default())
                            .map(ScriptBytes::new)
                            .map_err(|e| e.to_string())
                    })
                    .collect::<Result<_, _>>()?;
                let filter = build_filter(hash, &elements).map_err(|e| e.to_string())?;
                writeln!(
                    stdout,
                    "{}",
                    serde_json::json!({
                        "filter": hex::encode(filter.as_slice()),
                        "filter_hash": hex::encode(filter_hash(filter.as_slice()).0),
                        "bytes": filter.len(),
                        "elements": transparent_filter::element_count(&elements),
                    })
                )
                .map_err(|e| e.to_string())?;
            }
            stdout.flush().map_err(|e| e.to_string())
        }
        Command::BatchMatch => {
            let stdin = std::io::stdin();
            let mut stdout = std::io::BufWriter::new(std::io::stdout());
            for line in stdin.lock().lines() {
                let line = line.map_err(|e| e.to_string())?;
                if line.trim().is_empty() {
                    continue;
                }
                let input: serde_json::Value =
                    serde_json::from_str(&line).map_err(|e| e.to_string())?;
                let hash = BlockHash::from_display_hex(
                    input["block_hash_display"]
                        .as_str()
                        .ok_or("block_hash_display")?,
                )
                .map_err(|e| e.to_string())?;
                let bytes = hex::decode(input["filter"].as_str().ok_or("filter")?)
                    .map_err(|e| e.to_string())?;
                let scripts: Vec<ScriptBytes> = input["scripts"]
                    .as_array()
                    .ok_or("scripts")?
                    .iter()
                    .map(|value| {
                        hex::decode(value.as_str().unwrap_or_default())
                            .map(ScriptBytes::new)
                            .map_err(|e| e.to_string())
                    })
                    .collect::<Result<_, _>>()?;
                let validated =
                    validate_filter(&bytes, FilterLimits::default()).map_err(|e| e.to_string())?;
                let matched = transparent_filter::match_scripts(&validated, hash, &scripts)
                    .map_err(|e| e.to_string())?;
                writeln!(
                    stdout,
                    "{}",
                    serde_json::json!({"indices": matched, "elements": validated.element_count()})
                )
                .map_err(|e| e.to_string())?;
            }
            stdout.flush().map_err(|e| e.to_string())
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("transparent-filter-cli: {error}");
        std::process::exit(1);
    }
}
