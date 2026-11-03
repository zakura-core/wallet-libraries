//! Reference client: a dummy wallet, and a batched adapter for the research
//! harness.
//!
//! The `sync` subcommand is a **test double**, not a wallet. In particular it
//! can be told to take its accepted chain from the same service that serves the
//! filters, which a real wallet must never do. It exists to exercise the fetch,
//! validate and match path end to end against a live service.

#[path = "../cli_args.rs"]
mod cli_args;

use std::ffi::{OsStr, OsString};
use std::io::{BufRead, Write};
use zakura_pir_client::transparent::filter::{
    BlockHash, ChainMap, FilterLimits, RangeRequest, ScriptBytes, filter_hash, http::HttpTransport,
    sync_range, validate_filter,
};
use zakura_pir_publisher::transparent::filter::build_filter;

#[derive(Debug, PartialEq, Eq)]
enum Command {
    /// Fetch, validate and match a range against a running filter service.
    Sync {
        server: String,
        /// File of hex-encoded wallet scripts, one per line.
        scripts: std::path::PathBuf,
        /// First height to cover. Defaults to the service's start height.
        start_height: Option<u64>,
        /// Last height to cover. Defaults to the service's coverage tip.
        stop_height: Option<u64>,
        /// Take the accepted chain from the service being tested.
        ///
        /// A real wallet supplies its own. Required here because this client
        /// has no chain of its own, and named so the compromise is visible in
        /// every command line that relies on it.
        accept_server_chain: bool,
    },
    /// Report what the service says about itself.
    Info { server: String },
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

const HELP_ROOT: &str = r##"Transparent activity filter client

Usage: {program} <COMMAND>

Commands:
  sync         Fetch, validate and match a range against a running filter service
  info         Report what the service says about itself
  batch-build  Build filters from element sets. One JSON object per input line: `{"block_hash_display": "...", "elements": ["<hex>", ...]}`
  batch-match  Match scripts against filters. One JSON object per input line: `{"block_hash_display": "...", "filter": "<hex>", "scripts": ["<hex>", ...]}`
  help         Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
"##;
const HELP_SYNC: &str = r##"Fetch, validate and match a range against a running filter service

Usage: {program} sync [OPTIONS] --server <SERVER> --scripts <SCRIPTS>

Options:
      --server <SERVER>


      --scripts <SCRIPTS>
          File of hex-encoded wallet scripts, one per line

      --start-height <START_HEIGHT>
          First height to cover. Defaults to the service's start height

      --stop-height <STOP_HEIGHT>
          Last height to cover. Defaults to the service's coverage tip

      --accept-server-chain
          Take the accepted chain from the service being tested.

          A real wallet supplies its own. Required here because this client has no chain of its own, and named so the compromise is visible in every command line that relies on it.

  -h, --help
          Print help
"##;
const HELP_INFO: &str = r##"Report what the service says about itself

Usage: {program} info --server <SERVER>

Options:
      --server <SERVER>
  -h, --help             Print help
"##;
const HELP_BATCH_BUILD: &str = r##"Build filters from element sets. One JSON object per input line: `{"block_hash_display": "...", "elements": ["<hex>", ...]}`.

Batched on purpose: the harness makes one call for a whole generation rather than one process per script.

Usage: {program} batch-build

Options:
  -h, --help
          Print help
"##;
const HELP_BATCH_MATCH: &str = r##"Match scripts against filters. One JSON object per input line: `{"block_hash_display": "...", "filter": "<hex>", "scripts": ["<hex>", ...]}`

Usage: {program} batch-match

Options:
  -h, --help  Print help
"##;
const HELP_HELP: &str = r##"Print this message or the help of the given subcommand(s)

Usage: {program} help [COMMAND]...

Arguments:
  [COMMAND]...  Print help for the subcommand(s)
"##;

#[derive(Debug, PartialEq, Eq)]
enum Parsed {
    Command(Command),
    Help(&'static str),
}

fn help(command: &str) -> Option<&'static str> {
    match command {
        "sync" => Some(HELP_SYNC),
        "info" => Some(HELP_INFO),
        "batch-build" => Some(HELP_BATCH_BUILD),
        "batch-match" => Some(HELP_BATCH_MATCH),
        "help" => Some(HELP_HELP),
        _ => None,
    }
}

fn parse_args(arguments: impl IntoIterator<Item = OsString>) -> Result<Parsed, String> {
    let mut arguments = arguments.into_iter();
    let argument = arguments.next().ok_or("a subcommand is required")?;
    if cli_args::is_help(&argument) {
        return Ok(Parsed::Help(HELP_ROOT));
    }
    let name = argument.to_str().ok_or("invalid UTF-8 in subcommand")?;
    if name == "help" {
        let topic = match arguments.next() {
            None => HELP_ROOT,
            Some(topic) => topic
                .to_str()
                .and_then(help)
                .ok_or("unrecognized help subcommand")?,
        };
        if arguments.next().is_some() {
            return Err("unrecognized help subcommand".into());
        }
        return Ok(Parsed::Help(topic));
    }
    let usage = help(name)
        .filter(|_| name != "help")
        .ok_or("unrecognized subcommand")?;
    let mut server = None;
    let mut scripts = None;
    let mut start_height = None;
    let mut stop_height = None;
    let mut accept_server_chain = false;
    while let Some(argument) = arguments.next() {
        if cli_args::is_help(&argument) {
            return Ok(Parsed::Help(usage));
        }
        if argument == "--" {
            if arguments.next().is_some() {
                return Err("unexpected positional argument".into());
            }
            break;
        }
        if matches!(name, "sync" | "info")
            && let Some(value) = cli_args::take_value(&argument, "--server", &mut arguments)
        {
            if server.is_some() {
                return Err("--server cannot be used multiple times".into());
            }
            server = Some(
                value?
                    .into_string()
                    .map_err(|_| "--server requires UTF-8")?,
            );
        } else if name == "sync" {
            if let Some(value) = cli_args::take_value(&argument, "--scripts", &mut arguments) {
                if scripts.is_some() {
                    return Err("--scripts cannot be used multiple times".into());
                }
                scripts = Some(std::path::PathBuf::from(value?));
            } else if let Some(value) =
                cli_args::take_value(&argument, "--start-height", &mut arguments)
            {
                if start_height.is_some() {
                    return Err("--start-height cannot be used multiple times".into());
                }
                start_height = Some(cli_args::number(value?, "--start-height")?);
            } else if let Some(value) =
                cli_args::take_value(&argument, "--stop-height", &mut arguments)
            {
                if stop_height.is_some() {
                    return Err("--stop-height cannot be used multiple times".into());
                }
                stop_height = Some(cli_args::number(value?, "--stop-height")?);
            } else if argument == "--accept-server-chain" {
                if accept_server_chain {
                    return Err("--accept-server-chain cannot be used multiple times".into());
                }
                accept_server_chain = true;
            } else {
                return Err("unexpected argument; use --help for usage".into());
            }
        } else {
            return Err("unexpected argument; use --help for usage".into());
        }
    }
    Ok(Parsed::Command(match name {
        "sync" => Command::Sync {
            server: server.ok_or("--server is required")?,
            scripts: scripts.ok_or("--scripts is required")?,
            start_height,
            stop_height,
            accept_server_chain,
        },
        "info" => Command::Info {
            server: server.ok_or("--server is required")?,
        },
        "batch-build" => Command::BatchBuild,
        "batch-match" => Command::BatchMatch,
        _ => unreachable!("command was validated before parsing options"),
    }))
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

fn run(command: Command) -> Result<(), String> {
    match command {
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
                        "elements": zakura_pir_publisher::transparent::filter::element_count(&elements),
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
                let matched = zakura_pir_client::transparent::filter::match_scripts(
                    &validated, hash, &scripts,
                )
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
    let mut arguments = std::env::args_os();
    let executable = arguments.next().unwrap_or_default();
    let program = std::path::Path::new(&executable)
        .file_name()
        .unwrap_or(OsStr::new("transparent-filter-cli"))
        .to_string_lossy();
    let command = match parse_args(arguments) {
        Ok(Parsed::Command(command)) => command,
        Ok(Parsed::Help(text)) => {
            print!("{}", text.replace("{program}", &program));
            return;
        }
        Err(error) => {
            eprintln!(
                "error: {error}\n\n{}",
                HELP_ROOT.replace("{program}", &program)
            );
            std::process::exit(2);
        }
    };
    if let Err(error) = run(command) {
        eprintln!("transparent-filter-cli: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(arguments: &[&str]) -> Result<Parsed, String> {
        parse_args(arguments.iter().map(OsString::from))
    }

    #[test]
    fn commands_and_sync_defaults_remain_available() {
        assert_eq!(
            parse(&["batch-build"]),
            Ok(Parsed::Command(Command::BatchBuild))
        );
        assert_eq!(
            parse(&["batch-match", "--"]),
            Ok(Parsed::Command(Command::BatchMatch))
        );
        assert_eq!(
            parse(&["info", "--server="]),
            Ok(Parsed::Command(Command::Info {
                server: String::new()
            }))
        );
        assert_eq!(
            parse(&[
                "sync",
                "--server",
                "https://example.invalid",
                "--scripts",
                "scripts.txt"
            ]),
            Ok(Parsed::Command(Command::Sync {
                server: "https://example.invalid".into(),
                scripts: "scripts.txt".into(),
                start_height: None,
                stop_height: None,
                accept_server_chain: false,
            })),
        );
        assert_eq!(
            parse(&[
                "sync",
                "--scripts=scripts.txt",
                "--stop-height",
                "18446744073709551615",
                "--accept-server-chain",
                "--server=x",
                "--start-height=+1"
            ]),
            Ok(Parsed::Command(Command::Sync {
                server: "x".into(),
                scripts: "scripts.txt".into(),
                start_height: Some(1),
                stop_height: Some(u64::MAX),
                accept_server_chain: true,
            })),
        );
    }

    #[test]
    fn help_paths_and_terminators() {
        assert_eq!(parse(&["--help", "--unknown"]), Ok(Parsed::Help(HELP_ROOT)));
        assert_eq!(parse(&["help", "sync"]), Ok(Parsed::Help(HELP_SYNC)));
        assert_eq!(parse(&["sync", "-hfoo"]), Ok(Parsed::Help(HELP_SYNC)));
        assert_eq!(parse(&["help", "help"]), Ok(Parsed::Help(HELP_HELP)));
        for arguments in [
            vec![],
            vec!["--", "batch-build"],
            vec!["sync", "--", "--help"],
            vec!["help", "sync", "extra"],
            vec!["help", "--help"],
        ] {
            assert!(parse(&arguments).is_err(), "{arguments:?}");
        }
    }

    #[test]
    fn malformed_options_cannot_be_hidden_by_help() {
        for arguments in [
            vec!["sync", "--server", "--help"],
            vec!["sync", "--start-height=bad", "--help"],
            vec!["sync", "--stop-height=18446744073709551616", "--help"],
            vec!["sync", "--start-height=-1", "--help"],
            vec![
                "sync",
                "--accept-server-chain",
                "--accept-server-chain",
                "--help",
            ],
            vec!["sync", "--accept-server-chain=true"],
            vec!["sync", "--server=x", "--server=x", "--help"],
            vec!["info", "--scripts=f"],
            vec!["batch-build", "--server=x"],
            vec!["batch-match", "extra"],
        ] {
            assert!(parse(&arguments).is_err(), "{arguments:?}");
        }
    }
}
