//! Validates and pins wallet PIR config documents with the wallet's own types.
//!
//! ```text
//! wallet-pir-config verify --static-config PATH --dynamic-config PATH --network mainnet|testnet|regtest
//! wallet-pir-config pin --static-config PATH --source-url HTTPS_URL
//! ```
//!
//! Neither command touches the network. `verify` pins the static file to a
//! placeholder source (or `--source-url`) and resolves the dynamic file as if
//! fetched from the first declared mirror, so it runs every check a wallet
//! runs. `pin` prints the hash-pinned source string to ship.

use std::collections::BTreeMap;
use std::fs;
use std::process::ExitCode;

use zakura_pir_config::{
    WalletPirConfigProfile, WalletPirNetwork, WalletPirStaticConfig, pin_static_config_source,
    resolve_dynamic_config, resolve_static_config,
};

const USAGE: &str = "usage:
  wallet-pir-config verify --static-config PATH --dynamic-config PATH --network mainnet|testnet|regtest [--source-url HTTPS_URL]
  wallet-pir-config pin --static-config PATH --source-url HTTPS_URL";

/// Stands in for the real source in `verify`; only the pin matters there.
const PLACEHOLDER_SOURCE_URL: &str =
    "https://wallet-pir-config.invalid/static-wallet-pir-config.json";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.split_first() {
        Some((command, rest)) if command == "verify" => parse_flags(
            rest,
            &["--static-config", "--dynamic-config", "--network"],
            &["--source-url"],
        )
        .and_then(|flags| verify(&flags)),
        Some((command, rest)) if command == "pin" => {
            parse_flags(rest, &["--static-config", "--source-url"], &[])
                .and_then(|flags| pin(&flags))
        }
        _ => Err(Failure::Usage(
            "expected a verify or pin command".to_string(),
        )),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Usage(message)) => {
            eprintln!("error: {message}\n{USAGE}");
            ExitCode::from(2)
        }
        Err(Failure::Invalid(message)) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

enum Failure {
    /// Bad command line; exit code 2.
    Usage(String),
    /// Unreadable or invalid config; exit code 1.
    Invalid(String),
}

type Flags = BTreeMap<String, String>;

fn verify(flags: &Flags) -> Result<(), Failure> {
    let network: WalletPirNetwork = flags["--network"]
        .parse()
        .map_err(|error| Failure::Usage(format!("{error}")))?;
    let static_bytes = read(&flags["--static-config"])?;
    let dynamic_bytes = read(&flags["--dynamic-config"])?;
    let source_url = flags
        .get("--source-url")
        .map_or(PLACEHOLDER_SOURCE_URL, String::as_str);

    let source = pin_static_config_source(source_url, &static_bytes).map_err(invalid)?;
    let anchor = resolve_static_config(&source.raw, &static_bytes, network).map_err(invalid)?;
    let mirror = anchor.dynamic_config_urls()[0].clone();
    let profile = WalletPirConfigProfile::https_transport();
    let config =
        resolve_dynamic_config(&profile, &anchor, &mirror, &dynamic_bytes).map_err(invalid)?;

    println!(
        "ok network={network} static_sha256={}",
        source.sha256.unwrap_or_default()
    );
    println!("attestation={}", anchor.attestation().method);
    for url in anchor.dynamic_config_urls() {
        println!("mirror {url}");
    }
    if !config.is_active() {
        println!("inactive: no servers advertised");
    }
    for server in config.servers() {
        println!("server {} label={:?}", server.base, server.label);
    }
    Ok(())
}

fn pin(flags: &Flags) -> Result<(), Failure> {
    let static_bytes = read(&flags["--static-config"])?;
    // Pin only documents a wallet would accept for their own network.
    let document: WalletPirStaticConfig = serde_json::from_slice(&static_bytes)
        .map_err(|error| Failure::Invalid(format!("static config decode failed: {error}")))?;
    let source =
        pin_static_config_source(&flags["--source-url"], &static_bytes).map_err(invalid)?;
    resolve_static_config(&source.raw, &static_bytes, document.network).map_err(invalid)?;
    println!("{}", source.raw);
    Ok(())
}

/// Parses `--flag VALUE` pairs, requiring every flag in `required`.
fn parse_flags(args: &[String], required: &[&str], optional: &[&str]) -> Result<Flags, Failure> {
    let mut flags = Flags::new();
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        if !required.contains(&flag.as_str()) && !optional.contains(&flag.as_str()) {
            return Err(Failure::Usage(format!("unexpected argument {flag}")));
        }
        let value = args
            .next()
            .ok_or_else(|| Failure::Usage(format!("{flag} needs a value")))?;
        if flags.insert(flag.clone(), value.clone()).is_some() {
            return Err(Failure::Usage(format!("{flag} given twice")));
        }
    }
    match required.iter().find(|flag| !flags.contains_key(**flag)) {
        Some(missing) => Err(Failure::Usage(format!("missing {missing}"))),
        None => Ok(flags),
    }
}

fn read(path: &str) -> Result<Vec<u8>, Failure> {
    fs::read(path).map_err(|error| Failure::Invalid(format!("cannot read {path}: {error}")))
}

fn invalid(error: impl std::fmt::Display) -> Failure {
    Failure::Invalid(error.to_string())
}
