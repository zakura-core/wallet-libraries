//! The `wallet-pir-config` binary on the representative fixtures.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};

const SOURCE_URL: &str =
    "https://valargroup.github.io/wallet-pir-config/prod/static-wallet-pir-config.json";

fn fixture(name: &str, kind: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name)
        .join(format!("{kind}-wallet-pir-config.json"))
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wallet-pir-config"))
        .args(args)
        .output()
        .unwrap()
}

fn verify(name: &str, network: &str) -> Output {
    run(&[
        "verify",
        "--static-config",
        fixture(name, "static").to_str().unwrap(),
        "--dynamic-config",
        fixture(name, "dynamic").to_str().unwrap(),
        "--network",
        network,
    ])
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

#[test]
fn verifies_the_inactive_prod_and_stage_configs() {
    for (name, network) in [("prod", "mainnet"), ("stage", "testnet")] {
        let output = verify(name, network);
        assert!(output.status.success(), "{name}: {output:?}");
        let stdout = stdout(&output);
        assert!(
            stdout.starts_with(&format!("ok network={network} ")),
            "{stdout}"
        );
        assert!(
            stdout.contains("inactive: no servers advertised"),
            "{stdout}"
        );
        assert!(
            stdout.contains(&format!("/{name}/dynamic-wallet-pir-config.json")),
            "{stdout}"
        );
    }
}

#[test]
fn verifies_the_two_server_config() {
    let output = verify("two-servers", "mainnet");
    assert!(output.status.success(), "{output:?}");
    let stdout = stdout(&output);
    assert!(stdout.contains("server https://pir-a.example label=\"Example server A\""));
    assert!(stdout.contains("server https://pir-b.example/wallet label=\"Example server B\""));
}

#[test]
fn rejects_a_config_for_another_network() {
    let output = verify("stage", "mainnet");
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("network is testnet, expected mainnet")
    );
    assert_eq!(verify("prod", "main").status.code(), Some(2));
}

#[test]
fn pins_reproducibly() {
    let static_path = fixture("prod", "static");
    let args = [
        "pin",
        "--static-config",
        static_path.to_str().unwrap(),
        "--source-url",
        SOURCE_URL,
    ];
    let first = run(&args);
    assert!(first.status.success(), "{first:?}");
    let digest = hex::encode(Sha256::digest(std::fs::read(&static_path).unwrap()));
    assert_eq!(
        stdout(&first),
        format!("{SOURCE_URL}?checksum=sha256:{digest}\n")
    );
    assert_eq!(stdout(&run(&args)), stdout(&first));
}

#[test]
fn reports_usage_errors() {
    assert_eq!(run(&[]).status.code(), Some(2));
    assert_eq!(
        run(&["pin", "--source-url", SOURCE_URL]).status.code(),
        Some(2)
    );
    assert_eq!(
        run(&[
            "pin",
            "--static-config",
            "missing.json",
            "--source-url",
            SOURCE_URL
        ])
        .status
        .code(),
        Some(1)
    );
}
