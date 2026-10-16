#!/usr/bin/env python3
"""Verify the server ownership boundary and fresh wallet/server consumer graphs."""
import json
from pathlib import Path
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def wallet_pir_owned(value):
    """Recognize both historical and current ownership URLs, including git sources."""
    return "github.com/valargroup/wallet-pir" in (value or "").lower() or "github.com/zakura-core/wallet-pir" in (value or "").lower()


def problems(metadata, owned, node_packages=(), wallet=False, ownership=True):
    """Inspect declarations too: inactive optional/target/dev edges still count."""
    errors = []
    for package in metadata["packages"]:
        name = package["name"]
        if ownership and (name in owned or wallet_pir_owned(package.get("source")) or wallet_pir_owned(package.get("repository"))):
            errors.append(f"{name}: package owned by wallet-pir")
        if wallet and (name in node_packages or name == "zakura-server-chain"):
            errors.append(f"{name}: server/node package in wallet consumer")
        for dependency in package.get("dependencies", []):
            if wallet and (dependency["name"] in node_packages or dependency["name"] == "zakura-server-chain"):
                errors.append(f"{name}: server/node dependency in wallet consumer: {dependency['name']}")
            if ownership and (dependency["name"] in owned or wallet_pir_owned(dependency.get("source"))):
                errors.append(f"{name}: dependency on wallet-pir package {dependency['name']}")
    return errors


def metadata(manifest, locked=True, no_deps=False):
    command = ["cargo", "metadata", "--format-version", "1", "--all-features", "--manifest-path", str(manifest)]
    if locked:
        command.append("--locked")
    if no_deps:
        command.append("--no-deps")
    return json.loads(subprocess.check_output(command, cwd=ROOT, text=True))


def main():
    manifest = tomllib.loads((ROOT / "manifests/sources.toml").read_text())
    server = manifest["server"]
    workspace = ROOT / server["workspace"]
    owned, nodes = set(server["wallet_pir_packages"]), set(server["node_packages"])
    graph = metadata(workspace / "Cargo.toml")
    errors = problems(graph, owned)
    if Path(graph["workspace_root"]) != workspace:
        errors.append("server packages must resolve in their separate workspace")
    root_members = metadata(ROOT / "Cargo.toml", no_deps=True)["workspace_members"]
    if set(root_members) & set(graph["workspace_members"]):
        errors.append("server and ordinary wallet workspace members overlap")

    # Fresh lockfiles exercise downstream resolution independently of both checked-in
    # lockfiles. Neither consumer has a direct node or wallet-pir dependency.
    with tempfile.TemporaryDirectory(prefix="wallet-server-consumers-") as temporary:
        for kind, dependency, source in (
            ("wallet", f'zakura-receiver-crypto = {{ path = "{ROOT / "zakura/receiver-crypto"}" }}',
             'fn main() { let _ = zakura_receiver_crypto::RECORD_BYTES; }\n'),
            ("server-production", f'zakura-server-chain = {{ path = "{workspace}" }}',
             'fn main() { let _ = zakura_server_chain::NodeClient::new("http://127.0.0.1:1".into(), None); }\n'),
            # The RocksDB reader's public surface: its errors carry only this
            # repository's own types, so a consumer needs no node package to match them.
            ("server-rocksdb", f'zakura-server-chain = {{ path = "{workspace}", features = ["rocksdb"] }}',
             '''use std::path::PathBuf;
use zakura_server_chain::{Network, transparent::{TransparentBlock, state::{StateError, StateReader}}};
fn main() {
    let opened: Result<StateReader, StateError> = StateReader::open("/nonexistent", Network::Mainnet);
    let _: Option<Result<TransparentBlock, _>> = opened.as_ref().ok().map(|r| r.transparent_block(1));
    match opened {
        Err(StateError::Open { path, reason }) => { let _: (PathBuf, String) = (path, reason); }
        Err(StateError::NotArchive { path, reason }) => { let _: (PathBuf, &'static str) = (path, reason); }
        _ => {}
    }
}
'''),
            ("server", f'zakura-server-chain = {{ path = "{workspace}", features = ["testing"] }}',
             '''use zakura_server_chain::{Network, NodeClient, NodeError, receiver::ReceiverBlock, enhance::EnhanceBlock, status::StatusBlock};
use zakura_server_chain::transparent::{CompactBlock, Fee, TransparentBlock};
fn public_results(receiver: ReceiverBlock, enhance: EnhanceBlock, status: StatusBlock, transparent: TransparentBlock, compact: CompactBlock) {
    let _: Vec<[u8; 32]> = receiver.commitments;
    let _: Vec<[u8; 32]> = status.txids;
    let _: Option<u64> = enhance.actions.into_iter().next().and_then(|a| a.fee_zatoshis);
    let _: Option<Fee> = transparent.transactions.first().map(|t| t.fee);
    let _: Option<Vec<u8>> = transparent.transactions.into_iter().next().and_then(|t| t.outputs.into_iter().next()).map(|o| o.script);
    let _: u32 = compact.ironwood_tree_size;
}
fn main() {
    let _: Result<NodeClient, NodeError> = NodeClient::new("http://127.0.0.1:1".into(), None);
    let _ = Network::Mainnet;
    let _ = public_results;
    let _ = zakura_server_chain::testing::Tx::from_bytes;
}
'''),
        ):
            consumer = Path(temporary) / kind
            (consumer / "src").mkdir(parents=True)
            (consumer / "Cargo.toml").write_text(f'[package]\nname = "{kind}-boundary-consumer"\nversion = "0.0.0"\nedition = "2024"\n[dependencies]\n{dependency}\n')
            (consumer / "src/main.rs").write_text(source)
            fresh = metadata(consumer / "Cargo.toml", locked=False)
            errors.extend(problems(fresh, owned, nodes, wallet=kind == "wallet"))
            if not errors:
                subprocess.run(["cargo", "check", "--locked", "--manifest-path", str(consumer / "Cargo.toml")], cwd=ROOT, check=True)
        # The primary wallet facade must also remain node-free in each mutually
        # exclusive backend mode. Its legacy PIR dependencies are a separate
        # migration; only the node/server boundary is enforced here.
        for mode, options in (
            ("default", ""),
            ("zakura", ', default-features = false, features = ["zakura"]'),
            ("lrz", ', default-features = false, features = ["lrz"]'),
        ):
            consumer = Path(temporary) / f"facade-{mode}"
            (consumer / "src").mkdir(parents=True)
            (consumer / "src/main.rs").write_text("fn main() {}\n")
            (consumer / "Cargo.toml").write_text(
                f'[package]\nname = "facade-{mode}-boundary-consumer"\nversion = "0.0.0"\nedition = "2024"\n'
                f'[dependencies]\nzakura-wallet-lib = {{ path = "{ROOT / "wallet-lib"}"{options} }}\n'
            )
            fresh = metadata(consumer / "Cargo.toml", locked=False)
            errors.extend(problems(fresh, owned, nodes, wallet=True, ownership=False))
    if errors:
        raise SystemExit("server ownership boundary failed:\n  " + "\n  ".join(sorted(set(errors))))
    print("verified: separate server workspace and fresh consumers; no wallet-pir-owned dependencies in the affected graphs")


if __name__ == "__main__":
    main()
