#!/usr/bin/env python3
"""Verify the one-way ownership boundary and fresh wallet/server consumer graphs.

No package in either workspace, nor any fresh consumer of this repository's crates,
may declare a dependency of any kind (normal, optional, build, target-specific or
development) on a package wallet-pir owns or releases; wallet consumers must also
stay free of node and server packages.
"""
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
    owned, nodes = set(server["wallet_pir_packages"]), set(server["node_packages"])
    graph = metadata(ROOT / "server/Cargo.toml")
    errors = problems(graph, owned)
    if Path(graph["workspace_root"]) != ROOT / "server":
        errors.append("server packages must resolve in their separate workspace")
    root_members = metadata(ROOT / "Cargo.toml", no_deps=True)["workspace_members"]
    if set(root_members) & set(graph["workspace_members"]):
        errors.append("server and ordinary wallet workspace members overlap")
    # Every declaration in the wallet workspace, with every feature, including the
    # facade's exclusive backends, whose inactive edges still count.
    errors.extend(problems(metadata(ROOT / "Cargo.toml"), owned))

    # Fresh lockfiles exercise downstream resolution independently of both checked-in
    # lockfiles. Neither consumer has a direct node or wallet-pir dependency.
    with tempfile.TemporaryDirectory(prefix="wallet-server-consumers-") as temporary:
        for kind, dependency, source in (
            ("wallet", f'zakura-receiver-crypto = {{ path = "{ROOT / "zakura/receiver-crypto"}" }}',
             'fn main() { let _ = zakura_receiver_crypto::RECORD_BYTES; }\n'),
            ("transparent-wallet",
             f'zakura-pir-transparent = {{ path = "{ROOT / "zakura/pir-transparent"}", features = ["sqlite", "testing"] }}\n'
             f'zakura-pir-transparent-wallet = {{ path = "{ROOT / "zakura/pir-transparent-wallet"}", features = ["reqwest", "testing"] }}\n'
             f'zakura-pir-transparent-filter = {{ path = "{ROOT / "zakura/pir-transparent-filter"}", features = ["cli"] }}',
             'fn main() { let _ = transparent_wallet_store::SCHEMA_VERSION; }\n'),
            ("receiver-wallet",
             f'zakura-pir-receiver = {{ path = "{ROOT / "zakura/pir-receiver"}", features = ["wallet"] }}\n'
             f'zakura-receiver-pir = {{ path = "{ROOT / "zakura/receiver-pir"}", features = ["server"] }}\n'
             f'zakura-receiver-directory = {{ path = "{ROOT / "zakura/receiver-directory"}", features = ["store"] }}',
             'fn main() { let _ = zakura_pir_receiver::MAINNET_GENESIS; }\n'),
            ("server-production", f'zakura-server-chain = {{ path = "{ROOT / "server/chain"}" }}',
             'fn main() { let _ = zakura_server_chain::NodeClient::new("http://127.0.0.1:1".into(), None); }\n'),
            ("server", f'zakura-server-chain = {{ path = "{ROOT / "server/chain"}", features = ["testing"] }}',
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
            errors.extend(problems(fresh, owned, nodes, wallet=not kind.startswith("server")))
            if not errors:
                subprocess.run(["cargo", "check", "--locked", "--manifest-path", str(consumer / "Cargo.toml")], cwd=ROOT, check=True)
        # The primary wallet facade must also remain node-free and free of
        # wallet-pir packages in each mutually exclusive backend mode.
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
            errors.extend(problems(fresh, owned, nodes, wallet=True))
    if errors:
        raise SystemExit("server ownership boundary failed:\n  " + "\n  ".join(sorted(set(errors))))
    print("verified: separate server workspace and fresh consumers; no wallet-pir-owned dependency declared or resolved in either workspace or any consumer")


if __name__ == "__main__":
    main()
