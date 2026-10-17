#!/usr/bin/env python3
"""Verify the server ownership boundary and fresh wallet/server consumer graphs."""
import json
import posixpath
from pathlib import Path
import subprocess
import tempfile
import tomllib
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


GITHUB_HOSTS = ("github.com", "www.github.com", "ssh.github.com")


def wallet_pir_owned(value):
    """Recognize both historical and current ownership URLs, including git sources.

    Release and graph verification share this predicate; it names the repository
    only, so package-name checks must stay alongside it.
    """
    if not value:
        return False
    # Cargo source IDs add git+ and a revision; repository metadata can also
    # use Git's scp-style SSH URL. Parse the host independently of its port.
    value = value.strip().removeprefix("git+")
    # Cargo parses special-scheme URLs as WHATWG URLs, which read a backslash as
    # a slash; urlsplit would otherwise keep it inside the hostname.
    if value.split(":", 1)[0].lower() in ("http", "https"):
        value = value.replace("\\", "/")
    if "://" not in value and ":" in value:
        host, path = value.split(":", 1)
        if host.rsplit("@", 1)[-1].lower().rstrip(".") in GITHUB_HOSTS:
            value = f"ssh://{host}/{path}"
    try:
        parsed = urlsplit(value)
        if unquote(parsed.hostname or "").lower().rstrip(".") not in GITHUB_HOSTS:
            return False
    except ValueError:
        return False
    # Git accepts escaped hostnames and resolves dot segments in HTTP paths.
    # Decode once: double escaping names a different path on GitHub.
    path = posixpath.normpath(unquote(parsed.path).lower()).strip("/")
    return path.removesuffix(".git") in ("valargroup/wallet-pir", "zakura-core/wallet-pir")


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


def lock_problems(lockfile, owned):
    """A checked-in lockfile must not resolve a wallet-pir package, under any name or source."""
    errors = []
    for package in tomllib.loads(lockfile.read_text()).get("package", []):
        if package["name"] in owned or wallet_pir_owned(package.get("source")):
            errors.append(f"{lockfile.relative_to(ROOT)}: resolves wallet-pir package {package['name']}")
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
    # The ordinary wallet workspace too: every member's declarations of every kind,
    # and both checked-in lockfiles. A wallet-libraries release never waits on a
    # wallet-pir release.
    root = metadata(ROOT / "Cargo.toml", no_deps=True)
    errors.extend(problems(root, owned))
    # The Transparent cross-version workspace builds the baseline release from
    # its pinned wallet-libraries commit, never anything wallet-pir owns.
    compat = ROOT / "zakura/transparent-private-compat"
    errors.extend(problems(metadata(compat / "Cargo.toml"), owned))
    for lockfile in (ROOT / "Cargo.lock", workspace / "Cargo.lock", compat / "Cargo.lock"):
        errors.extend(lock_problems(lockfile, owned))
    if set(root["workspace_members"]) & set(graph["workspace_members"]):
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
        # Each mutually exclusive facade backend must remain free of both
        # node packages and wallet-pir ownership, including transitive packages.
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
    print("verified: separate server workspace and fresh consumers; no wallet-pir-owned dependency in either workspace or lockfile")


if __name__ == "__main__":
    main()
