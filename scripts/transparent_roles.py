#!/usr/bin/env python3
"""Verify the Transparent wallet/server split from fresh external consumers.

Each consumer is its own package with its own lockfile and its own Cargo
invocation, so no other package's features unify into its graph: what a
consumer resolves is exactly what a wallet or service depending on that crate
would build. For every consumer this checks the normal and build dependency
graph (not development dependencies), the features `zakura-pir-native` is
built with, that the consumer compiles, and that operations of the other role
do not compile at all.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import server_graph  # noqa: E402

SHARED = "zakura-transparent-private-shared"
WALLET = "zakura-transparent-private-wallet"
SERVER = "zakura-transparent-private-server"
NATIVE = "zakura-pir-native"
# What the protocol crate may never pull in: either role, a wallet backend or
# its storage, an HTTP stack or an async runtime.
BACKEND = {"zakura-client-backend", "zakura-client-sqlite", "rusqlite", "libsqlite3-sys"}
NETWORK = {"reqwest", "hyper", "axum", "tokio"}


def path(directory: str) -> str:
    return str(ROOT / "zakura" / directory)


def dependency(name: str, directory: str, features=()) -> str:
    listed = ", ".join(f'"{feature}"' for feature in features)
    return f'{name} = {{ path = "{path(directory)}", default-features = false, features = [{listed}] }}'


SHARED_USE = """
use zakura_transparent_private_shared::{filter, native::TableProfile, shard};
fn shared() {
    let _ = TableProfile::new(shard::SCHEMA, "decoupled-2k-8k", "directory", 2048, 4096);
    let _ = shard::candidate_rows(0, b"script", 2048);
    let _ = filter::validate_filter(&[0], filter::FilterLimits::default());
}
"""

# name, dependencies, source, forbidden packages, native features allowed
CONSUMERS = [
    ("shared", [dependency(SHARED, "transparent-private-shared")],
     SHARED_USE + "fn main() { shared(); }\n",
     {WALLET, SERVER} | BACKEND | NETWORK, set()),
    ("wallet", [dependency(WALLET, "transparent-private-wallet")],
     """use zakura_transparent_private_wallet::{native::TableQuery as _, shared::native::TableProfile, txid_client::TxidDisplayClient};
fn main() {
    let profile = TableProfile::new("s", "g", "directory", 2048, 4096).unwrap();
    let _ = profile.prepare(0);
    let _: Option<TxidDisplayClient> = None;
}
""", {SERVER} | BACKEND | NETWORK, {"client"}),
    ("wallet-engine-store-http", [dependency(WALLET, "transparent-private-wallet", ["engine-store", "reqwest"])],
     """use zakura_transparent_private_wallet::{engine::http::HttpOptions, engine_store::SqliteStore};
fn main() { let _: Option<(HttpOptions, SqliteStore)> = None; }
""", {SERVER, "zakura-client-backend", "zakura-client-sqlite", "axum"}, {"client"}),
    ("wallet-sqlite", [dependency(WALLET, "transparent-private-wallet", ["sqlite"])],
     """use zakura_transparent_private_wallet::{ApplyError, CompanionDir, TransparentHistoryRecoveryConfig};
fn main() { let _ = CompanionDir::new("."); let _: Option<(ApplyError, TransparentHistoryRecoveryConfig)> = None; }
""", {SERVER, "axum"}, {"client"}),
    ("server", [dependency(SERVER, "transparent-private-server"), dependency(SHARED, "transparent-private-shared")],
     """use zakura_transparent_private_server::{native::TableServe as _, shard::ShardStream};
use zakura_transparent_private_shared::native::TableProfile;
fn main() {
    let profile = TableProfile::new("s", "g", "directory", 2048, 4096).unwrap();
    let _ = profile.parse(&[]);
    let _: Option<ShardStream> = None;
}
""", {WALLET} | BACKEND | NETWORK, {"server"}),
]

# Each probe must fail to compile: the operation belongs to the other role, or
# to tests. `name` reuses a consumer's dependencies plus the generic native
# crate, with no features of its own, to see what the graph enabled.
PROBES = [
    ("wallet", "native server parse in a wallet", "fn main() { let _ = zakura_pir_native::parse_with; }\n"),
    ("wallet", "native server packing in a wallet", "fn main() { let _ = zakura_pir_native::pack::<zakura_pir_native::NativePreprocessed>; }\n"),
    ("wallet", "server table parsing in a wallet", "use zakura_transparent_private_wallet::shared::native::TableProfile;\nfn probe(p: TableProfile) { let _ = p.parse(&[]); }\nfn main() { let _ = probe; }\n"),
    ("wallet-sqlite", "relaxed txid floor in a production wallet", "fn main() { let _ = zakura_transparent_private_wallet::txid_client::TxidDisplayClient::with_min_recent_floor; }\n"),
    ("wallet-sqlite", "synthetic batches in a production wallet", "fn main() { let _ = zakura_transparent_private_wallet::testing::batch::<()>; }\n"),
    ("server", "native query preparation in a server", "fn main() { let _ = zakura_pir_native::prepare_with; }\n"),
    ("server", "native decoding in a server", "fn main() { let _ = zakura_pir_native::decode_cols; }\n"),
    ("server", "in-process service in a production server", "fn main() { let _ = zakura_transparent_private_server::testing::service::publish; }\n"),
    ("shared", "native query preparation in the protocol", "fn main() { let _ = zakura_pir_native::prepare_with; }\n"),
    ("shared", "native server parse in the protocol", "fn main() { let _ = zakura_pir_native::parse_with; }\n"),
]


def write(consumer: Path, name: str, dependencies: list[str], source: str) -> None:
    (consumer / "src").mkdir(parents=True, exist_ok=True)
    (consumer / "Cargo.toml").write_text(
        f'[package]\nname = "{name}-role-consumer"\nversion = "0.0.0"\nedition = "2024"\n'
        "[dependencies]\n" + "\n".join(dependencies) + "\n"
    )
    (consumer / "src/main.rs").write_text(source)


def resolved(metadata: dict) -> tuple[set[str], set[str]]:
    """Package names reachable through normal and build edges from the consumer,
    and the features the generic native crate is built with."""
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    names = {package["id"]: package["name"] for package in metadata["packages"]}
    seen, queue = set(), [metadata["resolve"]["root"]]
    while queue:
        node = queue.pop()
        if node in seen:
            continue
        seen.add(node)
        for edge in nodes[node]["deps"]:
            if any(kind["kind"] in (None, "build") for kind in edge["dep_kinds"]):
                queue.append(edge["pkg"])
    native = {feature for node in seen if names[node] == NATIVE for feature in nodes[node]["features"]}
    return {names[node] for node in seen}, native


def main() -> int:
    manifest = tomllib.loads((ROOT / "manifests/sources.toml").read_text())
    owned = set(manifest["server"]["wallet_pir_packages"])
    nodes = set(manifest["server"]["node_packages"])
    errors: list[str] = []
    with tempfile.TemporaryDirectory(prefix="transparent-role-consumers-") as temporary:
        for name, dependencies, source, forbidden, native_allowed in CONSUMERS:
            consumer = Path(temporary) / name
            write(consumer, name, dependencies, source)
            metadata = server_graph.metadata(consumer / "Cargo.toml", locked=False)
            errors.extend(f"{name}: {problem}" for problem in server_graph.problems(metadata, owned, nodes, wallet=True))
            packages, native = resolved(metadata)
            for package in sorted(packages & forbidden):
                errors.append(f"{name}: production graph resolves {package}")
            if native - native_allowed - {"default"}:
                errors.append(f"{name}: {NATIVE} built with {sorted(native)}, only {sorted(native_allowed)} allowed")
            built = subprocess.run(["cargo", "check", "--quiet", "--manifest-path", str(consumer / "Cargo.toml")], cwd=ROOT)
            if built.returncode:
                errors.append(f"{name}: the consumer does not compile")
            print(f"{name}: {len(packages)} packages; {NATIVE} features {sorted(native) or 'none'}", flush=True)
        for index, (base, description, source) in enumerate(PROBES):
            dependencies = next(c[1] for c in CONSUMERS if c[0] == base)
            consumer = Path(temporary) / f"probe-{index}"
            write(consumer, f"probe-{index}", dependencies + [dependency(NATIVE, "pir-native")], source)
            probe = subprocess.run(
                ["cargo", "check", "--quiet", "--message-format", "short", "--manifest-path", str(consumer / "Cargo.toml")],
                cwd=ROOT, capture_output=True, text=True,
            )
            # Only "not found" errors count: the operation does not exist here.
            unavailable = probe.returncode != 0 and any(code in probe.stderr for code in ("E0425", "E0433", "E0599", "E0432"))
            print(f"probe {description}: {'unavailable' if unavailable else 'AVAILABLE'}", flush=True)
            if not unavailable:
                errors.append(f"probe {description}: compiled, or failed for another reason:\n{probe.stderr[-2000:]}")
    if errors:
        print("Transparent role boundary failed:\n  " + "\n  ".join(errors), file=sys.stderr)
        return 1
    print("verified: shared, wallet and server consumers resolve and build only their own role")
    return 0


if __name__ == "__main__":
    sys.exit(main())
