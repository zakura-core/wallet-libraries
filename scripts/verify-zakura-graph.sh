#!/usr/bin/env bash
set -euo pipefail

# Check the vendored wallet layer and prove that it resolves onto the Zakura
# crypto stack alone.
#
# Compiling is not sufficient on its own: an edge that escapes the rewiring
# pulls the crates.io original alongside the fork, and the build only fails
# later, in a consumer, where the two types meet. So the graph is inspected
# directly for the crates.io names `zakura-core/libraries` forks.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$repo_root/manifests/sources.toml"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_root/target/verify-zakura-graph}"

# The facade is excluded here and checked by verify-wallet-lib-modes.sh:
# its backend features are mutually exclusive, so `--all-features` cannot build
# it, and its optional upstream dependencies would appear in this graph.
# The facade's package name, read through the directory the manifest names.
facade="$(python3 - "$manifest" "$repo_root" <<'PY'
import sys
import tomllib
from pathlib import Path

manifest_path, repo_root = Path(sys.argv[1]), Path(sys.argv[2])

with manifest_path.open("rb") as manifest_file:
    directory = tomllib.load(manifest_file)["layout"]["facade"]

with (repo_root / directory / "Cargo.toml").open("rb") as facade_manifest:
    print(tomllib.load(facade_manifest)["package"]["name"])
PY
)"

cargo check --manifest-path "$repo_root/Cargo.toml" \
  --workspace --exclude "$facade" --all-targets --all-features --locked

cargo metadata --manifest-path "$repo_root/Cargo.toml" \
  --format-version 1 --all-features \
  > "$repo_root/target/zakura-graph-metadata.json"

python3 - "$repo_root/target/zakura-graph-metadata.json" "$manifest" <<'PY'
import json
import sys
import tomllib
from collections import defaultdict
from pathlib import Path

metadata = json.loads(Path(sys.argv[1]).read_text())
with open(sys.argv[2], "rb") as manifest_file:
    manifest = tomllib.load(manifest_file)

forbidden = set(manifest["graph"]["forbidden"])
expected_packages = {
    crate.get("package", crate["path"]) for crate in manifest["crate"]
}

packages = {package["id"]: package for package in metadata["packages"]}
nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}

reachable: set[str] = set()
queue = [
    package_id
    for package_id, package in packages.items()
    if package["name"] in expected_packages
]
while queue:
    package_id = queue.pop()
    if package_id in reachable:
        continue
    reachable.add(package_id)
    queue.extend(dependency["pkg"] for dependency in nodes[package_id]["deps"])

versions = defaultdict(set)
for package_id in reachable:
    package = packages[package_id]
    versions[package["name"]].add(package["version"])

problems = []

for name in sorted(forbidden & versions.keys()):
    problems.append(
        f"{name}: crates.io original present; an edge escaped the rewiring"
    )

for name, found in sorted(versions.items()):
    if len(found) > 1 and (name.startswith("zakura-") or name in expected_packages):
        problems.append(f"{name}: {len(found)} versions in the graph: {sorted(found)}")

missing = expected_packages - versions.keys()
for name in sorted(missing):
    problems.append(f"{name}: vendored crate is not in the resolved graph")

if problems:
    print("the resolved graph is not Zakura-only:", file=sys.stderr)
    for problem in problems:
        print(f"  {problem}", file=sys.stderr)
    raise SystemExit(1)

zakura = sorted(name for name in versions if name.startswith("zakura-"))
print(
    f"verified: {len(versions)} packages reachable from the vendored crates, "
    f"{len(zakura)} of them zakura, no crates.io originals"
)
print("  " + " ".join(zakura))
PY
