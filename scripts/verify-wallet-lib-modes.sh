#!/usr/bin/env bash
set -euo pipefail

# Build the wallet-lib facade in every base/Orchard mode and prove each build
# reaches exactly one stack.
#
# The facade is the only crate here whose features are mutually exclusive, so it
# is excluded from the whole-workspace check and verified by this script
# instead. Both directions matter: a Zakura build that pulls a crates.io
# original, and an upstream build that pulls a `zakura-*` fork, are the same
# bug — two families of the same types in one binary — seen from either side.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$repo_root/manifests/sources.toml"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_root/target/verify-wallet-lib-modes}"

probe_root="$(mktemp -d "${TMPDIR:-/tmp}/wallet-lib-modes.XXXXXX")"
trap 'rm -rf "$probe_root"' EXIT
export WALLET_LIB_PROBE_ROOT="$probe_root"
export WALLET_LIB_REPO_ROOT="$repo_root"

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

# The crates.io originals of everything the Zakura stack forks, as a regex
# alternation anchored to the start of a `cargo tree --prefix none` line.
forbidden="$(python3 - "$manifest" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as manifest_file:
    names = tomllib.load(manifest_file)["graph"]["forbidden"]

print("^(" + "|".join(names) + ") v")
PY
)"

check_mode() {
  local feature="$1"
  local pattern="$2"
  local description="$3"

  echo "== $facade with --features $feature"
  cargo check --manifest-path "$repo_root/Cargo.toml" \
    --package "$facade" --no-default-features --features "$feature" --locked

  # The facade is the root of its own tree, and its name starts with the same
  # prefix the upstream check looks for, so drop it before matching.
  local tree
  tree="$(cargo tree --manifest-path "$repo_root/Cargo.toml" \
    --package "$facade" --no-default-features --features "$feature" \
    --edges normal,build --prefix none --locked | grep -v "^$facade v")"

  if grep -Eq "$pattern" <<<"$tree"; then
    echo >&2
    echo "$description" >&2
    grep -E "$pattern" <<<"$tree" | sort -u | sed 's/^/  /' >&2
    return 1
  fi
}

echo "== $facade with default features"
cargo check --manifest-path "$repo_root/Cargo.toml" \
  --package "$facade" --locked

default_tree="$(cargo tree --manifest-path "$repo_root/Cargo.toml" \
  --package "$facade" --edges normal,build --prefix none --locked \
  | grep -v "^$facade v")"

if grep -Eq "$forbidden" <<<"$default_tree"; then
  echo >&2
  echo "a crates.io original entered the default Zakura build:" >&2
  grep -E "$forbidden" <<<"$default_tree" | sort -u | sed 's/^/  /' >&2
  exit 1
fi

check_mode lrz "^zakura-" \
  "a Zakura fork entered the upstream build:"

check_mode zakura "$forbidden" \
  "a crates.io original entered the Zakura build:"

check_mode lrz-orchard "^zakura-" \
  "a Zakura fork entered the LRZ Orchard build:"

check_mode zakura-orchard "$forbidden" \
  "a crates.io original entered the Zakura Orchard build:"

check_mode lrz-voting "^zakura-" \
  "a Zakura fork entered the LRZ voting build:"

check_mode zakura-voting "$forbidden" \
  "a crates.io original entered the Zakura voting build:"

# `cargo tree` reports the active build graph, but Cargo #10801 can retain
# disabled weak dependencies in a downstream lockfile and metadata. Exercise
# the facade from outside this workspace in the two real consumer shapes.
python3 <<'PY'
import os
from pathlib import Path

probe_root = Path(os.environ["WALLET_LIB_PROBE_ROOT"])
wallet_lib = Path(os.environ["WALLET_LIB_REPO_ROOT"]) / "wallet-lib"
dependencies = {
    "gemini": (
        f'zakura-wallet-lib = {{ path = "{wallet_lib}", '
        'default-features = false, features = ["lrz-voting"] }'
    ),
    "vizor": f'zakura-wallet-lib = {{ path = "{wallet_lib}" }}',
    "vizor-voting": (
        f'zakura-wallet-lib = {{ path = "{wallet_lib}", '
        'default-features = false, features = ["zakura-voting"] }'
    ),
    "vizor-legacy": (
        f'zakura-wallet-lib = {{ path = "{wallet_lib}", '
        'default-features = false, features = ["zakura", "orchard"] }'
    ),
}

for name, dependency in dependencies.items():
    consumer = probe_root / name
    (consumer / "src").mkdir(parents=True)
    (consumer / "Cargo.toml").write_text(
        f"""\
[package]
name = "{name}-wallet-lib-probe"
version = "0.0.0"
edition = "2021"

[dependencies]
{dependency}
"""
    )
    (consumer / "src" / "main.rs").write_text(
        'fn main() { println!("{}", zakura_wallet_lib::BACKEND); }\n'
    )
PY

for consumer in gemini vizor vizor-voting vizor-legacy; do
  cargo metadata --manifest-path "$probe_root/$consumer/Cargo.toml" \
    --format-version 1 > "$probe_root/$consumer/metadata.json"
done

python3 - "$probe_root" "$manifest" <<'PY'
import json
import re
import sys
import tomllib
from pathlib import Path

probe_root, source_manifest = Path(sys.argv[1]), Path(sys.argv[2])
with source_manifest.open("rb") as manifest_file:
    upstream_names = set(tomllib.load(manifest_file)["graph"]["forbidden"])

for consumer in ("gemini", "vizor", "vizor-voting", "vizor-legacy"):
    root = probe_root / consumer
    metadata = json.loads((root / "metadata.json").read_text())
    packages_by_id = {
        package["id"]: package["name"] for package in metadata["packages"]
    }
    package_names = set(packages_by_id.values())
    resolved_names = {
        packages_by_id[node["id"]] for node in metadata["resolve"]["nodes"]
    }
    lock_names = set(
        re.findall(
            r'^name = "([^"]+)"$',
            (root / "Cargo.lock").read_text(),
            re.MULTILINE,
        )
    )

    if consumer == "gemini":
        allowed = {"zakura-wallet-lib"}
        checks = {
            "metadata packages": {
                name for name in package_names if name.startswith("zakura-")
            } - allowed,
            "resolved nodes": {
                name for name in resolved_names if name.startswith("zakura-")
            } - allowed,
            "lockfile": {
                name for name in lock_names if name.startswith("zakura-")
            } - allowed,
        }
    else:
        checks = {
            "metadata packages": package_names & upstream_names,
            "resolved nodes": resolved_names & upstream_names,
            "lockfile": lock_names & upstream_names,
        }

    failures = {label: names for label, names in checks.items() if names}
    if failures:
        for label, names in failures.items():
            print(
                f"{consumer} {label} contains the other backend: "
                + " ".join(sorted(names)),
                file=sys.stderr,
            )
        raise SystemExit(1)

print(
    "verified: external Gemini metadata/lock contains no Zakura forks, "
    "and external Vizor metadata/lock contains no LRZ originals"
)
PY

[[ "$(cargo run --quiet --manifest-path "$probe_root/gemini/Cargo.toml")" == "lrz" ]]
[[ "$(cargo run --quiet --manifest-path "$probe_root/vizor/Cargo.toml")" == "zakura" ]]
[[ "$(cargo run --quiet --manifest-path "$probe_root/vizor-voting/Cargo.toml")" == "zakura" ]]
[[ "$(cargo run --quiet --manifest-path "$probe_root/vizor-legacy/Cargo.toml")" == "zakura" ]]

# The compatibility `orchard` alias is Zakura-specific. Combining it with LRZ
# must fail as mixed mode rather than weak-reference both families.
if cargo check --manifest-path "$repo_root/Cargo.toml" \
  --package "$facade" --no-default-features --features lrz,orchard \
  --locked 2>/dev/null; then
  echo "the removed conditional Orchard selector must not compile" >&2
  exit 1
fi

# Neither backend selected must fail loudly rather than build an empty facade.
if cargo check --manifest-path "$repo_root/Cargo.toml" \
  --package "$facade" --no-default-features --locked 2>/dev/null; then
  echo "selecting no backend must not compile" >&2
  exit 1
fi

# Both backends at once is what an LRZ consumer that forgot `default-features =
# false` produces; it must fail rather than resolve two stacks.
if cargo check --manifest-path "$repo_root/Cargo.toml" \
  --package "$facade" --features lrz,zakura --locked 2>/dev/null; then
  echo "selecting both backends must not compile" >&2
  exit 1
fi

echo "verified: Zakura is the clean default, each explicit backend resolves"
echo "to exactly one stack, and neither no-backend nor both-backends compiles"
