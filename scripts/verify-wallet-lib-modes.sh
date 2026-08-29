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

# `cargo tree` reports the active build graph, but Cargo #10801 can retain
# disabled weak dependencies in a downstream lockfile and metadata. Exercise
# the facade from outside this workspace in the two real consumer shapes.
python3 <<'PY'
import os
from pathlib import Path

probe_root = Path(os.environ["WALLET_LIB_PROBE_ROOT"])
wallet_lib = Path(os.environ["WALLET_LIB_REPO_ROOT"]) / "wallet-lib"
dependencies = {
    "lrz": (
        f'zakura-wallet-lib = {{ path = "{wallet_lib}", '
        'default-features = false, features = ["lrz"] }'
    ),
    "zakura": (
        f'zakura-wallet-lib = {{ path = "{wallet_lib}", '
        'default-features = false, features = ["zakura"] }'
    ),
    "zakura-default": f'zakura-wallet-lib = {{ path = "{wallet_lib}" }}',
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

for consumer in lrz zakura zakura-default; do
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

for consumer in ("lrz", "zakura", "zakura-default"):
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

    if consumer == "lrz":
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
    if consumer == "zakura":
        drifted_rcs = {
            f'{package["name"]} {package["version"]}'
            for package in metadata["packages"]
            if package["name"].startswith("zakura-")
            and package["version"].startswith("1.0.0-rc.")
            and package["version"] != "1.0.0-rc.5"
        }
        if drifted_rcs:
            failures["non-RC5 Zakura packages"] = drifted_rcs

    if failures:
        for label, names in failures.items():
            print(
                f"{consumer} {label} contains the other backend: "
                + " ".join(sorted(names)),
                file=sys.stderr,
            )
        raise SystemExit(1)

print(
    "verified: external LRZ metadata/lock contains no Zakura forks, "
    "and external Zakura metadata/lock contains no LRZ originals"
)
PY

[[ "$(cargo run --quiet --manifest-path "$probe_root/lrz/Cargo.toml")" == "lrz" ]]
[[ "$(cargo run --quiet --manifest-path "$probe_root/zakura/Cargo.toml")" == "zakura" ]]
[[ "$(cargo run --quiet --manifest-path "$probe_root/zakura-default/Cargo.toml")" == "zakura" ]]

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

# Resolve the facade as a fresh external consumer. The workspace lockfile
# cannot protect downstream users, and Cargo's prerelease ranges otherwise
# allow a newer Zakura release with a higher MSRV into their graph.
consumer="$(mktemp -d "${TMPDIR:-/tmp}/zakura-wallet-lib-consumer.XXXXXX")"
trap 'rm -rf "$consumer"' EXIT
mkdir -p "$consumer/src"
cat > "$consumer/Cargo.toml" <<EOF
[package]
name = "external-wallet-lib-consumer"
version = "0.0.0"
edition = "2024"
rust-version = "1.91"

[dependencies]
zakura-wallet-lib = { path = "$repo_root/wallet-lib" }
EOF
cat > "$consumer/src/lib.rs" <<'EOF'
pub use zakura_wallet_lib::*;
EOF

echo "== fresh external consumer with Rust 1.91"
if ! rustup run 1.91 rustc --version >/dev/null 2>&1; then
  rustup toolchain install 1.91 --profile minimal --no-self-update
fi
cargo +1.91 generate-lockfile --manifest-path "$consumer/Cargo.toml"
cargo +1.91 metadata --manifest-path "$consumer/Cargo.toml" \
  --format-version 1 --locked > "$consumer/metadata.json"

python3 - "$consumer/metadata.json" <<'PY'
import json
import sys
from pathlib import Path

packages = {
    package["name"]: package["version"]
    for package in json.loads(Path(sys.argv[1]).read_text())["packages"]
}
expected = {
    "zakura-bellman",
    "zakura-bls12-381",
    "zakura-halo2-gadgets",
    "zakura-halo2-legacy-pdqsort",
    "zakura-halo2-poseidon",
    "zakura-halo2-proofs",
    "zakura-jubjub",
    "zakura-keys",
    "zakura-orchard",
    "zakura-pairing",
    "zakura-pasta-curves",
    "zakura-primitives",
    "zakura-reddsa",
    "zakura-redjubjub",
    "zakura-sapling-crypto",
    "zakura-sinsemilla",
}
required_version = "1.0.0-rc.5"
problems = [
    f"{name}: expected {required_version}, found {packages.get(name, 'missing')}"
    for name in sorted(expected)
    if packages.get(name) != required_version
]
if problems:
    print("fresh consumer did not stay on the RC5 crypto family:", file=sys.stderr)
    for problem in problems:
        print(f"  {problem}", file=sys.stderr)
    raise SystemExit(1)
PY

cargo +1.91 check --manifest-path "$consumer/Cargo.toml" --locked

echo "verified: Zakura is the clean default, each explicit backend resolves"
echo "to exactly one stack, a fresh Rust 1.91 consumer stays on RC5, and"
echo "neither no-backend nor both-backends compiles"
