#!/usr/bin/env bash
set -euo pipefail

# Build the wallet-lib facade both ways and prove each build reaches exactly
# one stack.
#
# The facade is the only crate here whose features are mutually exclusive, so it
# is excluded from the whole-workspace check and verified by this script
# instead. Both directions matter: a Zakura build that pulls a crates.io
# original, and an upstream build that pulls a `zakura-*` fork, are the same
# bug — two families of the same types in one binary — seen from either side.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$repo_root/manifests/sources.toml"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_root/target/verify-wallet-lib-modes}"

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
