#!/usr/bin/env bash
set -euo pipefail

# Prove the vendored tree got here by merging the vendor branch.
#
# `librustzcash/` is edited directly, so it cannot be checked by regenerating
# it. What can be checked is its provenance: the vendor commit recorded in the
# manifest must be an ancestor of HEAD. That fails if someone pastes an
# upstream change into the tree and bumps the pin without merging, which would
# leave the next real merge without a usable base.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

vendor_commit="$(python3 - "$repo_root/manifests/sources.toml" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as manifest_file:
    print(tomllib.load(manifest_file)["source"][0]["vendor_commit"])
PY
)"

if ! git -C "$repo_root" cat-file -e "${vendor_commit}^{commit}" 2>/dev/null; then
  echo "recorded vendor commit is not in this repository: $vendor_commit" >&2
  echo "fetch the vendor branch, or run ./scripts/sync-upstream.sh" >&2
  exit 1
fi

if ! git -C "$repo_root" merge-base --is-ancestor "$vendor_commit" HEAD; then
  echo "recorded vendor commit is not an ancestor of HEAD: $vendor_commit" >&2
  echo "the vendored tree was changed without merging the vendor branch" >&2
  exit 1
fi

echo "verified: $vendor_commit is an ancestor of HEAD"
