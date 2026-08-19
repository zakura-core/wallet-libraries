#!/usr/bin/env bash
set -euo pipefail

# Take an upstream librustzcash release into this fork.
#
#   ./scripts/sync-upstream.sh                    re-check the pinned release
#   ./scripts/sync-upstream.sh <tag-or-commit>    move to a new release
#
# The vendored crates are edited directly here, so a release arrives as a merge
# rather than a regeneration: the vendor branch moves to the new release and is
# merged into the current branch, letting git reconcile upstream's changes with
# ours. Only the root Cargo.toml is still generated.
#
# A conflicting merge is left in place for a person to finish (exit status 2).
# That is the expected outcome now and then — it is what carrying real changes
# costs — and it is why this script stops rather than guessing. CI commits the
# conflicted merge onto the automation branch and opens a draft pull request.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$repo_root/manifests/sources.toml"
ref="${1:-}"

read -r vendor_branch vendored_directory pinned_ref < <(
  python3 - "$manifest" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as manifest_file:
    parsed = tomllib.load(manifest_file)

layout = parsed["layout"]
print(layout["vendor_branch"], layout["vendored_directory"], parsed["source"][0]["ref"])
PY
)

ref="${ref:-$pinned_ref}"

if ! git -C "$repo_root" diff --quiet || ! git -C "$repo_root" diff --cached --quiet; then
  echo "working tree is dirty; commit or stash before syncing" >&2
  exit 1
fi

vendor_commit="$("$repo_root/scripts/update-vendor-branch.sh" "$ref")"

# `-X subtree` tells the merge that the vendor branch's root corresponds to the
# vendored directory here; without it every path looks added-and-deleted.
if ! git -C "$repo_root" merge --no-edit -X "subtree=$vendored_directory" \
  -m "chore: merge librustzcash $ref" "$vendor_commit"; then
  echo >&2
  echo "upstream merge conflicts; resolve them, then run:" >&2
  echo "  python3 scripts/generate-workspace.py \"$repo_root\"" >&2
  echo "  ./scripts/verify-zakura-graph.sh" >&2
  echo "  ./scripts/verify-wallet-lib-modes.sh" >&2
  # Distinct from other failures so CI can open a draft pull request.
  exit 2
fi

python3 "$repo_root/scripts/generate-workspace.py" "$repo_root"

python3 - "$manifest" "$ref" "$vendor_commit" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
ref, vendor_commit = sys.argv[2:]
text = path.read_text()

text, refs = re.subn(
    r'^ref = ".*"$', f'ref = "{ref}"', text, count=1, flags=re.MULTILINE
)
text, commits = re.subn(
    r'^vendor_commit = "[0-9a-f]{40}"$',
    f'vendor_commit = "{vendor_commit}"',
    text,
    count=1,
    flags=re.MULTILINE,
)

if not refs or not commits:
    raise SystemExit("could not update the pin in the manifest")

path.write_text(text)
PY

if ! git -C "$repo_root" diff --quiet -- Cargo.toml "$manifest"; then
  git -C "$repo_root" add Cargo.toml "$manifest"
  git -C "$repo_root" commit --quiet \
    -m "chore: regenerate the workspace for librustzcash $ref"
fi

echo "merged librustzcash $ref ($vendor_commit)"
