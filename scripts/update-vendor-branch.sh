#!/usr/bin/env bash
set -euo pipefail

# Record an upstream release on the vendor branch.
#
# The vendor branch holds pristine upstream, pruned to the crates this
# repository forks, with their directories at its root. `main` carries the same
# tree under `librustzcash/` plus our changes, and takes upstream releases by
# merging this branch with `-X subtree=librustzcash`.
#
# Keeping upstream unmodified on its own branch is what makes those merges
# three-way: the merge base is a real upstream tree, so git can tell our edits
# apart from theirs instead of re-applying a patch series.
#
#   ./scripts/update-vendor-branch.sh <tag-or-commit>
#
# Prints the resulting vendor commit.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$repo_root/manifests/sources.toml"
ref="${1:-}"

if [[ -z "$ref" ]]; then
  echo "usage: $0 <tag-or-commit>" >&2
  exit 2
fi

read -r vendor_branch upstream_manifest < <(
  python3 - "$manifest" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as manifest_file:
    layout = tomllib.load(manifest_file)["layout"]

print(layout["vendor_branch"], layout["upstream_manifest"])
PY
)

read -r url < <(
  python3 - "$manifest" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as manifest_file:
    print(tomllib.load(manifest_file)["source"][0]["url"])
PY
)

mapfile -t crate_paths < <(
  python3 - "$manifest" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as manifest_file:
    for crate in tomllib.load(manifest_file)["crate"]:
        path = crate["path"]
        if "/" in path or path.startswith("."):
            raise SystemExit(f"unexpected crate path: {path}")
        print(path)
PY
)

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/wallet-libraries-vendor.XXXXXX")"
worktree="$tmp_root/worktree"
extract="$tmp_root/extract"
cleanup() {
  git -C "$repo_root" worktree remove --force "$worktree" 2>/dev/null || true
  rm -rf "$tmp_root"
}
trap cleanup EXIT

echo "Fetching $url at $ref" >&2
git -C "$repo_root" fetch --quiet --depth=1 "$url" "$ref"
resolved_commit="$(git -C "$repo_root" rev-parse FETCH_HEAD^{commit})"

mkdir -p "$extract"
git -C "$repo_root" archive "$resolved_commit" Cargo.toml "${crate_paths[@]}" \
  | tar -x -C "$extract"

for crate_path in "${crate_paths[@]}"; do
  if [[ ! -f "$extract/$crate_path/Cargo.toml" ]]; then
    echo "crate is not present upstream at $ref: $crate_path" >&2
    exit 1
  fi
done

# The upstream workspace manifest travels with the crates, under a name Cargo
# will not treat as a manifest: the root Cargo.toml is generated from it, and
# generating rather than merging it keeps our dependency rewiring out of every
# future merge conflict.
mv "$extract/Cargo.toml" "$extract/$(basename "$upstream_manifest")"

if git -C "$repo_root" show-ref --verify --quiet "refs/heads/$vendor_branch"; then
  git -C "$repo_root" worktree add --quiet "$worktree" "$vendor_branch"
else
  git -C "$repo_root" worktree add --quiet --detach "$worktree"
  git -C "$worktree" checkout --quiet --orphan "$vendor_branch"
  git -C "$worktree" rm -rq --cached . 2>/dev/null || true
fi

# Replace the tree wholesale: this branch is upstream and nothing else.
find "$worktree" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
cp -R "$extract"/. "$worktree"/

git -C "$worktree" add -A
if git -C "$worktree" diff --cached --quiet; then
  echo "vendor branch already at $ref" >&2
else
  git -C "$worktree" commit --quiet \
    -m "vendor: librustzcash $ref" \
    -m "Upstream commit $resolved_commit, pruned to the vendored crates."
fi

git -C "$worktree" rev-parse HEAD
