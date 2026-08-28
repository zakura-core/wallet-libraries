# Zakura wallet libraries

The wallet layer of the Zakura stack: the librustzcash crates a wallet needs
that [`zakura-core/libraries`](https://github.com/zakura-core/libraries) does
not already ship, forked and rewired onto the published `zakura-*` crypto
crates.

`libraries` covers the proving stack and the crates that sit directly on top of
it — `zakura-primitives`, `zakura-keys`, `zakura-proofs`, `zakura-orchard`, the
halo2 family. It stops below the wallet layer, so a wallet consuming it still
resolves `zcash_client_backend` and `zcash_client_sqlite` from crates.io, which
drags the crates.io `orchard` and `zcash_primitives` back into the graph
alongside their Zakura forks. This repository closes that gap.

## What is vendored

| Directory | Published as | Forked from |
| --- | --- | --- |
| `librustzcash/pczt` | `zakura-pczt` | `zcash/librustzcash` |
| `librustzcash/zcash_client_backend` | `zakura-client-backend` | `zcash/librustzcash` |
| `librustzcash/zcash_client_sqlite` | `zakura-client-sqlite` | `zcash/librustzcash` |

Directory names and library target names keep their upstream spelling, so crate
sources and `use` paths are untouched; only the package name changes. This is
the convention `libraries` already follows.

**Membership rule.** A crate belongs here when it depends on the renamed crypto
stack and `libraries` does not already ship it. A crate that `zakura-*` resolves
from crates.io must *not* be vendored here — two copies of a package whose types
cross the boundary are two different types, and the build only fails later, in a
consumer. `zcash_address`, `zip321`, `zcash_protocol`, `zcash_transparent`,
`zcash_encoding` and `equihash` therefore stay on crates.io.

`zcash_client_sqlite` upstream also depends on `zcash_pool_migration`. Vizor
does not use the pool-migration engine, so this fork cuts that dependency
instead of carrying the crate: the module and its tests are gone, the schema
and its migrations are not, and an existing database still opens.

## Layout

Three directories:

```text
librustzcash/   forked upstream crates   generated; sync deletes and rewrites it
wallet-lib/     the backend selector     hand-written
zakura/         new Zakura work          hand-written; empty for now
```

Only `librustzcash/` and the root `Cargo.toml` are generated. Anything
hand-written goes in `wallet-lib/` or `zakura/` and is listed in
`layout.extra_members` in `manifests/sources.toml`, which the workspace
generator appends to the members it produces — a crate placed under
`librustzcash/` would be deleted by the next sync.

## How the rewiring works

Nothing is patched at the source level. `manifests/sources.toml` holds a
`[rewire]` table, and the generated root `Cargo.toml` turns each entry into a
Cargo dependency rename:

```toml
orchard = { version = "1.0.0-rc.3", package = "zakura-orchard" }
```

The dependency key stays `orchard`, so every `orchard::` path in the vendored
sources keeps compiling, while the package that satisfies it is the fork. The
vendored crates inherit these through `workspace = true`, which is why the fork
currently carries **no source patches at all**.

There is no `[patch.crates-io]` anywhere in this design. Package names differ
from their upstream originals, so consumers declare these crates directly and
every edge is explicit — the same reasoning `libraries` documents.

## Verify

```bash
./scripts/verify-zakura-graph.sh
```

Checks the workspace with all targets and all features, then reads
`cargo metadata` to prove the resolved graph is Zakura-only: no crates.io
original of a forked crate is present, and no vendored crate appears twice.
Compiling alone would not prove this — an edge that escapes the rewiring builds
fine here and fails later where the two type families meet.

## Selecting a backend

`wallet-lib/` holds `zakura-wallet-lib`, which exists for code that has to build
for **both** Gemini and Vizor from one source tree — `zcash_voting` and the vote
commitment tree. It re-exports one family under stable names:

```rust
use zakura_wallet_lib::{client_backend, orchard};
```

```toml
# Vizor: Zakura with Orchard, the default
zakura-wallet-lib = "0.1.0-rc3"

# Gemini: upstream LRZ with Orchard
zakura-wallet-lib = { version = "0.1.0-rc3", default-features = false, features = ["lrz-orchard"] }
```

The two features are mutually exclusive. Cargo features are additive and there
is no way to enable a dependency when a feature is *off*, so the upstream
family needs its own named feature rather than being the implicit
`not(zakura)` case. Because `zakura` is the default, selecting `lrz` requires
`default-features = false`. Enabling both, or neither, is a compile error.

`scripts/verify-wallet-lib-modes.sh` builds it each way and fails if a crate from
the other family appears, if disabled packages leak into an external
consumer's lockfile or Cargo metadata, or if the mutually-exclusive rules stop
holding. The legacy cross-family `orchard` selector is replaced by explicit
`zakura-orchard` and `lrz-orchard` combinations. Consumers without Orchard
can select the base `zakura` or `lrz` feature. The old `orchard` name remains
a compatibility alias for the default `zakura-orchard` path. Consumers that
need the complete voting capability set use `zakura-voting` or `lrz-voting`.

An end consumer that builds for exactly one stack does not need this crate at
all — it declares the packages it wants directly, as below.

## Consume from a wallet

The dependency keys keep their upstream names, so wallet source needs no changes:

```toml
zcash_client_backend = { version = "0.1.0-rc3", package = "zakura-client-backend" }
zcash_client_sqlite = { version = "0.1.0-rc3", package = "zakura-client-sqlite" }
pczt = { version = "0.1.0-rc1", package = "zakura-pczt" }
```

The crypto stack comes from crates.io as `zakura-*`; do not also declare the
upstream crates.

## Working on the fork

`librustzcash/` is ours to change. Edit the files, commit, done — there is no
regeneration step and no patch series to keep in sync.

Upstream arrives as a merge. `vendor/librustzcash` is a branch holding pristine
upstream, pruned to the crates we vendor, with their directories at its root.
Moving to a new release updates that branch and merges it here:

```bash
./scripts/sync-upstream.sh                    # re-check the pinned release
./scripts/sync-upstream.sh <tag-or-commit>    # move to a new release
```

Because the vendor branch is unmodified upstream, the merge base is a real
upstream tree and git can tell our changes from theirs. Conflicts happen — that
is what carrying real changes costs — and the script stops (exit status 2) and
leaves the merge in place rather than guessing. Finish it, then re-run the
verification scripts. The scheduled sync job commits that conflicted merge onto
the automation branch and opens a **draft** pull request instead of failing
silently.

The root `Cargo.toml` stays generated, from the upstream workspace manifest the
vendor branch carries as `librustzcash/upstream-workspace.toml`. That is what
keeps the dependency rewiring out of merge territory: upstream bumps versions
on the same lines our renames touch, and generating the file means the two
never meet.

CI checks provenance rather than regenerating — the vendor commit recorded in
`manifests/sources.toml` must be an ancestor of `HEAD` — so a change pasted
into `librustzcash/` without a merge fails the build.

Not every upstream tag is consumable. Release candidates are cut before their
sibling crates are published, and upstream builds them against in-repo paths,
so a tag can call an API that does not exist in the crates.io release we
resolve. `zcash_client_sqlite-0.22.0-rc.8` is exactly that: it calls
`zcash_protocol::TxId::from_hex`, unpublished at the time of writing, so the
pin stays at `-rc.7`. The verification scripts are the gate; a sync that fails
them does not become a pull request.

## Automatic upstream updates

The **Sync upstream releases** workflow runs daily. It lists the upstream tags,
keeps those matching `tag_pattern` in `manifests/sources.toml` — the
`zcash_client_sqlite` release train, which is how `zcash_voting` selects its LRZ
version — and compares the highest semantic version against the current pin.
`allow_prerelease` decides whether a prerelease may be proposed automatically.

A newer release is synced, verified, and raised as a pull request on the
long-lived `automation/upstream-sync/librustzcash` branch. Nothing is
auto-merged. If the merge conflicts, verification is skipped and a **draft**
pull request is opened with the conflict markers committed, so someone can
check out the branch and finish the merge. A sync that merges cleanly but fails
verification still does not open a pull request. The same discovery runs
locally:

```bash
./scripts/discover-upstream-updates.py
```

Pull requests created with the default `GITHUB_TOKEN` do not trigger other
workflows, so a sync pull request shows no checks even though the sync job
verified the result before opening it. Setting an `UPSTREAM_SYNC_TOKEN` secret
that may open pull requests makes `verify.yml` run on the branch as well.

## Files

```text
librustzcash/           forked wallet-layer crates, edited directly
wallet-lib/             zakura-wallet-lib, the backend selector
zakura/                 new Zakura work
Cargo.toml              workspace manifest (generated)
manifests/sources.toml  layout, upstream pin, crate list, rewiring rules
scripts/
  sync-upstream.sh            move the vendor branch and merge it here
  update-vendor-branch.sh     record an upstream release on the vendor branch
  generate-workspace.py       root manifest from the upstream workspace
  verify-zakura-graph.sh      build and graph-purity check
  verify-wallet-lib-modes.sh  build the facade against each backend
  verify-vendor-ancestry.sh   the recorded vendor commit is an ancestor
  discover-upstream-updates.py
```
