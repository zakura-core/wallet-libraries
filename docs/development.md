# Development workflow

Python 3.11+, Rust, and Git are sufficient for ordinary development on macOS
and Linux. `rust-toolchain.toml` pins the CI/development compiler; the facade
verification also checks a fresh Rust 1.91 consumer. Protobuf regeneration
requires the pinned compiler described below; ordinary builds do not.

## Commands

```sh
python3 scripts/dev.py doctor --config transparent
python3 scripts/dev.py test --config transparent -p zakura-client-sqlite transparent_ledger
python3 scripts/dev.py check --config orchard -p zakura-client-backend
python3 scripts/dev.py lint --config transparent -p zakura-client-sqlite
python3 scripts/dev.py verify --only wallet-lib-modes
python3 scripts/dev.py verify
```

| Configuration | Packages and features |
| --- | --- |
| `default` | Workspace except the facade, Enhance PIR and the transparent PIR adapter; default features |
| `orchard` | Backend + SQLite; `orchard,test-dependencies` |
| `transparent` | Backend + SQLite; `orchard,transparent-inputs,test-dependencies,unstable` |
| `transparent-import` | Backend + SQLite; transparent features plus `transparent-key-import` |
| `sqlite` | SQLite; `test-dependencies`, without Orchard |
| `enhance-wallet` | Enhance PIR; `wallet` |
| `enhance` | Enhance PIR; default features |
| `transparent-pir` | Transparent PIR adapter; `wallet` |
| `transparent-pir-sqlite` | Transparent PIR adapter; `sqlite` (`wallet` plus the SQLite apply-and-acknowledge integration and the in-process end-to-end tests) |
| `transparent-pir-testing` | Transparent PIR adapter; `sqlite` and `testing` (the test support applications build their recovery and txid display tests on) |

`default` builds the backend and SQLite crates without Orchard or transparent
inputs, which `orchard` and `transparent` test, so items used only under those
features warn as dead code in `default`.

The Python configuration table is authoritative. `-p` replaces the package
selection; features still come from the selected configuration. Test-name
filters use libtest substring matching; add `--exact` for exact matching.
An empty selection fails before execution. Unfiltered commands include
doctests. `verify` runs repository checks and all configurations; use it for
final evidence rather than repeatedly during small edits.

`lint` uses Clippy with `--no-deps`, without globally promoting inherited
warnings to errors. Inspect warnings on changed code and compare with the base
when needed. `cargo fmt --all -- --check` remains the read-only formatting check.
A runtime/sandbox rejection is an environment issue; formatting does not need
broader permissions, Cargo compilation, or a shared build lock.

## Build ownership and results

Build directories live under `~/.cache/wallet-libraries/targets/`, keyed by
compiler identity, target platform, configuration, and profile. Set
`WALLET_LIB_BUILD_ROOT` to relocate them. Each invocation takes a nonblocking
OS lease on a persistent numbered directory. Concurrent calls use different
numbers; later calls reuse released directories across worktrees. Cargo still
checks source/dependency fingerprints. Source revisions are result provenance,
not cache keys. Do not run other Cargo processes directly inside leased directories.

`owner.json` records the active process, checkout, and source inputs;
`last-result.json` records duration, source identity, exit code, and status.
Changing HEAD or source inputs during a command invalidates success. OS locks
release on exit or process death; a stale owner file is replaced on reuse.
Doctor reports recorded owners, which may be stale after a killed process.
Keep rust-analyzer's target directory separate (for example,
`rust-analyzer.cargo.targetDir = true`). No caches belong in Git.

For durable checks use the installed roman-dev-ux skill's helper:

```sh
python3 ~/.agents/skills/roman-dev-ux/scripts/start-local-check.py \
  --tool codex --session YOUR_SESSION --cwd "$PWD" -- \
  python3 scripts/dev.py test --config transparent -p zakura-client-sqlite transparent_ledger
```

The helper returns PID, owner, log, result path, and HEAD. The development
command additionally checks source inputs. Inspect both results. This retains
completion after a turn ends; automatic agent wake depends on the runtime.
Use the native skill to record commands over 60 seconds and actual blockers,
without credentials or raw output in observations.

Keep the optimized `test` profile for final checks. To evaluate an iteration
profile without editing generated Cargo.toml, use `--profile iteration`. The
opt-in candidate in `.cargo/config.toml` keeps dependencies optimized and lowers
workspace optimization/debug information. Measure cold setup and repeated edits
separately before adopting it for a workload. Do not adopt a slower aggregate
compile-and-test configuration merely because compilation alone improves.

## Protobufs

`python3 scripts/proto.py check` generates into Cargo build output and compares
with all three checked-in bindings. `python3 scripts/proto.py write` explicitly
updates them. Both require `libprotoc 34.1`; set `PROTOC` to that executable.
The locked Rust generator dependencies determine the remaining output.
Source packages without `.proto` files keep using checked-in bindings.

## CI and completion

CI runs existing configurations independently, retains doctests and repository
checks, and publishes a final `tests` result. Documentation/guidance-only PRs
run lightweight checks. Unknown file types conservatively trigger full checks.
Older revisions of the same PR cancel; main runs remain independent. Compiler
and configuration specific caches accelerate compilation without retaining the
fresh external-consumer lockfiles.

A passing focused check does not prove all privacy, migration, protocol, or
feature combinations; use their affected lanes and final CI. Keep process-local
proving-key caches and the cargo test runner.

## Publishing the release candidates

A maintainer with crates.io ownership and publishing credentials runs the release
from a clean, reviewed checkout of `main`, using the pinned Rust toolchain and
Python 3.11 or newer. Supply the publishing credential through the approved
credential store at runtime; never put it in this repository or a command argument.

Inspect the selected versions and upstream availability without building or uploading:

```sh
python3 scripts/publish-crates.py --plan
```

Publish the prepared versions in dependency order:

```sh
python3 scripts/publish-crates.py --publish
```

The script reads versions from the manifests, checks local dependency ordering,
and checks crates.io before starting. Each unpublished crate must pass Cargo's
publishing dry run before it is uploaded. It waits for the version to appear
on crates.io before moving on, and stops on the first error. Rerun the same
command after resolving a failure: versions already available are skipped.
A yanked version or a dirty or changed checkout stops the release. Already
published versions are skipped by name and version; the script does not claim
that their contents match this checkout.

Verify packages without uploading (also the default when no mode is specified):

```sh
python3 scripts/publish-crates.py --dry-run
```

`--plan`, `--dry-run`, and `--publish` are mutually exclusive. Dry-run mode
verifies every selected crate together, including versions already published.
Cargo temporarily overlays the packaged workspace crates on the registry, so
unpublished local dependencies do not block verification. It uses `--keep-going`
to continue independent build verification after failures and uploads nothing.
A successful run means all selected packages passed; a failed run must be
investigated before publishing. This checks package contents and builds, not
crates.io ownership or all wallet behavior. Required repository CI still applies.

Transparent PIR requires the registry versions declared for its eight `wallet-pir`
dependencies, including optional test support. Publish those upstream packages
first. To release the other nine crates separately, add `--without-transparent`
to any of the commands above. This script does not publish `wallet-pir` or change
credentials, changelog dates, tags, or source files. After publication, confirm the
registry versions and update the corresponding `PLANNED` changelog dates.
