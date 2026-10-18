# Development workflow

Python 3.11+, Rust, and Git are sufficient for ordinary development on macOS
and Linux. `rust-toolchain.toml` pins the CI/development compiler; the facade
verification also checks a fresh Rust 1.97 consumer. Protobuf regeneration
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
| `default` | Workspace except the facade, Enhance PIR, the transparent PIR adapter, receiver PIR and the one-time IVK scenarios; default features |
| `orchard` | Backend + SQLite; `orchard,test-dependencies` |
| `transparent` | Backend + SQLite; `orchard,transparent-inputs,test-dependencies,unstable` |
| `transparent-import` | Backend + SQLite; transparent features plus `transparent-key-import` |
| `pczt` | PCZT; `internal-tests`, including signing and end-to-end proof construction |
| `proving` | Backend + SQLite; real Sapling proving fixtures, migration tests, standalone-key shielding and PCZT integration tests |
| `sqlite` | SQLite; `test-dependencies`, without Orchard |
| `enhance-wallet` | Enhance PIR; `wallet` |
| `enhance` | Enhance PIR; default features |
| `enhance-testing` | Enhance PIR; `testing` (the synthetic Ironwood output fixture service tests authenticate PIR-returned records with) |
| `transparent-filter-client` | Transparent filter with its wallet HTTP `client` (profile validation and bounded streaming responses) |
| `transparent-pir` | Transparent PIR adapter; `wallet` |
| `transparent-pir-sqlite` | Transparent PIR adapter; `sqlite` (`wallet` plus the SQLite apply-and-acknowledge integration and the in-process end-to-end tests) |
| `transparent-pir-testing` | Transparent PIR adapter; `sqlite`, `testing` and `reqwest` (the test support applications build their recovery and txid display tests on; the private recovery and discovery tests go through the HTTP transport) |
| `pir-receiver` | Receiver PIR; `wallet` (which enables the backend's `orchard`; its tests use SQLite with `orchard`) |
| `receiver-wire` | Library-owned receiver codec with default features disabled |
| `receiver-pir-server` | Receiver PIR client with the `server` evaluator, which the golden client/evaluator vectors need |
| `server` | Separate `zakura/pir-chain` workspace, including the node fixture helpers under `testing` and the opt-in RocksDB reader under `rocksdb`; `-p` retains this workspace and doctor checks its lockfile |
| `one-time-ivk-scenarios` | One-time IVK scenario suite (see its README); `ONE_TIME_IVK_SLOW=1` adds the scenarios that wait months of chain time. CI runs it nightly, not on PRs |

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
The generator lives in the standalone `tools/proto` workspace, with its own
lockfile. Ordinary wallet builds do not compile the protobuf compiler. Run
`cargo fmt --manifest-path tools/proto/Cargo.toml --all -- --check` when editing it.

Ordinary `test-dependencies` expose mock provers without embedding Sapling
parameters. Enable `proving-tests` for real proving fixtures; the `proving` and
`pczt` configurations retain that coverage. This feature is only for tests.
`python3 scripts/dev.py verify --only dependency-graph` checks fresh external
consumers, including fixture availability and the engine's transport-free graph.

The PIR clients temporarily pin the IPIR family to the exact head of
[IPIR PR 38](https://github.com/valargroup/ipir-sp/pull/38), which removes CLI-only
dependencies from the library. Keep IPIR, InspiRING and ReinspiRING on the same
source when repinning, since their exposed types must share one identity.
Repin to the published family after that change is released.

## CI and completion

CI runs existing configurations independently, retains doctests and repository
checks, and publishes a final `tests` result. The exception is
`one-time-ivk-scenarios`, which takes about 45 minutes on a hosted runner, so the
**One-time IVK scenarios** workflow runs it nightly and on demand instead of on
PRs. Documentation/guidance-only PRs run lightweight checks. Unknown file types conservatively trigger full checks.
Older revisions of the same PR cancel; main runs remain independent. Compiler
and configuration specific caches accelerate compilation without retaining the
fresh external-consumer lockfiles.

A passing focused check does not prove all privacy, migration, protocol, or
feature combinations; use their affected lanes and final CI. Keep process-local
proving-key caches and the cargo test runner.

## Publishing the release candidates

### GitHub Actions

Use **Publish crates** from `main` in `zakura-core/wallet-libraries`. The workflow
uses the exact commit selected by the dispatch, and reads versions from all twenty-one
crate manifests. It does not create tags, change versions, or publish wallet-pir.
Successful **Verify wallet libraries** CI for that exact main commit is required;
wait for it to finish before dispatching the release workflow.

Choose **verify** first (the default). All packages are fully dry-run together
without registry credentials. The workflow saves a verification receipt and
summarizes the crate versions and registry availability. After Sean approves the
`crates-io` environment, a separate job exchanges and revokes a temporary token
without uploading. This proves the authentication exchange; it does not prove
that each crate has the right publisher configuration.

Before the first run, a repository administrator must create the `crates-io`
GitHub Environment, allow only the `main` branch, and require approval by `ebfull`
(self-approval is allowed, matching Zakura). An owner of **each of the twenty-one crates**
must configure this Trusted Publisher on crates.io:

| Setting | Value |
| --- | --- |
| GitHub owner | `zakura-core` |
| Repository | `wallet-libraries` |
| Workflow filename | `publish-crates.yml` |
| Environment | `crates-io` |

Use `python3 scripts/publish-crates.py --plan` to list the twenty-one names and versions.
Check every crate's publisher settings, including names already reserved by a
placeholder release. Trusted Publishing needs existing crate names.
Check that the five `zakura-transparent-{native,events,filter,shard,txid-client}`
names and the three receiver names, `zakura-receiver-crypto`,
`zakura-receiver-directory`, and `zakura-receiver-pir`, are reserved. Reserve
`zakura-filters` as well. Reserve any missing names and configure each crate's Trusted Publisher before the first run
that includes it. No permanent API token or new Infisical secret is required.

Choose **publish** for an actual release. It repeats verification for the dispatch
commit, requires environment approval, then acquires its temporary credential.
Only the upload step sees that credential. It validates the verification receipt,
uploads without recompiling, and waits for each version before its dependents.
The final check confirms availability and checks crates.io's workflow attribution
for newly published versions. Already available versions are checked without
claiming this run published them.

Only one release workflow runs at a time. On failure, inspect the full registry
response in the failed step and the retained `crate-publication-<attempt>` artifact and
summary. Results distinguish `published`, `previously_available`, `failed`,
`uploaded_unconfirmed`, and `remaining`. Redispatch from the **same main commit**
(or rerun the failed workflow if main has advanced); available versions are
skipped. Do not change versions merely to retry a transient failure. Crate
versions cannot be overwritten. Fix source errors in a reviewed new commit and
use new versions for any packages whose earlier versions were already uploaded.

### Local maintainer commands

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

The release never waits on `wallet-pir`: the script refuses any selected crate
that declares a `wallet-pir` package, of any dependency kind or source, so no
`wallet-pir` tag or registry release is ever a prerequisite. This script does not
change credentials, changelog dates, tags, or source files. After publication, confirm the
registry versions and confirm the corresponding changelog dates.

`--output PATH` writes a JSON receipt and partial progress outside the checkout.
CI uses `--publish-verified RECEIPT` instead of `--publish` to upload without
recompiling only after checking a successful receipt against the clean checkout,
commit, selection, and ordered versions. Ordinary `--publish` retains its dry-run
checks before uploads. Every packaging command uses `--locked`; release commands
must not rewrite the workspace lockfile.
