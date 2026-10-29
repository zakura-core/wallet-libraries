# Development workflow

Python 3.11+, Rust, and Git are sufficient for ordinary development on macOS
and Linux. `rust-toolchain.toml` pins the CI/development compiler; the facade
verification also checks a fresh Rust 1.97 consumer. Protobuf regeneration
requires the pinned compiler described below; ordinary builds do not.

The PIR package and feature map is in [PIR packages](pir-packages.md).

## Commands

```sh
python3 scripts/dev.py doctor --config transparent
python3 scripts/dev.py test --config transparent -p zakura-client-sqlite transparent_ledger
python3 scripts/dev.py check --config orchard -p zakura-client-backend
python3 scripts/dev.py lint --config transparent -p zakura-client-sqlite
python3 scripts/dev.py verify --only dependency-boundary
python3 scripts/dev.py verify --only wallet-lib-modes
python3 scripts/dev.py verify
```

| Configuration | Packages and features |
| --- | --- |
| `default` | Workspace except the facade, the PIR client and the one-time IVK scenarios; default features |
| `sync` | Ordinary sync with Orchard and Ironwood enabled |
| `zewif` | Wallet interchange import and atomic rollback, with the SQLite test fixtures |
| `orchard` | Backend + SQLite; `orchard,test-dependencies` |
| `transparent` | Backend + SQLite; `orchard,transparent-inputs,test-dependencies,unstable` |
| `transparent-import` | Backend + SQLite; transparent features plus `transparent-key-import` |
| `pczt-wallet` | Backend + SQLite; transparent configuration plus `pczt-tests`, including current-branch finalization checks |
| `pczt` | PCZT; `internal-tests`, including signing and end-to-end proof construction |
| `proving` | Backend + SQLite; real Sapling proving fixtures, migration tests, standalone-key shielding and PCZT integration tests |
| `sqlite` | SQLite; `test-dependencies`, without Orchard |
| `pir-protocol` | Shared formats, native identities and byte compatibility, with Receiver validation |
| `pir-client` | All four transport-free product clients, including the Receiver client/evaluator golden vectors |
| `pir-server` | Publisher and query-server packages, all four products, with Receiver witness paths |
| `enhance-wallet` | Enhance PIR; `wallet` |
| `enhance` | Enhance PIR; default features |
| `enhance-testing` | Enhance PIR; `testing` (the synthetic Ironwood output fixture service tests authenticate PIR-returned records with) |
| `transparent-filter-client` | Transparent filter with its wallet HTTP `client` (profile validation and bounded streaming responses) |
| `transparent-recovery-types` | Shared recovery records and byte-preserving hash conversions |
| `transparent-recovery` | Transparent recovery, companion storage and txid lookup through caller transports, without the wallet backend or proving stack |
| `transparent-pir` | Transparent PIR adapter; `wallet` |
| `transparent-pir-sqlite` | Transparent PIR adapter; `sqlite` (`wallet` plus the SQLite apply-and-acknowledge integration and the in-process end-to-end tests) |
| `transparent-pir-testing` | Transparent PIR adapter; `sqlite`, `testing` and `reqwest` (the test support applications build their recovery and txid display tests on; the private recovery and discovery tests go through the HTTP transport) |
| `receiver-wallet` | PIR client; `receiver-wallet` (which enables the backend's `orchard`; its tests use SQLite with `orchard`) |
| `transaction-status-core` | Status source selection and observations, without the bundled lightwalletd adapter |
| `transaction-status-lightwalletd` | Status policy plus the explicit lightwalletd adapter, including payload validation and cancellation |
| `receiver-protocol` | PIR protocol; `receiver` alone: the receiver codec and formats without Common |
| `transaction-wire` | Unpublished borrowed transaction wire reader, with the typed decoders as dev-only differential oracles |
| `service-config` | Transport-free static/dynamic service config resolution: hash pins, mirrors and pluggable attestation |
| `pir-config` | Wallet PIR config profile (schema, normalized server identity, explicit server selection) and its `wallet-pir-config` CLI |
| `one-time-ivk-scenarios` | PIR-only wallet scenarios with an independent chain oracle (see its README). CI runs it nightly, not on PRs |

`default` builds the backend and SQLite crates without Orchard or transparent
inputs, which `orchard` and `transparent` test, so items used only under those
features warn as dead code in `default`.

Node chain readers and their RPC, fixture and RocksDB checks live in wallet-pir.
The `dependency-boundary` check rejects node and wallet-pir packages in this
repository's declarations, resolved graphs, lockfiles and fresh wallet consumers.
The release tooling applies the same policy before packaging. Lightweight CI
and the local push self-check share `.github/preflight.json`.

The Python configuration table is authoritative. `-p` replaces the package
selection; features still come from the selected configuration. Test-name
filters use libtest substring matching; add `--exact` for exact matching.
`--ignored` runs only the ignored tests a filter selects, with their output,
for timing experiments such as `scripts/bench-one-time-batch-overhead.py`.
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

The PIR clients temporarily pin the IPIR family to the main revision that merged
[IPIR PR 39](https://github.com/valargroup/ipir-sp/pull/39). Native setup derivation and byte framing live in the shared protocol package;
client encryption and server operations use ReinspiRING directly. Production
roles do not import IPIR's native-client facade, evaluator or SimplePIR. The receiver's explicit `server` feature still
uses the evaluator. Enhance retains the legacy parameter metadata as a shared serialized contract,
with tests against the previous provider; its production client no longer
depends on the IPIR evaluator.
Keep IPIR, its native client, InspiRING and ReinspiRING on the same source when
repinning, since their exposed types must share one identity. Repin to the
published family after the extracted client is released.

## Common dependency compatibility

Wallet library manifests use compatible Common version requirements so downstream
consumers can select a shared release without matching exact pins. The lockfiles
record the concrete versions tested by this repository. Orchard notes, keys and
proof components must still have one package identity across each consumer's
graph; the fresh-consumer checks retain that boundary and the Rust 1.97 build.
Changing the allowed range does not establish that an untested future prerelease
preserves those APIs or cryptographic behavior.

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
uses the exact commit selected by the dispatch, and reads versions from the selected
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
(self-approval is allowed, matching Zakura). An owner of **each selected crate**
must configure this Trusted Publisher on crates.io:

| Setting | Value |
| --- | --- |
| GitHub owner | `zakura-core` |
| Repository | `wallet-libraries` |
| Workflow filename | `publish-crates.yml` |
| Environment | `crates-io` |

Use `python3 scripts/publish-crates.py --plan` to list the selected names and versions.
Check every crate's publisher settings, including names already reserved by a
placeholder release. Trusted Publishing needs existing crate names.
The five `zakura-pir-{protocol,client,publisher,query-server,server-core}` names
are registered and have been published through this workflow. No permanent API
token or new Infisical secret is required.

`zakura-service-config` and `zakura-pir-config` are also selected for release,
in dependency order after any packages they use. Both `0.0.0` placeholders are registered on crates.io. Before their first
implementation release, an owner must configure the same Trusted Publisher for
each crate: owner `zakura-core`, repository `wallet-libraries`, workflow
`publish-crates.yml`, and environment `crates-io`.
A reservation merged into `zakura-core/reserved` does not register the name on
crates.io until the placeholder is published. Trusted Publishing can only be
configured after that initial publication. The `verify` workflow's successful
token exchange alone does not prove that either new crate grants permission to
publish; confirm both crates' publisher settings before dispatching `publish`.

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

### Standalone transparent recovery

The `zakura-pir-client` feature `recovery` opens the companion, runs recovery
and returns candidate batches using `zakura-pir-protocol::transparent::recovery`. It does
not depend on the wallet backend, PCZT or shielded circuits. The `transparent-wallet`
feature adds `WalletChain` and wallet txid-detail orchestration; `sqlite` also adds
settlement. Standalone batches can be inspected or discarded, never acknowledged
through a new public operation. Wallet validation and durable settlement remain
required before candidate facts can affect financial state.

`RecoveryBlockHash` holds internal-order bytes. The wallet boundary converts
hashes explicitly and preserves explorer display order. The backend re-exports
the shared records with its existing hash type, so its database interface keeps
one record definition without requiring a Common change. The contract package
has not been released; no publishing or downstream adoption is implied.

The `transparent_recovery-without-backend` example opens and reopens a companion using caller
chain information and no wallet backend. Dependency-graph verification builds
and runs it as a fresh external consumer, where workspace test features cannot
supply a missing production dependency.
