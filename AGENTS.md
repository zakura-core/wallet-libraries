# Working on wallet-libraries

Use the development workflow in [docs/development.md](docs/development.md).
These rules apply to Codex, Claude Code, and Cursor. Shared personal/runbook
instructions still apply; do not duplicate them here.

## Repository map

- `librustzcash/zcash_client_backend`: package `zakura-client-backend`.
- `librustzcash/zcash_client_sqlite`: package `zakura-client-sqlite`.
- `librustzcash/pczt`: package `zakura-pczt`.
- `zakura/`: PIR clients/primitives/types, transaction status, one-time IVK
  keys (`zakura-one-time-ivk`) and their provider adapter (`zakura-near-intents`).
- `zakura/pir-chain/`: server-only chain readers in a separate Cargo workspace
  with their own lockfile; never add them to the wallet dependency graph.
- `wallet-lib/`: package `zakura-wallet-lib`; its `zakura` and `lrz` backends
  are mutually exclusive. Never run workspace `--all-features` on the facade.

Vendored Rust sources are edited directly; upstream updates merge through the
vendor branch. Root `Cargo.toml` is generated: change `manifests/sources.toml`
or the workspace generator rather than hand-editing its output. Protobuf
bindings are generated explicitly, never by ordinary builds.

## Iteration and validation

Start with `python3 scripts/dev.py doctor --config transparent` (choose the
configuration relevant to the task). Use `dev.py` for Cargo work so concurrent
checks have exclusively owned build directories. Keep editor builds separate.

For SQLite ledger work:

```sh
python3 scripts/dev.py test --config transparent -p zakura-client-sqlite transparent_ledger
python3 scripts/dev.py lint --config transparent -p zakura-client-sqlite
```

Configuration names and feature combinations are defined once in `scripts/dev.py`.
Read the command help. A filtered run selecting no tests is a failure. Record
whether checks ran on a commit or changing source inputs. Inspect `last-result.json`.

When a PR is requested, publish after inspecting the diff and target; report
long checks as pending and monitor CI while continuing authorized work. Avoid
repeating broad local CI suites during small edits. Use focused checks when
they add evidence; complete final validation on stable source inputs.

Privacy boundaries, migrations, dependency-family changes, protocol changes,
and feature interactions require the affected configurations plus repository
verification before merge. Preserve feature-off, graph, facade, migration,
independent-oracle, and failure-injection coverage. Pending checks are pending.
Scope Clippy with `--no-deps`; distinguish existing warnings from introduced
warnings without blanket suppression. Keep wallet behavior and public APIs
unchanged during tooling or fixture changes.

Use the native roman-dev-ux skill to log delays/blockers and detach long local
checks; commands and concrete ownership examples are in docs/development.md.
Do not promise automatic wake unless the runtime provides it.

## Dependency and release boundary

- Keep release dependencies one-way: wallet-pir may consume wallet-libraries, but wallet-libraries must not depend on packages owned or released by wallet-pir, including normal, optional, build, target-specific and development dependencies.
