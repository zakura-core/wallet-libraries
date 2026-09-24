# Ironwood Enhance PIR initial release

This prepares the repository for the `v0.0.1-rc0` Git tag. Package versions are:

| Package | Version |
| --- | --- |
| `zakura-pir-enhance-types` | `0.0.1-rc0` |
| `zakura-client-backend` | `0.1.0-rc6` |
| `zakura-client-sqlite` | `0.1.0-rc6` |
| `zakura-pir-enhance` | `0.0.1-rc0` |

The backend and SQLite releases provide the PIR features missing from their
published `0.1.0-rc5` versions. The client uses the published IPIR
`0.1.0-rc.3` dependency. Rust 1.91 is the minimum supported compiler.
The wallet facade consumes the new local versions but is not being released
as part of this preparation.

## Validation

Run from the repository root:

```sh
cargo test -p zakura-pir-enhance-types --locked
cargo test -p zakura-pir-enhance --all-features --locked
cargo test -p zakura-pir-enhance --no-default-features --locked
cargo test -p zakura-client-backend -p zakura-client-sqlite \
  --features zakura-pir-enhance,test-dependencies --locked
cargo package -p zakura-pir-enhance-types -p zakura-client-backend \
  -p zakura-client-sqlite -p zakura-pir-enhance --all-features
```

Use a Cargo version with multi-package packaging support for the last command;
it resolves the unpublished sibling packages together. Packaging and tests do
not publish crates. Repository CI also verifies feature compatibility, the
wallet facade's backend modes, dependency graphs, and vendor ancestry.

## Publication order

After merging the release preparation and approving the release, create the
`v0.0.1-rc0` tag at the reviewed commit. Publish these crates in order, waiting
for each version to be available from crates.io before proceeding:

1. `zakura-pir-enhance-types 0.0.1-rc0`.
2. `zakura-client-backend 0.1.0-rc6`.
3. `zakura-client-sqlite 0.1.0-rc6`.
4. `zakura-pir-enhance 0.0.1-rc0`.

Use `cargo publish --dry-run -p <package>` before each real publication. The
client's optional wallet integration and its test dependencies require the
new backend and SQLite versions, even though the core transport can run
without the `wallet` feature. Publishing only the two PIR packages first
would leave the client without resolvable wallet dependencies.

## Compatibility

The client requires an Enhance v7 server and schema-11 records. It rejects
older wire protocols; package version `0.0.1-rc0` is independent of wire
protocol revision v7. No server deployment is part of this release.

The SQLite PIR tables are the initial release schema. There is no migration
from intermediate, unreleased PIR schemas; do not use this release as an
in-place upgrade of a database created by those development revisions.
Ordinary wallet database migrations remain managed by the SQLite backend.

Cover traffic is optional and does not hide timing, round counts, birthday
coverage, or cross-interval intersection. Encoding validation does not
replace wallet note authentication. See the client and types changelogs for
these boundaries and the functionality included in the initial release.
