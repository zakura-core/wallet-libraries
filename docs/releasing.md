# Releasing wallet-libraries

The next release is a set of release candidates. Changelog entries marked
`PLANNED` describe the candidate source, not a published release. Replace that
marker with the actual publication date when each crate ships.

## Candidate versions and publication order

Publish dependencies before their consumers. The shared record types have a packaging-only update; their wire format is
unchanged.

| Order | Crate | Candidate | Previous implementation |
| --- | --- | --- | --- |
| 1 | `zakura-pczt` | `0.1.0-rc5` | `0.1.0-rc4` |
| 1 | `zakura-pir-native` | `0.0.1-rc1` | `0.0.1-rc0` |
| 1 | `zakura-pir-enhance-types` | `0.0.1-rc1` | `0.0.1-rc0` |
| 2 | `zakura-client-backend` | `0.1.0-rc8` | `0.1.0-rc7` |
| 2 | `zakura-pir-status` | `0.0.1-rc1` | `0.0.1-rc0` |
| 3 | `zakura-client-sqlite` | `0.1.0-rc8` | `0.1.0-rc7` |
| 4 | `zakura-wallet-lib` | `0.1.0-rc7` | `0.1.0-rc6` |
| 4 | `zakura-pir-enhance` | `0.0.1-rc2` | `0.0.1-rc1` |
| 4 | `zakura-transaction-status` | `0.0.1-rc1` | `0.0.1-rc0` |
| 4, after wallet-pir | `zakura-pir-transparent` | `0.0.1-rc0` | reservation only |

This ordering includes development dependencies needed for package verification.
The generator takes vendored versions from `manifests/sources.toml`; update it
and regenerate the root manifest rather than editing generated output.

## Name reservations and publishing access

All ten workspace names were checked on crates.io on 2026-10-12. Nine already
had implementation releases. The remaining name, `zakura-pir-transparent`, is
reserved by a published `0.0.0` placeholder owned by `p0mvn`, with its source
in [zakura-core/reserved](https://github.com/zakura-core/reserved).
When its first implementation ships, remove the placeholder from that workspace
and move its README entry to the graduated list.

At that check, the PCZT, backend and SQLite crates were owned only by `ebfull`.
Their release requires that owner's publishing access or a separately authorized
owner change. The other existing workspace names list both `ebfull` and `p0mvn`.
Recheck owners immediately before publishing; a name reservation alone does not
grant publishing access to every release operator.

## Transparent adapter prerequisite

`zakura-pir-transparent` still uses one pinned wallet-pir revision. Each Git
edge now declares `version = "=0.1.0"`, which is the version at that revision.
Cargo strips the Git source from a registry package and resolves the declared
version on crates.io. The pin continues to govern repository builds.

These eight direct dependencies had no crates.io registration at the audit:

- `transparent-wallet`
- `transparent-wallet-store`
- `transparent-events`
- `transparent-filter`
- `transparent-txid-client`
- `transparent-shard`
- `transparent-native`
- `transparent-shard-server`

The wallet-pir release owner must prepare their publishable transitive graph,
register their names, and publish implementations matching the pinned source
before packaging the adapter. Placeholder reservations do not satisfy this
implementation dependency. The test-service crates are optional production
manifest dependencies behind `testing`, so they also need registry releases;
disabling that feature does not remove the publication requirement.

Do not replace the Git pin with an older or merely available registry crate.
Until those releases exist, the transparent adapter is a Git-consumed candidate
with a reserved name, not a publishable crates.io implementation. The remaining
wallet-libraries candidates can be published independently of this prerequisite.

## Validation and publication

Use [the development workflow](development.md) on stable source inputs. Retain
the repository graph, facade and vendor checks and the affected feature lanes.
For this train, keep the published-wallet upgrade probes, independent financial
oracles and privacy failure-injection coverage; changelog cleanup does not qualify
activation, downgrades, service rollout or application/device behavior.

For each crate, after its registry dependencies exist:

1. Recheck the candidate manifest, owners and absence of the candidate version
   on crates.io. Inspect the package file list, including generated bindings,
   README and license texts.
2. Run `cargo publish --dry-run -p <crate>` in a separate packaging target
   directory outside managed development build directories. Select one facade
   backend; never use workspace `--all-features` on the facade.
3. Publish the reviewed candidate, wait for registry availability, and verify
   the version before advancing to consumers. A successful local path build
   does not prove a fresh registry consumer resolves the same family.
4. Record the actual date in its changelog and tag the exact published commit
   as `<crate>-<version>`. Run fresh consumer checks with registry dependencies,
   preserving the facade's exact Common v2.0.0 pins.

Release preparation does not itself publish implementation crates or deploy
services. Keep publication and deployment as explicit operator steps.
