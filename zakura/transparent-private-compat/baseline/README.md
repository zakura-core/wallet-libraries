# Frozen baseline

Outputs of the Transparent crates this workspace's current crates replaced,
captured before they were consolidated. Tests compare against these files; they
are never regenerated from the current crates.

- `vectors.json`: encodings, digests, identities and published bytes from the
  baseline packages at wallet-libraries
  `1c1bd327e493b740f8ffbd109039acb88a45e100`: events, block and range filters
  and their envelopes and digest chain, placement, tags, page rows, every
  table's native scheme and seeds, a seeded native query with the evaluated
  reply and decoded row, a txid display shard (tables, manifest, map, split),
  and a history publication (every file, every table's setup, its routes and
  query bindings). Long values are `sha256:<hex>:<length>`.
- `interrupted/`: a wallet the baseline left between committing a recovery
  batch to the wallet and acknowledging it in the companion. Both databases are
  SQL that recreates them (`wallet.sql`, `companion.sql`); `account` is the
  account's companion name and `owned` the scripts the publication pays.
  `notes.txt` lists what each pass reported.
- `interrupted-rc1/`: the same scenario written by the release Vizor ships,
  `zakura-pir-transparent` 0.0.1-rc1 from crates.io (crate SHA-256
  `7ed09da24bf34864f20d22d32a1ec147d14d80fdd00f80d0979d87479a56e233`) with the
  published `zakura-client-sqlite` and `zakura-client-backend` 0.1.0-rc9.
- `resumed-baseline.json`, `resumed-rc1.json`: what the baseline left in both
  databases after restoring each interrupted wallet, reopening it as an
  application starts, replaying the unacknowledged batch and settling once
  more: every SQL object, and each table's row count and the SHA-256 of its
  sorted rows. The `.txt` files list what those passes reported.

To reproduce, run `cargo run --features live-baseline --bin capture -- <dir>
<interrupted-rc1 dir>` in this workspace. The release Vizor ships depends on
wallet-pir's published crates, which no wallet-libraries workspace may resolve,
so its capture program is kept here as text: copy `rc1-capture/Cargo.toml.rc1`
to `Cargo.toml` and `rc1-capture/main.rs` to `src/main.rs` in a scratch directory
two levels below this workspace, such as `baseline/rc1-run/` (the program
includes `src/dump.rs` and `src/scenario.rs` by relative path), run
`cargo run -- <dir>` there, and delete the scratch directory and its lockfile
afterwards. Account names
are random, so a new capture differs from these files in them alone.
