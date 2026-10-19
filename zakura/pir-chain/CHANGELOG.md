# Changelog

## Unreleased

- Block decoding and chain interpretation compile without an HTTP client or
  asynchronous runtime. The opt-in `rpc` feature adds the node client and
  asynchronous product readers. `testing` keeps synthetic fixtures only;
  `testing-node` adds the HTTP JSON-RPC test server. Dependency-graph checks
  enforce this boundary for decoding-only consumers.

- `transparent::state::StateError` no longer exposes the node's
  `zakura_state::StateInitError`: `Open` carries the node's message as a `String`.
  A database that is not an archive database is refused with the new
  `StateError::NotArchive` instead of a panic inside the node's initializer.
  `StateReader` is documented and tested as a snapshot taken at open (including
  the primary's unflushed write-ahead log), to be reopened during long backfills;
  real databases carrying either pruning marker are tested to be refused; and the
  server graph check builds a fresh consumer with `rocksdb` enabled.

- Read transparent blocks for the transparent services: raw output and spent-output
  scripts with exact fees, resolved from the same block, a bounded cache and batched
  reads, plus compact blocks and raw JSON-RPC calls for independent checks.
- Add the opt-in `rocksdb` feature, a reader of an archive node's finalized state as
  a RocksDB secondary, tested against a real database beside its primary.
- Read an Enhance block's tree size by the hash of its extracted actions, so a
  reorg between reads cannot combine one block's actions with another's tree size.
- Document the existing mainnet-only activation gates for receiver backfill and
  the combined Enhance block reader.
- Verify production and fixture-enabled server consumers independently, and keep
  node/server packages out of each wallet facade backend graph.
