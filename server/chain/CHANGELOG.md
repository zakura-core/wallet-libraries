# Changelog

## Unreleased

- Read transparent blocks for the transparent services: raw output and spent-output
  scripts with exact fees, resolved from the same block, a bounded cache and batched
  reads, plus compact blocks and raw JSON-RPC calls for independent checks.
- Add the opt-in `rocksdb` feature, a reader of an archive node's finalized state as
  a RocksDB secondary, tested against a real database beside its primary. The reader
  catches up with the node on each tip read and on a block read that finds nothing,
  so it follows blocks finalized after it opened.
- Read an Enhance block's tree size by the hash of its extracted actions, so a
  reorg between reads cannot combine one block's actions with another's tree size.
- Document the existing mainnet-only activation gates for receiver backfill and
  the combined Enhance block reader.
- Verify production and fixture-enabled server consumers independently, and keep
  node/server packages out of each wallet facade backend graph.
