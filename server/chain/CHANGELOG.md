# Changelog

## Unreleased

- Read an Enhance block's tree size by the hash of its extracted actions, so a
  reorg between reads cannot combine one block's actions with another's tree size.
- Document the existing mainnet-only activation gates for receiver backfill and
  the combined Enhance block reader.
- Verify production and fixture-enabled server consumers independently, and keep
  node/server packages out of each wallet facade backend graph.
