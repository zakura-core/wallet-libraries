# Changelog

## [Unreleased]

### Changed

- Replace the store-owning discovery pass and provider seen checks with bounded `publication`, `lookup` and `witness` network steps behind the `wallet` feature. The caller commits results through the wallet recovery queue after requests complete.
- `lookup` and `witness` read against a captured shard inventory (`InventoryClient`), and `publication` describes that inventory. A lookup step covers sealed shards excluded by a validated filter, then reads at most one segment, returning a cursor bound to the inventory. `witness` makes one PIR query to the payment session's companion witness table per candidate. A request bound to another session is `Revision`.
- Re-export the receiver directory and PIR transport, including rolling block hints. Parsed records remain untrusted until the wallet authenticates the payment and checks local inclusion and spends. Remove `discover`, `WriteLock`, `Discovered`, `Error`, `FIRST_WINDOW`, `GAP`, `KEYS_PER_RUN`, `fetch_seen` and `Seen`.
