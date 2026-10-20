# Changelog

## [Unreleased]

### Changed

- Replace `witnesses` with `witness`, one PIR query to the payment session's companion witness table per candidate. A request bound to another session is `Revision`.

- Replace the store-owning discovery pass and provider seen checks with bounded `publication`, `lookup` and `witnesses` network steps behind the `wallet` feature. The caller commits results through the wallet recovery queue after requests complete.
- Re-export the receiver directory and PIR transport, including rolling block hints. Parsed records remain untrusted until the wallet authenticates the payment and checks local inclusion and spends. Remove `discover`, `WriteLock`, `Discovered`, `fetch_seen` and `Seen`.
