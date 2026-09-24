# Changelog

## [Unreleased]

## [0.0.1-rc0] - 2026-09-24

Initial release candidate for the mainnet Ironwood enhancement client.

### Added

- Enhance v7 routing with canonical fixed storage domains, composed successor
  tails, schema-11 records, and the P16Q48 SimplePIR profile. Each row contains
  33 records of 653 bytes.
- Wallet acceptance of locally scanned anchors before session setup or routing
  rebinding, with configurable setup and session-cache limits.
- Reuse of unchanged public session material across routing and placement
  changes, with affected sessions invalidated by recovery epochs. Each query
  uses fresh randomness and a request ID in its 116-byte `EPQ7` binding.
- Bounded HTTPS transport, lazy session loading, row-deduplicated streaming
  queries, and optional wallet helpers for preserving request identities and
  grouping same-transaction row queries.
- Explicit routing refresh and expiry handling. HTTP 409/410 requires renewed
  wallet acceptance; HTTP 429/503 supports bounded application retries.
- Optional birthday-based cover traffic with randomized domain order, uniform
  rounds, and whole-round overload retries. Record validation errors do not
  change the scheduled traffic, and cancellation preserves observed expiry.

### Compatibility and privacy

- Requires an Enhance v7 server; older protocol revisions are rejected.
- Uses the published `ipir-sp = "=0.1.0-rc.3"` dependency with CUDA disabled.
- Cover traffic is opt-in. Timing, round counts, birthday coverage, and
  cross-interval intersection remain observable; ordinary queries also reveal
  the queried domains and row counts.
- Record decoding validates encoding. Wallet note authentication and stale
  request checks remain required; transaction metadata and some send-only
  associations require trust in the server.
