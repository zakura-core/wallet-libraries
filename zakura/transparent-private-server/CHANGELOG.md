# Changelog

## [Unreleased]

### Added

- The crate, from the publisher's side of `zakura-transparent-filter`,
  `zakura-transparent-shard` and `zakura-transparent-native`, and the in-process
  shard service of `zakura-pir-transparent`'s `testing` feature:
  - `filter`: building per-block and range filters, and experimental parent
    filters (`ParentBuild`).
  - `shard`: the builder, sealers, history packing, choice table construction
    (`ChoiceBuild`), tag salt resolution, revision numbering, the txid display
    records and source codecs, and the display tables, seal planning, manifest
    construction (`DisplayManifestBuild`) and map split (`DisplayMapSplit`).
  - `native`: upload admission and parsing and segment sizing (`TableServe`),
    `row_coefficient` and the batched hint, with its known-answer vectors.
  - `testing` (feature): the synthetic publisher and in-process shard service,
    evaluating queries with this crate's native operations.
  Builders produce the same bytes, digests and identities as before; the
  filter encoder keeps its exact `bitcoin` pin.
- `ChoiceTable` construction returns the table as the decoder reads its
  encoding, so a table that would not decode is never published.

### Changed

- The license is MIT. The builders moved from wallet-pir were MIT; the native
  code was MIT or Apache-2.0.
