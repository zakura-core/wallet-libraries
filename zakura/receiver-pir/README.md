# zakura-receiver-pir

Encrypted row retrieval from a receiver directory publication over the shared
`zakura-pir-protocol` two-mask profile, one row per 2,048-coefficient packing
block.

- Session manifests (`Manifest`, `WitnessManifest`), their IDs, and the geometry and
  size limits. `Publication` pairs a payment session with the companion witness session
  bound to it, which `/v1/receiver/init` serves.
- `AcceptedCoverage`, which checks a publication against an anchor the wallet
  accepted from its own chain validation.
- `Client`/`Query` and `WitnessClient`/`WitnessQuery`: request construction and
  response decoding for payment rows and witness payloads.
- `transport`: the wallet `Transport` interface and `DirectoryClient`, which
  validate coverage, revisions and continuation pages, and read a payment's witness
  payload over PIR by its ordinal. Both query kinds share `/v1/receiver/query`; the
  session ID in the header selects the table.
- With the `server` feature, `Server` and `WitnessServer`, which answer requests by
  scanning the rows with `ipir-sp`, as Transparent's workers do.

Results are candidates for wallet validation, not chain proofs. A witness query is sent
only after a candidate is found, so its timing reveals that candidate recovery occurred;
PIR hides which ordinal was read. The HTTP
service, its routers and processes stay in wallet-pir and consume this crate.

The library target keeps wallet-pir's name, `receiver_pir`.

## Rolling filter transport

`DirectoryClient::fetch_block_head` reads `/v1/receiver/block-filters/head` with a 16 KiB limit and checks the configured network. `fetch_block_batch` reads `/v1/receiver/block-filters/{revision}/{from}/{limit}` with the shared batch bound. Transport errors, unavailable ranges and changed revisions never mean negative membership. Refresh metadata or use direct PIR according to the wallet policy. These public requests contain no receiver and open no PIR session. The wallet owns scheduling and chain checks; ordinary sync must not wait for these requests.
