# zakura-receiver-pir

Encrypted row retrieval from a receiver directory publication over the shared
`zakura-pir-protocol` two-mask profile, one row per 2,048-coefficient packing
block.

- Session manifests (`Manifest`), their ID, and the geometry and size limits.
- `AcceptedCoverage`, which checks a publication against an anchor the wallet
  accepted from its own chain validation.
- `Client` and `Query`: request construction and response decoding.
- `transport`: the wallet `Transport` interface and `DirectoryClient`, which
  validate coverage, revisions, continuation pages and witness-file bounds.
- With the `server` feature, the evaluator that answers requests by scanning
  the rows with `ipir-sp`, as Transparent's workers do.

Results are candidates for wallet validation, not chain proofs. The HTTP
service, its routers and processes stay in wallet-pir and consume this crate.

The library target keeps wallet-pir's name, `receiver_pir`.

## Rolling filter transport

`DirectoryClient::fetch_block_head` reads `/v1/receiver/block-filters/head` with a 16 KiB limit and checks the configured network. `fetch_block_batch` reads `/v1/receiver/block-filters/{revision}/{from}/{limit}` with the shared batch bound. Transport errors, unavailable ranges and changed revisions never mean negative membership. Refresh metadata or use direct PIR according to the wallet policy. These public requests contain no receiver and open no PIR session. The wallet owns scheduling and chain checks; ordinary sync must not wait for these requests.
