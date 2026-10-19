# zakura-receiver-pir

Encrypted row retrieval from a receiver directory publication over the shared
`zakura-pir-protocol` two-mask profile, one row per 2,048-coefficient packing
block.

- Session manifests (`Manifest`), their ID, and the geometry and size limits.
- `AcceptedCoverage`, which checks a publication against an anchor the wallet
  accepted from its own chain validation.
- `Client` and `Query`: request construction and response decoding.
- `transport`: the wallet `Transport` interface and `DirectoryClient`, which
  validate coverage, revisions, continuation pages and witness-file bounds. It also
  fetches the recovery objects every wallet downloads alike, each from an
  immutable route by digest and checked against the catalog head:
  `/v1/receiver/catalog/<digest>` (the head the manifest commits to),
  `/v1/receiver/bucket-index/<digest>`, `/v1/receiver/bucket/<start>/<digest>`,
  `/v1/receiver/paid/<digest>` and `/v1/receiver/seen/<digest>`. No request names a
  receiver.
- With the `server` feature, the evaluator that answers requests by scanning
  the rows with `ipir-sp`, as Transparent's workers do.

Results are candidates for wallet validation, not chain proofs. The HTTP
service, its routers and processes stay in wallet-pir and consume this crate.

The library target keeps wallet-pir's name, `receiver_pir`.
