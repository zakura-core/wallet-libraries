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


## Public archive transport

`archive::ArchiveClient` uses the caller's bounded `Transport` and privacy routing
for common public requests, independently of PIR preparation:

- `/v1/receiver/archive/head` returns the small current head.
- `/v1/receiver/archive/range/{head_digest}/{page_number}` returns one complete
  page and its Merkle proof under that exact head.
- `/v1/receiver/archive/seen/{digest}` returns the immutable complete seen object.
- `/v1/receiver/archive/coverage/{archive_id}/{epoch}/{session_id}` returns the
  PIR session's declaration for that archive revision.

All hashes in paths are lowercase hex. Unknown or retired immutable revisions
return HTTP 410, never an empty range. Keep requests and retries outside ordinary
block scanning and outside shared scan/database locks. The client validates
bounds and content bindings. Callers still validate the connected chain, monotone
archive state, seen freshness and work generations. Existing discovery callers
migrate separately and must use these checks before declaring recovery complete.
