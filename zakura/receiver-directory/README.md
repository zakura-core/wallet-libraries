# zakura-receiver-directory

Receiver directory publications: the canonical layout a receiver PIR service
publishes and a wallet looks up. A match is a candidate, never proof of
ownership or spendability.

- `record`: the 285-byte payment record, re-exported from
  `zakura-receiver-crypto::wire` with cryptography disabled.
- `filter`: the labeled receiver filters a publication commits to. No wallet reads
  them any more, so a publisher can drop the session-bound route that serves them.
- `paid`: paid sets, the receivers paid in a closed interval `(start, end]`. One
  type serves fixed 48-block buckets and cumulative sets over any interval. Each
  binds the network, its boundary block hashes and the payment-history epoch, with
  a salt that depends only on the network and the boundary hashes.
- `seen`: the monotone seen set of receivers swap provider feeds reported. Values
  are fixed 32-bit hashes under a salt fixed per network, so membership never
  shrinks across unions, re-encodings or publications.
- `catalog`: the catalog head a manifest commits to, naming the epoch, the
  retained buckets and the digests of the cumulative paid set, the seen set and the
  bucket index, which maps each retained bucket's start height to its digest.
  Every object is immutable, addressed by digest and strictly decoded within size
  limits.
- `snapshot`: publication manifests and their revision, row placement, snapshot
  construction and validation, continuation-page rules, and row lookup.

This crate parses structure only. Callers validate receivers, Action fields and
inclusion proofs at their trust boundaries with `zakura-receiver-crypto`.
Durable stores (the indexer's SQLite store and `ProviderStore`) stay with the
services in wallet-pir, which consume this crate; nothing here depends on
wallet-pir.

The library target keeps wallet-pir's name, `receiver_directory`.
