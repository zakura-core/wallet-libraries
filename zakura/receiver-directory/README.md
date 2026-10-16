# zakura-receiver-directory

Receiver directory publications: the canonical layout a receiver PIR service
publishes and a wallet looks up. A match is a candidate, never proof of
ownership or spendability.

- `record`: the 285-byte payment record, re-exported from
  `zakura-receiver-crypto::wire` with cryptography disabled.
- `filter`: the labeled receiver filters a publication commits to.
- `snapshot`: publication manifests and their revision, row placement, snapshot
  construction and validation, continuation-page rules, and row lookup.

This crate parses structure only. Callers validate receivers, Action fields and
inclusion proofs at their trust boundaries with `zakura-receiver-crypto`.
Durable stores (the indexer's SQLite store and `ProviderStore`) stay with the
services in wallet-pir, which consume this crate; nothing here depends on
wallet-pir.

The library target keeps wallet-pir's name, `receiver_directory`.
