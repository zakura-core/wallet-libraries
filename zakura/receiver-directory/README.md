# zakura-receiver-directory

Receiver directory publications: the canonical layout a receiver PIR service
publishes and a wallet looks up. A match is a candidate, never proof of
ownership or spendability.

- `record`: the 289-byte payment record, re-exported from
  `zakura-receiver-crypto::wire` with cryptography disabled.
- `blocks`: bounded rolling GCS hints, separate from full payment history.
- `snapshot`: publication manifests and their revision, row placement, snapshot
  construction and validation, continuation-page rules, and row lookup. Each record's
  witness ordinal is the rank of its note position (`assign_ordinals`), so a payment
  table's identity fixes its companion mapping.
- `witness`: companion witness tables. Ordinal `o` lives in row `o / 8`, slot `o % 8`.
  The manifest binds the payment table's revision, one payload per record and the
  construction tree, so a witness-only replacement keeps the payment table and its
  ordinals, and a replaced payment table needs a new companion.

This crate parses structure only. Callers validate receivers, Action fields and
inclusion proofs at their trust boundaries with `zakura-receiver-crypto`.
Durable payment and proof stores stay with the services in wallet-pir, which
consume this crate. Nothing here depends on wallet-pir.

The library target keeps wallet-pir's name, `receiver_directory`.

## Rolling block hints

`blocks::Head` advertises a network, correction revision and inclusive available range. `blocks::Batch` contains at most 256 consecutive filters and 4 MiB. A server may return a shorter nonempty prefix to honor the byte limit. Empty blocks have explicit empty GCS sets; missing/pruned ranges are errors and require the wallet's direct PIR path.

The batch binds the captured revision and requested range, and checks parent linkage. Consumers must still compare block identities with their independently synced chain before using negative hints or advancing progress. The service is trusted for complete indexing. Matches only schedule PIR queries; payment authentication, inclusion and spend checks happen separately. Newly exposed receive indexes need historical PIR checks even if their blocks were already processed.

`IWBATCH1` encodes the genesis hash, little-endian correction revision (`u64`), block count (`u32`), then each height (`u32`), block hash, parent hash, payload length (`u32`) and GCS payload. Hashes use protocol byte order. GCS uses P=20 and M=1,569,792 with a salt derived from network, height and hash. No archive index, permanent seen set or scan/cache state is part of this format.

PIR manifests require `history_revision`, the operator correction generation also advertised by rolling hints. It is bound into the immutable publication/session identity. Clients must retain the required generation with unfinished work and reject answers from an older generation, even when block heights and hashes match. Reorgs still use chain hashes.

Snapshots contain only the manifest and payment rows; witnesses live in the companion table. Aggregate `paid`, provider `seen` and `recent` sets and the `IWFLT1` envelope are removed. This is an incompatible change to the unlaunched format. It does not prune PIR history or change row placement.
