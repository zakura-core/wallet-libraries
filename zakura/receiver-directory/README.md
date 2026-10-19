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

## Block recovery formats

`blocks::BlockFilter` encodes recipient hints for one exact height and block hash.
Its GCS profile is `P = 20`, `M = 1,569,792`. The salt binds the network genesis,
height and block hash, independently of PIR table placement. Empty blocks have
explicit filters. The limit is 65,536 distinct recipients and 1 MiB encoded.

`seen::SeenSet` preserves the union of provider-reported receiver hashes in a
fixed 32-bit universe. Re-encoding, reorgs and corrections must never remove a
published value, including a false positive. Its feed timestamps describe source
coverage, not payment finality. Publishers must durably merge prior values and
complete backfill before advertising issuance-safe coverage. The codec checks
structure only and cannot enforce those operational requirements.

Both object encodings begin with an 8-byte type magic, version `1` as a
little-endian `u16`, a `u8` profile length, the UTF-8 profile
`ironwood-zero-ovk-receiver-v1`, and the 32-byte genesis hash. Numeric fields are
little-endian. Object digests are SHA-256 of the complete canonical bytes.

| Object | Fields after the common header |
| --- | --- |
| Block (`IWBLKF1` followed by NUL) | Height `u32`, block hash, derived salt, `P` as `u8`, `M` as `u64`, recipient count `u32`, payload length `u32`, GCS payload including its canonical CompactSize count |
| Seen (`IWSEEN` followed by two NULs) | Feed start and complete-through times as `i64` Unix seconds, Rice parameter `u8`, unique hash count `u32`, payload length `u32`, strictly increasing hash deltas without an inner count |

Decoders reject unsupported profiles, inconsistent counts, nonzero padding,
trailing bytes and oversized objects before membership is used. A valid encoding
alone does not establish the expected network, canonical chain, archive revision,
completeness or ownership. Callers must validate those separately, then verify
candidate payments with their own keys.

These are the first replacement primitives. The existing `filter` and `snapshot`
formats remain active until publisher and wallet callers migrate. The archive
head, bounded range transport and compatible PIR publication binding belong to
the next format change. No wallet discovery behavior changes here.
