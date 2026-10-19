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
formats remain active until publisher and wallet callers migrate. The `archive` module supplies the head, bounded page index and compatible PIR
coverage contracts. Publisher and wallet integration are separate changes. No wallet discovery behavior changes here.


## Archive contract

A `Head` commits to the network, a nonzero durable archive identity, the correction
epoch, first supported height, contiguous frontier and its block hash, a Merkle
index root, and optional complete provider seen data. Missing seen data leaves
issuance pending but does not stop payment-filter publication. Callers must anchor
the frontier to their connected chain and persist identity/epoch transitions.

Transport pages cover up to 256 blocks at fixed height boundaries. A page must
contain the exact intersection of its boundary with the head's supported history.
It shares the format and network header, followed by start height (`u32`), count
(`u16`), preceding block hash, then each block hash and a `u32` payload length plus
GCS bytes. Empty payload length canonically represents an empty filter. Every
height remains explicit, including empty blocks. Complete empty pages take about
9.3 KB before their proof, rather than one request per empty block.

The sparse index covers all 2^24 page positions. Its SHA-256 domains distinguish
missing leaves, position-bound page digests and ordered branches with their level.
A range response is the page length (`u32`), page bytes, then 24 sibling hashes
from leaf to root. A head is at most 1 KiB, a page at most 64 MiB, and a response
adds 772 bytes. Historical page bytes remain reusable when an unrelated page or
head changes. The index verifies consistency, not honest indexing of every output.
Publishers durably store each page before publishing a root and advertise no gaps.

`Coverage` binds an immutable PIR session ID to its network, archive identity,
epoch, first height and frontier. Serve it under the archive identity, epoch and
session ID together. A correction may legitimately leave PIR row bytes and the
session ID unchanged, so session ID alone cannot name this declaration. The client
checks the actual manifest fields and then `Coverage::check` against a captured
head and independently validated connected-chain evidence. Equality of epochs
alone never establishes post-reorg compatibility. Account, settings and rewind
generation checks remain the caller's responsibility after every await.

Ordinary forks replace affected pages without changing the epoch. Corrections of
already published history change the epoch even if page bytes do not change.
Lost durable continuity requires a new archive identity. These lifecycle rules
belong to the publisher and wallet stores, not this transport-free codec.
