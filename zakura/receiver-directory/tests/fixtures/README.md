# Receiver test fixtures

- `zero-ovk-action.json`: a public mainnet refund Action recoverable with the zero
  outgoing viewing key, with its independently decoded receiver; see
  `zero-ovk-action-oracle/README.md`.
- `recovery-vectors.json`: inputs and the expected salts, encodings and digests
  of a paid bucket, an empty bucket, a cumulative paid set, a seen set (with each
  receiver's value), a bucket index and a catalog head, for publishers to check
  their output against. The receivers are `receivers.json`'s seeds 1 to 4; the
  genesis is mainnet's, in display order. `tests/recovery.rs` checks them.
- `receivers.json`: valid Ironwood receivers for tests that need real addresses, so
  these crates need no key derivation. Each is the raw address at an external index of
  a ZIP 32 Orchard spending key whose 32 bytes all equal one value, generated with
  `zakura-orchard` 3.0.0: `seeds.<n>` and `other`/`third` at index zero for bytes
  `n`, 3 and 4, and `spread` at indices 0 to 15 for bytes 5.
