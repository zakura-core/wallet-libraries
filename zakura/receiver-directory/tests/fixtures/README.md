# Receiver test fixtures

- `zero-ovk-action.json`: a public mainnet refund Action recoverable with the zero
  outgoing viewing key, with its independently decoded receiver; see
  `zero-ovk-action-oracle/README.md`.
- `receivers.json`: valid Ironwood receivers for tests that need real addresses, so
  these crates need no key derivation. Each is the raw address at an external index of
  a ZIP 32 Orchard spending key whose 32 bytes all equal one value, generated with
  `zakura-orchard` 3.0.0: `seeds.<n>` and `other`/`third` at index zero for bytes
  `n`, 3 and 4, and `spread` at indices 0 to 15 for bytes 5.

- `seen-vectors.json`: preserves the fixed-universe hash identities, canonical
  encoding and digest from the earlier recovery-format implementation at
  `3c57bbb2b9c6a92eba8da48846d88d555646125d`. It contains only the durable seen
  fixture, not the superseded bucket or catalog formats. Membership and malformed
  encoding tests supplement this regression vector.
