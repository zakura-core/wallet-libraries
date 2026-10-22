# Receiver test fixtures

- `receivers.json`: valid Ironwood receivers for tests that need real addresses, so
  these tests need no key derivation. Each is the raw address at an external index of
  a ZIP 32 Orchard spending key whose 32 bytes all equal one value, generated with
  `zakura-orchard` 3.0.0: `seeds.<n>` and `other`/`third` at index zero for bytes
  `n`, 3 and 4, and `spread` at indices 0 to 15 for bytes 5. Do not regenerate;
  `zakura-pir-client`'s `tests/receiver/fixtures/receivers.json` is an exact copy, so
  change both together.
