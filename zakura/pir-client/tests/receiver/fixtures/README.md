# Receiver client test fixtures

- `receivers.json`: an exact copy of `zakura-pir-publisher`'s
  `tests/receiver/fixtures/receivers.json`, kept inside this package so its tests build
  from the published crate. Valid Ironwood receivers, each the raw address at an
  external index of a ZIP 32 Orchard spending key whose 32 bytes all equal one
  value, generated with `zakura-orchard` 3.0.0: `seeds.<n>` and `other`/`third`
  at index zero for bytes `n`, 3 and 4, and `spread` at indices 0 to 15 for
  bytes 5. Do not regenerate; change both copies together.
