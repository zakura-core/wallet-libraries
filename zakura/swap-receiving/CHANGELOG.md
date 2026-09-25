# Changelog

## [Unreleased]

- Add unpublished swap receiving-key derivation, shared purpose/index identities,
  and refund memo helpers, with independent KDF vectors and an Ironwood
  receive/reconstruct/spend proof test.
- Add shared completion policy with durable grace and reconciliation deadlines,
  receipt and coverage checks, shared-key decisions, and reorg invalidation.
  SQLite operation persistence and active-key filtering remain pending.
