# Changelog

## Unreleased

- Use the published IPIR v0.1.0-rc.3 crate and InspiRING v0.1.0-rc.1 test dependency with exact version pins; retain the v7 wire protocol and CPU backend.

- Preserve observed v7 routing expiration when an in-flight cover future is dropped; cancellation without an expiration signal keeps the accepted view usable.

- Require fresh wallet acceptance for v7 session rebinding; keep in-flight batches valid past the routing refresh cadence.
- Keep cover traffic scheduling independent of record validation errors, and preserve every observed 409/410 expiration signal across mixed failures.
- Apply reduced session cache limits immediately when accepting routing, evicting least-recently-used setups.

- Add protocol v6 with the distinct P16Q48 transport profile and exact IPIR dependency pin; reject v5/q46 manifests and sessions. Retain schema-11 record encoding and wallet acceptance.
- Use the validated production client constructor and opaque public setup API.

- Add wallet-side schema 11/v5: 653-byte ciphertext-suffix records, retaining 33-record rows and the existing shard/session transport.
- Add same-transaction row queries, prepared-work grouping, and atomic wallet batch application. Persist compact encryption fields in the initial Ironwood note schema; no existing-client migration is provided.
- Trust send-only server association when decryption cannot authenticate the action; retain incoming authentication and stale-identity checks.
- Add synthetic wallet v5 fixtures and reject the historical v4 server manifest. Server implementation and interoperability qualification remain separate work.

### Earlier v4 work

- Replace Enhance PIR v2 schema 7 with architecture_2 v4 schema 10: manifest coverage, shard sessions, P16Q46 parameters, 33-record rows, and EPQ4 query binding.
- Require wallet acceptance of the manifest anchor before lazy shard setup; add per-shard row and cache limits.
- Surface typed HTTP statuses and require fresh wallet acceptance after a 410 expiry. Keep 429/503 work available for bounded application retries.
- Pin ipir-sp and compatibility fixtures to the v4 reference revisions. The 737-byte record format and wallet database schema are unchanged.
