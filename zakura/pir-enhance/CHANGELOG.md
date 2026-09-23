# Changelog

## Unreleased

- Replace Enhance PIR v2 schema 7 with architecture_2 v4 schema 10: manifest coverage, shard sessions, P16Q46 parameters, 33-record rows, and EPQ4 query binding.
- Require wallet acceptance of the manifest anchor before lazy shard setup; add per-shard row and cache limits.
- Surface typed HTTP statuses and require fresh wallet acceptance after a 410 expiry. Keep 429/503 work available for bounded application retries.
- Pin ipir-sp and compatibility fixtures to the v4 reference revisions. The 737-byte record format and wallet database schema are unchanged.
