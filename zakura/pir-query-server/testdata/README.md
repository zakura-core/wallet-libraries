# Previous-provider Receiver scans

`previous_provider_scans.json` freezes IPIR-SP `0.1.0-rc.7` at commit
`5ea080a3281a01c5459f585e0a1bbbde50ec2bd2`. Digests are SHA-256 of column-major
database coefficients as little-endian `u16`, or scan outputs as little-endian
`u64`. The two row counts, input generator and three query families are in
`scripts/probes/previous_provider.rs` and the Receiver unit test.

Dependency-graph verification recomputes every digest with the pinned IPIR
server. Ordinary tests compare the private database/scan to these fixtures and
retain independent exact `u128` modular checks and malformed-input tests.
