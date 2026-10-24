# Orchard empty-root expectations

`orchard-empty-roots.txt` retains all 33 roots, in order from height 0 to 32,
from `zakura-orchard` 1.0.1 `src/test_vectors/commitment_tree.rs`. Each line
is the original 32-byte vector written as hexadecimal; no root was recalculated.

That source attributes the vectors to
[zcash-test-vectors](https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/orchard_empty_roots.py).
The version 3.0.0 source contains identical vector bytes. The source file hashes
used to check this provenance are:

- `zakura-orchard 1.0.1` source file SHA-256: `f8217ba483d3583981166264d190bb774e772f27182495f8f72a7329a489827a`.
- `zakura-orchard 3.0.0` source file SHA-256: `f8217ba483d3583981166264d190bb774e772f27182495f8f72a7329a489827a`.

The legacy demo lockfile selected 1.0.1 (crates.io checksum
`79f40234883ea702da695f1cbf470a0ba3b9fe0ac51d24af588a058afc383d68`).
The retained vectors are checked against both the byte-array helpers and direct
Common calls in `tree_hashing.rs`; the external cross-version comparison also
runs 1.0.1 hashing directly. Source equality alone is not execution evidence.
