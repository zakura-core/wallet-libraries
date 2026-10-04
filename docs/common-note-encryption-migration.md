# Common 3.0 dependency migration

Depends on [Common #540](https://github.com/zakura-core/common/pull/540).
Coordinated node draft: [#1292](https://github.com/zakura-core/zakura/pull/1292).
Based on fetched wallet main `0497bc3`, rather than the stale local checkout.

## Changes and API review

All Zakura backend dependencies use Common 3.0.0. Client-backend, SQLite,
and PCZT explicitly select `zakura-note-encryption` with allocation enabled.
Common Sapling/primitives retain `pre-zip-212`. The library import spelling
remains `zcash_note_encryption`. The upstream-only `lrz` facade backend is
still mutually exclusive with `zakura`.

There are no new public or `pub(crate)` definitions, constructors, variants,
features, aliases, or handwritten signature changes. Existing public
`ScanningKeyOps` bounds, scanning APIs, `WalletOutput::from_parts` and its
`ephemeral_key` accessor, protobuf compact-output `ephemeral_key` accessors,
and PCZT/facade APIs now carry the Common note-encryption type family.
The crate-visible scanning `DecryptedOutput`, `Decryptor`, `BatchReceiver`,
`Batch`, and Ironwood domain alias have the same dependency identity change.
These upstream and fork types are not interchangeable despite the retained
library names. Existing wallet prerelease numbers are retained for this
staged draft; release preparation must assign fresh wallet versions before
publication, and update the source configuration/facade requirements together.

Root Cargo.toml is generated from the pristine upstream manifest and
`manifests/sources.toml`. The generator removes standalone encoding and its
adjacent comment, and preserves configured `default-features = false`.
Vendored manifests/imports are edited directly for merge-based upstream sync.
Graph policy rejects upstream encoding and note-encryption in the Zakura
production graph. Inactive LRZ packages in metadata/lockfiles are expected.

## Validation and local overrides

The relevant Orchard, transparent, SQLite, and PCZT configurations pass checks.
Orchard scanning passes 23 tests; SQLite Ironwood exercises 67 tests; PCZT
Sapling, Orchard, and Ironwood round trips pass all three tests. The graph
verifier and facade verifier pass, including both mutually exclusive backends
and a fresh Rust 1.91 consumer. Production graph inspection finds one Common
note-encryption package and no standalone encoding or upstream note encryption.
Scoped backend/SQLite Clippy passes with existing unused code/import warnings;
no blanket lint suppression was added. The Python tooling suite passes all
12 tests, including generation from pristine upstream sources.
No benchmarks were run.

Initial cross-repository checks used temporary `.cargo/config.toml` patches
for every Common package. Facade external-consumer checks used temporary
path dependencies instead, keeping inactive patch entries out of the LRZ
lockfile. All overrides and their local lockfiles are excluded from commits.
Consumer source files were stable during each successful dev.py invocation;
its leased build directories retain `last-result.json` validation evidence.

Publish Common 3.0.0 first, with protocol/note encryption before their
consumers. Then regenerate the wallet registry lockfile and repeat locked
feature, graph, and facade checks without local overrides. The draft retains
the original registry lockfile until these unpublished dependencies resolve.
Publish PCZT, backend, SQLite, and facade in dependency order afterward.
No crates were published and no PRs were merged.

Folding encoding removes one compilation unit. Forking note encryption
primarily changes ownership and does not itself save compilation work.
