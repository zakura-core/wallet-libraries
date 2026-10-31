# `zakura-wallet-lib`

Selects the complete Zakura wallet stack by default and re-exports the selected
family under stable names. Crates that must build both for Gemini and for Vizor
depend on this instead of naming either family directly.

`zakura` and `lrz` select a backend. Each includes Orchard. The Zakura backend
uses the Common revision pinned in `manifests/sources.toml` (Common 5 at the
head of Common PR #650 while Common 5 is unpublished); its Orchard proof
implementation uses the explicit Halo 2 backend. Common no longer exposes the `unstable-voting-circuits` feature that the upstream backend enables. Applications that use Enhance PIR
depend directly on `zakura-client-backend`/`zakura-client-sqlite` with Orchard
storage enabled and on `zakura-pir-client` with its `enhance` and `wallet` features; this facade does not
expose the client.
Keeping the two dependency
graphs explicit avoids weak cross-family references, so Cargo does not retain
the disabled family in downstream lockfiles and metadata.

The name is reserved on crates.io as `zakura-wallet-lib`.

See `src/lib.rs` for the selection rules and the guarantees this crate does and
does not provide.
