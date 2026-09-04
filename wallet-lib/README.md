# `zakura-wallet-lib`

Selects the complete Zakura wallet stack by default and re-exports the selected
family under stable names. Crates that must build both for Gemini and for Vizor
depend on this instead of naming either family directly.

`zakura` and `lrz` select a backend. Each includes Orchard and the complete
feature set required by `zcash_voting`. The additive `zakura-pir-enhance` feature
selects Zakura and enables the private, position-keyed Ironwood enhancement APIs.
Applications use the unpublished `zakura-pir-enhance` client as a direct path or
Git dependency; it is intentionally not re-exported by this published facade.
Keeping the two dependency
graphs explicit avoids weak cross-family references, so Cargo does not retain
the disabled family in downstream lockfiles and metadata.

The name is reserved on crates.io as `zakura-wallet-lib`.

See `src/lib.rs` for the selection rules and the guarantees this crate does and
does not provide.
