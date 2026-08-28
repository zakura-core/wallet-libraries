# `zakura-wallet-lib`

Selects either the Zakura wallet stack (`zakura-orchard`, the default) or the
upstream librustzcash stack (`lrz-orchard`), and re-exports the selected family
under stable names. Crates that must build both for Gemini and for Vizor depend
on this instead of naming either family directly. Gemini selects LRZ with
`default-features = false, features = ["lrz-orchard"]`; Vizor uses the
defaults.

Consumers that do not need Orchard can select the base `zakura` or `lrz`
feature. The old cross-family `orchard` selector is replaced by explicit
`zakura-orchard` and `lrz-orchard` combinations so Cargo does not retain the
disabled family in downstream lockfiles and metadata. `orchard` remains a
compatibility alias for `zakura-orchard`; LRZ consumers use `lrz-orchard`.

The name is reserved on crates.io as `zakura-wallet-lib`.

See `src/lib.rs` for the selection rules and the guarantees this crate does and
does not provide.
