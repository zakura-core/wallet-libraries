# `zakura-wallet-lib`

Selects either the Zakura wallet stack (`zakura`, the default) or the upstream
librustzcash stack (`lrz`), and re-exports the selected family under stable
names. Crates that must build both for Gemini and for Vizor depend on this
instead of naming either family directly. Gemini selects LRZ with
`default-features = false, features = ["lrz"]`; Vizor uses the defaults.

The name is reserved on crates.io as `zakura-wallet-lib`.

See `src/lib.rs` for the selection rules and the guarantees this crate does and
does not provide.
