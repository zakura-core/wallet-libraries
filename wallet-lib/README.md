# `zakura-wallet-lib`

Selects either the upstream librustzcash wallet stack (`lrz`, the default) or
its Zakura forks (`zakura`), and re-exports the selected family under stable
names. Crates that must build both for ZODL and for Vizor depend on this
instead of naming either family directly.

The name is provisional: nothing consumes it yet, and no crates.io reservation
exists for it.

See `src/lib.rs` for the selection rules and the guarantees this crate does and
does not provide.
