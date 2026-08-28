# `zakura-wallet-lib`

Selects the Zakura wallet stack with Orchard by default and re-exports the
selected family under stable names. Crates that must build both for Gemini and
for Vizor depend on this instead of naming either family directly.

Capabilities compose explicitly: `zakura-orchard` / `lrz-orchard` add Orchard,
while `zakura-voting` / `lrz-voting` add the complete feature set required by
`zcash_voting`. This avoids weak cross-family references, so Cargo does not
retain the disabled family in downstream lockfiles and metadata. `orchard`
remains a compatibility alias for `zakura-orchard`.

The name is reserved on crates.io as `zakura-wallet-lib`.

See `src/lib.rs` for the selection rules and the guarantees this crate does and
does not provide.
