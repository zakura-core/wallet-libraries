# New Zakura work

Hand-written crates that are ours rather than forks. `pir-enhance/` contains the
position-keyed Ironwood compact-action enhancement client, and `pir-enhance-types/` contains its shared wire records.

Nothing here is generated. `scripts/sync-upstream.sh` never touches this
directory, unlike `librustzcash/`, which it deletes and re-extracts on every
run. Add a crate here, then list it in `layout.extra_members` in
`manifests/sources.toml` so the generated workspace picks it up.
