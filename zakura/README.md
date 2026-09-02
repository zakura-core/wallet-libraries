# New Zakura work

Hand-written crates that are ours rather than forks. `pir-memo/` contains the
unpublished, position-keyed Ironwood memo retrieval client.

Nothing here is generated. `scripts/sync-upstream.sh` never touches this
directory, unlike `librustzcash/`, which it deletes and re-extracts on every
run. Add a crate here, then list it in `layout.extra_members` in
`manifests/sources.toml` so the generated workspace picks it up.
