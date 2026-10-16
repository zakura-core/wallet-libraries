# New Zakura work

Hand-written crates that are ours rather than forks. `pir-enhance/` contains the
position-keyed Ironwood compact-action enhancement client, and `pir-enhance-types/` contains its shared wire records.
Transparent private mode is three crates. `transparent-private-shared/` is the
protocol both sides read: event and filter encodings, shard and display
layouts, manifests and native PIR profiles. `transparent-private-wallet/`
adapts transparent PIR retrieval over caller-supplied transports into candidate
wallet recovery commits, and looks up transaction details.
`transparent-private-server/` builds and seals the publications and holds the
native operations that answer queries. The wallet and server crates depend on
the shared one and never on each other outside tests.
`transparent-private-compat/` is not published: its own workspace checks the
three against the release they replaced.

Nothing here is generated. `scripts/sync-upstream.sh` never touches this
directory, unlike `librustzcash/`, which it deletes and re-extracts on every
run. Add a crate here, then list it in `layout.extra_members` in
`manifests/sources.toml` so the generated workspace picks it up.
