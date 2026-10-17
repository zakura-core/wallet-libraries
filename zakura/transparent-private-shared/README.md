# zakura-transparent-private-shared

What a Transparent private-mode wallet and its publisher both need:

- `events`: transparent event records and their codecs.
- `filter`: the activity filter profiles, keys, digests, envelopes, shard map
  wire types and filter validation.
- `shard`: shard and txid display layouts, manifests, maps, script placement,
  tags and row codecs.
- `native`: each table's native PIR profile, seeds and published scheme, derived
  the same way on both sides.

Recovery, lookups and persistence are in `zakura-transparent-private-wallet`;
building, publishing and answering tables is in
`zakura-transparent-private-server`. Both depend on this crate and never on each
other, so a wallet build carries no publisher code and a service build no
wallet code. This crate has no features.
