# zakura-filters

The byte codec shared by transparent activity filters and receiver-directory filters.
It contains a Golomb-coded set writer, a bit reader, and canonical CompactSize
integer encoding/decoding. It does not interpret scripts, addresses, transactions,
chain identities, or publication metadata.

The writer and bit operations were extracted from rust-bitcoin **0.32.102**
(`src/bip158.rs`, CC0-1.0), whose attribution to Tamas Blummer's murmel
implementation is retained in the source. CompactSize follows that version's
`src/consensus/encode.rs`. SipHash is provided by the pinned `bitcoin_hashes`
library; no hash implementation is maintained here. Tests use the exactly pinned
Bitcoin implementation as an independent oracle.

Callers must validate the full filter: bound counts and allocations, check decoded
ranges, padding and trailing bytes, and choose the correct application keys and
parameters. The low-level reader alone makes no claim about a filter's validity
or completeness. Filter profiles and their wire formats remain in the consumers.
