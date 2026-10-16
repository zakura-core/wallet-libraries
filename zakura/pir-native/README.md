# Zakura native PIR primitives

The native two-mask InspiRING profile, shared by the Enhance PIR
(`ironwood-enhance-pir-v9-native-two-mask-m29`), Status PIR
(`status-pir-v3-native-two-mask-m29`), receiver directory and transparent PIR
clients and by the wallet-pir services that answer them. It is the one
implementation of the profile: clients prepare and decode with it, and servers
compute the hint, preprocess, publish, parse and pack with it. The 8-bit
profile (`P8`) serves Transparent's history tables.

A request is one uploaded `K_g` packing key followed by a selection query,
either rounded to nearest at 49 bits (`prepare_with`) or dithered to 44 bits
(`prepare_dithered`). Dithering rounds each coefficient up with probability
equal to the dropped fraction, using fresh randomness per coefficient, so
rounding errors are independent and zero-mean. A server tells the two widths
apart by exact length. A response is a sequence of 22-bit coefficients that
decode under two published masks rounded to 29 bits. Setup seeds, database shapes and envelopes
are protocol-specific and stay in the protocol crates.

The `test-server` feature adds an in-memory database over those server
operations, so protocol crates can round-trip their clients without depending on
a server. It is not a server.

See [CHANGELOG.md](CHANGELOG.md) for release notes.
