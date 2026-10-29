# Zakura native PIR primitives

Client primitives for the native two-mask InspiRING profile, shared by the
Enhance PIR (`ironwood-enhance-pir-v9-native-two-mask-m29`) and Status PIR
(`status-pir-v3-native-two-mask-m29`) clients.

A request is one uploaded `K_g` packing key followed by a 49-bit selection
query. A response is a sequence of 22-bit coefficients that decode under two
published masks rounded to 29 bits. Setup seeds, database shapes and envelopes
are protocol-specific and stay in the protocol crates.

The `test-server` feature exposes the matching server-side operations
(publishing masks, parsing requests, packing responses) so protocol crates can
round-trip their clients without depending on a server implementation. It is
not a server.

See [CHANGELOG.md](CHANGELOG.md) for release notes.

## Compatible PIR dependency maintenance

This maintenance line retains the published rc.7 wallet backend and Common 2
family. Version `0.0.1-rc0.1` adopts `ipir-sp` 0.1.0-rc.6.1 to remove CLI-only
dependencies without changing PIR parameters, setup identities or wire formats.
Publish the IPIR maintenance package first; then publish the native, status,
enhancement and transaction-status adapters in dependency order.
