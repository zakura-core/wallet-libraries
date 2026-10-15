# Public mainnet block fixture

Raw mainnet block `00000000017d40c50ef7f27bd2e997ed5d1009a332e4fa85b9939652b8dd516b`
at height 1,687,106, the block test vector
`crates/zakura-test/src/vectors/block-main-1-687-106.txt` (SHA-256
`0e0c7456caacfc7b48839bd603e3426c456d02f972a2f33dfc07d4d7bddc4776`) in the
zakura checkout at revision `1faf150fc3648aae22c55a6b30f8f5a9b9ce934e`. It is
byte-identical to wallet-pir's
`transparent/services/transparent-filter-server/tests/fixtures/compact-mainnet-1687106.hex`,
whose protoc round trip remains the independent oracle for the compact encoding.

`tests/transparent.rs` reads it as a compact block and as transparent parts, and
checks the two agree. This is public chain data, not a wallet export.
