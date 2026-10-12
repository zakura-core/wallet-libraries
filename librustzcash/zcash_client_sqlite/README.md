# Security Disclaimer

This is a beta build, and is currently under active development. Please be advised
of the following:

* This code currently is not audited by an external security auditor, use it at
  your own risk.
* The code **has not been subjected to thorough review** by engineers at the Electric Coin Company.
* We **are actively changing** the codebase and adding features where/when needed.

----

# zcash_client_sqlite

This library contains APIs that collectively implement a Zcash light client in
an SQLite database.

## One-time IVKs

With the `one-time-ivk` feature, which enables `orchard`, `WalletDb` keeps one-time
IVKs: a durable registry of derived refund and incoming keys, their scanning, seed
recovery through receiver-directory sweeps, and spending. The migration creates its
tables in every build, but a build without `one-time-ivk` refuses to open a database
holding any of this state. `WalletDb` implements the backend's `OneTimeIvkRead` and
`OneTimeIvkWrite`, so a wallet scans with `scan_cached_blocks_with_one_time_ivks`, and
the restore protocol's `OneTimeIvkRestoreRead` and `OneTimeIvkRestoreWrite`. Compact
scanning and software spending retain each note's derived key; change uses ordinary
account keys. The `wallet::one_time_ivk` rustdoc lists the calls a wallet makes; swap
issuance, operations and closing are in `wallet::one_time_ivk::swap`. The
[`zakura-one-time-ivk` README](../../zakura/one-time-ivk/README.md) describes the key
derivation and refund memo.

A restore sweep credits a directory-reported payment only after the wallet
authenticates its ciphertext, verifies its inclusion against its own chain, and
checks its spend state against locally retained Ironwood nullifiers. Incomplete
evidence leaves the payment queued without crediting balance, and a directory
failure never queues a public replay.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
