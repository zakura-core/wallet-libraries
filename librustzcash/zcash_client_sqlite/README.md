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

With the `orchard` feature, `WalletDb` keeps one-time IVKs: a durable registry of
derived refund and incoming keys, their scanning, discovery of a restored seed's keys
through a receiver directory, and spending. `WalletDb` implements the backend's
`OneTimeIvkRead` and `OneTimeIvkWrite`, so a wallet scans with
`scan_cached_blocks_with_one_time_ivks`, and the restore protocol's
`OneTimeIvkRestoreRead` and `OneTimeIvkRestoreWrite`. Compact scanning and software
spending retain each note's derived key; change uses ordinary account keys. The
`wallet::one_time_ivk` rustdoc lists the calls a wallet makes; swap issuance,
operations and closing are in `wallet::one_time_ivk::swap`. The
[`zakura-one-time-ivk` README](../../zakura/one-time-ivk/README.md) describes the
key derivation and refund memo.

Recovery turns each payment a directory lookup reports into a scan hint, so the scan finds
the note itself, or, if the scan already passed its block, into a late candidate. The
wallet admits a late candidate only after it authenticates the ciphertext, verifies the
note's inclusion and position against its own chain, and its scan has covered every
block from the payment on for the account. The spend journal, which keeps every
Ironwood nullifier of the wallet's own transactions, then says whether it was spent.
Until then the payment adds nothing to balance. `zakura-pir-receiver` runs recovery
against a receiver directory.

`WalletDb` also implements `OneTimeIvkCoverageRead` and `OneTimeIvkCoverageWrite`, the
state of continuous recovery from a directory's paid buckets: every registered key and a
window of each purpose's indices, the frontier the directory has covered for them, the
history still owed to receivers that joined later, and lookup targets fenced by
generation. Each write commits with the work it creates, and a rewind keeps only the
coverage its floor supports.

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
