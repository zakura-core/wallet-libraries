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

## Experimental swap receiving

The `experimental-swap-receiving` feature exposes a durable receiving-key
registry through `WalletDb`. It supports atomic refund/receive reservations,
authenticated recovery registration, and incoming lookahead that does not
advance allocation. Reservation and application operation state can share a
`transactionally_with_extension` transaction. Expose the address only after
commit, and reuse its key ID when retrying that operation.

The feature is disabled by default. The migration creates its table in every
build so feature changes preserve existing reservations. Registration does not
yet enable scanning or spending these notes. See the
[shared POC contract](../../zakura/swap-receiving/README.md) for the APIs and
remaining integration work.

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
