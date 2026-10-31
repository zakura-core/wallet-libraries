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

With the `orchard` feature, `WalletDb` stores derived refund and receive keys and recovers their payments through a durable PIR queue. Ordinary block and transaction scanning uses account keys. Returned payments are authenticated with the specific derived key and credited only after local inclusion and spend checks pass. The spend journal retains nullifiers from recognized wallet transactions so a late recovered note cannot resurrect spent funds.

Enable recovery per account with `enable_one_time_recovery`. Read bounded work with `one_time_recovery`, perform network requests without a database lock, and commit through `record_one_time_lookup`, whose records carry their witness payloads. Filter ranges (`record_one_time_filter_span`) move the account's marker forward exactly from where it is, and a complete check (`begin_one_time_recovery` with `complete`) reads every monitored key by PIR and moves the marker to its end. A filter match queues a lookup, and every newly watched key gets one bootstrap lookup through the processed frontier. Only lookups complete a key's history. Filters only reduce network cost. They do not establish ownership. `zakura-pir-client`'s `receiver-wallet` feature performs bounded network steps and never owns the wallet database.

Seed recovery stops after four complete empty receive histories. Payments extend the four-index issuance window once mined on the wallet's chain, unpaid holes are recycled, and authenticated funding memos identify refund keys. A funded refund key leaves automatic monitoring once every local operation on it is conclusive, and stays monitored while any is active or inconclusive. One with no local operation, such as a key recovered from its funding memo, leaves once the account's marker reaches 90 days of chain time after its funding block. A memo learned late is checked over that window first. A receive address is handed out once its own lookup completed and the marker is within 10 blocks of the chain tip. A payment from another device mined in those last blocks, or a reservation made on another device at the same moment, can still go unseen at hand-out. `check_one_time_history` explicitly checks older addresses, supports an exclusive receive bound, and can be cancelled and resumed. Filters and complete checks keep watching paid keys, so a repeat payment to a monitored address is found automatically. One to a key out of monitoring is found only by `check_one_time_history`. Discovery has no pause: an enabled account stays enabled and keeps repairing its receipts after a reorg, and an app stops querying an account by leaving it out of its rounds. Payments before the account birthday are ignored, so complete recovery needs a birthday before the account's first one-time address use.

See `wallet::one_time_ivk::restore` for the queue contract and `wallet::one_time_ivk::swap` for quote ownership and funding. The [`zakura-one-time-ivk` README](../../zakura/one-time-ivk/README.md) describes key derivation and the refund memo.

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
