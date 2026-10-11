# Receiver directory restore sweeps

A restored wallet finds payments to its dynamic keys by looking each one up in a
receiver directory over PIR. `fetch_seen` downloads the swap provider seen sets that
a wallet checks before issuing a swap address. With the `wallet` feature, `sweep`
runs one account's restore sweeps for any wallet store that implements the backend's
dynamic IVK traits (`zcash_client_backend::data_api::dynamic_ivk`), such as
`zakura-client-sqlite`. Its rustdoc states which publications a run accepts, when it
sends requests, which keys keep scanning or are checked again, and how failures are
retried.

Applications supply:

- the directory's HTTPS origin and a `Transport` for it, and a `NoteSource` for the
  note data of found payments, usually `EnhanceNotes` over Enhance PIR. Both carry
  the application's route policy, timeouts and cancellation; this crate has no HTTP
  client.
- a `WriteLock` that serializes the sweep's wallet writes with the application's
  other writers.
- the wallet's consensus parameters, the network's genesis hash (`MAINNET_GENESIS` on
  mainnet) and the clock.

`tests/sweep.rs` serves a directory in process through the receiver service's own
routes and real PIR, and checks each of those rules against restored SQLite wallets.
