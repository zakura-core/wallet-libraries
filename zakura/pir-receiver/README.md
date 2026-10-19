# Receiver directory discovery

A restored wallet finds payments to its one-time keys by checking candidate receivers
against a receiver directory's public filters and looking the paid ones up over PIR.
`fetch_seen` downloads the permanent provider-membership object advertised by the archive head. `Seen::digest` identifies its exact bytes for bounded issuance checks. With the `wallet` feature, `discover` runs one account's discovery for any
wallet store that implements the backend's restore traits
(`zcash_client_backend::data_api::one_time_ivk::restore`, from its `orchard` feature),
such as `zakura-client-sqlite`. Its rustdoc states when a run starts a new pass, which
keys it checks and watches, how it pages through a history, and how failures are
retried.

Applications supply:

- the directory's HTTPS origin and a `Transport` for it, which carries the
  application's route policy, timeouts and cancellation; this crate has no HTTP
  client.
- a `WriteLock` that serializes discovery's wallet writes with the application's
  other writers.
- the wallet's consensus parameters, the network's genesis hash (`MAINNET_GENESIS` on
  mainnet) and the clock.

`tests/discovery.rs` serves a directory in process through the receiver service's own
routes and real PIR, and checks each of those rules against restored SQLite wallets.

## Validation

From the workspace root:

```sh
python3 scripts/dev.py test --config pir-receiver
```

## Block filters

`filters::FilterRequest` owns captured wallet work and fetches one authenticated public page without borrowing a wallet connection or write lock. Accept a connected archive head first, then commit the response under the caller's short write lock. Settings, corrections and rewinds fence stale responses. Public membership checks do not make receiver PIR requests.

The production scanner and application scheduler cutover is still separate work. See [the recovery contract](../../docs/block-filter-recovery.md) for cache ownership and pending integration requirements.

## Compatible history sessions

`history::SessionMetadata::fetch` captures the actual PIR manifest and its archive coverage before opening a receiver session. The caller independently anchors the genesis, matched block and publication frontier to its local chain. `connect` checks those anchors and the archive epoch against that exact manifest. The filter head may be ahead of the PIR publication, provided the publication covers the matched block.

A connected `RecoverySession` walks a bounded receiver history without borrowing wallet storage. It returns crypto-format-checked records and a common witness snapshot. The wallet must authenticate each note, check canonical inclusion and spend coverage, and fence every write against its captured account generation and session. A successful page is not proof that the pending filter match is settled. Durable settlement and application scheduling are separate integration work.
