# Receiver directory discovery

A wallet finds payments to its one-time keys by testing its receivers against a
receiver directory's public paid sets and looking the paid ones up over PIR. With the
`wallet` feature, `recover` runs one step of an account's continuous recovery on every
sync and on a timer: it follows the directory's closed hourly paid buckets, bootstraps
from cumulative snapshots, grows its receiver windows from the seen set, and looks hits
up through the same paging, hints and late admission discovery uses. `check_history` is
"Check swap history", which reads every window receiver's history whatever the paid sets
say. Their rustdoc gives the cadence, the budgets and how failures delay recovery.

`fetch_seen` downloads the swap provider seen sets that a wallet checks before issuing a
swap address. With the `wallet` feature, `discover` runs one account's discovery for any
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

`tests/discovery.rs` and `tests/recovery.rs` serve a directory in process through the
receiver service's own routes, recovery objects and real PIR, and check each of those
rules against restored SQLite wallets.

## Validation

From the workspace root:

```sh
python3 scripts/dev.py test --config pir-receiver
```
