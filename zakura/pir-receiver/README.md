# Receiver directory recovery

A wallet finds payments to its one-time keys by testing its receivers against a
receiver directory's public paid sets and looking the paid ones up over PIR. With the
`wallet` feature, `recover` runs one step of an account's continuous recovery on every
sync and on a timer: it follows the directory's closed hourly paid buckets, bootstraps
from cumulative snapshots, grows its receiver windows from the seen set, and looks hits
up over PIR, turning payments into scan hints or late candidates. `check_history` is
"Check swap history", which reads every window receiver's history whatever the paid sets
say. Their rustdoc gives the cadence, the budgets and how failures delay recovery.

Both work for any wallet store that implements the backend's coverage and restore
traits (`zcash_client_backend::data_api::one_time_ivk`, from its `orchard` feature), such
as `zakura-client-sqlite`. `fetch_seen` downloads the seen set that a wallet checks
before issuing a swap address.

Applications supply:

- the directory's HTTPS origin and a `Transport` for it, which carries the
  application's route policy, timeouts and cancellation; this crate has no HTTP
  client.
- a `WriteLock` that serializes recovery's wallet writes with the application's
  other writers.
- the wallet's consensus parameters, the network's genesis hash (`MAINNET_GENESIS` on
  mainnet) and the clock.

`tests/recovery.rs` serves a directory in process through the receiver service's own
routes, recovery objects and real PIR, and checks each of those rules against SQLite
wallets.

## Validation

From the workspace root:

```sh
python3 scripts/dev.py test --config pir-receiver
```
