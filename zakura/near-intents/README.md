# NEAR Intents adapter

Normalizes NEAR Intents 1Click execution statuses into the provider-neutral
`zakura_one_time_ivk::swap::Observation` that one-time IVK stores record. The app
fetches statuses itself and passes the fields that set local operation ownership
and receipt expectations as a `NearStatus`. This crate makes no network requests.

A status never proves or discovers a payment. Wallets find payments through PIR.
Its reported Zcash transaction hashes only attribute an authenticated payment to
the operation: the destination chain's for an incoming key, and both chains' for a
refund key, since NEAR sometimes files a ZEC refund under the destination. An empty history never ends a funded refund key's monitoring.
The wallet stops monitoring it automatically only once every local operation on it
is conclusive: the provider reported that no refund is coming, or the expected
refund was received and settled.

`near_observation(purpose, &status)` interprets a status by key purpose: a payout
for an incoming key, and a refund to a refund key. A refund on the source chain is
never a Zcash receipt, and an unrecognized status counts as active.

## Validation

From the workspace root:

```sh
python3 scripts/dev.py test --config default -p zakura-near-intents
```
