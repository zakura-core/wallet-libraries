# NEAR Intents adapter

Normalizes NEAR Intents 1Click execution statuses into the provider-neutral
`zakura_one_time_ivk::swap::Observation` that one-time IVK stores record. The app
fetches statuses itself and passes the fields that set local operation ownership
and receipt expectations as a `NearStatus`. This crate makes no network requests.

A status never proves or discovers a payment. Wallets find payments through PIR.
Its reported Zcash transaction hashes only attribute an authenticated payment to
the operation: the destination chain's for an incoming key and the origin chain's
for a refund key. A funded refund key with no refund yet stays unfinished, even
after an empty history or a `SUCCESS`.

`near_observation(purpose, &status)` interprets a status by key purpose: a payout
for an incoming key, and a refund to a refund key. A refund on the source chain is
never a Zcash receipt, and an unrecognized status counts as active.

## Validation

From the workspace root:

```sh
python3 scripts/dev.py test --config default -p zakura-near-intents
```
