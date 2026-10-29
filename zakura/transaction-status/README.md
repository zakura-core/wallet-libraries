# Zakura transaction status

`StatusReader` selects one status source per batch and never falls back to the
other source after an error. The public lightwalletd source uses the existing
`GetTransaction` RPC, validates the returned transaction ID, and discards the
payload. The private source is supplied by the wallet and can use
`zakura-pir-status` with a wallet-verified chain anchor and coverage context.

Construct sources lazily: a selected private mode must not connect to a public
transaction endpoint; the unselected source is dropped unopened. An opening
failure, or an opening cancelled by dropping `observe`, is terminal; create a
new reader for a later retry. Status observations do not satisfy transaction enhancement work.

See [CHANGELOG.md](CHANGELOG.md) for release notes.

## Compatible PIR dependency maintenance

This maintenance line retains the published rc.7 wallet backend and Common 2
family. Version `0.0.1-rc0.1` adopts `ipir-sp` 0.1.0-rc.6.1 to remove CLI-only
dependencies without changing PIR parameters, setup identities or wire formats.
Publish the IPIR maintenance package first; then publish the native, status,
enhancement and transaction-status adapters in dependency order.

The lightwalletd adapter enables Tonic channels without server/router features.
Callers continue to supply their own connected client.
