# Zakura transaction status

`StatusReader` selects one status source per batch and never falls back to the
other source after an error. The public lightwalletd source uses the existing
`GetTransaction` RPC, validates the returned transaction ID, and discards the
payload. The private source is supplied by the wallet and can use
`zakura-pir-status` with a wallet-verified chain anchor and coverage context.

Construct sources lazily: a selected private mode must not connect to a public
transaction endpoint. Create a new reader for a later retry after an opening
failure. Status observations do not satisfy transaction enhancement work.
