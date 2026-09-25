# Zakura Status PIR client

This crate holds the release-facing status row format and transport-neutral
client. It retrieves one encrypted row and returns only an observation. The
synthetic fixture protocol in `wallet-pir` uses a different protocol identifier
and cannot be accepted by this client.

`PendingClient::fetch` validates the manifest and checks freshness with a clock
callback read after `/init` returns. The application must obtain an
independent chain anchor from its wallet before `PendingClient::accept` fetches
public session material. `StatusPirClient::observe` takes local coverage
evidence; an absent txid is inconclusive without a conservative earliest
inclusion bound inside the published window. The application implements
`transport::Transport` with its own route, timeouts, body bounds, and
cancellation policy. No status error authorizes a public txid lookup.

This crate alone does not enable private status in a wallet or qualify a live
Status PIR service. The server and client must use the same frozen release
protocol and pass live-source qualification before activation.
