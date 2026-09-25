# Zakura Status PIR client

This crate holds the release-facing status row format and transport-neutral
client. It retrieves one encrypted row and returns only an observation. The
synthetic fixture protocol in `wallet-pir` uses a different protocol identifier
and cannot be accepted by this client.

`PendingClient::fetch` validates the manifest and keeps the wallet clock
callback for the session; the clock is read after each response. The
application must obtain an independent chain anchor from its wallet before
`PendingClient::accept` fetches public session material. `StatusPirClient` is
the only way to observe; the low-level PIR client is not public.
`StatusPirClient::observe` takes local coverage
evidence; an absent txid is inconclusive without a conservative earliest
inclusion bound inside the published window. The application implements
`transport::Transport` with its own route, timeouts, and cancellation policy,
and must not collect a body beyond the bound passed to it; session and query
responses are bounded to their exact protocol lengths. No status error authorizes a public txid lookup.

This crate alone does not enable private status in a wallet or qualify a live
Status PIR service. The server and client must use the same frozen release
protocol and pass live-source qualification before activation.
