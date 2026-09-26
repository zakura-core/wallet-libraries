# Zakura Status PIR client

This crate holds the release-facing status row format and transport-neutral
client. It retrieves one encrypted row and returns only an observation. The
synthetic fixture protocol in `wallet-pir` uses a different protocol identifier
and cannot be accepted by this client.

`PendingClient::fetch` validates the manifest and keeps the wallet clock
callback for the session; the clock is read after each response. A manifest is
fresh for 20,000 ms after its `observed_ms`; a manifest up to 5,000 ms ahead of
the wallet clock is treated as observed now, and one further ahead is rejected
as malformed. The application must obtain independently verified chain anchors
from its own wallet state before `PendingClient::accept` fetches public session
material. `accept` takes an `AnchorVerifier`: `AcceptedAnchor` accepts exactly
one `(height, hash)`, and `AcceptedAnchors` accepts any anchor in a
wallet-verified window so a manifest a few blocks behind the wallet tip remains
usable.

## What the server asserts and what the client verifies

The client verifies only what it can check locally: the manifest identity,
the public-material digest, the exact protocol lengths, and the wellformedness
of the retrieved row. Everything else in a manifest or row is a server
assertion, not a proof:

- `Observation::NotFound` means the retrieved row held no record for the txid.
  It is not evidence that the transaction is absent from the chain or mempool;
  a dishonest or lagging server can omit records.
- `coverage_start` and `anchor_height` describe the window the server claims
  to have indexed. The client never confirms that every block in that window
  was scanned.
- `observed_ms` is the server's own clock reading. Freshness checks bound how
  far a stale snapshot can be replayed; they do not authenticate the server.
- `anchor_height` and `anchor_hash` are trusted only once the caller's
  `AnchorVerifier`, built from the wallet's own verified chain state, accepts
  them. Never construct a verifier from values read out of the manifest.

Records carry no inclusion proof. A `Mined(height)` observation is a claim to
be reconciled against the wallet's own chain data before it is acted on. `StatusPirClient` is
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
