# zakura-pir-enhance

Release candidate `0.0.1-rc1` requires Rust 1.91. The crate has no default
features and bundles no HTTP client: applications implement `transport::Transport`.
The optional `wallet` feature integrates with `zakura-client-backend 0.1.0-rc7`.
The crate speaks the experimental native two-mask protocol (v9). Shared records come from
`zakura-pir-enhance-types =0.0.1-rc0`. See [CHANGELOG.md](CHANGELOG.md) for
release notes.

This crate implements the mainnet Ironwood enhancement v9 client. Wire schema 11 uses 653-byte suffix-only records, 33 records per row, independently parameterized shards, and the P16Q48 SimplePIR profile with native two-mask payloads. The wallet retains compact encryption fields and supports same-transaction row queries and atomic batch application. SQLite upgrades existing rc5 wallets with a forward migration that preserves notes and adds nullable compact encryption fields. Rescanning compact blocks fills those fields for older notes. A matching v9 server is required.

Fetch a `PendingClient` manifest from `/v1/enhance/init`, call `wallet::acceptance` using locally scanned state, then call `accept` with the returned `GenerationAcceptance`. The client fetches shard sessions lazily from `/v1/enhance/session/{session_id}` and retains at most `ClientResourceLimits::max_cached_shards` expanded setups. `max_shard_rows` limits each setup, separately from total chain coverage. Query methods borrow the client mutably so one client has at most one active batch; an idle setup is evicted before its replacement is built.

A batch stays bound to one accepted manifest. Queries are deduplicated by shard and local row. Covered results arrive in ascending row and position order, followed by uncovered positions; duplicates are coalesced. Earlier yielded records may be committed if a later row fails. Dropping the stream prevents further dispatch.

On `ClientError::HttpStatus(409)` or `ClientError::HttpStatus(410)`, stop the batch, fetch a new pending manifest, repeat wallet acceptance, and reschedule unfinished durable work. Use bounded application scheduling for 429/503. Transport and validation errors must not trigger public LWD fallback.

Transports should reject redirects and enforce a deadline covering the response body. They must stream into `Request::response_body()`, reject non-success status with `ClientError::HttpStatus(code)`, and honor cancellation and deadlines. Plaintext positions, rows, slots, txids, and action indexes stay out of requests and URLs; domain and routing revision are public.

Refresh routing at sync start and before starting new work whenever `refresh_due()`
is true (30 seconds). In-flight operations keep their accepted routing view until
completion or a server rejection; the refresh cadence is not a batch deadline.
Fetch a new pending manifest, independently accept its anchor, then call
`accept_routing` to reuse unchanged session material. `transport::Client`
exposes `accept_routing` and `refresh_due`; fetch the new manifest with
`PendingClient::fetch`. A routing or placement change
does not by itself invalidate immutable session material. A deep recovery epoch
change does. Accepting a lower cache limit immediately evicts the least-recently-used
retained setups. Every request has fresh randomness and a fresh request ID.

Optional `query_positions_with_cover` queries every domain since a supplied
birthday position with uniform rounds and randomized order. It retries an entire
round once on session or query 429/503 and returns no partial records. Record validation
errors are deferred until the scheduled cover traffic finishes and do not change
round counts or transport retries. Any observed 409/410 expires the client even
when another error is returned or the cover future is subsequently dropped.
Cancellation before any expiration signal leaves the accepted view usable.
Cover is off by default;
timing, round count, the birthday window and cross-interval intersection remain
observable. Ordinary streaming batches retain their existing partial-result semantics.

The q48 profile uses the published `ipir-sp =0.1.0-rc.6` and
`reinspiring =0.1.2` crates.
Earlier protocol revisions are rejected. Schema-11 records and the deterministic
public setup domain are unchanged. The `EPQ7` header is 116 bytes and binds routing,
domain, packing material, recovery epoch, session ID, request ID and accepted anchor. Noise
qualification remains separate from wallet acceptance and note authentication.

## Native two-mask profile (experimental)

The client uses protocol revision
`ironwood-enhance-pir-v9-native-two-mask-m29`, mirroring the `enhance-pir`
crate in `wallet-pir`. Manifests advertising another revision fail validation.
Routing, session identities, wallet acceptance, the 116-byte `EPQ7` binding and
the per-shard public setup seed retain the established wire layout.

`parameters()` reports the served profile, `query_bits = 49` and
`q_prime_1 = 2^22`, and every shard's public session material is 89,088 bytes
(12,288 columns, two masks each rounded to 29 bits). A request is the header,
one uploaded 27,648-byte `K_g` packing key and a selection dithered to 44 bits
per row (207,988 bytes for a 32,768-row shard); a response is the header plus
33,792 bytes of 22-bit packed columns. The server also accepts the profile's
49-bit selection (228,468 bytes) and tells the two apart by length; a server
that predates 44-bit requests rejects them. The `native` module exposes the profile
constants, the mask and length helpers, and `NativeSession`.

This protocol is experimental. `ipir-sp`'s cryptographic gates for the native
path remain open: its noise and correctness qualification is snapshot-specific,
and the rounded two-mask output has not completed independent review. Do not
ship it in a production wallet until those gates close and a matching v9 server
has passed qualification.

## Integration changes

`QuerySession::rebind` now requires a `GenerationAcceptance` argument, just like
initial session construction. Recreate it from locally scanned state for the new
manifest; a session ID match alone does not accept a new chain anchor. The
higher-level `Client::accept_routing` API already takes this argument.
