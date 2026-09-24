# zakura-pir-enhance

This crate implements the mainnet Ironwood enhancement v7 client. Wire schema 11 uses 653-byte suffix-only records, 33 records per row, independently parameterized shards, and the P16Q48 SimplePIR profile. The wallet retains compact encryption fields and supports same-transaction row queries and atomic batch application. The initial SQLite schema is rewritten; no existing-client migration is provided. A matching v7 server is required.

Fetch a `PendingClient` manifest from `/v1/enhance/init`, call `wallet::acceptance` using locally scanned state, then call `accept` with the returned `GenerationAcceptance`. The client fetches shard sessions lazily from `/v1/enhance/session/{session_id}` and retains at most `ClientResourceLimits::max_cached_shards` expanded setups. `max_shard_rows` limits each setup, separately from total chain coverage. Query methods borrow the client mutably so one client has at most one active batch; an idle setup is evicted before its replacement is built.

A batch stays bound to one accepted manifest. Queries are deduplicated by shard and local row. Covered results arrive in ascending row and position order, followed by uncovered positions; duplicates are coalesced. Earlier yielded records may be committed if a later row fails. Dropping the stream prevents further dispatch.

On `ClientError::HttpStatus(409)` or `ClientError::HttpStatus(410)`, stop the batch, fetch a new pending manifest, repeat wallet acceptance, and reschedule unfinished durable work. Use bounded application scheduling for 429/503. Transport and validation errors must not trigger public LWD fallback.

The built-in Reqwest transport requires HTTPS, rejects redirects, and has a 120-second deadline. Custom transports must stream into `Request::response_body()`, reject non-success status with `ClientError::HttpStatus(code)`, and honor cancellation and deadlines. Plaintext positions, rows, slots, txids, and action indexes stay out of requests and URLs; domain and routing revision are public.

Refresh routing at sync start and whenever `refresh_due()` is true (30 seconds).
Fetch a new pending manifest, independently accept its anchor, then call
`accept_routing` to reuse unchanged session material. The HTTPS wrapper exposes
`fetch_routing`, `accept_routing`, and `refresh_due`. A routing or placement change
does not by itself invalidate immutable session material. A deep recovery epoch
change does. Every request has fresh randomness and a fresh request ID.

Optional `query_positions_with_cover` queries every domain since a supplied
birthday position with uniform rounds and randomized order. It retries an entire
round once on 429/503 and returns no partial records. Cover is off by default;
timing, round count, the birthday window and cross-interval intersection remain
observable. Ordinary streaming batches retain their existing partial-result semantics.

The q48 profile requires IPIR revision
`611a29284264d844bf4dba00de2874c5b762f8c2`. v5/q46 and v6/q48 manifests and
sessions are rejected. Schema-11 records and the deterministic public setup domain
are unchanged. The v7 `EPQ7` header is 116 bytes and binds routing, domain, packing
material, recovery epoch, session ID, request ID and accepted anchor. Noise
qualification remains separate from wallet acceptance and note authentication.
