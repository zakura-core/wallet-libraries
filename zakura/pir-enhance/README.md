# zakura-pir-enhance

This crate implements the mainnet Ironwood enhancement v4 client. Wire schema 10 uses 737-byte records, 33 records per row, independently parameterized shards, and the P16Q46 SimplePIR profile. It does not change the wallet SQLite schema or record decoder.

Fetch a `PendingClient` manifest from `/v1/enhance/init`, call `wallet::acceptance` using locally scanned state, then call `accept` with the returned `GenerationAcceptance`. The client fetches shard sessions lazily from `/v1/enhance/sessions/{generation}/{shard_id}` and retains at most `ClientResourceLimits::max_cached_shards` expanded setups. `max_shard_rows` limits each setup, separately from total chain coverage. Query methods borrow the client mutably so one client has at most one active batch; an idle setup is evicted before its replacement is built.

A batch stays bound to one accepted manifest. Queries are deduplicated by shard and local row. Covered results arrive in ascending row and position order, followed by uncovered positions; duplicates are coalesced. Earlier yielded records may be committed if a later row fails. Dropping the stream prevents further dispatch.

On `ClientError::HttpStatus(410)`, stop the batch, fetch a new pending manifest, repeat wallet acceptance, and reschedule unfinished durable work. Use bounded application scheduling for 429/503. Transport and validation errors must not trigger public LWD fallback.

The built-in Reqwest transport requires HTTPS, rejects redirects, and has a 120-second deadline. Custom transports must stream into `Request::response_body()`, reject non-success status with `ClientError::HttpStatus(code)`, and honor cancellation and deadlines. Plaintext positions, rows, slots, txids, and action indexes stay out of requests and URLs; shard and generation are public.
