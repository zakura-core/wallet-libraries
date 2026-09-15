# zakura-pir-enhance

An unpublished iPIR+SP client for privately retrieving the fields needed to
enhance Ironwood compact actions by note-commitment-tree position.

The transport-neutral `QuerySession` supports application-owned direct or Tor
HTTP routing. The default `https-client` feature also provides a Reqwest client
for the schema-v7 `/v1/enhance/*` API.

Before constructing a query session, the application must provide a
`GenerationAcceptance` containing an anchor height, block hash, and Ironwood
tree size already accepted by its wallet, plus a local `max_logical_rows`
resource limit. The limit must be chosen for the least-capable supported
device; it must never come from the PIR server.

For the Reqwest client, call `EnhancePirClient::fetch_session`, validate the
pending generation against wallet state, and then call
`PendingEnhancePirClient::connect` with that acceptance. The size-limited JSON
fetch is cheap; public-parameter decoding, PIR parameter derivation, and setup
allocation are deferred until `connect`. `EnhancePirClient::connect` is a
one-shot convenience when the accepted anchor is already known.

Custom transports receive the same allocation protection: the encoded public
parameters are checked against the generation's exact expected size before
base64 decoding.

The client and `zakura-client-backend` use the same `EnhanceRecord` from
`zakura-pir-enhance-types`. Pass a decoded record and the originally captured
request to `EnhancePirWrite::apply_ironwood_enhance_record`; no conversion or
`wallet-integration` feature is needed. The wallet validates and applies incoming
and outgoing work atomically using that local action identity.
Either transparent-presence flag routes the entire transaction to ordinary LWD.
The flags are trusted server metadata, not authenticated by note decryption.
See [the integration contract](../../docs/zakura_pir_enhance.md) for construction,
unified work scheduling, migration, recovery, and privacy limitations.

Batch APIs return `Result<Stream, ClientError>` and reject more than 4096 input
items by default. Use `query_batch_with_limit` to select a local bound; duplicates
count toward the limit. The built-in routed HTTP adapter is
`transport::ReqwestTransport::new()`, which enforces HTTPS, no redirects, and a
120-second deadline; plain Reqwest clients no longer implement `Transport`.
