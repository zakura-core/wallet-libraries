# zakura-pir-enhance

An unpublished iPIR+SP client for privately retrieving the fields needed to
enhance Ironwood compact actions by note-commitment-tree position.

The transport-neutral `QuerySession` supports application-owned direct or Tor
HTTP routing. The default `https-client` feature also provides a Reqwest client
for the schema-v5 `/v1/enhance/*` API.

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
