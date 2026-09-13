# zakura-pir-enhance

An unpublished iPIR+SP client for privately retrieving the fields needed to
enhance Ironwood compact actions by note-commitment-tree position.

The transport-neutral `QuerySession` supports application-owned direct or Tor
HTTP routing. The default `https-client` feature also provides a Reqwest client
for the schema-v6 `/v1/enhance/*` API.

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

Enable `wallet-integration` when using `zakura-client-backend`. Its
`apply_record` helper converts the wire record and applies it to both incoming
and outgoing work atomically using the request's captured local action identity.
Either transparent-presence flag routes the entire transaction to ordinary LWD.
The flags are trusted server metadata, not authenticated by note decryption.
See [the integration contract](../../docs/zakura_pir_enhance.md) for routing,
migration, recovery, and privacy limitations.
