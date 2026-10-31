# Configured PIR HTTP endpoints

The optional `zakura-pir-protocol::endpoint` module validates the service addresses configured for PIR clients
and appends their routes without a browser URL parser or Unicode hostname tables.
It uses the `http` crate for URI parsing and performs no network access.

An endpoint must have an explicit `http://` or `https://` scheme, an ASCII DNS
hostname (including an already encoded `xn--` punycode name), dotted-decimal IPv4
or bracketed IPv6. Optional ports must fit a `u16`. Paths use ASCII URI syntax;
percent-encode Unicode characters and spaces before passing them to the client.
Credentials, queries, fragments, backslashes, embedded whitespace, malformed
percent escapes and browser-style shortened, octal or hexadecimal IPv4 addresses
are rejected. Surrounding ASCII whitespace is accepted.

Scheme and hostname case, IP literals, default ports and dot path segments are
normalized. Encoded separators such as `%2F` remain encoded. Joining a route
appends it to the base path; a route cannot replace the authority or add a query
or fragment. The caller chooses its transport policy: Enhance requires HTTPS
except for literal loopback IPs and the exact name `localhost`; Status requires
HTTPS; transparent recovery permits HTTP and HTTPS as before.

## One server base, one namespace per product

A client is configured with one PIR server base URL. Every product request is
built by `Endpoint::product_url`, which appends the product's canonical,
versioned prefix and then the operation:

| Product | Namespace | Operations (examples) |
| --- | --- | --- |
| Enhance | `/enhance/v1` | `init`, `session/{id}`, `query` |
| Status | `/status/v1` | `init`, `session/{id}`, `query` |
| Transparent | `/transparent/v1` | `shards/init`, `shards/{id}/revisions/{rev}/…`, `filters/shards…`, `filters/info`, `txid/…` |
| Receiver | `/receiver/v1` | `inventory`, `inventory/{inventory}/{chunk}`, `block-filters/…`, `shard-filters/{digest}`, `choice/{digest}`, `public/{id}`, `query` |

For example, the base `https://wallet-pir.valargroup.dev` serves Enhance at
`https://wallet-pir.valargroup.dev/enhance/v1/init`; a base path such as
`https://edge.example/pir` is kept, giving `https://edge.example/pir/enhance/v1/init`.
The namespace version is independent of the protocol versions inside payloads.
An operation cannot climb out of its namespace with dot segments.

Clients request only canonical routes: they never probe legacy paths, fall back
to them, or switch to another server. Servers keep the previously deployed
paths (`/v1/enhance/…`, `/v1/status/…`, Transparent `/v1/filters/…` and
`/v2/…`, `/v1/receiver/…`) as aliases for already released clients.

The previous URL parser is a development-only oracle for normalization tests.
It is absent from this crate's production dependencies.
