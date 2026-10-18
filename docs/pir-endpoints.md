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
except for literal loopback IPs and the exact name `localhost`; transparent
recovery permits HTTP and HTTPS as before.

The previous URL parser is a development-only oracle for normalization tests.
It is absent from this crate's production dependencies.
