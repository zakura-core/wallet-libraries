These DER fixtures are public test material for the loopback HTTPS tests.
`server.der` is an ECDSA P-256 certificate for `localhost`, signed by `ca.der`.
`server-key.der` is its unencrypted PKCS#8 test key. The CA signing key is not
retained. The certificates were generated with OpenSSL 4.1.0 on 2026-10-29 and
expire in 2126.

The test trusts the CA only in its success and wrong-hostname cases. The default
HTTP client must reject it before any private query is sent.
