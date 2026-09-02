# zakura-pir-memo

An unpublished, transport-neutral iPIR+SP client for privately retrieving
Ironwood memo ciphertexts by note-commitment-tree position.

The default `https-client` feature adds the production HTTPS transport. The
core query preparation and response decoding APIs can instead be used with an
application-owned transport. Server metadata is accepted only for full
Ironwood-pool coverage beginning at position zero.

