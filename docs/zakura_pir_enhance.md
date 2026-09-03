# Zakura Ironwood Enhance PIR integration

`zakura-pir-enhance` implements the wallet-facing client for the
`ironwood-enhance-pir-v1` service. It retrieves encrypted fields omitted from
compact blocks by commitment-tree position, without sending a transaction ID
or action position to the service.

The schema-v5 record is 724 bytes: a 32-byte ephemeral key, 580-byte encrypted
note ciphertext, 32-byte net value commitment, and 80-byte outgoing ciphertext.
Nine records form a 6,516-byte row. The client pins the setup seed, validates
the generation and public-parameter digest, and binds requests and responses to
one immutable generation.

Applications fetch the atomic `/v1/enhance/session` payload and submit
generation-pinned randomized queries to `/v1/enhance/query`. A shard
descriptor's `worker` is an opaque
logical group identifier; replication and failover are server concerns.

## Wallet storage

Compact scanning queues two kinds of work by Ironwood tree position:

- received notes whose full memo ciphertext is missing;
- actions in transactions that spend wallet funds and may be recoverable with
  a funding account's outgoing viewing key.

A record is accepted only after normal note decryption or outgoing recovery
authenticates it. Incoming completion must reproduce the scanned note.
Outgoing completion records the recovered recipient, value, and memo.
Malformed or unrelated records leave the queue unchanged.

Queued transactions are marked as protected. A client that enables private
Ironwood recovery must not fall back to a transaction-ID enhancement request
for a protected transaction. Non-Ironwood recovery can continue normally.

PIR hides the selected row and transaction identifier, but not contact with the
service, timing, or query volume. This crate does not implement cover traffic.
