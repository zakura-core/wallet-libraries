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

Applications fetch the atomic `/v1/enhance/init` payload and submit
generation-pinned randomized queries to `/v1/enhance/query`. A shard
descriptor's `worker` is an opaque
logical group identifier; replication and failover are server concerns.

## Generation acceptance

The session payload is untrusted. Before deriving PIR parameters or allocating
the deterministic query setup, an application must bind the advertised
generation to wallet-accepted chain state:

- `anchor_height` and `anchor_block_hash` must identify a block the wallet has
  accepted;
- `ironwood_tree_size` must match the wallet's tree size at that block;
- `used_rows` and `logical_rows` must be the canonical values derived from that
  tree size; and
- `logical_rows` must fit an application-selected local resource limit.

Use `EnhancePirClient::fetch_session` to obtain a
`PendingEnhancePirClient`, inspect its generation, and look up the matching
anchor in wallet storage. Pass that state and a locally configured
`ClientResourceLimits` to `PendingEnhancePirClient::connect`. Custom transports
must pass the same `GenerationAcceptance` to `QuerySession::from_session` or
`QuerySession::new`.

The row limit is a setup-memory budget, not an HTTP limit. A small session JSON
can advertise a very large logical database and otherwise cause a large
deterministic setup allocation. Select `max_logical_rows` for the least-capable
supported device and never derive it from server fields.

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
for a protected transaction. Only compact transactions containing Ironwood and
no other represented pool are eligible for PIR protection. Mixed-pool
transactions remain on standard transaction-ID enhancement. Transaction-ID
enhancement of other, unprotected transactions and transaction status requests
also continue normally.

Applications that expose PIR as an advanced runtime setting must compile with
the `zakura-pir-enhance` Cargo feature in both setting states. Set the wallet's
runtime enhancement mode to `PrivateIronwood` while PIR is enabled and back to
`Standard` when it is disabled. Protection markers and pending work are
maintained in either mode. A partially processed transaction therefore returns
to the standard path when PIR is disabled, while successful completion of every
PIR position retires its dormant transaction-ID enhancement request.

PIR hides the selected row and transaction identifier, but not contact with the
service, timing, or query volume. This crate does not implement cover traffic.
