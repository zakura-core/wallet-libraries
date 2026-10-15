# Server chain adapters

`zakura-server-chain` reads Zakura node data for the PIR services in wallet-pir and
interprets it, returning plain values (bytes, heights, amounts, positions) that the
services map onto their own records. It is the only place those services touch
node or Zakura Common types.

- `rpc`: the node JSON-RPC client. `NodeClient::new` rereads a cookie file on every
  request and bounds every response; `NodeClient::from_cookie_file` reads it once.
  Nodes rank by tip on a checked network.
- `hash`: conversions between the node's display order and protocol order.
- `receiver`: Ironwood blocks checked against their headers and the node's tree
  sizes, every Action's note position (coinbase included), the payments
  recoverable with the zero outgoing viewing key, and Ironwood roots.
- `enhance`: each Ironwood Action's Enhance fields with its transaction's exact fee,
  resolving spent outputs from the same block, a bounded cache, then batched reads;
  an unresolved output fails the block.
- `status`: canonical blocks' transaction IDs and the mempool's.
- `testing` (feature): synthetic transactions, block envelopes and a JSON-RPC node
  double built with the node's own encoders, for service tests.

This crate is server-only. It lives in the separate `server/` workspace with its
own lockfile, so no wallet build resolves the node's packages, and it may use the
wallet-owned crates under `zakura/` by path, never the reverse. Its dependency
graph, including test support and inactive optional or platform dependencies, must
contain no package owned or released by wallet-pir. Service-facing values contain
only library-owned records, errors, bytes, heights and network choices; node and
Common types remain implementation details.

## Validation

From the repository root:

```sh
python3 scripts/dev.py doctor --config server
python3 scripts/dev.py verify --only server-graph
python3 scripts/dev.py test --config server
python3 scripts/dev.py lint --config server
```

The graph check also builds fresh wallet-component and server consumers with their
own lockfiles. It proves this adapter boundary; the unrelated older wallet PIR
adapters are outside this change and still need their separate ownership migration.
