# Public `GetStatus` protocol

`CompactTxStreamer.GetStatus` is a unary, txid-disclosing observation. It never
returns serialized transaction bytes. The request's 32-byte `txid` uses the
same byte order as `TxFilter.hash`; `minimumTipHeight` is the caller's known
chain height. A server must reject a malformed txid before lookup.

The server must evaluate each request after receiving it against a coherent
best-chain view. `liveComplete=true` asserts complete main-chain transaction
lookup through `observedTip` and a current mempool check. The tip includes a
32-byte block hash and must be at least `minimumTipHeight`. If the view changes
during lookup, indexing is incomplete, or either check cannot be made, the
server returns an error. It must not report `NotFound` or claim completeness.
No server implementation or deployment is supplied by the client package.

The response echoes the txid and sets exactly one tagged outcome. `Mined`
names a main-chain block height from 1 through the observation tip. `Mempool`
means present in the current mempool. `Forked` means known on a non-main-chain
branch, with no current main-chain or mempool observation. `NotFound` means no
main-chain, mempool, or known fork observation; it is not proof that the
transaction was never broadcast. The server's tip is an assertion by that
server, not a cryptographic proof of global freshness.

Clients must validate identity, tip hash and height, completeness, and the
tagged outcome before using the result. A bare gRPC `NotFound` is a transport
error, not the tagged `NotFound` observation. `Unimplemented` means the server
does not support this RPC; clients must not retry through `GetTransaction`.
An insufficient or untrusted view leaves the wallet's status request pending.
