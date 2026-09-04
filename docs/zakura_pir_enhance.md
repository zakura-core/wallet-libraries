# Zakura Ironwood Enhance PIR integration

`zakura-pir-enhance` implements the wallet-facing client for the
`ironwood-enhance-pir-v1` service. It retrieves encrypted fields omitted from
compact blocks by commitment-tree position, without sending a transaction ID
or action position to the service.

The schema-v6 record is 725 bytes: a 32-byte ephemeral key, 580-byte encrypted
note ciphertext, 32-byte net value commitment, 80-byte outgoing ciphertext,
and one byte describing transaction-wide transparent inputs and outputs.
Nine records form a 6,525-byte row. The client pins the setup seed, validates
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

- `anchor_height` and `anchor_block_hash` must identify the wallet's exact
  fully-scanned tip;
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
for a protected transaction. Transactions containing Ironwood and no other
shielded pool are provisionally protected during compact scanning. Because
compact sources may omit vin/vout, the Enhance flag byte releases that
protection when the transaction has transparent outputs. Transparent inputs do
not release protection: spends of wallet-owned transparent outputs are resolved
independently by the outpoint-keyed transparent-spend PIR. Transactions that
mix Ironwood with another shielded pool remain on standard transaction-ID
enhancement. Transaction-ID enhancement of other, unprotected transactions and
transaction status requests also continue normally.

Applications that expose PIR as an advanced runtime setting must compile with
the `zakura-pir-enhance` Cargo feature in both setting states. Set the wallet's
runtime enhancement mode to `PrivateIronwood` while PIR is enabled and back to
`Standard` when it is disabled. Protection markers and pending work are
maintained in either mode. A partially processed transaction therefore returns
to the standard path when PIR is disabled, while a protected transaction whose
every PIR position has completed retires its dormant transaction-ID enhancement
request.

Provisional protection is established only by scanning; the PIR record then
supplies the transparent portion of transaction shape that compact scanning
cannot reliably observe. An authenticated transparent-input flag leaves the
transaction protected; an authenticated transparent-output flag releases it.
A transaction that is not protected is not Enhance PIR's to complete, and its
transaction-ID request is never retired — including for notes an upgrading
wallet had already scanned before this protocol existed, which are queued for
memo retrieval but stay on the standard path until a rescan.

PIR hides the selected row and transaction identifier, but not contact with the
service, timing, or query volume. This crate does not implement cover traffic.

## Transparent spend lookup

`zakura-pir-transparent-spend` resolves `GetSpendingTx(OutPoint)` without
revealing the outpoint. It always queries both the cold table (genesis through
`tip - 100000`) and the warm table (the trailing 100,000 blocks through tip),
then exact-matches locally. The session carries the same tip height, block hash,
and Ironwood tree size used by Enhance; pass `snapshot_anchor(session)` to the
wallet snapshot check and proceed only when it returns `Accepted`.

`apply_lookup` records either the spending transaction metadata or an unspent
observation through tip. In private mode, transparent outputs are not eligible
for selection until that observation height equals the fully-scanned tip. PIR
or generation failures are fail-closed and must not fall back to a direct
lightwalletd outpoint request. Mempool spends are outside this index.


## Wallet Cases

A. Ironwood-only receive

Today: enhance tx by id

Changing to: Enhance PIR by output note commitment tree index.

B. Wallet-funded Ironwood send

Changing to: One Enhance PIR query per non-change action by output note commitment tree index.

Result: Recover sent outputs using candidate OVKs

C. Mixed transparent + Ironwood

Today: enhance tx by id. Find Transparent outputs and match against wallet's address.

Possible solution: PIR by tx ID for transparent outputs

D. Transparent-only receive

Today: `derived addresses` → `GetAddressUtxos`
- The server returns currently unspent outputs. This discovers funds, but reveals the queried transparent addresses to the server.

E. Spend of a known transparent UTXO

Today: known outpoint → spender lookup
- Legacy mode queries transactions involving the address.

Possible solution: The new transparent-spend PIR instead queries the outpoint privately and records spent or unspent status through tip.

## Architecture Possibilities

### Shielded Only Case

For Ironwood-only transactions and mixed Ironwood + Transparent, use Ironwood Enhance PIR.

For mixed Ironwood + Other Pools, fallback to today's LWD enhacement. The case should
be rare enough for it to not matter.

### Handling Transparent

1. **vin/vout in Compact Block**

vin/vout in Compact Block is the approach upstream is pursuing.

In this approach, the compact block data returns all data necessary for
transparent management in the wallet.

There is no need to do external public queries anymore because we can deconstruct
and attribute wallet's full transparent ledger during sync.

The downside is that every block pays additional transparent sync bandwidth.

If someone does many transparent sends or spams, every wallet pays bandwidth overhead
every block.

2. **Transparent-PIR**

See [Transparent PIR: activity filters and paged history](zakura_transparent_pir_design.md)
for the proposed complete-history design, privacy tradeoffs, and evaluation plan.

For Transparent PIR, one PIR table is insufficient, and every case must be handled separately.

First, facts:

At height 3,471,419

- Spent: 1,375,697 — 4.68%
- Unspent: 28,033,883 — 95.32%
- Total transparent outputs created: 29,409,580

Around same time, there were 844,457 transparent addresses holding positive balance.

First, it helps to answer: does my wallet own any transparent?

Instead of wasting bandwidth or server compute for having every wallet query the
full PIR database, we could have a light Bloom-filter like PIR table.

Wallet wakes up and efficiently asks privately: "do I own any transparent at current tip?". If the answer is no, I do not need to do any further transparent PIR work.



## Appendix

### Definitions

- **vin**:

- **vout**:
