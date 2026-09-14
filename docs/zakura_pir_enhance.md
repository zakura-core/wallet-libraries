# Enhance PIR wallet integration

Enhance PIR lets a wallet retrieve missing Ironwood memos, recover outgoing
recipients, amounts, and memos, and populate transaction fee and expiry metadata
without sending the selected transaction ID to the PIR service. It operates on
transactions provisionally identified as Ironwood-only. Transactions known to
contain transparent, Sapling, or Orchard activity use ordinary lightwalletd (LWD)
enhancement.

PIR hides which record the wallet requests within a query domain. It does not
hide service contact, timing, query volume, or coarse shard routing.
Transaction-shape flags, fees, and expiry heights are trusted service metadata;
note decryption does not authenticate those fields.

## Architecture

Compact scanning records received notes and identifies transactions eligible for
private enhancement. Wallet storage maintains their routing and durable work for
incoming memos, outgoing recovery, transaction metadata, and outgoing discovery.
The application reads this work, fetches records through the PIR client or compact
blocks through its normal download path, and passes responses back to the wallet.

The PIR client queries records by Ironwood commitment-tree position within an
immutable snapshot generation. Before connecting, the application checks that
generation against locally scanned chain state and its own resource limits.
Each wallet request captures a position, transaction ID, and action index before
network I/O. Only the position selects the PIR item; the transaction and action
identities remain local.

The backend validates responses against scanned wallet data. Incoming decryption
must reproduce the scanned V3 note. Outgoing records must match the scanned
ephemeral key and compact ciphertext prefix; outgoing plaintext is accepted only
if exactly one funding account's outgoing viewing key (OVK) recovers it. SQLite
keeps validation, identity rechecks, and all resulting writes in one transaction.
A response from before a reorg cannot modify a new occupant of the same tree
position.

### Routing and completion

Routing applies to the entire transaction:

| Stored state | Ordinary enhancement in private mode | Private work |
| --- | --- | --- |
| No row | Available | None |
| `PrivateCandidate` | Withheld | Incoming, outgoing, metadata, and discovery obligations |
| `LwdRequired` | Available | Cleared for the entire transaction |

Eligibility is provisional. The compact source must include all shielded pools;
a stream filtered to Ironwood cannot establish it safely. Explicit transparent
inputs or outputs, Sapling spends or outputs, or Orchard actions exclude a
transaction. Empty compact `vin` and `vout` fields do not prove transparent
absence.

For an otherwise eligible transaction, the wallet consults the PIR record's
transparent-presence flags after binding the record to pending wallet state.
Either flag being set marks the transaction `LwdRequired`, clears its private
work, and preserves its ordinary enhancement request. For example, a shielding
transaction whose compact representation omitted transparent inputs initially
looks eligible; the record's input flag then routes it to LWD.

This LWD decision is sticky across rescans and reorgs. It does not erase previously
recovered memos or sent outputs. Invalid or stale responses and transport errors
leave routing unchanged and never cause public fallback.

Private completion requires every incoming, outgoing, metadata, and discovery
obligation to finish, including suspended work. Storage then retires ordinary
enhancement intent while preserving transaction-status intent. There is no
separate completed routing state, and later funding discovery can reopen work.

### Trust and privacy limits

Action validation authenticates note data, not the service's transaction-shape
flags. A malicious service can force a transaction-ID fallback with a false
positive or suppress needed transparent enhancement with a false negative.
Schema 7 does not prove transaction shape against a malicious server.

Fees and expiry heights are also trusted metadata. After action binding, storage
fills unknown values atomically with action work; conflicting known values reject
the response. A zero fee is a known value, and expiry zero means expiry is
disabled. Responses that require transparent fallback do not populate fee or
expiry metadata. Full-transaction storage remains authoritative.

The integration adds no cover traffic. Existing transaction-status requests and
transparent queries remain unchanged, and mixed-transaction fallback exposes
the transaction ID to LWD. Fetching a particular compact block for rediscovery
also reveals interest in its height. These are limits on enhancement privacy;
this integration does not provide end-to-end wallet network privacy.

## Wallet integration

### 1. Enable the feature and configure each database handle

Compile with the `zakura-pir-enhance` Cargo feature whether the runtime preference
is on or off. The facade feature enables the backend and SQLite APIs. Add the
`zakura-pir-enhance` client crate for network queries; its default
`https-client` feature provides the Reqwest client. Custom transports can use
`QuerySession`.

Both `WalletDb::for_path` and `WalletDb::from_connection` retain their
four-argument constructors. Before requesting work, configure each handle with
`with_enhancement_mode` or `set_enhancement_mode`, choosing
`EnhancementMode::Standard` or `EnhancementMode::PrivateIronwood`.
Without configuration, `transaction_data_requests()` and `enhance_pir_work()`
return `SqliteClientError::EnhancementModeNotConfigured`, even for an empty
wallet.

Load the application's saved preference on every reopen; the library does not
persist another copy. Transaction wrappers inherit the handle's configuration.
When the preference changes, update the mode and cancel or discard old in-memory
network batches before scheduling more work. An already dispatched LWD request
cannot be recalled.

Continue obtaining ordinary work through `transaction_data_requests()`. Storage
withholds protected enhancement requests in private mode while leaving other
ordinary work available. Disabling private mode exposes unfinished ordinary
enhancement requests, including transactions with suspended private work.

### 2. Accept a snapshot generation before allocating PIR setup

With the HTTPS client:

1. Call `EnhancePirClient::fetch_session(base_url)` to obtain a
   `PendingEnhancePirClient`, then inspect `generation()`.
2. Build an `EnhancePirSnapshotAnchor` from its anchor height, block hash, and
   Ironwood tree size. Call `db.enhance_pir_snapshot_status(anchor)` through
   `EnhancePirRead`. Proceed only on `Accepted`: the anchor must be within the
   fully scanned frontier and match local hash and tree-size metadata at that
   exact height, which need not be the current tip. `NotYetScanned` requires
   further scanning; `Mismatch` requires resolving the disagreement.
3. Construct `GenerationAcceptance` with the wallet's network, Enhance PIR
   activation height, an `AcceptedAnchor` for the checked generation, and
   `ClientResourceLimits`. Choose the maximum logical row count for the
   least-capable supported device; never take this limit from server metadata.
4. Call `pending.connect(&acceptance).await`. The client checks schema,
   protocol, network, activation height, pinned setup seed, canonical row
   geometry, resource limits, and public parameters before using the session.
   Public-parameter decoding and deterministic setup are deferred until
   acceptance.

Custom transports use the same `GenerationAcceptance` with `QuerySession`.
The client uses the atomic `/v1/enhance/init` payload and randomized queries to
`/v1/enhance/query`, binding requests and responses to one generation. A position
outside that generation's coverage must wait for a suitable wallet-accepted
generation; it is not a reason to fall back publicly. See the
[client implementation](../zakura/pir-enhance/src/client.rs) for acceptance and
transport APIs.

### 3. Process durable work

Read `EnhancePirRead::enhance_pir_work()` after scanning and on reopening.
Enumeration is available in either configured mode; schedule private network
work when the application enables private mode.

The following Rust-style pseudocode shows one scheduling pass.
`compact_blocks` and `scheduler` represent application-owned cache, transport,
result handling, and retry policy, not library APIs. Imports, error handling,
and cancellation checks are omitted.

```rust
for work in db.enhance_pir_work()? {
    match work {
        EnhancePirWork::Query(request) => {
            let record = pir.query_position(u64::from(request.position())).await?;
            let result = db.apply_ironwood_enhance_record(request, &record)?;
            scheduler.handle_query_result(request, result);
        }
        EnhancePirWork::Rediscover(request) => {
            let block = compact_blocks.get(request.height, request.block_hash).await?;
            let result = db.rebuild_ironwood_enhancement(request, &block)?;
            scheduler.handle_discovery_result(request, result);
        }
        EnhancePirWork::Suspended(reason) => {
            scheduler.report_incomplete(reason);
        }
    }
}
```

Keep the original `Query` request across network I/O. Never reconstruct its
identity from current wallet state when a response arrives, and never send the
local request identity to the service. The client and backend share
`EnhanceRecord` from `zakura-pir-enhance-types`; pass it directly to
`EnhancePirWrite::apply_ironwood_enhance_record` without conversion.

`Rediscover` requests are grouped by height and locally scanned block hash.
Obtain the block from the same trusted compact source used for scanning,
preferably from the cache or normal batched downloads. Matching the claimed
block hash checks branch identity; it does not cryptographically authenticate
the compact contents. The library performs no network I/O or automatic retries
for rediscovery.

Reread work after applying results: reconstruction can create queries or route
mixed transactions to LWD. Schedule another pass according to progress and retry
policy, rather than immediately repeating unchanged or invalid work.

### 4. Handle results and suspensions

| Result or work item | Application behavior |
| --- | --- |
| Query `Stored` | Reread work; this action's result does not establish transaction-wide completion. |
| `AlreadyResolved` | Discard this stale or redundant request; other active or suspended work may remain. |
| Query `LwdRequired` | Let the ordinary request path enhance the transaction through LWD. |
| Query `NotRecoverable` / `Suspended(OutgoingNotRecoverable(...))` | Report incomplete outgoing recovery without automatic retries. New funding or a rescan may reactivate it. |
| `Rejected` or transport error | Keep pending work and routing intact. Retry only under application policy; never fall back publicly because of the error. |
| Rediscovery `Rebuilt(...)` | Reread work to obtain reconstructed queries or ordinary enhancement requests. |
| Rediscovery `Incomplete { rebuilt, unresolved }` | Preserve successful progress and handle unresolved `TransactionMissing` or `ContextMismatch` jobs individually; they remain retryable. |
| Discovery suspension: `NoFundingAccounts` | Wait for funding associations to be restored; downloading the block again does not resolve the missing accounts. |
| Discovery suspension: `AnchorUnavailable` | Scan or retain the spending block and its predecessor's tree-size metadata before reconstruction. |

A transaction can have several independent obligations. Suspensions appear
alongside active work, so an empty set of active queries does not establish
completion. Invalid block-wide identity or geometry rejects the whole
rediscovery call without mutation; transaction-local failures can coexist with
successful jobs. Database errors roll back all writes in that call.

Outgoing recovery covers wallet-funded actions except same-account change,
which uses incoming decryption. Cross-account wallet payments need both sender
recovery and receiver decryption. Failure to recover outgoing plaintext can
mean a dummy action, `OvkPolicy::Discard`, or corrupt service data; the wallet
cannot distinguish them and retains the obligation as incomplete. Recovering
metadata does not complete suspended outgoing work.

### 5. Support restores and wallet lifecycle changes

A recent-first restore can scan a send before its funding note. When scanning
later links funding to that send, storage repairs change classification, queues
outgoing rediscovery, and restores ordinary enhancement intent if needed. The
request remains withheld in private mode. Reconstruction uses current durable
funding associations, including spent notes, and requires tree-size metadata
for the spending block and its predecessor.

Pending and suspended work survives reopening. Explicit rescans can requeue
suspended outgoing candidates; additional funding can reactivate recovery and
discovery. Rewinds invalidate position bindings before positions are reused.
Full-transaction storage clears redundant private work.

Account deletion removes transactions exclusive to that account. For surviving
transactions, jobs that lose all funding associations remain suspended and
protected; losing a key does not prove recovery complete. Linking funding again
reactivates discovery. Reimporting a deleted funding key rewinds the wallet, and
rescanning rebuilds the necessary work. Account-deletion cleanup also runs in
PIR-disabled builds; the
[feature-transition check](../scripts/verify-pir-feature-transition.sh) exercises
that path and a subsequent PIR-enabled reopen.

### 6. Use recovered history data and migrate existing wallets

Recovered fees and expiry heights populate `transactions.fee` and
`transactions.expiry_height` for the existing history API. PIR does not retrieve
raw transactions: `get_transaction()` returns `None` when
`transactions.raw` is absent. Raw export and parsed inspection remain
unavailable for those transactions.

Run the normal wallet migrations. The
[`ironwood_enhance` migration](../librustzcash/zcash_client_sqlite/src/wallet/init/migrations/ironwood_enhance.rs)
creates the feature tables empty, including in PIR-disabled builds. Existing
ordinary history continues through LWD until explicitly rescanned; enabling the
setting alone does not privatize it. Rescanning an eligible mined transaction can
queue missing fee and expiry metadata while retaining an already recovered memo.
No application database reset is required.

### Compatibility and extension points

Clients and servers must use schema 7 and protocol `ironwood-enhance-pir-v2`.
Moving to schema 7 requires the wallet migration, a compatible Enhance PIR server
update, and a canonical snapshot rebuild. This integration introduces no new
compact-block format. Transparent PIR, spentness discovery, and UTXO gating
remain outside its scope.

Custom scanners attach `IronwoodEnhancementPlan::Ineligible` or
`Eligible { outgoing }` through `with_ironwood_enhancement_plan`. An empty
outgoing list expresses eligibility, not completion of durable work. Consult the
[backend application API](../librustzcash/zcash_client_backend/src/data_api/enhance_pir.rs)
for work and result types.

Custom storage implementations must keep context reads, validation, identity and
metadata comparisons, and all note, routing, and queue changes in one consistent
transaction. Follow the
[transaction-scoped storage contract](../librustzcash/zcash_client_backend/src/data_api/enhance_pir/storage.rs);
applications using SQLite call `EnhancePirWrite` instead.

The shared
[record definitions](../zakura/pir-enhance-types/src/lib.rs) specify wire layout,
flags, and metadata validation. Custom record producers use
`EnhanceRecord::from_parts(EnhanceRecordParts { ... })`; byte decoding uses
fallible `EnhanceRecord::from_bytes`. Decoding checks encoding, while the wallet
validates the record against pending state before applying it.
