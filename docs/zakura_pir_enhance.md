# Ironwood enhancement through PIR v7

`zakura-pir-enhance` implements the wallet side of suffix-only Ironwood enhancement for **mainnet only**. The wire schema is **11** and revision is `ironwood-enhance-pir-v7`. A matching server is required; server changes and deployment are outside this repository change.

Records are **653 bytes**; 33 occupy each **21,549-byte row**:

| Field | Offset | Bytes |
|---|---:|---:|
| Encrypted ciphertext suffix | 0 | 528 |
| Net value commitment | 528 | 32 |
| Outgoing ciphertext | 560 | 80 |
| Flags | 640 | 1 |
| Expiry height | 641 | 4 |
| Fee | 645 | 8 |

The wallet persists the ephemeral key and 52-byte ciphertext prefix from compact scanning on `ironwood_received_notes`, and stitches the prefix and returned suffix before decryption. A forward SQLite migration adds nullable compact encryption fields to existing rc5 wallets while preserving notes, spends, and locks. Older notes acquire this context when their compact blocks are rescanned; migration alone does not create private enhancement work. Notes inserted without compact context may omit both fields; queued compact-scanned incoming work requires both.

The service publishes a `Manifest` at `GET /v1/enhance/init`. It contains the chain anchor, fixed query domains, canonical routing, recovery epochs, and immutable session references. Shard query domains are 4,096, 8,192, 16,384, or 32,768 rows. The client validates domain geometry, coverage, routing, and session identities before use. It uses P16Q48 parameters with the published `ipir-sp =0.1.0-rc.3` crate. Earlier v5/q46 and v6/q48 manifests and sessions are rejected; schema-11 records and the deterministic public setup domain are unchanged.

## Wallet acceptance and resources

A manifest must be checked against locally scanned wallet state before allocating expanded PIR setup. Check network, activation height, anchor block hash, and `coverage.records` as the Ironwood tree size. The manifest's displayed hash is reversed when used as the wallet's internal `BlockHash`. Only an accepted pending client can become usable.

```rust,ignore
use zakura_pir_enhance::{ClientResourceLimits, wallet::{acceptance, Acceptance}};
use zakura_pir_enhance::transport::PendingClient;

let pending = PendingClient::fetch(&transport, base_url).await?;
let limits = ClientResourceLimits::with_cache(32_768, 2);
let accepted = match acceptance(db, pending.manifest(), consensus_params, limits)? {
    Ok(Acceptance::Accepted(accepted)) => accepted,
    Ok(Acceptance::WaitingForScanning) => return Ok(()),
    Ok(Acceptance::Mismatch) => return Err("anchor mismatch".into()),
    Err(error) => return Err(error.into()),
};
let mut client = pending.accept(&accepted)?;
```

The application chooses limits for its least capable device. `max_shard_rows` bounds each shard setup independently of total chain records; `max_cached_shards` bounds retained setups. Query methods take `&mut self`, allowing one active batch per client. An idle setup is evicted before its replacement is built. Sessions load lazily from `GET /v1/enhance/session/{session_id}`. Before setup, the client checks P16Q48 parameters, exact public material length, digest, and immutable session identity against the accepted manifest. The public setup seed retains the server's v4 mainnet domain and shard ID. The 116-byte `EPQ7` query and response header binds routing revision, domain, packing material, recovery epoch, session ID, a fresh request ID, and the accepted anchor. Responses require the exact binding and length before decoding.

## Batches and expiry

`query_batch(&transport, positions)` bounds input count, coalesces duplicate positions, and sends one encrypted request per shard and local row under an immutable accepted manifest. Covered results arrive in ascending row and position order, then uncovered positions. A row error is reported for each position in that row; earlier yielded records may already have been applied. Dropping the stream prevents remaining dispatch. No plaintext position, row, slot, txid, or action index appears in requests or URLs. Shard, generation, timing, and request count are public.

`query_row_requests` accepts a nonempty bounded slice of captured requests with one txid and one global row. Mixed txids, cross-row inputs, and uncovered positions fail before network I/O. It returns only requested slots in input order, preserving duplicate identities while retrieving each position once. A valid call issues one query POST, with session setup as needed; a failed query returns no partial row result.

```rust,ignore
use zakura_pir_enhance::wallet::PreparedWork;
use zcash_client_backend::data_api::enhance_pir::EnhancePirBatchResult;

let prepared = PreparedWork::new(db.enhance_pir_work()?);
// Schedule prepared.rediscover and retain suspended obligations as before.
for ((_txid, _row), requests) in prepared.batches_by_tx_and_row() {
    let row = client.query_row_requests(&transport, &requests).await?;
    match db.apply_ironwood_enhance_records(&row.slots)? {
        EnhancePirBatchResult::Committed(results) => handle_results(results),
        EnhancePirBatchResult::Rejected { index, reason } => handle_rejection(index, reason),
    }
}
```

Batch application requires one txid but permits multiple rows. All live actions are validated before writes in one SQL transaction. Rejected records, conflicting flags/fee/expiry, conflicting duplicate records, and database errors roll back the entire batch. Stale identities are no-ops and cannot contribute metadata or routing. Identical duplicate requests share an outcome. Positive transparent routing is applied once and remains sticky. The single-record API uses the same transaction boundary.

Transactions can span arbitrarily many rows, and separate transaction groups can query the same row repeatedly. The example's atomicity is per row batch, not across all rows of a transaction. Applications wanting cross-transaction row coalescing can retain `query_batch`, then group decoded results for wallet application. Batching does not hide observable query volume, shard selection, or timing.

On HTTP 409 or 410, discard the expired client, stop its batch, fetch a fresh manifest, and repeat wallet acceptance before any new query. Reschedule unfinished durable Query work from the wallet database; do not relabel old responses with the new generation. For 429/503, use bounded application retries and preserve the work. Transport or manifest validation errors must not trigger ordinary LWD fallback. Refresh routing at sync start and before new work whenever `refresh_due()` is true (30 seconds). In-flight operations keep their accepted view until completion or server rejection. Independently accept each refreshed anchor before calling `accept_routing`; unchanged immutable sessions can be reused, but a deep recovery epoch change invalidates them.

## Wallet state and application integration

Every SQLite handle must be configured in Standard or PrivateIronwood mode. The backend keeps durable Query, Rediscover, and Suspended work, original `(position, txid, action index)` response identities, and atomic note, metadata, routing, and queue writes. Reorgs reject stale identities. Incoming decryption must reproduce the scanned note. Successful outgoing recovery authenticates the recovered note data. Without successful decryption, the wallet explicitly trusts the server's position-to-record association: send-only shape and metadata can affect routing even when outgoing recovery fails. A dishonest server can therefore influence send-only metadata and trigger public fallback through transparent flags. Captured request identity is always checked first. Service-supplied shape, fee, and expiry are not authenticated by note decryption. Failed incoming authentication is rejected; unsuccessful outgoing recovery is suspended as `NotRecoverable`.

For privately routed transactions, `v_transactions.expiry_height` displays the service's expiry assertion when the wallet has no authoritative expiry. `transactions.expiry_height` remains unchanged until raw transaction data supplies it; spendability and `expired_unmined` continue to use that authoritative field. Conflicting expiry assertions from different PIR records are rejected without completing the pending work.

Application integration must configure each wallet handle, accept manifests against locally scanned state, choose per-shard setup and cache limits, and reschedule durable work after routing refresh or expiry. Preserve captured request identities and use bounded application retries for 429/503.

Optional `query_positions_with_cover` sends uniform rounds across every domain since a supplied birthday position, in randomized order. It returns no partial records and retries a whole round once on 429/503. Cover is off by default; timing, round count, the birthday window, and cross-interval intersection remain observable.
