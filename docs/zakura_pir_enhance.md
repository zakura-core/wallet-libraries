# Ironwood enhancement through PIR v4

`zakura-pir-enhance` implements wallet-pir architecture_2 v4 for **mainnet only**. The wire schema is 10 and revision is `ironwood-enhance-pir-v4`. This wire schema is independent of SQLite's schema version; this update needs no database reset or migration.

The service publishes a `Manifest` at `GET /v1/enhance/init`. It contains the chain anchor, canonical coverage and loan geometry, shard session references, and unit identities. Records remain 737 bytes; 33 occupy each 24,321-byte row. Shard query domains are 4,096, 8,192, 16,384, or 32,768 rows. Mutable units are 2K, 4K, or 8K rows. The client validates geometry, coverage, and loan return rules before using the manifest. It uses P16Q46 parameters with ipir-sp revision `225972648cc2982abfac66ba5b7a3930b223051a`. The reference server revision is wallet-pir `436dcc7efda3e09a6734342fd4f55e07bf1d9d95` (same relevant Rust sources as deployed candidate `9718a6dcf9801385f69f31bb71f02efd261914f0`).

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
let client = pending.accept(&accepted)?;
```

The application chooses limits for its least capable device. `max_shard_rows` bounds each shard setup independently of total chain records; `max_cached_shards` bounds retained setups. Sessions load lazily from `GET /v1/enhance/sessions/{generation}/{shard_id}`. Before setup, the client checks generation, shard, P16Q46 parameters, exact public material length, SHA-256 digest, and the manifest reference. The public setup seed uses the server's v4 mainnet domain and shard ID. Query and response headers contain `EPQ4`, generation and shard ID as little-endian u64 values, and the first eight bytes of SHA-256 of decoded public material. Responses require the exact binding and length before decoding.

## Batches and expiry

`query_batch(&transport, positions)` bounds input count, coalesces duplicate positions, and sends one encrypted request per shard and local row under an immutable accepted manifest. Covered results arrive in ascending row and position order, then uncovered positions. A row error is reported for each position in that row; earlier yielded records may already have been applied. Dropping the stream prevents remaining dispatch. No plaintext position, row, slot, txid, or action index appears in requests or URLs. Shard, generation, timing, and request count are public.

On HTTP 410, discard the expired client, stop its batch, fetch a fresh manifest, and repeat wallet acceptance before any new query. Reschedule unfinished durable Query work from the wallet database; do not relabel old responses with the new generation. For 429/503, use bounded application retries and preserve the work. Transport or manifest validation errors must not trigger ordinary LWD fallback. Retained server sessions permit an older accepted generation to continue until expiry.

## Wallet state and Vizor migration

Every SQLite handle must be configured in Standard or PrivateIronwood mode. The backend keeps durable Query, Rediscover, and Suspended work, original `(position, txid, action index)` response identities, and atomic note, metadata, routing, and queue writes. Reorgs reject stale identities. Incoming decryption, outgoing recovery, transaction-wide routing, and sticky validated transparent fallback remain unchanged. Decoded note data is authenticated by wallet keys; service-supplied shape, fee, and expiry metadata remain assertions.

Vizor PR #601 must fetch a pending v4 manifest, pass it through synchronous wallet acceptance, choose per-shard setup and cache limits, use lazy shard sessions, and handle 410 by stopping the batch and repeating wallet acceptance before rescheduling unfinished durable work. It must schedule bounded 429/503 retries and retain original local request identities. Full Vizor application integration requires separate verification in that PR.
