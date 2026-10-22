# Transaction history query benchmark

`history_batch_benchmark` scans generated Orchard compact blocks into a migrated
wallet and calls `TransparentLedgerRead::transaction_history_details`. It checks
that one full request, requests of 256 transactions, and sampled single-entry
requests return identical details. Every transaction receives four outputs.
The ordinary test run uses 16 transactions. For the large fixture, run:

```sh
HISTORY_BENCH_TRANSACTIONS=5000 RUST_TEST_NOCAPTURE=1 \
  python3 scripts/dev.py test --config transparent -p zakura-client-sqlite history_batch_benchmark
```

Fixture generation and scanning happen before the timers. The timings include all
queries, classification and materialization in each history-details call, but do
not include the application's initial transaction listing, sorting or rendering.
The fixture is in memory and has no concurrent writer. There is no wall-clock
assertion in CI; the output and account-isolation assertions are deterministic.

## Measured comparison

On Apple Silicon, Rust 1.98.0, the optimized `test` profile and bundled SQLite
3.50.2, 5,000 transactions / 20,000 outputs produced these single-run measurements:

| Implementation | One 5,000-transaction call | Calls of 256 transactions |
| --- | ---: | ---: |
| Base `87fa67b7346ec8a5eae47eec91e73b54e88fe20c` | 87.085 s | 85.624 s |
| Batched outputs only | 29.082 s | 29.657 s |
| Batched outputs and received/spent amounts | 0.806 s | 1.469 s |

The same test and generated fixture were used for all three runs. The intermediate
result identifies why batching only `v_tx_outputs` is insufficient: the amount
query also joins grouped output views once per transaction. Both reads now group
results by transaction inside the caller's existing read snapshot. Request order,
duplicates, unknown transactions and account scoping are unchanged.

This is a receive-heavy scaling benchmark, not a claim about every wallet or total
app sync time. Outgoing transactions and private recovery can require additional
per-transaction queries. The regular history tests cover those classification and
completeness rules; the two-account compact-scan regression additionally covers
spends of an earlier transaction's output and a transfer between accounts.
