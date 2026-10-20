# Receiver PIR

This crate provides bounded network steps for private receiver lookups. With the `wallet` feature, `publication`, `lookup` and `witnesses` connect a receiver session to the SQLite wallet's recovery queue. The application owns networking and scheduling. No network future holds a database handle or lock.

## Wallet flow

1. Enable recovery for each account with `set_one_time_recovery_enabled`. Ordinary block sync continues independently.
2. Fetch the manifest and validate its network and coverage against a locally scanned block before opening `DirectoryClient`. Pass `publication` to `begin_one_time_recovery`.
3. Choose rolling filters for a short gap when their measured download cost is lower. Match the returned batch against `one_time_receivers`, then atomically commit its block identities and positive keys with `record_one_time_filters`. A negative match makes no receiver query. An unavailable or pruned range is never a negative.
4. For direct catch-up, call `begin_one_time_recovery` with `direct = true`. It queues unfinished receives, funded unresolved refunds and existing obligations, without querying every old completed key.
5. Read bounded work with `one_time_recovery`. Call `lookup` outside the wallet lock, then commit with `record_one_time_lookup`. Failures use `defer_one_time_lookup`, never an empty result. Reconnect when the session changes and wait for a compatible publication if it has not reached the work's target.
6. Fetch the session's common `witnesses` file once. Supply each requested path to `record_one_time_witness`. The wallet authenticates the note, checks local chain inclusion and spend coverage, and then records ordinary wallet ownership.

Seed recovery walks receive indexes until four consecutive complete empty histories at a captured frontier. A paid key resets the gap only after authentication and inclusion. New lookahead keys are queued through the already processed frontier in the same transaction. Receive issuance reuses the lowest unpaid eligible hole within the four-index confirmed window. Refund identities come from authenticated funding memos or locally funded operations, not an index sweep. Recovering funding before the account birthday requires lowering that birthday and rescanning ordinary history.

`check_one_time_history` starts or resumes an explicit history check. An optional exclusive receive bound crosses the normal four-empty stopping point. `cancel_one_time_history` pauses that manual work without losing its cursor or independent positive hints. Repeated payments to completed keys outside retained filters require this manual check.

## Boundaries

Turning recovery off invalidates held callbacks and exposes no discovery work. It preserves existing notes, spending and reorg repair. There are no one-time-key scan watches, compact-block caches, aggregate filters, provider seen gates or restore passes. Targeted authentication of a PIR-returned payment remains necessary.

PIR hides the receiver within a query, but request timing is visible. The service is trusted for complete indexing and honest negative answers. Wallet authentication and chain proofs prevent it from crediting an invented payment.

`tests/discovery.rs` uses the production snapshot builder and encrypted PIR evaluator against a real SQLite wallet. The service router and full application scheduling are tested in their owning repositories.
