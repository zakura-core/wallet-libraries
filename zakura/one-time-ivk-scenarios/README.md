# Private receiver scenarios

Run `python3 scripts/dev.py test --config one-time-ivk-scenarios`. These standard Rust integration tests use separate persistent wallet databases, the production directory and companion tables, witness payloads, shard inventory and GCS codecs (history sealed into a shard every 32 blocks, with a recent tier), real encrypted Receiver PIR queries, and an independent chain with note commitments and nullifiers. The refund/spend story also constructs real transactions and independently verifies their proofs and signatures.

The stories cover seed recovery's four-empty stopping rule and recycled holes, a pre-birthday payment in a sealed shard extending the seed walk, live negative and positive filters, independently lagging PIR publication, late callbacks, offline repeats found by a complete check, authenticated funding memos across devices, spending recovered funds, multiple accounts, birthday lowering, and cancellation across restart. A refund arriving after the birthday remains undiscoverable until an ordinary rescan finds its earlier funding memo, including after a manual history check. SQLite state-machine tests cover additional reorg, pagination, stale callback, operation-ownership, and admission cases. Receiver adapter tests cover encrypted forged answers and held responses.

Ordinary scanning runs without a directory handle. Filter matches only schedule PIR. This suite has no live key watches, scan replay, provider address feed, or block cache for payment discovery. Explicit chain advancement replaces wall-clock sleeps. Byte counters count actual request and response bodies, and assertions distinguish query calls from filter downloads.

Every drain step and every mutation in the randomized story checks a no-stall invariant: unless discovery is off, an unfinished seed walk or active manual search exposes a runnable lookup or waits only on a retry backoff, and no settled request keeps a target nothing would clear.

The in-process directory is a transport fixture, not a production HTTP server. The publisher repository tests its real HTTP routes and binary lifecycle. Application scheduling and the bandwidth selection policy require the corresponding Vizor integration tests. Passing these library stories alone does not complete that application evidence.

A seeded randomized story varies receive indexes, amounts, repeat payments and restarts across an online phone, an intermittently offline desktop and a new seed restore. Its oracle records mined output identities and values independently of wallet progress. It checks that live filter rounds and offline complete checks recover every payment, repeats included, and that manual recovery and fresh restore recover the full payment set.

The nightly workflow retains the full test log. There is no separate legacy scenario/report engine.
