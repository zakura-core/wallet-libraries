# Receiver directory restore sweeps

`sweep` runs a restored wallet's swap-key sweeps. Each swap key recovered from the
seed, a refund key from its funding memo or an incoming lookahead key, is looked up
once in a receiver directory over PIR, and the payments found are imported only
after the wallet checks them against its own chain, through the swap receiving
steps of `zakura-client-sqlite`.

Applications supply:

- the directory's HTTPS origin and a `Transport` for it, and a `NoteSource` for the
  note data of found payments, usually `EnhanceNotes` over Enhance PIR. Both carry
  the application's route policy, timeouts and cancellation; this crate has no HTTP
  client.
- a `WriteLock` that serializes the sweep's wallet writes with the application's
  other writers.
- the network's genesis hash (`MAINNET_GENESIS` on mainnet) and the clock.

See the `sweep` rustdoc for when a run sends requests, which publications it
accepts, and how failures are retried.

The receiver crates are pinned to a commit of wallet-pir's swap integration branch
until they land on its `main`.

`tests/sweep.rs` serves a directory in process through the receiver service's own
routes and checks that a restored wallet finds and imports a payout, extends its
lookahead past it, repeats no finished sweep, imports every payment of a key paid
twice, and refuses a publication that is not on its chain before any lookup.
