# Receiver directory restore sweeps

With the `wallet` feature, `sweep` runs a restored wallet's sweeps of its dynamic keys
for any wallet store that implements the backend's dynamic IVK traits
(`zcash_client_backend::data_api::dynamic_ivk`), such as `zakura-client-sqlite`.
Each dynamic key recovered from the seed, a refund key from its funding memo or an
incoming lookahead key, is first tested against the publication's filters, which
every wallet downloads alike. Only a receiver in the paid set is looked up over PIR,
and the payments found are imported only after the wallet checks them against its own
chain. A swap provider's sets decide what happens to the key afterwards: one the
provider was given within the wallet's restore watch keeps scanning after its sweep,
and one it ever had is marked seen, so issuance does not hand it out again. A
provider's recent set is trusted only if its feed read the provider within the last
fifteen minutes and its window and feed history cover that watch; otherwise every key
keeps scanning. A run that finds nothing to look up opens
no PIR session and fetches no witnesses.

Applications supply:

- the directory's HTTPS origin and a `Transport` for it, and a `NoteSource` for the
  note data of found payments, usually `EnhanceNotes` over Enhance PIR. Both carry
  the application's route policy, timeouts and cancellation; this crate has no HTTP
  client.
- a `WriteLock` that serializes the sweep's wallet writes with the application's
  other writers.
- the wallet's consensus parameters, the network's genesis hash (`MAINNET_GENESIS` on
  mainnet) and the clock.

See the `sweep` rustdoc for when a run sends requests, which publications it
accepts, and how failures are retried.

The receiver crates are pinned to a commit of wallet-pir's open receiver stack
until they land on its `main`.

`tests/sweep.rs` serves a directory in process through the receiver service's own
routes and checks that a restored wallet finds and imports a payout, extends its
lookahead past it, repeats no finished sweep, imports every payment of a key paid
twice, makes no lookup when nothing was paid, keeps scanning only recently quoted
addresses, keeps every address scanning when the recent set cannot vouch for the
whole watch, and refuses a publication that is not on its chain before any lookup.
