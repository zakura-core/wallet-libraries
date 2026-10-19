# PIR trust and privacy contracts

The [package map](pir-packages.md) separates implementation roles. It does not
change what a PIR response proves or which party the wallet trusts.

## Shared native profiles

The native two-mask profiles remain experimental. Correctness certificates are
snapshot-specific, and moving code into separate packages is not cryptographic
qualification. Parameter descriptions, setup seeds, encoded identities and
accepted query widths are protocol contracts. Clients derive the expected
parameters locally and reject a publication that changes them.

Query encryption uses fresh operating-system entropy through the existing
ChaCha20-based preparation path. Public setup derivation is deterministic and
contains no secret. The protocol package owns that derivation and the wire byte
codec; client encryption, server preparation and query evaluation consume it.
Compatibility tests compare it with the pinned previous provider and cross old
and new client/server operations for both native profiles.

## Enhance

Applications accept a manifest against independently scanned wallet state
before obtaining a usable session. A batch remains bound to that manifest;
queries are grouped by shard and row, and cancellation prevents further
dispatch. A stale session requires renewed wallet acceptance.

Record encoding validation is not cryptographic authentication. Wallet code must
validate request identity and authenticate decrypted notes. Transaction metadata
is indexer data; some send-only associations require server trust when decryption
cannot authenticate the action. Transport, refusal, timeout and cancellation
failures must not trigger a public lightwalletd fallback or count as unreadable
records. An unreadable record and an unreadable row remain distinct cases.

## Status

A server's manifest, coverage and clock are assertions, not proofs of complete
indexing. `NotFound` does not prove a transaction is absent from the chain or
mempool. A mined observation must be reconciled with wallet chain data before it
is acted on.

The accepted anchor comes from the wallet's independently verified chain state,
never from the manifest itself. Private observations use the accepted-anchor
transport; the raw selector and decoder are not exposed through the client API.
The caller supplies conservative local coverage evidence. Selecting a source
opens only that source, including on failure; the optional lightwalletd adapter
is explicitly enabled and selected.

## Transparent

Retrieval produces candidate evidence about what the configured publisher
reports. The wallet owns source qualification, chain and account validation,
activation, balances and spending. A public activity filter is not a proof of
completeness: trusting a negative result requires trusting the indexer's complete
input set. Publication digests establish consistency, not complete indexing.

A recovery batch cannot grant financial authority by itself. Wallet validation
and durable settlement precede companion acknowledgment. Interrupted writes,
unacknowledged batches and publication changes retain their existing recovery
behavior. The application chooses publisher trust and job scheduling.

See the [wallet integration guide](transparent-pir-wallet-integration.md) and
[remaining privacy analysis](pir-remaining-leaks-plan.md) for the complete
application boundary and traffic-reaction limitations. These packages do not
hide whether or when a client contacts a service.

## Application transports

Applications retain route policy, cancellation and timeouts. Transports should
reject redirects and enforce a deadline covering the response body. Clients
retain their exact length, binding and response-budget checks. A transport or
validation error is not evidence of absence and must not silently select a
less-private source.
