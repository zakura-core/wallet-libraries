# Transparent PIR history testing and qualification

Status: proposed acceptance specification for future implementation. This document
adds no tests, fixtures, client behavior, txid PIR service, or qualification result.
It extends the [ledger architecture](transparent-pir-ledger-architecture.md),
including its [compact metadata and accepted cases](transparent-pir-ledger-architecture.md#activity-calculation-and-explicit-acceptance).
The two implementation layers are **wallet-libraries** and **Vizor**. Both are
required: correct recovered balances do not establish correct activity rendering.

## Goal and evidence model

Prove that client recovery produces the expected owned ledger and that Vizor
presents it honestly before and after optional transaction-detail enrichment.
Use the architecture's minimum metadata: optional exact fee, complete transparent
input count, and shielded-components bit. Keep payment amount, account movement,
fee availability, detail completeness, and chain status distinct.

For each scenario, create a reference wallet that constructs transactions and
retains its local history, then recover the same controlled keys into a fresh
wallet database without its local transaction or operation records. Also test an
upgrade/reopen of the retained database. Recovery must match the financial facts
it can establish; it is not required to reproduce details intentionally unavailable
without enrichment or records that cannot be reconstructed from chain data.

Expected values must come from independently decoded canonical transactions,
resolved prevouts, accepted block data, and authored ownership/operation evidence.
Do not use the candidate ledger reducer, history classifier, or activity mapper
to generate its own expected output. Independently verify fees, complete input
counts, and shielded-component presence against the exact publication under test.
A reference wallet is useful for retained intent but is not, alone, an independent
financial oracle if it shares the candidate recovery logic.

The initial profile trusts the publisher for correctness and completeness. A
self-consistent false fee/count or omitted event may not be detectable by the
client. Such a publication must fail independent qualification; do not claim
that PIR, a txid match, or note decryption proves metadata truth or completeness.

## Fixture construction and scenario coverage

Generate controlled regtest wallets and valid transactions for the deterministic
suite. Use Alice, Bob, Carol, and multiple Alice accounts to make ownership and
shared funding explicit. Generate disposable test keys at runtime through existing
test harnesses; do not export wallet mnemonics or spending keys into fixtures.
Use public transaction data and non-secret account/script associations in fixture
exports. Preserve retained-operation evidence only in test-local application data.

Pending status, retained intent, and incomplete coverage require scenario state
or fault injection, not just a mined transaction. A scenario can satisfy multiple
rows, but give every row explicit assertions and a stable identifier.

| ID | Case | Fixture construction | Required client result and accepted limitation |
| --- | --- | --- | --- |
| H01 | Transparent-only send | Alice pays Bob with change | Correct aggregate payment and fee after complete coverage; address/output breakdown deferred |
| H02 | Several inputs or recipients | Spend several Alice outputs; pay Bob and Carol | Group by spending txid and deduplicate input identities; exact aggregate, no invented per-recipient breakdown |
| H03 | Ordinary transparent receive | Bob pays Alice without Alice-owned inputs | Correct received amount and confirmed status/date; sender from txid display v2 (first address-shaped input, not owned), other inputs named as an omission |
| H04 | Retained local transaction | Run with retained construction records and separately with a fresh database | Preserve rich local facts; restored view follows reduced capabilities rather than false full-history equality |
| H05 | Shared funding | Valid transaction with Alice and Bob inputs; repeat across Alice accounts | Correct per-account owned effects and whole fee; no fabricated payment attribution or fee share |
| H06 | Self/cross-account transfer | Transfer within an account and between two accounts | Correct ownership/scope effects; no double counting or gross self-payment inferred from net movement |
| H07 | Owned shielding/unshielding | Move funds between owned transparent and shielded outputs | Correct combined financial effects; classification provisional when missing effects could change it |
| H08 | External transparent unshielding | Alice pays Bob's transparent address from shielded funds | Known owned debit remains visible; owned-script TPIR cannot supply Bob's output by itself |
| H09 | Other mixed-pool transaction | Combine owned pool movements and external payments | Correct known effects; incomplete breakdown/pool classification when evidence is insufficient |
| H10 | TEX/multi-step operation | Generate supported linked funding and payment steps | Individual transactions visible; grouping/combined fee only with supporting evidence |
| H11 | Swap/gift-card operation | Keep application records in one run and omit them in another | Preserve known operation labels; never manufacture intent or grouping after restore |
| H12 | Pending/expired/conflicted | Leave unmined, advance accepted height, or introduce a valid conflicting spend | Existing local/status paths handle state; confirmed TPIR invents no pending history |
| H13 | Incomplete coverage | Withhold a required range/page, delay publication, or interrupt retrieval | Visible partial facts; no final movement/payment or synchronized/spendable claim from incomplete evidence |

Add a small real-chain replay suite for historical versions, large/reused script
histories, and uncommon shapes. Selected public scripts are synthetic test
associations, not proof of a real wallet population or seed/address-discovery
coverage. Mnemonic/account discovery requires controlled keys. Regtest requires
appropriate supported pool/upgrade activation; identify unsupported historical
cases and cover them with frozen valid transaction vectors or real-chain replay.
Do not silently omit a required case or substitute an invalid transaction.

## Layer 1: wallet-libraries

Exercise the production discovery, recovery, persistence, projection, and history
read paths, not just direct inserts into expected SQL rows. The integration runner
must start from a fresh account/database, follow real derivation/import rules,
consume filter/directory/page responses, validate/decode metadata, commit the
ledger, and read the consumer-facing history API. Include retained-database runs.

Use three separable levels of evidence:

1. Focused deterministic tests of metadata validation, ledger commits, history
   contracts, and classification from authored inputs. These localize failures
   but do not establish transport or address-discovery correctness.
2. Client integration with versioned encoded publication data and controlled
   transport faults. It must use actual decoders and durable commits rather than
   bypassing recovery by inserting final history rows.
3. End-to-end qualification using the real client adapter and native PIR requests
   against a pinned candidate publication, checked by an independent chain oracle.
   Mock transport or injected plaintext records cannot replace this gate.

At each accepted checkpoint, compare exact receives, spends, UTXOs, balances,
script/scope coverage, unresolved work, metadata provenance, and independent chain
status. Compare missing details explicitly as unknown/unsupported rather than zero.
For complete ordinary sends, assert all selected-account input identities match
the complete input count before applying payment arithmetic. Include coinbase and
unknown, zero, and conflicting fees; preserve known locally constructed fees.

Close/reopen SQLite, repeat the checkpoint, interrupt pagination, deliver spends
before receives, and reverse transparent/shielded arrival order. Exercise reorgs
through recent/sealed coverage, re-mining, source replacement, and rollback while
retaining independent local facts. Add imported scripts and earlier required
ranges so fixed watch-list fixtures do not stand in for derivation/discovery tests.

Existing candidate recovery and policy tests are starting points in
[`transparent_ledger` tests](../librustzcash/zcash_client_sqlite/src/wallet/transparent_ledger/tests.rs).
Use the repository [development workflow](development.md) and focused transparent
configuration. Add fixture builders through supported test APIs; do not assume
that currently proposed metadata/history interfaces are already implemented.

## Layer 2: Vizor

Consume the same scenario expectations through the real Rust history API and
native/Dart boundary, then exercise the production activity mapper and screens.
Include desktop and mobile. Widget tests with authored `TransactionInfo` values
are useful for presentation but cannot establish recovery or binding correctness.

For every H01-H13 case, assert the intended title/icon, amount and its semantics,
pool label, timestamp source, confirmation/pending/failed status, and explicit
incomplete-detail state. Preserve a tappable row for known activity even without
external output rows. No known debit may disappear because enrichment is missing.
An unknown fee must not become zero; incomplete movement must not become a final
payment. Confirmation can be complete while display details remain incomplete.

Preserve known local intent, self-transfer scope, and application operation
records. After a fresh restore, assert the specified generic/partial presentation
where intent or grouping is absent. Do not demand identical rich reference rows
for cases whose accepted limitation is incomplete classification or attribution.

Future txid PIR tests must show cached facts immediately after navigation and
prioritize only missing details. Confirm zero txid/parent requests for fee-only
activity recovery, one deduplicated enrichment obligation across views, cache
reuse on a second opening, and updates under the same transaction identity.
Distinct legitimate activity roles may remain separate; enrichment must not
create duplicate rows for one role. Refresh may refine classification/row roles
without losing the underlying transaction or selecting another account's data.

Test loading, retryable error, unsupported details, cancellation, account switch,
and a reorg during enrichment. Resolve only required parent-output values for
independent fee checking, without recursive ancestor recovery. Capture transport
requests and prove no public address, txid, outpoint, or parent fallback under
`PrivateRequired`. Financial recovery continues when the detail screen closes.

Reuse Vizor's regtest send/import/multi-account tests, Rust history tests, and
Flutter activity-row, screen-handoff, and detail-screen tests. Reference these by
the pinned tested Vizor revision in each qualification report, since its code and
native binding layout evolve independently of this repository.

## Fixture manifest and acceptance gates

Freeze scenario identifiers, canonical transactions/prevouts, network and accepted
checkpoint hashes, supported pool activations, account/script ownership and
scope, required discovery ranges, retained-operation state, publication/schema
identity, client revision pins, and fixture checksums. Keep three separately
authored expected views: owned ledger/coverage, activity before enrichment, and
activity after enrichment including intentionally unresolved fields. Requests
also have expectations so a correct-looking UI cannot conceal a privacy leak.

Compare after each checkpoint, restart, repeat, and enrichment transition. Do not
regenerate golden expectations from a failed candidate. Inject a wrong expected
fee, input count, omitted event, and ownership mapping as negative controls;
verify the independent comparison fails nonzero even for internally consistent
publisher data. Malformed bytes and contradictory records separately exercise
client rejection. A test selecting zero cases or skipping a required case is not
a successful qualification run.

Record per-case results and missing capabilities. First qualify wallet-libraries
financial/history contracts, then the matching Vizor consumer at exact revisions.
Once future txid PIR exists, qualify its detail and privacy behavior separately.
Before its implementation, accepted unknown recipient/details states can pass
the pre-enrichment gate; the future detail gate remains unqualified. Documentation
or mock-only tests cannot claim end-to-end PIR qualification.

Reports must include exact code/publication pins, oracle provenance, case counts,
failed/unexecuted cases, request-capture results, and measured runtime/resource
and packing costs. Keep private diagnostic data local and export only safe
aggregate results. Release decisions remain governed by the architecture's
financial-authority and qualification gates, not by matching final balances alone.
