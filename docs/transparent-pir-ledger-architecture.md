# Transparent PIR ledger architecture

Status: proposed design; production private authority is not enabled by the
[preparatory refactor](transparent-pir-preparatory-refactor.md). Private
recovery over transparent PIR, behind a development flag, is planned in
[private transparent recovery](transparent-pir-private-recovery.md).

The [history testing and qualification plan](transparent-pir-history-qualification.md)
defines the proposed 13-case fixture suite at the wallet-libraries and Vizor
layers, including accepted incomplete activity and future txid PIR tests.

## Reader's guide

The transparent ledger gives the wallet a durable answer to three questions:
**what transparent activity happened, how much history has been checked, and
whether the resulting funds are safe to spend**.

LRZ already stores transparent outputs and spends. Here LRZ denotes the existing
`zcash_client_backend` and `zcash_client_sqlite` APIs, published by this repository
as `zakura-client-backend` and `zakura-client-sqlite`. The refactor adds the
recovery evidence and lifecycle rules needed to make private discovery
authoritative while continuing to use LRZ's wallet machinery.

The new ledger APIs and tables below are proposed, not implemented by these
documents. The design specifies the `tpir_*` namespace and storage
responsibilities; the exact SQL schema remains to be implemented. This guide
explains the arrangement before the detailed contracts later in the document.

### What the ledger does

1. **Tracks wallet-owned scripts and their recovery bounds.** A script is the
   output's spending condition, such as P2PKH or P2SH. Each watched script has
   account ownership, derivation/import information, and a conservative history
   start. Deriving an address today does not establish coverage of its past.
2. **Recovers receives and spends.** A receive identifies an output by txid and
   output index, with its script, amount, and coinbase classification. A spend
   identifies the spending transaction/input and the outpoint it consumes.
   Spends received before their outputs remain unresolved until the outputs
   arrive.
3. **Tracks continuous coverage.** Knowing some transactions is different from
   knowing that all relevant activity in a range has been recovered. Coverage
   binds each checked script and height interval to a publication and accepted
   chain anchor. Checked empty ranges count; an absence of stored rows does not.
4. **Determines financial eligibility.** Coverage combines with LRZ's existing
   confirmation, maturity, pending-spend, and lock rules. An output that looks
   unspent can still be unavailable because a missing range may contain its
   spend.
5. **Handles restart, reorganization, and migration.** The ledger preserves
   pending retrieval work, rejects contradictory records, invalidates evidence
   from replaced blocks, and preserves local transactions and reservations.
   Isolated candidate recovery and guarded account promotion are part of this
   lifecycle.

For example, an output received 3 ZEC at height 120 and spent at height 160
looks unspent if recovery has reached only height 150. At decision height 200,
the recovered amount is 3 ZEC but the actual unspent amount is zero. The API
therefore returns balance together with coverage and authority. A partially
recovered amount is not necessarily a lower bound.

### How the data is stored

Retain LRZ's existing tables and add the ledger tables inside the **same SQLite
wallet database**. The new tables hold recovery evidence; the existing tables
remain the representation used by wallet history and transaction construction.

| Existing LRZ structure | What it already provides |
| --- | --- |
| `accounts`, `addresses` | Account ownership, derivation/scope, imported receivers, and address exposure information. |
| `blocks`, `scan_queue` | Locally stored block hashes and scanning progress, including contiguous scanning. |
| `transactions` | Transaction identity, mining placement, optional raw bytes, and transaction metadata. |
| `transparent_received_outputs` | Output index, script, value, account/address ownership, unspent-observation information, and proposal locks. |
| `transparent_received_output_spends` | Links known received outputs to transactions that spend them. |
| `transparent_spend_map` | Records spent outpoints, including those whose corresponding receives are not yet available. |
| Shielded note and spend tables | Received notes and detected spends, linked to the same transaction identities as transparent effects. |
| `sent_notes` | Known sent-output details, including recipient and amount, from local construction or supported outgoing recovery. |
| Transaction/output views | The representation consumed by transaction history and other wallet reads. |

A concrete decomposition of the new ledger storage could look like this.
These table names and fields illustrate the responsibilities, rather than
constituting finalized migration DDL:

| Proposed table or group | Main data |
| --- | --- |
| `tpir_meta` | Applied privacy policy, policy generation, and reader compatibility/version metadata. |
| `tpir_account_state` | Per-account candidate/active lifecycle and activation context. |
| `tpir_scripts` | Script bytes, owning account, scope/derivation information, recovery start, and watch-set generation. |
| `tpir_receive_events` | Immutable receive identity and content: txid, output index, script, value, and coinbase classification. |
| `tpir_spend_events` | Immutable spend identity and content: spending txid, input index, and spent outpoint; unresolved spends remain here. |
| Event placement and observation tables | Canonical mined height/hash, plus publications/revisions that supplied each event and their record digests. |
| `tpir_coverage` | Per-script checked intervals, accepted terminal hashes, source revisions, and sealed/provisional status. |
| `tpir_pending_pages` | Bounded resumable retrieval work with its source, revision, and operation context. |
| `tpir_projection_origins` | Links projected LRZ records to ledger evidence, legacy observations, local construction, or independently authorized payloads. |

The relationships matter more than the table names:

- Events and coverage are separate. A range can have complete coverage with no
  events, or recovered events with incomplete coverage.
- Event identity and mining placement are separate. A transaction can be mined
  again after a reorg without becoming a different receive.
- One event can have multiple publication observations. Seeing it in another
  revision is not itself a contradiction.
- One LRZ record can have multiple origins. Removing invalid PIR evidence must
  not delete an independently recorded local transaction, reservation, or
  shielded-scan contribution to a shared transaction.
- Balances are computed from active events/projection and wallet rules. A cached
  amount cannot substitute for the underlying evidence.

**Projection** means writing recovered events into the existing LRZ output,
spend, and transaction representation. The deliberate duplication lets the
ledger retain its evidence while established wallet APIs continue to work.
For an activated account, evidence, coverage, and projection commit in one
transaction. A crash cannot leave new coverage committed while its corresponding
spend is missing from the projection. Candidate commits remain isolated from
the production projection.

### What LRZ already enables

`WalletDb::transactionally` supplies the all-or-nothing database boundary.
Account/address APIs provide ownership and derivation information; block-hash
and fully-scanned-state APIs provide accepted-chain context. Existing
output/spend handling, locks, confirmation policies, and input selectors supply
the transaction-building rules. Rewind entry points provide the place to roll
back ledger evidence together with wallet chain state.

The `tpir_*` tables are library-owned schema. Vizor does not implement this
ledger through application extension tables or a separate database. The new
library work is source-bound coverage, candidate isolation, guarded promotion,
and enforcement of those rules throughout transparent financial operations.
There is no replacement transaction builder or independent input selector.

### What Vizor implements

The existing application obtains transparent information through UTXO refresh,
Ledger address-history discovery, and transparent-history enhancement. Those
paths insert outputs or decoded transactions into LRZ. A `.receive.redb`
sidecar assists receive/discovery caching.

Currently, a UTXO refresh inserts the output and queues full transaction
retrieval because the UTXO response alone does not provide everything needed
for spend detection and coinbase recognition. The new private ledger supplies
explicit events and classification without requiring a public payload lookup
to make its outputs usable.

Vizor's new coordinator resolves the existing private-queries setting, captures
an accepted chain point, obtains the watched-script snapshot, runs the selected
source under cancellation/resource limits, and submits normalized results through
the ledger API. It repeats when address-window growth introduces more scripts
and exposes recovery state through Rust/Flutter results.

Vizor continues to own networking, scheduling, and presentation. Wallet-libraries
decides whether a commit, promotion, or input selection is valid. Missing raw
transactions or fees cannot turn private ledger discovery into public txid
queries. Payload recovery and status observation retain their separate work and
evidence contracts.

### How shielded sync and history fit

There are two logical discovery loops: shielded compact-block scanning and
transparent script recovery. They share one wallet database and accepted chain,
and join their effects through the same `transactions` row by txid. Enhance PIR
adds supported transaction details; it is not a third ownership-discovery loop.
Status work observes known transactions under its separate evidence contract.

Shielding and unshielding can therefore be reconstructed as movements between
pools within one transaction. Restoring a balance does not imply restoring every
recipient, memo, or fee: the transparent ledger discovers wallet-owned scripts,
and the current Ironwood Enhance record does not contain external transparent
outputs. Existing local-send details must survive migration; a seed restore may
have only partial payment details. The [sync contract](#shielded-sync-and-shared-transactions)
and [history contract](#shielding-unshielding-and-history-reconstruction) below
define how to combine discoveries without duplicate accounting, hidden debits,
or public lookups to fill missing details.

### Primary API and data-layout changes

| Area | Existing behavior | Intended behavior after the refactor |
| --- | --- | --- |
| Discovery writes | Individual UTXO insertion and full-transaction ingestion. | Ledger commits combine normalized events, coverage, provenance, and progress; local-send and authorized-payload paths retain independent roles. |
| Balance reads | LRZ balances/summaries with application recovery checks. | `TransparentLedgerSnapshot<AccountId>` exposes authority, target, coverage, authorized balance, last-known amount, and blockers together. |
| Input selection | Individual, address, batched, and value-bounded selectors. | The same selectors enforce ledger eligibility internally; callers cannot bypass it by choosing another selector. |
| Chain target | Callers work with scanned heights and transaction target heights. | Explicit `ChainPoint { height, hash }`; coverage through `H` supports a transaction targeting `H + 1`, subject to current-chain and other eligibility rules. |
| Rewind | LRZ rewinds plus application discovery/cache handling. | Ledger evidence and projection participate in applicable LRZ rewind transactions, using the actual retained height. |
| Privacy configuration | Enhance/Status policy alongside separate transparent discovery paths. | The same user setting governs transparent recovery, with durable applied policy and generation checks across handles and entry points. |
| Transaction history | Existing transaction/output views and Vizor classification, often supplemented by full payloads. | The same transaction identity joins pool effects; history also exposes incomplete classification, recipient details, memos, and fees without fabricating values. |
| Financial storage | Existing LRZ output/spend records and public-path discovery caches. | Those records remain, with same-database `tpir_*` evidence, coverage, progress, and provenance supporting authoritative private projection. |
| Migration | Existing records support public discovery behavior. | Legacy evidence, isolated candidate recovery, and guarded per-account promotion become explicit states. |

Preparation keeps public discovery authoritative and exercises the new lifecycle
with fixtures. When production private recovery is later enabled, public
transparent queries stop immediately. Incomplete accounts cannot use transparent
inputs; qualified accounts are promoted atomically. Vizor keeps its established
sending, shielding, and hardware-wallet flows while their discovery source gains
a stricter wallet-library contract.

Coverage remains relative to the accepted publication and its trust model. The
publisher is trusted for accurate and complete indexing; matching hashes and
digests do not independently prove every event against the chain. The detailed
[trust model](#trust-and-privacy-model),
[wallet contract](#wallet-facing-contract), and
[storage rules](#durable-state-and-atomic-projection) below define the required
boundaries.

## Objective and boundaries

Recover transparent receives and spends privately while retaining Vizor's
existing wallet database, transaction construction, shielding, hardware-wallet,
and account lifecycle. Wallet-libraries owns financial correctness; Vizor owns
policy, scheduling, transport, and presentation.

The central invariant is:

> A private transparent balance is authoritative only when validated ledger
> events, continuous per-script coverage, the locally accepted chain, and the
> LRZ projection agree in one durable database state.

```text
                  Vizor private queries setting
                              |
                   immutable operation policy
                              |
        +---------------------+---------------------+
        |                     |                     |
 transparent recovery   payload recovery      status observation
        |
 public filters downloaded whole and matched locally
        |
 private retrieval from matching shards
        |
 normalized events + coverage + source provenance
        |
 wallet-libraries ledger API and SQLite transaction
        |
        +-- candidate ledger: initial private recovery
        |
        +-- authoritative ledger + LRZ projection: activated account
```

The diagram expands transparent discovery and its follow-on work. Shielded
compact scanning continues alongside it. The two discovery loops, payload
recovery, and status observation share policy resolution and transport
facilities but retain independent queues, completion rules, evidence, and
retries. Success in one never completes another or authorizes a different source.

| Owner | Responsibilities |
| --- | --- |
| Protocol client | Filter encoding and matching, manifests, shard layout, PIR requests and response validation, publication revisions, protocol byte/query bounds. |
| Wallet-libraries ledger and SQLite adapter | Watched scripts, recovery bounds, accepted-chain binding, durable events and coverage, provenance, projection, financial eligibility, rewind and account lifecycle. |
| Vizor | Existing private-queries preference, operation lifecycle, endpoints and network route, deadlines and cancellation, bounded scheduling, recovery UI, rollout gates. |

No HTTP, filter layout, shard wire type, or PIR client type appears in the
wallet-facing API. The adapter accepts normalized events and bounded opaque
source/revision identifiers. Applications and protocol clients cannot write LRZ
projection tables directly.

## Shielded sync and shared transactions

### Two discovery loops, one wallet state

| Process | Facts it contributes | What its completion does not establish |
| --- | --- | --- |
| Shielded compact scanning | Wallet-owned received notes, spends matched to known nullifiers, and scanned chain state. | Transparent script coverage or complete recipient, memo, and fee details. |
| Transparent ledger recovery | Receives and spends for watched scripts, with continuous source-bound coverage. | Shielded scan completion or a complete list of external transaction outputs. |
| Payload recovery, including Enhance PIR | Details supported by the selected format, such as shielded memos and recoverable outgoing outputs, or an authorized full transaction. | Completion of either discovery loop or transaction-status work. |
| Status observation, including Status PIR | Status evidence for already known transactions, subject to its own coverage and trust rules. | Discovery of all wallet effects or recovery of payment details. |

These are logical responsibilities, not a requirement for separate threads or
one combined network loop. Vizor can interleave or schedule them concurrently.
Transparent recovery captures a fixed locally accepted, contiguously scanned
chain point as specified in [coverage](#coverage-synchronization-and-financial-authorization);
it does not establish a competing chain tip. The loops may finish different
ranges at different times. A shielded scan checkpoint cannot certify transparent
coverage, and transparent completion cannot advance a shielded scan checkpoint.

### Joining mixed transactions

A transaction spending both a wallet-owned transparent output and a wallet-owned
shielded note has one transaction identity in the wallet database. The scanner
attaches the shielded spend and received notes; the active transparent ledger
attaches the transparent spend and receives. Neither arrival order changes the
result. LRZ already upserts scanned and full transactions by txid in
[`put_tx_meta` and `put_tx_data`](../librustzcash/zcash_client_sqlite/src/wallet.rs);
the ledger projection must preserve this behavior.

Required integration rules are:

- Keep one shared transaction row and pool-specific output/spend identities.
  Repeated observations and later payload ingestion are idempotent; neither
  discovery path replaces the other path's effects with its partial view.
- Commit each source's validated facts atomically with its own progress. Do not
  wait for both network loops to finish before recording a known spend. Active
  facts participate in existing spend/conflict rules immediately; isolated
  candidate facts remain subject to promotion and cannot mutate production state.
- Preserve independently recorded local sends. LRZ's local-send ingestion
  records selected transparent and shielded spends, sent outputs, and available
  transaction metadata together. Preserve Vizor's existing send/outbox lifecycle;
  later discovery confirms or augments those records rather than reconstructing
  the user's intent from scratch.
- Deduplicate follow-on work at its actual identity, such as transaction plus
  action/output and requested detail. Completing one action's memo must not
  mark all outputs, fees, or other recovery lanes complete.
- Keep ownership account-scoped. A transaction involving two wallet accounts
  can have a wallet-internal transfer and separate account debits/credits.
  Owning one input does not prove that every output was paid by that account.
- Reconcile mined placement against the same accepted chain. Conflicting source
  assertions are integrity failures, not last-writer-wins updates. Rewinds
  invalidate affected pool evidence and derived history together while
  preserving independent local origins and shared transaction identities.

### Shared privacy policy and the current Enhance gap

The required-private policy must apply before either discovery path dispatches
follow-on requests. A shielded scan may discover a mixed transaction first;
waiting until the transparent ledger tags that transaction would leave a public
lookup race. Dispatch checks must also cover already queued payload/status work,
reopened handles, and retries after a setting transition. A server's transaction
shape flag cannot authorize disclosure of a txid or parent outpoint.

The current Enhance implementation is not yet sufficient for this contract:

- [`EnhanceRecordParts`](../zakura/pir-enhance-types/src/lib.rs) enhances one
  Ironwood action. It includes transparent-presence flags and transaction
  metadata, but no transparent input/output list. It is not a generic payload
  format for every shielded pool or mixed transaction.
- [SQLite enhancement application](../librustzcash/zcash_client_sqlite/src/wallet/enhance_pir.rs)
  currently sends `has_transparent` results through `require_lwd` and returns
  `LwdRequired`.
- [Private outgoing recovery](../librustzcash/zcash_client_backend/src/data_api/enhance_pir/storage.rs)
  skips mixed transactions. Removing the routing branch alone would not supply
  the missing recipient data or make outgoing recovery correct.

Before production private activation, route unavailable mixed-transaction
details to explicit pending/unsupported private work, and retain the discovered
financial facts. Implement and qualify any supported private mixed enhancement
with its own identity, decryption, metadata, and partial-completion checks.
`LwdRequired` is not permission for a public request in `PrivateRequired`.
Do not claim equivalent memo/outgoing recovery across shielded pools until each
pool's format and path are supported and tested.

## Shielding, unshielding, and history reconstruction

### Reconstructing movements between pools

| Transaction | Shielded discovery | Transparent discovery | Intended history |
| --- | --- | --- | --- |
| Own transparent funds to own shielded address | Owned shielded receive. | Owned transparent spend and any transparent change. | One shielding operation with pool movements and fee shown separately when known. |
| Own shielded funds to own transparent address | Owned shielded spend and any shielded change. | Owned transparent receive. | One unshielding operation, distinguished from ordinary change using available scope and intent evidence. |
| Own shielded funds to an external transparent address | Owned shielded spend and any shielded change. | No external recipient output from owned-script recovery. | An outgoing payment; recipient, amount breakdown, and fee may need additional payload recovery. |
| Own transparent and shielded inputs in the same transaction | Owned shielded spends/receives. | Owned transparent spends/receives. | One logical transaction containing all known effects and any external payments. |

The table describes effects that can be recovered, not classifications that
may be finalized from the first arriving rows. Receiving a shielded note funded
by someone else's transparent inputs is an incoming payment, not the wallet's
own shielding. A transaction may combine self-transfer, change, and external
payments; an internal-transfer label must not hide those payments. Preserve
account and address scope, including internal/ephemeral change, and distinguish
locally recorded intent from reconstructed classification.

For a known transaction with only 5 ZEC of own transparent inputs and an own
shielded output of `5 ZEC - fee`, history shows one shielding operation, and
the total wallet balance changes only by the fee. Apply that interpretation
only when the transaction details justify the assumed shape. The presence of
an owned spend and receive alone does not establish that all other effects
are absent or that the wallet's net loss equals the transaction fee.

### Existing wallet migration versus seed restoration

An upgrade preserves local transaction bytes, known sent outputs, recipients,
fees, and available operation/grouping metadata. The ledger adds chain evidence
to this history. It must not replace rich local records with event-only stubs.

A seed restore or discovery of a transaction created on another device may lack
those local records. Shielded scanning plus complete transparent coverage can
recover the wallet's owned effects, subject to the supported keys/scripts and
recovery bounds. This is not a promise to recover every payment detail. In
particular, an external transparent recipient is outside the owned-script
ledger, and shielded outgoing-note recovery does not reveal transparent outputs.

For example, a restored 5 ZEC shielded spend and 1 ZEC shielded change imply a
4 ZEC wallet debit only after other owned effects have been accounted for. They
do not identify the external recipients or split that debit into payments and
fees. The same limitation affects external transparent outputs in other mixed
or transparent-only sends. Never display the full debit as the payment amount
by treating an unavailable fee as zero.

Multi-transaction operations such as TEX funding and payment steps are a
separate grouping problem. Preserve local grouping evidence when available;
do not promise to recover the original UI grouping from a seed. Reconstructed
grouping needs validated transaction links and sufficient details, not matching
amounts or timestamps alone. Individual transactions remain visible when
grouping cannot be established.

### Proposed compact transaction metadata for activity

This is a proposed extension, not a claim that the current script-history
response contains fees or that private authority is enabled. It permits an
accurate activity summary for the cases below without eager full-payload recovery.
"Fully displayed" means accurate title, amount semantics, pool label, date, and
status, not complete transaction details. Confirmation remains independent of
detail completeness.

This proposed extension adds only:

| Transaction metadata | Meaning | Proposed encoding |
| --- | --- | --- |
| Optional exact fee | Actual whole-transaction fee calculated by the publisher; unknown, zero, and not applicable remain distinct | Canonical unsigned base-128 variable-length integer when present; a presence bit |
| Transparent input count | Complete count of non-coinbase transparent inputs, not merely inputs discovered for this wallet; zero for coinbase | Canonical unsigned base-128 variable-length integer |
| Has shielded components | Presence of any supported shielded transaction component, including historical Sprout, Sapling, Orchard, and Ironwood; not proof of real input/output roles or ownership | One versioned flag bit |

Reuse spare event flag bits only in a newly versioned codec. Do not reinterpret
existing v10 bytes. A 10,000-zatoshi fee takes two bytes and an input count below
128 takes one byte: typically **three additional bytes per event**, with no
additional flag byte. For today's 51/79/43-byte compact receive/spend/local-spend
forms, that example becomes 54/82/46 bytes. Larger values take more bytes.
This is encoding arithmetic, not a measured storage, page-count, or latency claim.

Metadata belongs to the creating transaction for a receive and the spending
transaction for a spend. Initially repeat it on events, verifying agreement for
one transaction identity across scripts and pages. An adjacent receive/local-spend
pair generally refers to two transactions and must not share their fee. Defer
fragment-local metadata deduplication until measurement justifies its complexity.

Exclude transparent output counts/totals, separate or aggregate shielded value
balances, and per-pool presence flags from this minimum proposal. Obtain dates
from wallet-accepted block data using event height; do not repeat timestamps in
events. Keep recipient addresses, memos, and external output breakdowns in detail
recovery. Counts are bounded by the decoded type and supported transaction rules;
monetary values must preserve exact zatoshis and protocol bounds, not a fixed u16
or rounded-unit approximation. Reject noncanonical, overflowing, or truncated
variable-length encodings and unknown version/flag combinations.

The publisher supplies these facts under the existing trusted-indexer accuracy
and completeness model. A txid, publication digest, or successful note decryption
does not authenticate an asserted fee or count. Preserve independently known
local fees; contradictory metadata is an integrity failure, not permission to
overwrite local facts or silently choose one assertion.

#### Activity calculation and explicit acceptance

Group spend events by spending txid and deduplicate by input index and consumed
outpoint. Join owned receives under that transaction identity. Grouping collects
known inputs; it does not prove the absence of another party's input.

For a non-coinbase transaction, derive the amount leaving the selected account
only when the exact fee is known, there are no shielded components, required
owned-effect coverage and input values are complete, and the number of distinct
inputs owned by that account equals the published complete transparent input
count. Conflicting identities or metadata invalidate the calculation.

`amount leaving account = owned input total - owned output total - fee`

For a 1 ZEC input, 0.5999 ZEC owned change, and 0.0001 ZEC fee, this is
0.4 ZEC. A positive amount supports an aggregate outgoing payment in the ordinary
case; it does not identify recipients. Preserve local intent and ownership/scope
evidence for explicit self-transfers and gross payment presentation. Do not
assign the whole fee to one account in a shared-funding transaction or apply this
formula to mixed transactions. Coinbase is not an ordinary fee-paying send.

When classification or attribution is unresolved, keep a tappable transaction
row with explicit incomplete details. A complete known account movement may be
shown as a debit/credit, including fees, rather than labeled as the payment
amount. If owned recovery itself is incomplete, the movement is also partial or
unavailable. Keep payment amount, account movement, fee availability, detail
completeness, and chain status separate. Do not use missing outgoing output rows
to suppress a known spend. Existing locally constructed transaction details take
precedence over a reconstructed summary.

| Case | Covered before txid enrichment | Explicitly accepted limitation |
| --- | --- | --- |
| Transparent-only send funded entirely by the selected account | Aggregate amount leaving the account, fee, transparent classification, chain status/date, after complete owned-effect recovery | Recipient addresses and individual external outputs wait until opening |
| Several owned transparent inputs or external recipients | Group events by spending txid; show the aggregate outgoing amount under the same complete-recovery and ownership conditions | No per-recipient breakdown |
| Ordinary transparent-only receive | Owned received amount, transparent classification, chain status/date | Covered by txid display v2: the first address-shaped sender, with other inputs, outputs past two and mixed funding named as omissions (`docs/transparent-txid-enhancement.md`) |
| Locally created transaction with retained records | Preserve its existing payment details and classification | Do not replace rich records with partial summaries |
| Shared funding across accounts or parties | Known selected-account movement and whole-transaction fee | Do not infer that account's payment amount or fee share |
| Self-transfer or cross-account transfer | Ownership/scope-based presentation where supported | Net movement alone does not reproduce gross self-payment presentation |
| Shielding or unshielding involving owned outputs | Combine transparent and shielded recovery | Classification stays provisional when other effects could change it |
| Shielded send to an external transparent address | Preserve facts from existing shielded recovery | Owned-script TPIR does not supply the external output; the new metadata alone cannot complete this case |
| Other mixed-pool transaction | Known owned effects and independent chain status | Exact payment breakdown and pool classification may remain incomplete |
| TEX or another multi-transaction operation | Individual recovered transactions | Original grouping and combined operation fee are not guaranteed |
| Restored swap/gift-card operation | Underlying recovered financial activity | Application intent and labels require retained records or separate evidence |
| Pending, expired, or conflicted transaction | Existing local-send and status paths | Confirmed TPIR does not provide pending history |
| Incomplete ledger coverage | Visible known activity marked partial | No final account movement, payment amount, or spendability claim from incomplete evidence |

### History completeness and storage contract

The library/consumer boundary must expose the following distinctions, using
existing transaction/output views where possible. Exact type names and any
additional metadata tables are implementation choices; `TransparentLedgerSnapshot`
continues to describe transparent financial recovery, not whole-wallet history.

| History facet | Required meaning |
| --- | --- |
| Owned effects | Known per-account, per-pool spends and receives, with discovery completeness relative to the relevant chain point and recovery bounds. Partial net amounts are not final transaction deltas. |
| Classification | Local intent or an evidence-based reconstruction; provisional while missing effects/details could change it. |
| Recipients and payment amounts | Known outputs plus explicit completeness; missing output rows do not mean there were no external payments. |
| Memos | Per-output availability and recovery state; one recovered memo does not complete the transaction. |
| Fee and other metadata | Optional values with source/trust provenance. Unknown, zero, and not applicable remain distinct. Server metadata is not authenticated merely because a note decrypts. |
| Mining/status | Placement and status evidence on the accepted chain, independent of payment-detail completeness. |

Persist facts and resumable work, and derive the history result from a consistent
database read. A cached classification is invalidated when relevant discovery,
enhancement, policy, or chain state changes. Any stored detail-completion marker
must be tied to its evidence and supported capability, not the presence of a
transaction row or absence of queued work. Retain independent projection origins
so invalidating one source cannot delete valid details from another.

Vizor groups pool effects under the same transaction as recovery proceeds. A
simple self-transfer should not become unrelated sent and received payments;
a complex transaction may legitimately expose multiple payment details. Show
known activity with an explicit incomplete-details state while one side is
missing, then refine the classification under the same transaction identity.
Do not hide a known debit because its external outputs have not been recovered.

The current Vizor `rust/src/wallet/sync/transactions.rs` needs explicit changes
for this contract: `HISTORY_BASES_CTE` infers shielding from currently present
rows, `read_history_bases` maps missing fees to zero, and `classify_history_tx`
can suppress a mined transaction with spends and change when no displayable
outgoing details are available. These are implementation gaps to cover with
partial-recovery fixtures, not behavior that the new projection may assume is
already safe.

### Capability and rollout boundary

A future **txid PIR** capability retrieves private transaction details separately
from owned-script history discovery. This proposal does not implement that
service or assert that current Enhance PIR is a generic txid payload store.

Opening a transaction prioritizes its missing detail obligation. Render cached
facts immediately after navigation; do not block opening the screen on a network
request. One durable enrichment path can serve both explicitly scheduled
background work and on-demand priority, deduplicated by transaction identity.
The initial policy does not require eager enrichment of every historical row.

Retrieve canonical transaction data privately and validate its identity with the
version-aware transaction library. A txid binds transaction effects according to
its format; do not claim that matching it authenticates all authorizing bytes or
proves mining. Maintain independent accepted-chain placement evidence. Fetch
missing parent information privately only when independent exact-fee calculation
requires prevout values not already known. Verify the parent identity and referenced
output; resolving that output does not require calculating the parent's fee or
recursively recovering its ancestors.

Persist validated facts and bounded, resumable obligations; reuse caches and
refresh the detail screen and activity row after commits. Keep an incomplete,
retryable or explicitly unsupported state on failure. Under `PrivateRequired`,
never fall back to public txid, script, address, outpoint, or parent lookups.
Query identity and protected locators remain private across paging and retries;
variable request counts/timing still require a composed privacy assessment.

Transaction data does not guarantee recovery of contact names, original payment
intent, collaborative payment attribution, or swap/gift-card/TEX grouping. Keep
payload work necessary to recover owned financial effects independent of optional
display enrichment, so closing a detail screen never stops financial recovery.
Recipient, fee-verification, and ledger completion remain distinct capabilities.

Display metadata never establishes ledger coverage or spendability. The compact
metadata extension and future txid PIR have separate compatibility and
qualification gates. Implement the metadata through a new journal/shard
publication lineage and explicit consumer migration; preserve existing
journals/publications rather than reinterpret them. Measure packing and query
counts before accepting the extension.

Preparation must preserve existing history and support honest partial history,
including fixtures for mixed transactions and both discovery orders. Production
activation requires all mixed-transaction paths to obey the shared privacy
policy and to expose unsupported details accurately. Full seed-restored
recipient/memo/fee parity is a separate capability gate, not implied by a
qualified transparent balance. Missing display-only details need not block
otherwise eligible spending; missing coverage required for the selected inputs
still does. Private failures never authorize public enrichment.

## Trust and privacy model

PIR protects the requested table row; it does not hide all access patterns.
Filters are public data downloaded for every applicable range and matched
locally. Filter requests therefore do not select only matching ranges, but still
reveal the requested recovery range. The shard service can observe approximate
activity ranges, query counts and timing, response sizes, and network origin
unless an anonymity route hides it. Correlation between services can expose
these patterns. In `PrivateRequired`, transparent recovery and its follow-on
retrieval requests must not disclose a wallet address, script, outpoint, or
transaction identifier.

This is a **trusted-indexer profile for accuracy and completeness**. Digests,
manifests, record checks, and accepted-chain anchors detect inconsistent bytes,
mixed revisions, and disagreement with local anchors. They do not prove that
the published events match the chain. A publisher can supply the correct block
hash alongside a self-consistent fabricated or incomplete event set. Trust
includes negative filter results, amounts, spend records, and coinbase
classification.

Production publication requires an independent verifier that reads blocks from
an independently operated node, reconstructs receives and spends, and checks
filters, directory/page contents, counts, and deterministic digests. Verification
must bind to the exact publication digest and block anchors being promoted;
mismatches prevent promotion. This is an operational qualification control,
not a cryptographic inclusion or completeness proof. Designing those proofs is
outside this work.

The privacy boundary includes follow-on requests. A ledger transaction stub,
unknown fee, unresolved spend, or missing raw transaction does not authorize a
public txid or parent-output lookup. Locally constructed transactions, already
authorized payloads, and identifier-independent chain/mempool observations retain
their own provenance; they never establish ledger coverage. Broadcasting a
user-authorized transaction remains a separate operation.

## Authority and the shared Vizor setting

The library makes source authorization explicit:

```rust
pub enum TransparentLedgerMode {
    Public,
    PrivateRequired,
}
```

`Public` retains current public discovery. `PrivateRequired` forbids public
transparent discovery even while private recovery is unavailable or incomplete.
Private recovery runs only under `PrivateRequired`; there is no mode that
recovers privately while public discovery keeps financial authority.

Vizor derives this authorization from the same install-scoped **private queries**
preference used by Enhance and Status; there is no transparent-specific user
toggle. The policy applies to the whole wallet database on the selected network,
while each account has its own recovery state.

Preparation preserves existing production behavior and makes no new
transparent-privacy claim. In the first release that enables private transparent
authority, the saved private-queries preference is applied before discovery
starts. That release needs working private integration and the qualification
gates below; the presence of the new schema is insufficient. Once private
authority is selected, a disabled service, missing configuration, or release
kill switch pauses transparent operations rather than selecting public mode.

Every handle performing transparent discovery or financial authorization must
be explicitly configured. An unconfigured handle returns `ModeNotConfigured`,
including for an empty wallet. Transactional handles inherit configuration;
reopened foreground, read-only, and native/background handles resolve it again.

The database durably records applied policy, a policy generation, and the
reader compatibility requirement. The install preference remains the
user-facing choice; the database record prevents a missing startup value or stale
handle from silently weakening it. Operation policy is immutable, but a policy
transition revokes older operations. Dispatch and commit check the generation.

Setting changes extend Vizor's existing pause-and-resume flow:

1. Block new discovery and drain or cancel accepted public work before reporting
   private mode enabled.
2. Persist the shared preference and database policy transition, with native and
   background work no less restrictive during the transition.
3. Invalidate old work and cached financial summaries, then resume under a new
   operation policy.

Preference and database writes are not one transaction. Interrupted transitions
resume conservatively under the stricter state; startup must reconcile them
before dispatch. Public behavior can resume only after an explicit setting
change is durably reconciled. A read-time default is not that authorization.
An import or preview without a wallet database must resolve the same shared
policy before its first network request.

## Migration and activation

### Additive migration and legacy evidence

Schema migration requires no seed and does not rewrite public balances. It must
support long-lived wallets, multiple seeds/accounts, imported-only databases,
and hardware-first wallets.

Existing remotely observed rows receive legacy provenance, not private
coverage. Preserve independently established local-send evidence, pending
transactions, outboxes, proposal locks, address reservations, and payload
provenance. Do not infer local creation from a row's presence or a later
observation height. One projected row can have several origins.

The existing transparent receive sidecar remains a public-path cache during
preparation. Its checkpoints, legacy address checks, and legacy balances cannot
certify private recovery.

### Isolated candidate recovery

Candidate commits update candidate events, coverage, pending work, and candidate
address-window progress only. They cannot change production LRZ balances,
spend links, locks, address-use flags, or receive-address selection. Derivation
logic can be shared, but candidate-only discoveries stay in the candidate watch
set until activation.

The candidate ledger never ingests the LRZ projection as discovery evidence.
Compare exact receive/spend and UTXO sets at a common accepted chain point,
not balances alone. Legacy parity is a useful discrepancy check, not an
independent correctness oracle or proof of complete history.

### Private activation and account promotion

Enabling private mode immediately stops public transparent discovery. Accounts
without qualified coverage enter initial private recovery: transparent input
selection and shielding are unavailable; independently eligible shielded-only
operations continue. Keep the previous amount explicitly marked last-known,
never current or spendable.

Existing candidate state can be reused only after revalidating its production
source, chain anchors, publication lineage, script bounds, and current watch
set. Test fixtures cannot qualify a production account.

An account is promotable when the complete current watch set has continuous
coverage through the accepted decision point, address-window expansion is
stable, no relevant pages or unresolved spends remain, supported receive/spend
history is available, and legacy discrepancies have been explained against
accepted-chain evidence. Display-only recipient, memo, or fee gaps are tracked
separately under the [history contract](#history-completeness-and-storage-contract).
Neither agreement with an incomplete legacy snapshot nor deleting mismatching
rows resolves a discrepancy.

A wallet-libraries transaction rechecks these conditions, materializes the
candidate projection, merges independent local evidence, records active
authority, and invalidates the candidate work generation. Preserve shared
transaction rows, pending-spend overlays, and locks. Legacy-only observations
must not contribute to the new authoritative UTXO set. Failure rolls back the
entire promotion; restart sees either the prior state or the activated account.

After promotion, ledger commits update the authoritative projection atomically.
If the chain advances or recovery becomes incomplete, transparent authorization
pauses until coverage catches up. The prior covered balance can remain visible
with its chain point. One account's recovery failure does not block an otherwise
ready account or unrelated shielded operations.

### Rollback and repair

Supported rollback uses a privacy-aware release or forward repair. Retain
durable evidence for rebuilding the projection; do not require a user to discard
the wallet database or pending local transactions. A restored database must
reconcile the install preference before networking and revalidate coverage.
An outage or disabled rollout keeps private policy and pauses transparent
operations. Returning to public discovery requires the existing setting change.

Test the designated supported rollback release against the upgraded database.
Do not claim that arbitrary older binaries will honor new privacy metadata;
a new marker cannot retrofit enforcement into an old application.

## Wallet-facing contract

Use `zcash_client_backend::data_api::transparent_ledger` for the product-neutral
contract. `TransparentLedgerRead` extends `WalletRead`;
`TransparentLedgerWrite` extends the read trait and `WalletWrite`. Reuse the
existing account and error types.

The API provides:

- a watched-script snapshot containing ownership, recovery bounds, and watch-set
  generation;
- one atomic `TransparentLedgerSnapshot<AccountId>`;
- one `apply_transparent_ledger_commit` operation for normalized events,
  coverage, resumable progress, and expected operation context; and
- a guarded account-promotion operation that performs the activation transaction
  described above.

Configuration and policy transitions are explicit. A recovery source cannot
choose its own destination or bypass promotion by marking a commit authoritative;
storage checks the account lifecycle and current policy.

```rust
pub struct ChainPoint {
    pub height: BlockHeight,
    pub hash: BlockHash,
}
```

`TransparentLedgerSnapshot` is the single balance-and-recovery result. Its
canonical fields and meanings are:

| Field | Meaning |
| --- | --- |
| Account, mode, authority | Account identity, configured mode, and whether current financial authority is public, private, or unavailable during recovery. |
| Target | Optional locally accepted `ChainPoint` captured for recovery; absent when the chain is unknown. |
| Covered / settled through | Optional accepted chain points for continuous coverage of the current account watch set; settled includes sealed ranges only. |
| Authorized balance | Optional transparent balance split into regular and coinbase `Balance` values, with existing confirmation and lock categories; absent when current financial authority cannot be established. |
| Last-known balance | Optional prior balance with its source and available chain point; legacy observations without a verified anchor retain that uncertainty. |
| Recovered net | Optional candidate amount from currently recovered events, explicitly unverified until coverage is complete. |
| Completion and blockers | Financial recovery state plus reasons such as publication lag, pending pages, unsupported receive/spend history, unresolved spends, or integrity failure; separate from display-only history gaps. |
| Diagnostic counts | Remaining work, unresolved spends, and unsupported scripts relevant to this account. |

A partially recovered net amount can overstate or understate the true balance.
It is neither an authoritative balance nor a reliable lower bound. Unavailable
is not zero. All fields come from one database read snapshot. Do not embed the
whole `AccountBalance`, which would conflate this result with shielded pools.

Existing `InputSource` methods remain the input-selection interface, with
ledger eligibility enforced internally. There is no separate selector callers
can bypass, and no standalone public ledger-rewind operation.

## Scripts and event evidence

Each watched script carries its account/scope and `required_from` bound.
Derivation today does not establish that the script had no earlier history.
A shielded account birthday is usable only when it is also a justified
transparent-history lower bound. Trusted supplied recovery information and
earlier known activity can move the bound earlier; it never moves later.

Unknown starts remain explicit and require recovery from genesis. Starting at
the earliest publication can make partial progress but cannot close an older
gap. Missing locally accepted historical anchors also remain incomplete; the
publisher cannot fill them with its own asserted hashes.

Receive content contains txid, output index, exact script, value, and explicit
coinbase classification. Spend content contains spending txid, input index,
and spent outpoint. Stable identities are:

```text
receive = transaction identifier + output index
spend   = spending transaction identifier + input index
```

The spent outpoint is checked content, not an extra identity component that
could hide contradictory spends for the same input. Retain unresolved spends
until their receives arrive; they block completeness for the affected account.
Reject incompatible canonical spends of the same outpoint; pending local
conflicts follow the existing wallet transaction rules.

Separate immutable content from mining placement and source observations.
Canonical placement records the mined height and locally accepted block hash.
Observations retain publication/revision identity, accepted-chain anchor, and
record bytes or digest. Identical content observed in another publication is
not a contradiction. Re-mining after an accepted rewind updates canonical
placement without changing identity. Conflicting immutable content, or
incompatible placements claimed on the same accepted chain, is an integrity
failure.

Local construction, reservations, and unmined/mempool observations form a
separate overlay. They can prevent input reuse or enrich history; they do not
advance coverage or become proof of absence.

## Durable state and atomic projection

Ledger state lives under the `tpir_*` namespace in the existing physical SQLite
wallet database. It stores policy/lifecycle metadata, scripts and generations,
events and source observations, coverage, resumable pending work, projection
origins.

Candidate and authoritative writes use the same validation rules but different
projection behavior. Candidate writes stop at isolated ledger state.
Authoritative writes atomically persist:

- validated events, observations, and unresolved-spend resolution;
- complete coverage intervals and pending-page progress;
- publication anchors and expected operation generations;
- address-use/window updates and any newly required recovery; and
- the corresponding LRZ output, spend, and transaction projection.

Partial pages may persist resumable progress but cannot advance coverage past
unfinished work. A validated negative filter result needs its own durable
coverage commit even when there are no events. Coverage cannot span missing
pages, unsupported scripts, or unvalidated ranges.

Financial correctness must not depend on cross-database crash atomicity.
Filters, manifests, and setup material may use a disposable cache; losing it
costs bandwidth, not evidence. Projection rollback removes only the invalidated
source's contribution, preserving independent local origins. The ledger does
not read back its own projection as evidence.

Projection supports known wallet activity in history without raw transaction
bytes; it does not promise a complete external-recipient list. Join transparent
effects to existing shielded effects by transaction identity and expose missing
details under the [history contract](#history-completeness-and-storage-contract).

The proposed compact activity metadata projects an optional fee, complete
transparent input count, and shielded-components bit with source provenance.
Apply it in the same database transaction as the associated source facts, keeping
known local fees immutable and rejecting contradictory assertions. Rewind only
the invalidated source contribution. A supplied fee is not independently verified
merely because a transaction row exists. Derive account movement and payment
amount as distinct history values under the
[activity calculation](#activity-calculation-and-explicit-acceptance); incomplete
display details do not advance ledger coverage or change input eligibility.

Preserve explicit coinbase classification in the existing balance and
input-selection queries: a missing transaction index must not make a PIR-created
output non-coinbase. Unknown fee, time, or other unavailable metadata stays
unknown rather than becoming a fabricated zero or triggering public enrichment.

## Coverage, synchronization, and financial authorization

Coverage binds a script and inclusive height interval to its source revision,
accepted terminal hash, sealed/provisional status, and original publication
anchor. Sealed publication is not chain finality: a reorg invalidates affected
sealed coverage too. A provisional revision replacement requires revalidation,
not extending the old revision's coverage by assumption.

A recovery run fixes the highest contiguous locally scanned `ChainPoint`.
This is distinct from LRZ's `TargetHeight`: a proposal intended for block
`T` needs coverage through accepted block `T - 1`. Live authorization also
requires local contiguous scanning through that decision point and no known
newer tip left uncovered. The future block `T` has no accepted hash to check.
Historical snapshots are informational and cannot authorize a current spend.

The bounded synchronization loop is:

1. Capture operation policy, accepted target, and chain/watch-set generations.
2. Validate configuration before dispatch, then publication network/genesis,
   schema, layout, and lineage.
3. Enumerate scripts and validate stored coverage against the accepted chain.
4. Download every applicable public filter and match scripts locally.
5. Retrieve matched shards privately, with query/byte/page budgets.
6. Commit validated progress after rechecking operation context in the database.
7. Expand the appropriate candidate or active address window and repeat at the
   same target until stable or a bound is reached.
8. Publish completion from durable state; recheck eligibility before promotion.

A shard extending beyond the fixed target may be retrieved and validated whole,
but only events through the accepted target enter canonical state or the
projection. Coverage retains both its accepted endpoint and original publication
anchor; publication refresh does not move the run's target.

No write lock is held across network I/O. Under the commit transaction,
revalidate policy generation, account existence, watch-set generation, and chain
anchors. Rewinds, deletion, imports, or bound changes invalidate affected work.
Expected window growth obtains a fresh watch snapshot for the next pass.
Stale work is retried from new context, not committed under obsolete authority.
Ordinary chain advance can leave an earlier valid commit useful but cannot make
it sufficient for a newer financial decision.

To consume transparent inputs in private spending or shielding, the affected
account must have complete coverage for its current watch set through the
decision point, no relevant pending pages or unresolved spends, no unsupported
receive/spend history or scripts, and a valid accepted receive. Apply existing
confirmations, coinbase maturity, spend, reservation, and lock rules as well.
There is no freshness tolerance.

Enforce this in individual-outpoint, address, batched, and value-bounded input
queries, plus proposal consumption and hardware finalization. Revalidate and
reserve inputs in the wallet transaction; a prior UI eligibility check is not
authorization. Existing legitimate same-proposal chained outputs use their
local construction evidence and reservations, not fictitious mined coverage.
A selector may continue with eligible shielded pools; a transparent-only
operation reports recovery unavailable rather than misleading insufficient
funds.

This gate follows the inputs being consumed. An unshielding payment funded
entirely by independently eligible shielded notes is not blocked merely because
transparent recovery is incomplete. Its discovery and enhancement still obey
the shared privacy policy. Any resulting own transparent output must satisfy
transparent eligibility before later spending, subject to the existing
same-proposal chained-output exception above. Receiving an output or knowing a
local send's details does not establish coverage of other transparent activity.

## Rewinds and account lifecycle

Integrate ledger rollback into LRZ's height truncation, chain-state truncation,
and rescan/rewind paths. Use the actual retained height and rescan floor
selected by each operation. Remove or invalidate unsupported canonical
placements, coverage, provisional revisions, pending work, and projection
contributions in the same database transaction as the chain change.

Never leave active evidence anchored above the retained height. If an ancestor
hash cannot be established, drop unverifiable coverage rather than invent an
anchor. Preserve independently valid local transactions, reservations, and
issued-address history; rewind must not make an exposed address unused again.
Recompute chain-derived address-use state separately.

Account import, deletion, and birthday lowering update script bounds, invalidate
affected generations, and integrate with Vizor's existing operation drain.
Delete account-owned ledger state and coverage atomically without deleting shared
transactions or another account's evidence. Adding earlier history cannot leave
a previously complete account marked current. Summary caches must invalidate
on these changes and on policy, promotion, and ledger writes.

## Failure semantics and qualification

The [two-layer history qualification plan](transparent-pir-history-qualification.md)
turns the activity cases into fixture expectations and client acceptance gates.
It is a future test specification, not evidence that those tests have run.

Timeout, overload, publication lag, cancellation, and budget exhaustion preserve
committed progress and leave recovery incomplete. Stale operation context
requires a new snapshot. Neither condition authorizes a source change.

Wrong network/schema, inconsistent digests, mixed revisions, or contradictory
content rejects the affected commit and ends trust in that session. Financial
eligibility remains blocked for affected state until revalidated. Database,
migration, or projection failure aborts the wallet operation; it cannot be
reported as successful synchronization.

Qualification requires an independent block-derived oracle for exact receive,
spend, UTXO, balance, and coverage results. Include:

- seedless upgrades of fresh, long-lived, multi-seed, imported-only, and
  hardware-first databases, with pending sends and prior rewinds;
- commit, promotion, and rewind failpoints; disk-full failures; process
  termination and WAL restart;
- idempotency, contradictions, spend-before-receive, negative filters, partial
  pages, unknown bounds/anchors, and address-window growth;
- coinbase maturity, all input selectors, software shielding, Ledger rounds,
  Keystone PCZTs, stale proposals, and local chained outputs;
- shielding, self-unshielding, external unshielding, combined transparent/shielded
  spends, and cross-account transfers, for preserved local history and seed
  restoration; include shielded-funded unshielding during incomplete transparent
  recovery and assert both financial effects and visible history;
- both discovery orders, duplicate/payload replay, and interruption between
  pool commits; retain a stable transaction identity, pending detail work, and
  correct history after restart and reorg;
- incomplete external outputs with shielded change, unknown fees/memos, mixed
  self-transfers and payments, and missing TEX grouping evidence; known debits
  remain visible without fabricated payment amounts or double-counted transfers;
- compact metadata versus an independent block-derived oracle: actual fee,
  complete input count, shielded-component presence, creating/spending transaction
  attribution, unknown/zero/non-applicable fees, and conflicting assertions;
- several owned inputs and external recipients, shared funding, and complete
  versus incomplete owned-effect coverage; fee metadata alone must require no
  txid lookup and must not assign a whole fee to one shared-funding account;
- canonical variable-length boundaries, overflow/truncation, unknown flags and
  versions, inline/page equivalence, fragment resumption, new publication lineage,
  and measured directory/page packing and query-count changes;
- future on-demand txid retrieval, validated cache reuse, bounded parent-output
  resolution, failure/cancellation without public fallback, and enrichment updates
  to the same visible history identity;
- same-height and sealed/provisional reorgs, re-mining, actual rewind heights,
  and concurrent import/deletion/policy changes;
- proof that candidate recovery cannot alter balances, selection, locks,
  address-use, or receive-address choice;
- request capture across sync, import, preview, fee/payload recovery, startup,
  setting transitions, cancellation, and native/background entry points,
  including shielded-first mixed discovery, stale queued public work, and
  server-supplied transparent-presence flags; and
- outage/lag exercises, supported rollback, and mobile resource and network-route
  measurements.

Production gates are fixture-backed wallet integration, real protocol validation
(including known-answer and malformed records), real-source candidate qualification,
independent publication verification, a controlled private cohort, then general
availability. Keep detailed comparisons local and export only redacted aggregate
diagnostics. Record the exact library pin, protocol/publication version, and
tested application release for each gate. Preparation alone qualifies none of
the remote protocol, service, or production privacy claims.

## Activity metadata implementation

Normalized recovery events now carry optional transaction metadata. `None` means
unavailable legacy evidence. `WholeTransactionFee` represents an exact fee,
unknown fee or coinbase's non-applicable fee; it remains separate from the
account-related `FeeState`. Metadata does not populate the local transaction fee
or replace local send records and intent.

SQLite records assertions with their account, source revision and mined height
in the same recovery transaction as events, coverage and pending pages. Any
conflicting assertion rejects the commit and enters the existing quarantine
path. Rewinds, trusted provisional replacement and ownership withdrawal remove
the associated assertions. The additive schema migration starts empty; storing
metadata raises the durable reader fence to version 7. Rollback requires a reader
that supports that fence.

History exposes agreed metadata only from active, qualified, non-quarantined
evidence. Aggregate outgoing payment is exact only for complete transparent
effects, transparent-only transactions, an exact fee, and distinct owned input
indices accounting for every published transparent input. Its value is owned
inputs minus owned outputs minus the whole-transaction fee. Shared funding,
mixed pools, incomplete coverage and unresolved inputs retain unknown or partial
amounts. Individual recipient details may remain incomplete even when this
aggregate is exact. Account movement reports known received and spent amounts
with a separate completeness flag; public unverified effects do not make it
complete. Metadata grants no qualification, promotion or spending authority.
