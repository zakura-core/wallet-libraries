# Shielding with compact scanning, Enhance PIR, and Transparent PIR

Status: conceptual draft for discussion and editing. This document describes
intended wallet behavior, including cases the current implementation does not
fully support. It changes no code and establishes no qualification result.

The implementation notes below were checked against `main` at
`cf1dcfec88062c420322578226d5240328002d3d` on 2026-10-06. They describe that
snapshot, not subsequent PR heads or deployed wallet behavior.

## Goal and scope

Combine transparent and Ironwood evidence into an accurate view of a shielding
transaction. The wallet should recover the financial effects first, enrich the
available details, and classify the operation only as far as the evidence permits.

This outline covers transactions containing transparent and Ironwood funds.
Transactions also involving Sapling, Orchard, or Sprout need additional cases
and the corresponding pool evidence. Pending status and multi-transaction
operation grouping are separate concerns.

The central distinction is between:

- Funds moving into the Ironwood pool in an on-chain transaction.
- This wallet moving its own transparent funds into its own Ironwood ownership.
- A payment from this wallet to another wallet's Ironwood recipient.

Those are different wallet interpretations of transactions that can share a
similar pool structure.

## Wallet ownership and independent ledgers

Keep each wallet's ledger independent. Never cancel its spends or receipts
against another wallet's effects, including another wallet belonging to the
same person.

A transaction ID identifies one on-chain transaction. Each involved wallet
records its own view of that transaction; sharing the ID does not merge ledgers.
Within a wallet, ownership must also remain account-scoped. An output owned by
another account is not change to the sending account.

Use the following notation:

- `T`: transparent funds.
- `I`: Ironwood funds.
- `owned`: owned by the selected account in the wallet whose view is being read.
- `external`: outside that wallet's ownership boundary.

### Ordinary self-shielding

```text
T_owned -> I_owned + fee

Transparent inputs spent:       0.0020 ZEC
Ironwood received:              0.0018 ZEC
Network fee:                    0.0002 ZEC

Transparent balance change:    -0.0020 ZEC
Ironwood balance change:       +0.0018 ZEC
Total account balance change:  -0.0002 ZEC
```

With sufficient evidence, the intended activity is "Shielded 0.0018 ZEC",
with the fee separately identified. The fee-sized total debit must not become
a payment-sized "Sent" row.

### A payment between separate wallets

```text
T_wallet_A -> I_wallet_B + fee

Wallet A:
  Transparent spent:     0.0020 ZEC
  Total balance change: -0.0020 ZEC

Wallet B:
  Ironwood received:     0.0018 ZEC
  Total balance change: +0.0018 ZEC

Transaction fee:         0.0002 ZEC
```

Wallet A sees an outgoing payment to an Ironwood recipient. Wallet B sees an
incoming Ironwood payment. Neither wallet offsets its effects against the other
wallet's effects. Wallet B may learn the whole-transaction fee as informational
metadata, but that does not make it a fee paid by B.

Retained local construction records may establish A's fee attribution and
recipient details. A fresh restore must preserve uncertainty where recovery
cannot establish them.

## Responsibility of each source

| Source | Contribution | Limit |
| --- | --- | --- |
| Compact scan | Discovers owned Ironwood notes and values, spends of previously discovered owned notes, transaction identity, mined placement, and commitment-tree data. | Does not by itself recover full memos, external recipient details, or original user intent. Spend detection requires the relevant viewing authority and prior note discovery. |
| Enhance PIR | Supplies missing Ironwood encrypted fields for memo recovery and supported outgoing-note recovery, transparent input/output presence flags, and optional whole-transaction fee metadata. | Does not supply the transparent input/output list or complete transparent discovery. Outgoing recovery depends on association, viewing keys, and implementation support. |
| Transparent PIR | Discovers owned transparent outputs and their values, spends referencing those outputs, owned change, and coverage evidence. Activity metadata may supply an exact whole-transaction fee and complete transparent input count. | Owned-script recovery does not enumerate arbitrary external transparent outputs, establish Ironwood ownership, or recover shielded memos. |

There are two ownership-discovery paths and one enrichment path. Enhance PIR
does not replace either discovery path. See the existing
[ledger architecture](transparent-pir-ledger-architecture.md#how-shielded-sync-and-history-fit).

The compact format permits transparent inputs and outputs. At the inspected
snapshot, compact scanning still has a TODO for consuming those fields as
transparent wallet discovery. This outline assigns that responsibility to
Transparent PIR rather than assuming the optional compact fields are consumed.

Note decryption authenticates the recovered note; it does not authenticate the
publisher's transaction-shape flags, input count, or fee. Those assertions retain
their separate source and trust requirements.

## Transaction-shape families

The following table describes actual shapes and their intended wallet views.
A recovering wallet may not yet have the evidence to identify the applicable
shape. Several rows can apply to a single complex transaction.

| ID | Actual shape | Intended wallet handling |
| --- | --- | --- |
| S01 | `T_owned -> I_owned + fee` | Full self-shielding. One transaction showing the Ironwood amount received and fee separately when established. |
| S02 | `T_owned -> I_owned + T_owned_change + fee` | Partial self-shielding. Transparent change remains transparent; it is not included in the shielding amount. |
| S03 | `T_wallet_A -> I_wallet_B + fee`, optionally with change to A | Separate ledgers: A records an outgoing payment and B records an incoming Ironwood payment. No cancellation between wallets. |
| S04 | `T_account_A -> I_account_B + fee` within one wallet | Preserve A's debit and B's credit independently. Identify the account transfer when ownership or retained intent supports it; do not treat B's output as A's change. |
| S05 | `T_owned -> I_external + fee`, optionally with owned change | An outgoing payment to an Ironwood recipient. Preserve the owned debit even when recipient details cannot be recovered. |
| S06 | `T_owned -> I_owned + I_external + fee`, optionally with transparent change | Self-shielding combined with an Ironwood payment. A shielding label must not hide the external payment. |
| S07 | `T_owned -> I_owned + T_external + fee`, optionally with owned change | Self-shielding combined with a transparent payment. Owned-script recovery alone does not return the external transparent output. |
| S08 | `T_owned + I_owned_inputs -> I_owned_outputs + other outputs + fee` | Combine both pools' effects. The net Ironwood increase is not the gross Ironwood receipt; preserve any accompanying payments. |
| S09 | `T_owned + T_other -> Ironwood outputs + other outputs + fee` | Shared transparent funding across accounts or wallets. Recover each account's effects; do not assign all outputs or the whole fee to one contributor. |
| S10 | `T_owned + I_other_inputs -> I_owned + other outputs + fee` | Foreign Ironwood participation. Owned pool movements can be final while payment or fee attribution remains uncertain. |
| S11 | `T_external -> I_owned + fee` | Incoming Ironwood payment. This wallet did not shield its own transparent funds and must not record an owned transparent spend or account-paid fee. |

Input and output multiplicity is independent of these families. Multiple
transparent inputs, multiple Ironwood notes, multiple recipients, and reused
addresses must preserve the same ownership and accounting rules.

To describe every combination within scope, vary four axes:

| Axis | Possibilities |
| --- | --- |
| Transparent input ownership | Selected account, other accounts in this wallet, external participants, or a mixture. |
| Ironwood output ownership | Selected account, other accounts in this wallet, external recipients, or a mixture. |
| Transparent outputs | None, selected-account change or other owned outputs, other-account outputs, external payments, or a mixture. |
| Real Ironwood spends | None, selected-account spends, other-account spends, external spends, or a mixture. |

For each combination, separately vary retained construction records versus a
fresh restore, viewing authority, and source completeness. These change what
the wallet can know, rather than the underlying transaction shape.

Ironwood action counts do not establish real value-bearing input counts because
dummy actions exist. Failure to decrypt an output does not prove it is dummy or
absent.

## Accounting before interpretation

For one account in one wallet, define:

```text
T_spent     = value of owned transparent inputs consumed
T_received  = value of owned transparent outputs created
I_spent     = value of owned Ironwood notes consumed
I_received  = value of owned Ironwood notes created

Transparent change = T_received - T_spent
Ironwood change    = I_received - I_spent
Total change       = Transparent change + Ironwood change
```

These are known amounts until ownership discovery and input-value resolution
are complete. A recorded zero must not be interpreted as proven absence while
coverage is incomplete.

For simple self-shielding with no real Ironwood inputs or external payments:

```text
T_spent - T_received = I_received + fee
```

For mixed owned inputs, use `I_received - I_spent` for the net Ironwood change.
Some received notes can replace Ironwood funds consumed in the same transaction.

### Matching arithmetic does not prove simple shielding

These two transactions have identical effects on the selected account. The
amounts and fee below are illustrative, not fee-policy recommendations.

```text
A:
  My transparent input:             10
  My Ironwood output:                9.9
  Fee:                               0.1

B:
  My transparent input:             10
  Someone else's Ironwood input:     5
  My Ironwood output:                9.9
  External transparent output:       5
  Fee:                               0.1

My account in either case:
  Transparent change:              -10
  Ironwood change:                   +9.9
  Total change:                      -0.1
```

B contains another participant and an external payment. Owned-script recovery
does not reveal that external output. Retained and trusted transparent-output
presence evidence can distinguish A from B; unknown presence is not false.

Even "no transparent outputs" does not exclude foreign Ironwood inputs and
outputs whose values balance internally. Accordingly, a balancing account
equation must not certify that the entire transaction had no external payments.

Keep these conclusions separate:

1. All owned effects are known.
2. The whole-transaction network fee is known.
3. Payment and fee attribution to this account is known.
4. The original operation intent is known.

The first two do not automatically establish the last two. A restored wallet
can show final transparent and Ironwood movement with incomplete payment
details. Retained construction records can support a richer interpretation.

## Joining evidence and handling arrival order

Within each wallet, join the sources through one transaction identity while
keeping pool-specific effects and progress independent.

| Available evidence | Intended behavior |
| --- | --- |
| Compact scan first | Record the Ironwood receipt or owned spend. Keep the transaction interpretation provisional while transparent discovery is incomplete. |
| Transparent PIR first | Record the transparent spend and owned outputs as the applicable qualified evidence permits. Keep destination or purpose unresolved until shielded discovery catches up. |
| Both discovery paths complete | Calculate final owned pool effects and net change. Resolve labels and attribution only as far as the evidence permits. |
| Enhance arrives later | Add supported memos, outgoing details, and metadata to the same transaction. Do not add a duplicate financial receipt or spend. |
| Memo arrives without fee | Retain the memo and preserve independent pending fee work. Completing one detail does not complete all enhancement obligations. |
| A spent transparent parent is unresolved | Preserve the known spend identity, but keep its value and derived movement incomplete until the parent output is privately resolved. |
| A source lags, fails, or does not cover the transaction | Preserve known facts and their provenance. Keep missing facts unknown; do not infer absence or select a public lookup fallback. |

Deduplicate transparent outputs by outpoint and Ironwood outputs by pool,
transaction, and action identity. Neither discovery source replaces the other's
effects with its partial view. Repeated responses must not change the totals.

Contiguous compact scanning with sufficient viewing authority establishes
owned shielded effects. Transparent completeness requires the applicable
qualified coverage and resolved spends. Completion of either path does not
certify the other path's progress or ledger authority.

Reorgs, source replacement, and stale responses must invalidate the affected
evidence and recompute the derived view. Conflicting assertions are integrity
failures, not last-writer-wins updates. Preserve independent local construction
records.

Confirmation, financial completeness, and detail completeness are separate. A
transaction can be mined and have complete owned effects while its memo,
recipient breakdown, or account fee attribution remains unknown.

In required-private mode, missing details never authorize public address,
script, transaction-ID, outpoint, or parent-output lookups.

## Current implementation boundary

At the inspected `main` snapshot:

- [Enhance records](../zakura/pir-enhance-types/src/lib.rs) contain separate
  transparent input/output presence flags, encrypted Ironwood fields, and
  optional whole-transaction fee metadata. That metadata is not authenticated
  by note decryption.
- [Compact scanning](../librustzcash/zcash_client_backend/src/scanning/compact.rs)
  leaves transparent wallet discovery as a TODO and excludes mixed transactions
  from its eligible private outgoing enhancement plan.
- [SQLite Enhance application](../librustzcash/zcash_client_sqlite/src/wallet/enhance_pir.rs)
  routes `has_transparent` results through `require_transparent_details` before
  subsequent memo, fee, and outgoing writes. The conceptual join above is not
  evidence that mixed enhancement already works.
- [Transparent activity metadata](../librustzcash/zcash_client_backend/src/data_api/transparent_ledger/activity.rs)
  distinguishes whole-transaction fee from account-related fee and carries
  transparent input count and shielded-component presence.
- [History reconstruction](../librustzcash/zcash_client_sqlite/src/wallet/transparent_ledger/history.rs)
  limits exact aggregate payment inference from that metadata to complete
  transparent-only funding. Mixed pools retain conservative unknown or partial
  attribution.

These notes are library source observations. They establish neither consumer
UI behavior nor production activation, deployment, or end-to-end qualification.

## Acceptance cases for the outline

For every shape family, compare a wallet retaining its construction records
with a fresh restored wallet. Require agreement on recoverable financial facts;
do not require restoration of intent that the chain does not encode.

At minimum, exercise:

- Full self-shielding and shielding with transparent change: one activity,
  correct pool effects, and no fee-sized payment row.
- Separate wallets: independent sender debit and recipient credit, with no
  cross-wallet cancellation or recipient-paid fee.
- Separate accounts in one wallet: correct account ownership and no treatment
  of another account's receipt as sender change.
- External Ironwood payments, mixed self-transfer/payment shapes, shared
  funding, and owned or foreign Ironwood inputs.
- The offsetting foreign-input/external-output example above, unknown
  transparent-output presence, and foreign shielded participation with no
  transparent outputs.
- Several inputs and outputs, duplicate delivery, both discovery arrival
  orders, incomplete coverage, and unresolved parent values.
- Memo-first/fee-later delivery, reopen, reorg, stale responses, and conflicting
  metadata. Missing fee is never silently zero.
- Required-private recovery with public lookup routes unavailable.

Expected amounts and shapes must come from independently decoded transactions,
resolved prevouts, authored ownership, and accepted chain data. A synthetic
history row does not qualify the real publication, transport, persistence, or
wallet presentation paths. See the existing
[history qualification specification](transparent-pir-history-qualification.md).

## Questions for refinement

- What evidence permits a restored self-transfer to receive a final "Shielded"
  label while payment or fee attribution remains incomplete?
- How should the activity row present complete owned movement with incomplete
  recipient details, and how should that differ from a partial balance delta?
- Which mixed outgoing details can the existing Enhance path recover after
  integration, and which require additional private transaction details?
- How should a transaction combining self-shielding and payments expose its
  components without duplicating the transaction or hiding a payment?
