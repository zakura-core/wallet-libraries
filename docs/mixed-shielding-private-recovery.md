# Private recovery of mixed transparent/Ironwood shieldings

A wallet that recovers a transparent-to-Ironwood shielding by private queries only
(`PrivateRequired`, private Ironwood enhancement) knows:

- its own effects: the transparent outputs it spent (transparent PIR spend events) and the
  Ironwood note it received (compact scanning);
- the Enhance PIR record for its received action: the authenticated memo, the service's
  transparent shape flags, and optionally the whole-transaction fee;
- the qualified transparent metadata on its spend events: the whole-transaction fee, the
  transparent input count, and whether any shielded component exists.

## What is now recovered (no wire change)

- The received memo, authenticated by decrypting the scanned note, even though the
  transaction's transparent details stay unsupported (route 2).
- The whole-transaction fee into `transactions.fee`, only when it agrees with every known fee,
  expiry, and displayed expiry. A disagreeing response is rejected without effect.
- The separate `has_transparent_outputs` assertion, with the mined height it was recovered at
  (`has_transparent_outputs_height`). `NULL` is unknown shape, and so is an assertion recovered
  at another height (the transaction was re-mined elsewhere since): it is queried again
  privately and a fresh answer replaces it. An assertion at the current height that a response
  contradicts rejects the response. This is trusted service display evidence; only the memo is
  authenticated by note decryption.
- Memo work for route-2 transactions, which is requeued on rescans and policy transitions and,
  for existing wallets, by the `ironwood_unsupported_memo_retry` migration.
- Shape evidence for existing route-2 wallets whose memos are already known, using one
  received-note-bound private metadata query. The additive `ironwood_transparent_output_shape`
  migration leaves old shape evidence unknown and queues that recovery; the additive
  `ironwood_transparent_output_shape_height` migration does the same for assertions recorded
  without their height. Public authority transitions and reorgs retain their existing dispatch
  guards; no public fallback is added.

## What the evidence cannot establish

Two shapes have identical evidence. Both spend the account's two transparent inputs (200,000
zatoshis), have no transparent outputs, a 20,000 fee, and two Ironwood actions with the account's
180,000 output at action 1:

1. Pure shielding: action 0 is the builder's padding. `OutputInfo::dummy` is a zero-value
   output with no OVK, so its outgoing ciphertext is encrypted to no key. The Ironwood builder
   uses `default_flags()`, which enables spends, so its dummy spend looks like any spend.
2. Another party spends 100,000 of its own shielded funds into action 0's 100,000 output. The
   pool's net inflow is still 180,000.

Neither action 0 is decryptable or OVK-recoverable by the wallet. The account's effects, the
transparent metadata, and the Enhance PIR record are the same. The test
`foreign_self_balanced_shielded_participation_is_indistinguishable` pins this.

The transparent txid display record (`TransparentDisplayRecord`, wallet-pir `648264bb`) adds the
complete transparent output list and coinbase flag to the same fee, input count, and
shielded-presence facts. Joined with the account's events it fixes the transparent side exactly
(every input, every output), and therefore the net shielded inflow. It does not change the
conclusion above: the remaining ambiguity is entirely inside the shielded bundle. (The adapter
does not fetch display records today.)

Evidence still missing after that join, all hidden by design:

- the values of shielded outputs the wallet cannot decrypt, including zero-value padding;
- whether any shielded spend is real rather than a dummy (spends are enabled in pure shieldings);
- which pools carry the shielded components (`has_shielded_components` is coarse).

A narrow no-wire path would exist only if every relevant shielded output's value could be
authenticated (including zeros) and other pools excluded, or if zero foreign shielded funding
were established independently. Neither is available: servers cannot detect real shielded
spends either.

Sender linkage: a standard shielding's own output is change to the account's internal address,
built with `internal_ovk = None` under `OvkPolicy::Sender`, so no key (Orchard or transparent
OVK) recovers it. The public path links it as sent by the account because it decrypts with the
internal IVK (`AccountInternal`); private recovery has the same fact (an internal-scope received
note in a transaction the account funded), but does not record a `sent_notes` row yet.

## Classification

Public history derived from full data has the same blind spot: `payments_accounted` balances the
account's settled effects against the canonical fee and does not prove padding is zero. Private
recovery does not reuse that inference silently. A mixed transaction without full data is
reported as `HistoryClassification::NetReconstructed` only when:

- every owned effect is complete;
- qualified metadata counts exactly the account's published transparent inputs;
- qualified metadata has an exact whole-transaction fee, which agrees with the canonical fee
  if one is stored; a missing canonical fee does not block reconstruction;
- Enhance PIR shape evidence recovered where the transaction is mined now explicitly says no
  transparent outputs exist;
- the account spent only transparent funds and received only Ironwood outputs, with no recorded
  outputs to others, and no other account of the wallet is known to have funded the
  transaction (spent one of its outputs, published one of its transparent spends, or sent an
  output);
- spent = received + fee.

The movement is final; the fee stays the whole transaction's (`FeeState::Unknown`) and no
aggregate payment is inferred. Anything else stays `Provisional`: another transparent funder,
funding by another wallet account, a receipt in another shielded pool, an external payment, an
unknown or stale shape, missing, unknown or disagreeing fees.

`zakura-pir-transparent`'s `mixed_shielding` test qualifies these rules over serialized
transactions: it builds, signs, proves and serializes each case, derives transparent events and
Enhance records from those bytes by the publishers' rules, and recovers through the in-process
transparent shard service and a native two-mask Enhance service, checking that no request
exposes public payload work.

## Qualified-fee workaround

The mixed Enhance PIR publisher can currently return a memo and shape without a fee. Once that
memo query is complete, no fee recovery work remains, so rebuilding or repeating sync cannot
fill `transactions.fee`. History now uses the exact fee from qualified transparent metadata
for the narrow net-shielding balance above. It does not copy that value into the canonical fee
column. Quarantined or unqualified transparent metadata, incomplete owned effects, a foreign
transparent input, unknown/present transparent outputs, a mismatched canonical fee, or a failed
balance leaves the entry provisional. A recovered memo is still required for complete payment
details. Even when net reconstruction succeeds, `FeeState::Unknown`, `AggregatePayment::Unknown`,
and the pending mixed-details marker remain: the whole fee is not proven to be the account's.

This is a wallet-library history workaround, not a publisher repair or a claim of complete
mixed-transaction reconstruction. A consumer that supports `NetReconstructed` can display the
owned transparent-to-Ironwood net transfer (for example 400,000 zatoshis received), but native
Vizor behavior must be tested after repinning the library.
