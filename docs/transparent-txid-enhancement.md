# Transparent txid enhancement

Status: prototype. This note describes the fourth wallet loop: after transparent
discovery records a transaction of ours without its raw bytes, the wallet keeps
durable work to fetch that transaction's transparent details by txid, checks
what comes back against what it already knows, and shows the result in the
transaction detail view.

## Four loops

| Loop | What it does | Where the work lives |
| --- | --- | --- |
| 1. Compact scan discovery | Trial-decrypts compact blocks | `scan_queue` |
| 2. Ironwood enhancement | Recovers Ironwood memos, outgoing notes and shape through Enhance PIR | `ironwood_enhance_*`, `tx_retrieval_queue` |
| 3. Transparent discovery | Finds transparent receives and spends: public lightwalletd lanes, or private transparent PIR recovery (`zakura-pir-transparent`) | `transparent_*`, `tpir_*` |
| 4. Transparent txid enhancement (new) | Fetches the transparent details of a transaction loop 3 or loop 2 recorded without raw bytes | `transparent_detail_work`, `transparent_tx_display*` |

Loop 4 is display only. Its failure never affects sync, balances, sends,
history classification, or `details_complete`. Until it succeeds the detail view
reports the details as pending or unavailable; it reconciles once the service is
back.

## Boundary

- **wallet-pir** owns the protocol client (`transparent-txid-client`): the display
  map, shard selection, the two private row queries per lookup, and the codec of
  the fixed-size display entry (`transparent-txid-display-v2`).
- **zcash_client_backend / zcash_client_sqlite** own durable work, validation,
  backoff and the read view. They do not depend on wallet-pir. The facts they
  accept are `TransparentDisplayFacts`, defined in
  `zcash_client_backend::data_api::transparent_ledger`.
- **zakura-pir-transparent** re-exports the client and maps wallet-pir's
  `DisplayEntry` to `TransparentDisplayFacts`
  (`display_facts(txid, entry, provenance, looked_up_height)`), refusing an entry
  whose tag is not the txid's or that disagrees with itself, and maps a lookup
  that found nothing to the outcome to defer it with (`deferral`). Its client's
  `refresh_map` fetches only the display map, to re-check coverage when only
  parked work remains.
- **Vizor** owns scheduling, transport, mode selection and the UI.

## Display facts

A display entry is 113 bytes, the same for every transaction, so every lookup
costs the same and a found txid looks like an absent one on the wire. It holds
the regular cases whole and names what it leaves out:

| Fact | Meaning |
| --- | --- |
| `coinbase`, `fee` | Coinbase flag; the exact whole-transaction fee, zero for coinbase |
| `input_count`, `output_count` | All transparent inputs (not a coinbase input) and outputs |
| `shielded_components` | Any Sprout, Sapling, Orchard or Ironwood component |
| `sender` | The first input, in input order, whose spent script is P2PKH or P2SH; `NonStandard` when inputs exist but none is; `Absent` exactly when there is no input |
| `outputs` | Outputs 0 and 1 as far as they exist, each a value and a P2PKH/P2SH address or none (P2PK, `OP_RETURN`, other) |
| `multiple_source_scripts` | The inputs spend two or more distinct scripts; only the first address-shaped one is given |
| `more_than_two_outputs` | `output_count > 2`; outputs past the first two are omitted |
| `shielded_and_transparent_funding` | There are transparent inputs and the shielded pools also contributed net value |

The publisher reports distinct spent scripts. It cannot know whether two
scripts belong to one wallet; only the wallet can tell its own inputs apart.

## How work is created

Work is one row per transaction in `transparent_detail_work`, keyed by the
wallet's transaction id and deleted with the transaction. `reasons` is a bit
set: 1 receive, 2 spend, 4 mixed. A row is written (reasons OR-ed into any
existing row) only while the transaction is mined, has no raw bytes, and has no
stored display facts (so re-reported receives, and re-promotion after leaving
and re-entering `PrivateRequired`, do not look a transaction up again):

- an active account's private ledger projects a receive or a spend (commit and
  promotion both project; candidate commits never do);
- Enhance PIR marks a mixed transaction as having private details it cannot
  supply (route 2), directly or when a transition to `PrivateRequired` rewrites
  an unresolved route 1 to route 2;
- a route-2 transaction is mined, by scanning (`put_tx_meta`) or a status
  observation. A route-2 marker written while the transaction was unmined (seen
  unmined, or rewound when `PrivateRequired` was applied) cannot queue work, so
  mining it does.

Public discovery never writes work: public lanes already queue the payload
through `tx_retrieval_queue`. Parent transactions (the outputs our transparent
inputs spend, whose height the wallet does not know) are never work: every
enqueue site and the backfill require a mined height.

Storing raw bytes (`put_tx_data`) deletes the work row and any display facts:
the raw transaction supersedes them.

Every enqueue site first re-validates stored display facts against what the
wallet now holds. Facts are validated when stored, but a later receive or spend
can contradict them: for example, facts stored while a ledger-only receive was
withdrawn (so not checked against it), and the receive reported again by a later
lineage. Contradicted facts are deleted in the same transaction, and the
transaction is queued for a fresh lookup.

The leaf migration backfills work for existing mined route-2 transactions and
for mined transactions with ledger-origin outputs (whose receive is still
placed) or spends that have no raw bytes.

These are new tables, not `tx_retrieval_queue` rows. That queue is payload work:
its rows are restamped by policy transitions and read by query type, and mixing
display work into it would let a display failure or retry hold payload work open.

## Listing

`transparent_detail_work(now, limit, map_sha256)` returns the due requests
(`txid`, `mined_height`, `reasons`) together with the handle's mode and the
durable policy generation, read in the same snapshot. Vizor fetches publicly
(`GetTransaction`) only when that mode retains public authority and the
generation is still current; otherwise only through the txid display service.

A row is due when the transaction is mined, has no raw bytes, is still related
to the wallet, and either

- its mined height differs from the height of its last attempt (a reorg re-arms
  it immediately and resets its backoff), or
- `next_attempt_at <= now` and it is not parked.

Related means the wallet still records an owned output or a spend of one that
financial queries count, a spend link, or a route-2 marker. A ledger-only
output whose receive was withdrawn keeps its row for history, but neither
relates the transaction, nor counts as owned in validation or the view.

Parked: a row whose last outcome was `NotCovered` or `Contradiction` while the
caller's map hash is absent or is the one that produced the outcome; an
`Unsupported` row while the caller has no map hash at all (any map, including
the first one seen, re-arms it). A parked row becomes due anyway seven days
after its last attempt, so a map that never changes cannot strand it.
Parking applies only without public authority: a map is the private source's,
and a public lookup answers with the raw transaction whatever the publication
covers, so under public authority these rows are due at their ordinary retry,
and `transparent_detail_parked` counts none.

`transparent_detail_parked(now, map_sha256, map_checked_at)` reports the rows
parked under the caller's current map only for want of a map change (`count`,
the map hash of the longest-parked row, and `refresh_at`). `map_checked_at` is
when the caller last fetched, or tried to fetch, the display map. `refresh_at`
is six hours (`TRANSPARENT_DISPLAY_MAP_RECHECK`) after the later of that time and
the newest parked lookup, since each lookup also refreshed the client's map.
When nothing is due, `count > 0` and `refresh_at` has passed, Vizor calls the
client's `refresh_map` and lists again with the returned hash. Without it, the
client would only refresh its map inside a lookup, which no parked row
triggers; with the bound, a parked row costs at most four map fetches a day.

An unmined (rewound) transaction is not listed; its row stays and becomes due
when it is mined again. Under a mode that retains public authority the listing
omits transactions whose payload retrieval `tx_retrieval_queue` already owns,
and privately protected Ironwood transactions (route 0), matching payload work.

Order: never-attempted and re-armed rows first, then the most recently mined.

## Outcomes and backoff

The caller reports a failed lookup with
`defer_transparent_detail(txid, looked_up_height, outcome, map_sha256, now)`.
The caller retains the mined height from the dispatched request. If the transaction's
current mined height differs, or it is now unmined, the result changes nothing. This
prevents a late failure from parking work that a rewind and re-mining made due again.
The library computes
the next attempt, with jitter derived from the txid and attempt count. The
attempt count restarts at 1 when the mined height changes or the outcome falls
in another class than the previous one (classes: `Unavailable` and `Protocol`;
`NotYetPublished`; `Absent`; the parked outcomes), so that minutes-apart
`NotYetPublished` retries do not lengthen a later `Unavailable` or `Absent`
backoff:

| Outcome | Meaning | Next attempt | View |
| --- | --- | --- | --- |
| `Unavailable { retry_after }` | Transport failure, overload, stale revision | 30 s doubling, capped at 1 h; at least `retry_after` (up to 24 h) | Unavailable |
| `Protocol` | The service answered with something unusable | 30 s doubling, capped at 1 h | Unavailable |
| `NotYetPublished` | The height is above the newest shard (`PlacementUnknown(Above)`) | 1 min doubling, capped at 5 min | Pending |
| `Absent` | The covering shard has no entry for the txid | 1 h doubling, capped at 24 h | Unavailable |
| `NotCovered` | No shard covers the height (`PlacementUnknown(Below)`) | at least 24 h, then parked until the map changes | NotCovered |
| `Unsupported` | The service does not offer display tables | at least 24 h, then parked until any map is seen | Unavailable |
| `Contradiction` | Facts disagreed with the wallet | at least 24 h, then parked until the map changes | Unavailable |

Parked rows are due again seven days after their last attempt regardless.

`store_transparent_display(facts, expected_generation, now)` returns:

- `Stored`: the facts passed validation; they are saved and the work row is deleted.
- `Superseded`: raw bytes are already stored, or the wallet neither has work for
  nor still relates to the transaction; nothing is saved.
- `Contradiction(kind)`: nothing is saved; if the looked-up height still matches the
  transaction's mined height, the work row records the outcome as `Contradiction` and is
  parked until the map changes. A stale placement leaves retry state unchanged.

A moved policy generation fails with `StaleTransparentPolicy` and changes nothing.

## Validation

Before anything is saved, the facts must agree with themselves (the codec's
rules, re-checked) and with everything the wallet already knows about the
transaction. Each failure is its own `TransparentDisplayContradiction`:

| Variant | Check |
| --- | --- |
| `Coinbase` | The flag matches a known `tx_index = 0` and recovered receive events; a coinbase transaction has no input, no fee, and no known spend |
| `Malformed` | The facts are well formed (`TransparentDisplayFacts::is_well_formed`) |
| `OutputIndexOutOfRange` | Every owned output financial queries count and every recovered receive is below `output_count` |
| `OwnedOutput` | Such an output at index 0 or 1 has the given value and script: P2PKH and P2SH by address; any other owned script faces an output without one |
| `Metadata` | Recovered metadata (`tpir_transaction_metadata`) has the same input count and shielded bit, a fee only when not coinbase, and an exact fee equal to the published one (an unknown recovered fee asserts nothing) |
| `Fee` | A stored fee equals the published fee; a coinbase transaction has none |
| `Shielded` | The shielded bit is set when the wallet knows a shielded note, sent note or spend in the transaction, or a route-2 marker |
| `InputIndex` | Every recovered spend's input index is below `input_count` |
| `InputCount` | The distinct outpoints the wallet knows the transaction spends (recovered spends, spend links, the spend map) do not exceed `input_count` |
| `SourceScripts` | `multiple_source_scripts` is set when the wallet knows two distinct spent scripts; when it knows the script of every input, it is set exactly when they differ |
| `Sender` | A non-standard sender is refused when the wallet knows an address-shaped spent script. When it knows every input's script, the sender is the first address-shaped one by input index (one of them when an index is unknown). With one source script, the sender is that script's address |
| `Funding` | When the wallet knows the value of every input: with the fee and the given outputs above the inputs, mixed funding must be set; with every output given, it must otherwise be clear, and a transaction without shielded components must balance exactly |

Contradictions on partial knowledge are only those the wallet can prove: a
check that needs every input applies only when the wallet knows every input.

Display facts are stored apart from financial state. They never change balances,
spendability, `details_complete`, or history classification.

## View

`transparent_display_view(account, txid)` returns (an output is owned when
`account` received it and financial queries count it):

- `Available`: `TransparentDisplayDetails` with the coinbase flag, fee, input
  and output counts, shielded bit, `sender`, the shown `outputs` (index, value,
  address with its encoding for the wallet's network, owned), `omissions`, and
  `source`: the raw transaction, or the display shard, revision, map hash and
  lookup height.
- `Pending`: work exists and has not failed yet or waits for the next
  publication, or (under public authority only) payload retrieval owns it.
  Work counts only while the listing would return it, now or once the
  transaction is mined again: work for a withdrawn or unrelated transaction, or
  for a route-0 transaction under public authority, shows as it would without
  work.
- `Unavailable`: work failed and will be retried, or no source exists.
- `NotCovered`: the display service does not cover the transaction.

`sender` is `Coinbase`, `Shielded` (no transparent input: unshielding),
`Address { address, owned }`, or `NonStandard`. A display record's sender is
owned when it is one of the account's addresses or trusted spend evidence shows
that the account spent an output paying it in this transaction. Raw transactions
require trusted spend evidence for an outpoint actually present in their inputs;
an unlocking script showing an owned address alone does not establish ownership.
Private spend evidence must belong to an active account, have a qualified
observation from a non-quarantined source and account, and match the transaction's
accepted mined height. Independently recorded public or local spends retain
their semantics. These same checks determine whether the account funded every
input before suppressing a multiple-source or shared-funding omission. Candidate
or withdrawn records still participate in conservative contradiction checks.

`omissions` lists what the view does not show in full, in a fixed order:

| Omission | When |
| --- | --- |
| `NonStandardSender` | No input shows a P2PKH or P2SH address |
| `MultipleSourceScripts` | Several source scripts and the account funded none of the inputs |
| `SharedFunding` | Several source scripts and the account funded some inputs but not all |
| `ShieldedAndTransparentFunding` | The shielded pools also funded a transaction with transparent inputs |
| `NonStandardOutput { index }` | A shown output has no address |
| `MoreThanTwoOutputs` | Outputs past the first two exist (`output_count` says how many) |

When the account funded every input, several source scripts are its own send
and not an omission; the first sender is still shown. Shared funding is the only
sign that another wallet or account took part, and only the wallet can see it.
A regular transaction (one source script or the account's own inputs, up to two
outputs with addresses, no mixed funding) has none, and
`TransparentDisplayDetails::is_complete` holds.

With raw bytes the view shows every output, and the sender is read from the
unlocking script of the first input that shows one, without fetching parent
transactions: a signature followed by a 33- or 65-byte public key is P2PKH (the
key's HASH160); a push-only script whose last push is a redeem script ending in
a signature check is P2SH (the redeem script's HASH160). Several inputs showing
different addresses, or one showing none, count as several source scripts.
Mixed funding is read from the shielded value balances.

`TransactionHistoryDetails` is unchanged; Vizor builds it as a struct literal.

## Public enhancement

Display facts omit only exotic cases. Fetching the raw transaction publicly
(lightwalletd `GetTransaction`) fills them in, but reveals the txid to the
server. Under `PrivateRequired` the wallet never does this on its own: Vizor may
offer it for a transaction whose view has omissions and `source` is `Display`,
and fetches it only when the user asks for that transaction. Storing the raw
transaction (`decrypt_and_store_transaction`) replaces the display facts with
the raw-transaction view.

## Privacy

In `PrivateRequired` details are fetched only through the txid display PIR
service; there is no automatic public fallback, including after failures. The
server learns the bucket and tier (archive or recent shard) of a lookup and its
timing. Every lookup sends the same two row queries, so it does not learn the
txid, the selected row, or whether the txid was found. In public modes Vizor fetches the transaction from lightwalletd
with `GetTransaction` and stores it through `decrypt_and_store_transaction`.

## Not built

No scheduler, transport, or UI (Vizor). No parent-transaction retrieval, so
the raw-transaction sender is read from unlocking scripts only. No display facts
for transactions the wallet does not relate to. No change to
balances, history classification, or `details_complete`.
