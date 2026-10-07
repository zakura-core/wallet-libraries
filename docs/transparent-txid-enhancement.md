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
  map, shard selection, the private directory and page queries, record assembly
  and the codec.
- **zcash_client_backend / zcash_client_sqlite** own durable work, validation,
  backoff and the read view. They do not depend on wallet-pir. The facts they
  accept are `TransparentDisplayFacts`, defined in
  `zcash_client_backend::data_api::transparent_ledger`.
- **zakura-pir-transparent** re-exports the client and maps wallet-pir's
  `TransparentDisplayRecord` to `TransparentDisplayFacts`
  (`display_facts(record, provenance)`), reusing the metadata mapping it already
  uses for recovery events.
- **Vizor** owns scheduling, transport, mode selection and the UI.

## How work is created

Work is one row per transaction in `transparent_detail_work`, keyed by the
wallet's transaction id and deleted with the transaction. `reasons` is a bit
set: 1 receive, 2 spend, 4 mixed. A row is written (reasons OR-ed into any
existing row) only while the transaction has no raw bytes:

- an active account's private ledger projects a receive or a spend (commit and
  promotion both project; candidate commits never do);
- Enhance PIR marks a mixed transaction as having private details it cannot
  supply (route 2), directly or when a transition to `PrivateRequired` rewrites
  an unresolved route 1 to route 2.

Public discovery never writes work: public lanes already queue the payload
through `tx_retrieval_queue`. Parent transactions (the outputs our transparent
inputs spend, whose height the wallet does not know) are never work.

Storing raw bytes (`put_tx_data`) deletes the work row and any display facts:
the raw transaction supersedes them.

The leaf migration backfills work for existing route-2 transactions and for
transactions with ledger-origin outputs or spends that have no raw bytes.

These are new tables, not `tx_retrieval_queue` rows. That queue is payload work:
its rows are restamped by policy transitions and read by query type, and mixing
display work into it would let a display failure or retry hold payload work open.

## Listing

`transparent_detail_work(now, limit, map_sha256)` returns the due requests
(`txid`, `mined_height`, `reasons`). A row is due when the transaction is mined,
has no raw bytes, still has a recorded output, spend or route-2 marker in the
wallet, and either

- its mined height differs from the height of its last attempt (a reorg re-arms
  it immediately and resets its backoff), or
- `next_attempt_at <= now` and it is not held: a row whose last outcome was
  `NotCovered`, `Unsupported` or `Contradiction` is held until the caller's
  current display map hash differs from the one that produced that outcome.

An unmined (rewound) transaction is not listed; its row stays and becomes due
when it is mined again. Under a mode that retains public authority the listing
omits transactions whose payload retrieval `tx_retrieval_queue` already owns.

Order: never-attempted and re-armed rows first, then the most recently mined.

## Outcomes and backoff

The caller reports a failed lookup with
`defer_transparent_detail(txid, outcome, map_sha256, now)`. The library computes
the next attempt, with jitter derived from the txid and attempt count:

| Outcome | Meaning | Next attempt |
| --- | --- | --- |
| `Unavailable { retry_after }` | Transport failure, overload, stale revision | 30 s doubling, capped at 1 h; at least `retry_after` |
| `Protocol` | The service answered with something unusable | as `Unavailable` |
| `Absent` | The covering shard has no record for the txid | 1 h doubling, capped at 24 h |
| `NotCovered` | No shard covers the height | held until the map changes, at least 24 h |
| `Unsupported` | The service does not offer display tables | held until the map changes, at least 24 h |
| `Contradiction` | Facts disagreed with the wallet | held until the map changes, at least 24 h |

`store_transparent_display(facts, expected_generation, now)` returns:

- `Stored`: the facts passed validation; they are saved and the work row is deleted.
- `Superseded`: raw bytes are already stored, or the transaction left the
  wallet; nothing is saved and the work row is deleted.
- `Contradiction(kind)`: nothing is saved; the work row records the outcome as
  `Contradiction` and is held until the map changes.

A moved policy generation fails with `StaleTransparentPolicy` and changes nothing.

## Validation

Before anything is saved, the facts must agree with everything the wallet
already knows about the transaction:

- the coinbase flag matches a known `tx_index = 0` and recovered receive events,
  and the metadata is valid for it;
- every owned output (`transparent_received_outputs`, `tpir_receive_events`) is
  present at its index with the same value and script;
- recovered metadata (`tpir_transaction_metadata`) and the stored fee are equal;
- the shielded bit is set when the wallet knows a shielded note, sent note or
  spend in the transaction, or a route-2 marker;
- every known spend input index is below the transparent input count.

Display facts are stored apart from financial state. They never change balances,
spendability, `details_complete`, or history classification.

## View

`transparent_display_view(account, txid)` returns:

- `Available`: outputs (index, value, script, decoded address when the script is
  standard, and whether `account` owns it), coinbase flag, fee, transparent input
  count, shielded bit, and provenance: raw transaction, or the display shard,
  revision, map hash and lookup height.
- `Pending`: work exists and has not failed yet, or payload retrieval owns it.
- `Unavailable`: work failed and will be retried, or no source exists.
- `NotCovered`: the display service does not cover the transaction.

`TransactionHistoryDetails` is unchanged; Vizor builds it as a struct literal.

## Privacy

In `PrivateRequired` details are fetched only through the txid display PIR
service; there is no public fallback, including after failures. The server learns
the bucket and tier (archive or recent shard) of a lookup, its page count, and
its timing. It does not learn the txid, the selected directory row, or overflow
page locators. In public modes Vizor fetches the transaction from lightwalletd
with `GetTransaction` and stores it through `decrypt_and_store_transaction`.

## Not built

No scheduler, transport, or UI (Vizor). No parent-transaction retrieval. No
display facts for transactions the wallet does not relate to. No change to
balances, history classification, or `details_complete`.
