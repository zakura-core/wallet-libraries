# Transparent PIR as the wallet's only transparent ledger

This wallet stops learning about transparent funds from the chain stream and
from the server's UTXO index, and learns about them from private retrieval
instead. Public BIP-158 activity filters over content-sealed shards are
downloaded whole and matched locally; history is then privately retrieved from
the shards that matched and replayed into a UTXO set. That ledger is the only
source of transparent receives and spends the wallet has.

The client half comes from `valargroup/enhance-pir`: `transparent-events`,
`transparent-filter`, `transparent-shard` and `transparent-wallet`, entering
this workspace as a pinned git dependency. Nothing in that repository is
vendored or forked here.

## What this replaces, and why

Two mechanisms are removed by this change.

The first was local and cost nothing to widen. `wallet-lwd` asks for all four
pool types, so compact blocks carry `vin` and `vout`, and `wallet-scan` matched
`scriptPubKey`s against a watch set of every address the wallet had ever
derived. It named no address to anybody. `wallet_core_rewrite.md` argues at
length that this is why the fork's address-polling subsystem was never built
here, and that argument was correct as far as it went.

The second was not local, and is the reason the first was not enough. Descending
recovery meets a receipt at a high address index while the address window is
still narrow, so a restored wallet could hold funds it would never detect.
`SyncEngine::sweep_transparent` closed that by calling
`ChainSource::address_utxos` once per run — handing the server every address of
an account in a single request, which is precisely the linkage the rest of this
wallet is built to avoid. It was a deliberate, documented trade, made once at
restore rather than continuously.

Private retrieval closes both at once. A wallet recovers from its birthday
without naming an address, and without depending on having derived the right
address before the block went past. The disclosure that remains is stated below
rather than argued away.

## What is disclosed

Filters are downloaded for every shard from the birthday forward, matched or
not, so which filters a wallet asks for is not a function of its scripts. The
private queries that follow go only to the shards that matched, so the service
learns which chain ranges the wallet had probable activity in. That is a real
leak, and shards are sealed by content rather than by width, so the
localization is sharper during busy periods than quiet ones.

What is not disclosed: no address, no script, no outpoint and no transaction
identifier ever crosses the wire. A private query names a row in a table, and
both candidate rows of a matched script are queried against every segment of
the shard, so the segment a script lands in is never named either.

## The loop

Transparent tracking is a third loop beside scanning and enhancement, and it
does not share a step with either.

1. Keep the address window full, then read every derived script.
2. Group scripts by the height their coverage currently reaches.
3. Per group, fetch the published shard map, validate the shard filters from
   that group's start height forward, and match locally.
4. Privately retrieve the matched shards' directory rows and pages, and replay
   the events.
5. Apply the ledger and the coverage it earned in one database transaction.

Step 2 is what makes a newly derived address correct rather than merely cheap.
A script the wallet derived yesterday has no coverage over the chain before
yesterday, and a single account-wide birthday would either re-derive everything
on every new address or silently grant a new script coverage it never had.
Coverage is therefore per script, and a sync runs once per distinct start
height.

Step 3 binds what the service says to what the wallet already believes. Every
shard's parent and terminal block hashes must be on the wallet's own accepted
chain at the stated heights, checked with `check_range_batch` against the
`blocks` table. Events carry no block hash for the same reason: a wallet that
took an event's block hash from the server could be handed an event placed on a
branch it never accepted. Heights are resolved to hashes locally or not at all.

Step 5 is atomic and conservative. Coverage advances only when every segment of
every shard in the run was retrieved and validated. A crash, a timeout, a
malformed response or an exhausted budget leaves coverage exactly where it was;
the alternative turns an interruption into a silent gap that looks identical to
an empty range.

## Two sources, never one

`FilterSource` and `ShardTransport` are separate traits upstream, and this
wallet keeps them pointed at separate hosts. Public filter bytes are identical
for every wallet and reveal nothing; private queries do not have that property,
and taking both from one service correlates them whatever the protocol says.
The configuration therefore has two URLs and no default that collapses them.

## Coverage is a first-class number, not an implementation detail

A transparent balance is true as of a height, and the interface says which one.
`settled_through` is the height covered by sealed shards alone.
`covered_through` may be higher, because the last shard in a map is a growing
tail that will be republished as a new revision; coverage taken from one is
recorded with that revision's digest and re-derived when the revision is
superseded, never extended.

Two more states are carried rather than smoothed over:

- **Unresolved spends.** A spend whose consumed output the ledger never saw is
  recorded, not absorbed. It means missing coverage, an unsupported script
  class, or a bad response, and absorbing it produces a balance that is too
  high and looks perfectly normal. A balance must not be presented as
  synchronized while any exist.
- **Scripts outside coverage.** The private tables index scripts up to
  `MAX_SCRIPT_BYTES`, which covers P2PKH and P2SH. A longer script may appear
  in a filter and have no directory entry, and its miss must not be read as
  absence.

## Sole source means sole *discovery*

Three things still write to the transparent tables, and only one of them can
find money the wallet was not already looking at. That one is the ledger. The
distinction is worth stating precisely, because "only ledger" read as "only
writer" would delete two things that cost nothing and lose real data.

A transaction this installation built records its own transparent spends and
change when it is stored, before it is broadcast, through the ordinary
`store_sent_transaction` path. So a send does not wait for coverage and cannot
re-spend the output it just spent.

A transaction fetched whole by enhancement has its transparent bundle read.
Its identifier was disclosed in order to fetch it, so reading the bundle
discloses nothing further, and discarding it would lose the transparent side of
a transaction the wallet already holds — a shielding built on another device,
say — until a shard covering it was published.

Scanning records the outpoints a transaction it keeps consumes. It cannot
create an output; the store's spend map only ever attaches a spend to an output
the ledger recovered, which is a correction that lowers a balance and never
raises one.

None of the three can discover a transparent receipt. What waits for coverage
is a receive the wallet did not already have a transaction for, and a spend
made by another installation of the same seed. Both become visible when a shard
covering them is published.

## What is deployed

Verified live on 2026-09-07. The two halves are served by two different hosts,
which is the arrangement this design asks for rather than a happy accident:

| half | host | routes |
| --- | --- | --- |
| filters | `enhance-pir.valargroup.dev` | `/v1/filters/shards`, `/v1/filters/shards/{id}/filter` |
| shards | `transparent-pir.valargroup.dev` | `/v1/shards/init`, `/v1/shards/{id}/setup/{table}/{segment}`, `/v1/shards/{id}/query/{table}` |

The published set is three shards covering Ironwood activation to 3,473,474,
the last of them an unsealed tail. Its layout schema is `transparent-shard-v6`;
a wallet pinned to the previous revision reads `v5` and refuses the service
rather than decoding a newer layout as the one it knows, which is the intended
behaviour and was how the drift was noticed.

`tests/live.rs` exercises this against the real services, ignored by default:

```text
ZAKURA_TRANSPARENT_FILTERS=https://enhance-pir.valargroup.dev \
ZAKURA_TRANSPARENT_SHARDS=https://transparent-pir.valargroup.dev \
  cargo test -p zakura-wallet-transparent --test live -- --ignored --nocapture
```

What it measured on that run: the public floor every wallet pays is 281,036
bytes for three filters plus a 1,813-byte map. A fresh seed matches nothing and
so spends no private query, recovering in 2.8 seconds to coverage of 3,473,474
with 3,465,652 settled and one provisional shard. One real private query — a
directory row, retrieved and decoded against locally re-derived parameters —
costs 19,325 bytes of setup, 128,008 up and 5,136 down, and takes under a
second.

Neither URL is a default in the code. A wallet is told where to look, because a
default is a host it talks to because nobody chose otherwise, and the point of
having two is that the choice is deliberate.

## Consequences worth stating plainly

Coverage begins at Ironwood activation. A wallet whose birthday is below that
height is not served by this deployment, and under a sole-source ledger its
earlier transparent funds are invisible rather than merely stale.

When no service is configured, transparent tracking is *off* and reported as
uncovered. It is never reported as a zero balance: a wallet that showed zero
because it could not ask is worse than one that says it does not know.

`pool_types(true)` in `wallet-lwd` stays. Its reason was never transparent
detection — eligibility for private Ironwood enhancement is decided by a
transaction touching no other pool, and a stream pruned to a subset would make
a Sapling-touching transaction look Ironwood-only. That argument survives this
change intact, and the code says so where a future contributor will look.
