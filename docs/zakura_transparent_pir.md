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
vendored or forked here. What this wallet supplies is what that repository's
[adapter contract](https://github.com/valargroup/enhance-pir/blob/main/docs/transparent-pir/wallet-adapter.md)
asks a wallet for: a durable store, the scripts with the height each needs,
the block hashes the wallet has accepted, and the transports.

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

## What is trusted

The service is trusted to be complete. Every check the wallet makes — the
manifest it recomputes and compares to the map before reading a shard, the
filter digest, the exact script bytes in a directory row, the page header
against the entry that located it — detects corruption, stale data and mixed
publications. None of it establishes that the index matches the chain: a
service that returns a consistent lie passes every one of them. This is the
contract's trusted-indexer profile and no stronger one, and the wallet runs the
ledger beside its existing sync until the owner accepts that profile for
balance and spendability.

## The loop

Transparent tracking is a third loop beside scanning and enhancement, and it
does not share a step with either.

1. Fetch the published shard map and capture the wallet's own accepted scanned
   height and hash. Keep that target fixed across every pass and map refresh.
   If publication ends below it, return `publication-behind:<height>`.
2. Read the service's declared geometry and refuse it unless it is the schema
   this build reads and the chain the map describes.
3. Keep every account's window of unused addresses full, then hand the library
   every derived script with the first height it needs covered.
4. Let the library continue what the store holds: it asks the wallet's chain
   about every block the existing coverage rests on, rolls back anything the
   wallet has since rejected, truncates coverage from a tail revision the map
   has moved past, and then reads — filters, then manifests, then directory
   rows and pages — committing each shard as it goes.
5. If the run found activity at the edge of the address window, the window
   moved. Widen it and run again, so the scripts it produced are read over
   their whole required range. Bounded, so a wallet paid at every fresh
   address in turn still returns.

Step 3 is what makes a newly derived address correct rather than merely cheap.
A script the wallet derived yesterday has no coverage over the chain before
yesterday, and a single account-wide birthday would either re-derive everything
on every new address or silently grant a new script coverage it never had.
Coverage is therefore per script, from a required height the store never
raises, and the library reads each script over exactly the range it lacks.

The target comes from the wallet's `blocks` table, independently of publication.
The library checks accepted coverage endpoints against that chain snapshot.
A shard extending beyond the target is retrieved and validated whole, but only
events through the accepted target enter the ledger. Coverage keeps both its
accepted endpoint and the full publication's source anchor. Missing hashes
remain unknown; they are never filled from the publisher's claims.

The app reads balance and coverage together in one SQLite snapshot. It displays
coverage and incomplete state even when the recovered transparent amount is zero.
Unresolved spends, pending pages, publication lag, and a scan ahead of the last
accepted transparent anchor prevent a synchronized label.

## The store

The library's [`WalletStore`] is implemented over the wallet's own database, in
`wallet-store`'s `transparent` module, with the adapter in `wallet-transparent`
a type mapping and nothing more. What that buys is one transaction: a shard's
events, the coverage it establishes for each script, the page work still owed,
and the projection of those events into the balance either all land or none
do. A retry of a committed shard writes nothing new; a retry that differs in
any field is a contradiction, refused before anything is written. The wallet's
own rewind rolls the ledger back with everything else, in the same cut, so
coverage never rests on a block the wallet no longer has.

The events are kept in their own tables, apart from the wallet's output and
spend tables. Those are the wallet's view, and they are also written by a send
this installation built and by a transaction enhancement fetched whole; neither
may feed the library's ledger back to it. The ledger reads only what the ledger
wrote. Everything in these tables is re-derivable from the service, so they
live in the cache database and are rebuilt if it is dropped.

Two more things the store keeps, because a sync that forgot them would repeat
work that reveals nothing new but costs real bytes: the published setup
parameters for each table segment, keyed by everything they were derived under,
and every filter, keyed by the revision it belongs to.

## Coverage, and what stops a balance being called synchronized

A transparent balance is true as of a height, and the interface says which one.
`settled_through` is the height covered by sealed shards alone.
`covered_through` may be higher, because the last shard in a map is a growing
tail that will be republished as a new revision; coverage taken from one is
recorded with that revision's digest and re-derived when the revision is
superseded, never extended.

Three more states are carried rather than smoothed over, and the interface
must not call the balance synchronized while any of them holds:

- **The last sync stopped short.** A run has limits — private queries and
  private bytes, set to a mobile bound by default — and the store has a bound
  on the page work it will carry. Reaching any of them ends the run with
  everything so far committed and the rest owed; so does a service at
  capacity, a chain the wallet has not scanned to, or a window that keeps
  widening. The reason is kept beside the balance in the library's own words:
  `query-budget`, `byte-budget`, `pending-limit`, `overloaded:<shard>`,
  `chain-unknown:<height>`, `discovery-unbounded`. Someone else can create a
  large history by sending to a wallet, so a large history is not assumed to
  be voluntary, and it is never assumed to be finished.
- **Unresolved spends.** A spend whose consumed output the ledger never saw is
  recorded, not absorbed. It means missing coverage, an unsupported script
  class, or a bad response, and absorbing it produces a balance that is too
  high and looks perfectly normal. Kept rather than dropped, it attaches the
  moment the receive arrives, however much later that is.
- **Scripts outside coverage.** The private tables index scripts up to
  `MAX_SCRIPT_BYTES`, which covers P2PKH and P2SH. A longer script may appear
  in a filter and have no directory entry; it is counted and reported, and its
  miss is not read as absence.

## Two sources, never one

`FilterSource` and `ShardTransport` are separate traits upstream, and this
wallet keeps them pointed at separate hosts. Public filter bytes are identical
for every wallet and reveal nothing; private queries do not have that property,
and taking both from one service correlates them whatever the protocol says.
The configuration therefore has two URLs and no default that collapses them.
The reference HTTP adapters are upstream's, because they are what turns a
service's `409` into a revision refresh and its `503` into a bounded retry;
a wallet with its own HTTP stack implements the two traits itself.

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

The two halves are served by two different hosts, which is the arrangement
this design asks for rather than a happy accident:

| half | host | routes |
| --- | --- | --- |
| filters | `enhance-pir.valargroup.dev` | `/v1/filters/shards`, `/v1/filters/shards/{id}/filter` |
| shards | `transparent-pir.valargroup.dev` | `/v1/shards/init`, `/v1/shards/{id}/revisions/{digest}/manifest`, `/v1/shards/{id}/setup/{table}/{segment}`, `/v1/shards/{id}/query/{table}` |

The shard service serves the two-tier set: 174 shards from genesis, an
`archive-wide` tier below the six-month cutoff and a `recent-8k` tier above
it, covered through 3,473,686 under layout schema `transparent-shard-v7`. A
build pinned to an older schema refuses the service rather than decoding a
newer layout as the one it knows, which is the intended behaviour and was how
an earlier drift was noticed. Nothing in the wallet assumes where the set
begins: each script's required height is its account's birthday clamped to the
map's start, and a shard boundary below the wallet's birthday is one it was
never going to scan and is taken as read, so an archive from genesis is
readable without scanning the chain from genesis.

`tests/live.rs` exercises this against the real services, ignored by default:

```text
ZAKURA_TRANSPARENT_FILTERS=https://enhance-pir.valargroup.dev \
ZAKURA_TRANSPARENT_SHARDS=https://transparent-pir.valargroup.dev \
  cargo test -p zakura-wallet-transparent --test live -- --ignored --nocapture
```

`tests/recover.rs` exercises everything else against the same shard server run
in process over a synthetic chain paying the wallet's own scripts: real private
retrieval, a query budget that stops between pages and resumes exactly, a
restart, the wallet's own rewind, a reorg found by the ledger and one found by
the wallet, a replaced provisional tail, and two accounts with a gap advance in
one run. Each ends by comparing the ledger with an independent traversal of the
same events, and `tests/store.rs` runs upstream's store contract suite over the
wallet's store.

Neither URL is a default in the code. A wallet is told where to look, because a
default is a host it talks to because nobody chose otherwise, and the point of
having two is that the choice is deliberate.

## Consequences worth stating plainly

Coverage begins at the later of the wallet's birthday and the first height
the published set covers. A wallet whose birthday is below the set's start is
served from the set's start, and under a sole-source ledger its earlier
transparent funds are invisible rather than merely stale. A shard is read
whole, so a wallet born inside a shard holds that shard's earlier history for
its scripts as well.

When no service is configured, transparent tracking is *off* and reported as
uncovered. It is never reported as a zero balance: a wallet that showed zero
because it could not ask is worse than one that says it does not know.

The lattice arithmetic behind retrieval lets products wrap on purpose, which
Rust's debug overflow checks call an error. The workspace turns those checks
off for that one crate, as upstream does; a build that forgot would fail its
first private query with an overflow rather than a wrong answer.

`pool_types(true)` in `wallet-lwd` stays. Its reason was never transparent
detection — eligibility for private Ironwood enhancement is decided by a
transaction touching no other pool, and a stream pruned to a subset would make
a Sapling-touching transaction look Ironwood-only. That argument survives this
change intact, and the code says so where a future contributor will look.

[`WalletStore`]: https://github.com/valargroup/enhance-pir/blob/main/pir/transparent-wallet/src/store.rs

## State format

Derived layout version 4 stores source anchors on coverage, target anchors on
pending pages, and the number of validated records including those beyond the
accepted target. Page progress, events and balance projections commit together.
Exact-ancestor rollback replaces both height and hash; an unscanned wallet
rewind drops crossing coverage and clears the unverifiable anchor.

There are no released clients requiring migration. Earlier development layouts
are rejected through the existing version-mismatch error; use a fresh development
database for this format. No wallet files are deleted automatically.
