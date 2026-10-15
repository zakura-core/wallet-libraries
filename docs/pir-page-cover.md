# Page cover for transparent PIR recovery

Increments 1 and 2 (`docs/pir-reaction-leak-closure.md`,
`docs/pir-remaining-leaks-plan.md`) closed the reaction leaks: a service can no
longer steer what a wallet asks next by how it answers. This note closes one
passive leak in transparent recovery: which page tables a wallet reads inside a
directory shard, and how many page queries it sends there.

Terms. A **directory shard** is one shard of the published map. It holds up to
32 **page tables**, `pages-<j>`, each a consecutive block range, older to newer.
A script's history is a chain of **runs**: the directory entry names the newest
run, and a run's first fragment gives its fragment count and links to an older
run in an earlier page table. The walk reads runs in **rounds**. **N** is the
number of page tables in a shard's manifest that hold rows. A page table
without rows publishes no segment and cannot be queried; every page table of the
production map holds rows.

## 1. The leak

Without cover, an honest-but-curious service sees exactly the page tables that
hold the wallet's runs, and one query per fragment. Each table is a block
range, so the service learns roughly when the wallet's addresses were active
in that shard and how long their histories are.

The walk is the recovery engine's (`zakura_pir_transparent::engine`, `walk_chains`).
Page cover changes nothing in it and needs one thing from it: a typed budget
stop, `BudgetStop`, with which a transport declines a request it has not sent
(section 2). wallet-libraries owns the transport the walk calls, and every page
query passes through it one at a time. Page cover is a wrapper around that
transport, `PageCover` in
`zakura/pir-transparent/src/transparent_history_recovery/page_cover.rs`. It
sees each page query as the walk sends it (shard, revision, table, body) and
adds dummy queries around it.

## 2. The rules as built

Per directory shard S, per pass:

1. **No page work, no page queries.** If the walk sends no page request in S,
   the wrapper sends none either.
2. **A cover set C is chosen when S first needs pages.** For N of at most 3, C
   is every page table. Otherwise its size is 3 with odds 0.7, and uniform from
   4 to N with odds 0.3. C holds the table of that first request, every table
   the store's pending page work in S already starts in, and uniformly random
   other tables up to the size. When the known tables outnumber the size, C is
   the known tables.
3. **Every real page query becomes a sweep over C.** One query to each table
   of C, in a fresh uniformly random order, the real query in its table's slot
   and a dummy everywhere else. A dummy is a fresh query for row 0 of its
   table, built by the reference client's own `TableClient::prepare_prefix`
   with the table's `query_rows`, as the walk builds its own dummies, so it has
   the length of any query to that table. A dummy is never reused. Only the
   real reply goes back to the walk; dummy replies are not read.
4. **Growth.** A real query to a table outside C adds that table to C when its
   sweep fits the budget. A refused expansion leaves C unchanged so the padding
   already reserved for the old cover still fits. The walk only reaches such a
   table through a link to an older run. The service sees C grow by one table
   (section 4).
5. **Padding.** When S's page work ends, the wrapper sends cover sweeps over C
   until S's sweep count is the next power of two. Work ends at the next
   request that is not a page request to S's revision, or at the end of the
   pass. A failed cover sweep, or a page reply of the wrong length (rule 10),
   ends padding for the pass.
6. **Same C for the session.** The recovery handle keeps C in memory, keyed by
   the shard, its page table count and the chained identities of its sealed
   page tables, with every table growth added. A walk resumed by a later pass
   of the same session, after a budget stop or a content failure, sweeps the
   same C, so the service cannot intersect sets across syncs. A growing tail
   republished over the same sealed tables keeps its C. Reopening the companion
   draws a new session. Nothing is stored.
7. **Setups single out nothing.** The first time a session needs pages in a
   shard revision, the wrapper fetches the setup of every segment of every page
   table of S, all N, in table order, and hands the walk the ones it asks for from memory. All
   N rather than C: one page table's setup is 30,363 bytes, a quarter of one
   archive page query, and fetching every table also hides the tables whose
   setup the store kept from an earlier session. If the walk asks for a setup a
   second time, having dropped it after a mismatch, all N are fetched again.
8. **Budgets bound the total.** The wrapper counts every private query and
   private byte it sends, cover included, against the pass's limits. A query
   and its upload count before it is sent, so a failed one counts too; its
   reply counts when it arrives. A real sweep starts only if it, and the
   padding its sweep count then requires, fit: before sweep k it needs
   |C| x (P(k) - k + 1) queries and their bytes, where P(k) is the next power
   of two. Otherwise the pass stops there, between sweeps, and the padding
   already reserved is still sent. Bytes are projected from the query lengths
   and the scheme's response size; setups from the scheme's mask size. The
   side that gives is the walk: it stops early.
9. **Nothing reply-dependent.** The draw, the order and the padding depend only
   on the session's random source, N, the tables the store's pending work
   names, the first request's table, and the count of real queries.
10. **Every reply has its published framing.** Each page reply, real or
    dummy, must be exactly the length its table's scheme fixes, a header and
    the scheme's response per segment, and each segment's header must carry
    the revision and table binding and the epoch of the setup fetched for it,
    as the client requires of the real reply. This is checked before the
    sweep's next query is sent. Otherwise a service could fail one slot's
    reply and learn from the walk's reaction whether that slot was real. Each
    page setup reply must be no longer than the estimate admitted for it
    before the next setup is fetched. A reply that fails this fails its
    request and ends padding for the pass; a wrong epoch also makes the next
    attempt fetch every setup again. The check is the same in every slot and
    reads nothing past the headers.

Randomness comes from a ChaCha generator seeded from the operating system when
the companion opens. Tests seed it through `seed_page_cover`, which exists only
with feature `testing`.

### How a budget stop reaches the walk

The wrapper declines the request it cannot afford, and everything after it in
the pass, with the client's `BudgetStop`, naming the query or the byte budget.
Nothing of a declined request is sent. The walk treats it as its own budget:
it keeps the replies of the round received before the stop, saves their
fragments, commits every run they complete, and reports the sync incomplete on
that budget (`Outcome::More`). It does not retry or wait, as it would for a
service at capacity, and a real refusal or failure from the service is still
reported as one.

A round can therefore be longer than a pass: each pass reads the sweeps it can
afford and the next resumes after them. A pass makes progress whenever it can
afford the work that must happen together before its first page query (a
shard's directory phase when it is not yet done, and every page table's setup
when the session does not hold them) and one sweep with its padding. A budget
smaller than that reads nothing.

A malformed reply is bounded, not prevented: the transport reads a reply up to
the pass's response limit before rule 10 can check it, so one oversized reply
can carry a pass past its byte budget by up to that limit. Rule 10 keeps it to
one: the sweep sends nothing after it.

## 3. Cost

Measured from the production map and the 33 manifests it named on 2026-10-14
(the tail was republished during the fetch), the published init, and
wallet-pir `main`.

**Page tables per shard.** The 12 archive shards (`decoupled-32k-32k`) declare
32, 18, 20, 24, 10, 11, 9, 8, 9, 9, 13 and 11 page tables, 174 in all. Of the
21 sealed recent shards (`decoupled-2k-8k`), 16 declare one and 5 declare two.
The tail declares one. Every recent shard therefore covers all its tables, and
a shard with one table only pads.

**Bytes per page query and setup.** An upload is the 8-byte binding, a
13,824-byte key and 3.5 bytes per query row (28-bit coefficients). Archive
tables query their full 32,768 rows: 128,520 bytes. Recent tables query a
prefix of 2,048 to 8,192 rows: 21,000 to 42,504 bytes. A reply is 5,136 bytes
per segment, and every production table has one segment. One page table's
setup is 30,363 bytes.

**Server time per page query** (wallet-pir
`transparent/evidence/p8-trial-2026-10-12`, the shipped 8-bit profile, p50):
5.17 ms archive, 2.50 ms recent. This confirms the figures in
`docs/pir-remaining-leaks-plan.md`.

**Multiplier.** A shard with k real page queries sends |C| x P(k) queries plus
any growth. The expected |C| for N above 3 is 0.7 x 3 + 0.3 x (N + 4) / 2:
3.9 at N = 8, 4.2 at N = 10, 5.7 at N = 20, 7.5 at N = 32, and 4.9 averaged
over the archive shards.

| Case | Page queries without cover | With cover | Upload | Server time |
| --- | --- | --- | --- | --- |
| One archive chain of 3 single-fragment runs, N = 10 | 3 | 4 sweeps of about 5.8 tables (4.2 drawn, 1.6 grown): 23 | 2.96 MB, was 0.39 MB | 119 ms, was 16 ms |
| The same at N = 32 | 3 | 4 sweeps of about 9.4 (7.5 + 1.9): 38 | 4.83 MB, was 0.39 MB | 195 ms, was 16 ms |
| One recent chain, one run, N = 1 | 1 | 1 | unchanged | unchanged |
| One recent chain, one run, N = 2 | 1 | 2 | 2x | 2x |
| Restore from genesis, one address active in every shard | about 58 | about 340 | about 46 MB, was 6 MB | about 1.7 s, was 0.25 s |
| Steady-state sync, new activity in the tail (N = 1) | 1 | 1 | unchanged | unchanged |

The restore row assumes the archive medians (3 runs per chain, 1.21 fragments
per run) in all 12 archive shards and one run in each of the 22 recent ones. It
adds 5.3 MB of setups (all 174 archive page tables) against about 0.4 MB
before. Directory traffic is unchanged.

At the 20 queries per second the service passed on 2026-10-09 (schema v11,
20.51 QPS, p99 59 ms), the restore above adds about 280 archive page queries,
14 seconds of that rate. The 20 QPS gate has not been run against schema v12
or the 8-bit profile, and the service's maximum has not been measured.
Steady-state syncs, which mostly touch the tail, are unchanged.

**Budgets.** Vizor's per-pass limits are 256 queries and 96 MiB. The restore
above needs about 380 queries and 50 MB, so it takes two passes, two blocks,
where it took one. Raising the query limit to 512 keeps it to one pass; bytes
fit as they are. Under Vizor's one pass per block, a second pass delays a
restore by one block and costs nothing else.

Not verified: the distribution of runs per chain and fragments per run (the
medians above are from `docs/pir-remaining-leaks-plan.md`; the manifests give
only totals, 1.9 runs per script in archive shard 0, for example), the
service's headroom above 20 QPS, and the 20 QPS gate under v12.

## 4. What stays visible

- **Whether a shard had page work at all,** and which directory shards the
  wallet queries. Shard cover is not part of this change.
- **A chain leaving C.** Each link to a table outside C adds it, visibly, and
  the added table is real. A chain of r runs in a shard of N tables, under a
  cover of size c, grows about (r - 1)(1 - (c - 1)/(N - 1)) times. With the
  archive median of 3 runs, at c = 3 and N = 32, that is 1.9: most older
  runs' tables show. At N = 10 it is 1.5. Recent shards never grow: C is
  already every table.
- **A wallet that needs more tables than the drawn size** shows at least that
  many. Honest wallets reach 4 or more only through the 30% branch, so a cover
  of 4 or more is weak evidence of a long or multi-script history, and a cover
  that grows more than once is strong evidence.
- **The sweep count up to its power of two,** and the timing between sweeps.
- **A new C after the companion is reopened.** A service that sees two sessions
  can intersect their covers. The app decides when that happens, as with
  increment 2's in-memory allowances.
- **What a refusal reveals.** A request outcome stays exempt, as in increment
  1, but a service that refuses a cover sweep can tell padding from real work:
  after a refused real sweep the walk retries the shard, after a refused cover
  sweep the wallet moves on. A budget stop is not a refusal and is never sent:
  the service sees the pass end between sweeps.
- **Import discovery** (`discover.rs`) sends its own syncs without cover.

## 5. What this does not build

- No directory shard cover, no directory-count padding, no Enhance cover.
- No change to the walk beyond the budget stop it takes from its transport,
  and no release or crate publish.
- No new tables, migrations or stored cover state; nothing outlives the open
  companion.
- No transport work (Tor, unlinking services) and no server change.
- No off switch.

## 6. Open questions

- **A strict byte bound.** One oversized reply can still cross the pass's byte
  budget by up to the response limit (section 2). Holding every reply to its
  published length while it is read needs the expected length passed down to
  the HTTP exchange, a transport change this note does not make.
- **Archive growth.** Most older runs in archive shards show through growth.
  Covering every table of archive shards would close it at N times the page
  queries there, up to 32x. Recommendation: keep the drawn cover for now and
  decide with the PIR operators once the 20 QPS gate is rerun under v12.
- **Budget defaults.** Recommendation: Vizor's query limit 256 to 512, bytes
  unchanged at 96 MiB, so a full restore fits one pass. Smaller limits only
  take more passes.
