# The remaining wallet PIR privacy leaks

Increment 1 (`docs/pir-reaction-leak-closure.md`) closed the reaction leaks in
transparent recovery, transparent receipts and Ironwood Enhance. Within a sync,
the requests a wallet sends there no longer depend on what the replies
contained. Across syncs, a record that fails on content is asked at most three
times.

This plan covers what is left. It ranks the remaining leaks, sets the scope of
increment 2, and sketches the later increments. Increment 2 changes the wallet and Vizor. The status polling change is
dropped; the remaining wallet changes delay Enhance queries and widen restores.

Terms, as in increment 1. A **content outcome** is anything the wallet reads
from a private reply: a record, "not in the table", or bytes that fail to
decode or verify. A **request outcome** is a refusal the server makes without
evaluating the private query: an HTTP status, overload, a stale publication, a
timeout. Only content outcomes can be aimed at chosen rows. An **active** leak
needs the service to change its answers; a **passive** one only needs it to
watch.

## 1. The leaks, ranked

| Leak | Who can use it | What it reveals | Cost to fix | Test | Increment |
| --- | --- | --- | --- | --- | --- |
| Status replies steer polling: a forged "mined" stops it, one bad reply stops all private status for the session, a missing record fails the sync | Active | The transaction's status bucket, about 4 transactions today | Wallet and Vizor | Exact transcript | Deferred |
| Status polling stops at the mined block | Passive | The mined height; with the broadcast time, often the transaction | Needs traffic cover | Exact transcript | Deferred |
| Vizor stops private Enhance for the rest of the sync after an unreadable or rejected reply | Active | The note position | Vizor only | Exact transcript | 2 |
| The first Enhance query follows the sync that found the transaction | Passive | The block range of a recent transaction | Wallet only | Seeded timing | 2 |
| The Enhance content-failure cap resets when the wallet is reopened | Active, across restarts | As the row above, two bits per record per session | Wallet only | Exact | Open question |
| Page queries per entry follow history size; directory queries per shard follow the number of matched scripts | Passive | A size class for an address's history in a shard | Server: more page and directory queries | Statistical | 3 |
| Private queries go only to shards whose filter matched | Passive | The block ranges where the wallet has activity | Server: one or more queries per shard in range | Statistical | 3 |
| A filter lists a script the service already knows | Active, needs the script | Whether this client watches that script | Same as the row above | Exact | 3 |
| The Enhance shard follows from the note position | Passive | A coarse range of note positions | None while there is one shard; then times the shard count | Exact | 3 |
| Import discovery runs extra passes | Active, once per import | Which matched shards belong to a confirmed account | Wallet only | Exact | Accepted |
| A filter forged to match every script | None | Nothing: the filter format rules it out (section 3, change E) | None | Statistical | Pin test only |
| Recovery range, receipt shard and bucket, counts, timing, network address, linking across services | Passive | Ranges, times and identity | Transport | None | Accepted (section 8) |

The status and Vizor Enhance rows come first for the reasons increment 1 gave.
They identify one record rather than describe a range or a size. Their fixes
send at most a few more queries. A test can compare request transcripts byte
for byte. The two timing rows follow because they are wallet-only and cheap,
and because the status fix closes its active and passive leaks with one
change.

Status matters more than its table size suggests. The table has 8,192 rows,
and the transaction's row is a hash of its txid. At the admission ceiling a
row would hold about 192 transactions (wallet-pir
`enhance/docs/architecture_status.md`). In use it holds about 4: 32,331
entries over 8,192 rows. One row is close to one transaction.

## 2. What increment 2 enforces

**Status polling is unchanged.** The proposed fixed status window and expiry
cover poll are dropped from increment 2. The wallet continues polling unresolved
transactions and stops after a conclusive status; there is no new attempt cap.
The broadcast height is already visible to the broadcast service, and status
query timing remains observable. Hiding traffic timing needs broader cover
traffic rather than a per-transaction window.

**Enhance waits stay in session memory.** Reopening draws queued waits again.
A restart is an application action, and the fresh wait is between zero and two
minutes; a position first read before a write waits the full two minutes.

**Enhance replies do not steer the rest of the sync.** An unreadable reply or
a rejected record fails that position only. The other positions are still
queried in the same order, and the failure counts toward the existing cap of
three.

**Enhance items wait a random time before their first query.** When an item
is first queued, the wallet draws a delay of 0 to 2 minutes from its random
source and does not query the item before then. A rescan in the same session
keeps the drawn time.

**A restore watches a fixed window.** Until an account is activated, its
transparent recovery watches 50 external and 25 internal addresses, whatever
the replies show, so a typical restore completes in one sync (change F).

## 3. Changes

Increment 2 has two pull requests, one per repository (section 5). Changes D and F are in wallet-libraries; A is dropped. B and C are separate Vizor work. Each change lists the
files, the rule, and its tests.

Every test lands in a first commit that contains only the tests. That commit
must fail on its parent, and the pull request names the assertion that fails
there. An increment 1 test passed against the old code; this step shows each
new test can catch the regression it is meant for.

### A. Status poll window (dropped)

This change is not part of increment 2. No fixed-height window, expiry cover
query, status-poll session, settled-query API, or status-row error split is added.
Status polling keeps the existing unresolved-work and expiry rules. Replies can
still influence when it stops; closing traffic-analysis leaks is deferred.

### B. Status reply handling (separate future work)

Vizor still needs an independent design for handling a failed status lookup
without skipping unrelated transactions or turning an inconclusive reply into
absence. The removed status-window APIs are not prerequisites or caller
requirements. No status-poll session, settled cover work, or private-poll
acknowledgment is introduced by this increment.

### C. Vizor Enhance after a bad reply (Vizor)

`run_queries` (`rust/src/wallet/sync_engine/enhancement/payload/private.rs`)
ends the pass on any error other than coverage and routing. That includes a
row that fails to decode. A rejected record also ends it. The coordinator
(`payload/coordinator.rs`, `defer_after`) then turns private Enhance off for
the rest of the sync. The positions after the bad one are never sent, so a
dishonest service sees where the walk stopped.

The Vizor increment 1 branch may already route unreadable replies to
`record_ironwood_enhance_unreadable` and keep one `EnhancePirSession`. Change
C covers whatever it leaves:

- In `run_queries`:
  - `ClientError::Response`, and `ClientError::Row` holding `Response` or
    `Pir`, are unreadable. Pass that batch's requests to
    `record_ironwood_enhance_unreadable`, then continue.
  - `Row` holding `Transport`, `HttpStatus`, `Json` or `Generation` stays a
    request outcome.
  - A body over the size limit, or a length or binding mismatch, is a request
    outcome, as in transparent change C.
- A rejected record no longer defers the sync. The store already counts it.
- `RecoveryWallet` gains `record_unreadable`, implemented for `WalletDatabase`
  under the write lock.

Tests use the scripted `Service` in `payload/tests.rs`:

- **Transcript.** The service answers row X with a truncated body. The
  request transcript (path, body length, order) equals the transcript of an
  honest service. Reverted, it ends at X.
- **Unreadable call.** The call to `record_unreadable` carries X's requests.
- **Real database.** Three syncs with the same corrupt row leave the position
  as `EnhancePirSuspension::Rejected`.

### D. Enhance not-before time (wallet-libraries)

Today an Enhance item is due as soon as it is queued.
`transaction_enhancement_work` (`zcash_client_sqlite/src/wallet/enhance_pir.rs`)
has no time condition. `queue_transaction` deletes and re-inserts the memo and
outgoing rows on every scan, so a time kept in those rows would be drawn again
at every rescan.

No table or migration. Each position's not-before time is kept in the
`EnhancePirSession`, beside #180's content-failure counts.

Library changes:

- The delay is drawn uniformly from 0 to 120 seconds with the wallet's
  `rng`, and added to the wallet's `clock`, when a wallet write first sees the
  position in the session: when scanning queues it, when rediscovery rebuilds
  it, or at the session's first `update_chain_tip`. A read cannot draw, so a
  position read before any write waits the full 2 minutes.
- `transaction_enhancement_work` lists any position whose time is later than
  now as waiting. The read impl gains a `CL: Clock` bound, so the signature
  does not change.
- `EnhancePirWork` gains `Waiting { request, not_before }`.
  `zakura/pir-enhance` `PreparedWork` counts these as `waiting`, and treats
  work with waiting items as incomplete, as it does suspended items.
- The time is forgotten when the position's work completes. A rewind that
  truncates the position forgets it, so a later requeue draws a new time.
- A fresh session draws each queued position's wait again. The restart is the
  app's doing, not a reply's; it costs at most a fresh 0–2 minute wait.

Tests, in `wallet/enhance_pir/tests.rs`, with `test_clock` and a seeded
`test_rng`:

- **Not due early.** At the queue time the item is `Waiting`. After its time
  it is `Query`. Reverted, it is `Query` at once.
- **Seeds.** Two seeds give different times. Items found in one scan get
  independent times.
- **Rescan.** A rescan keeps the time. Reverted to storing the time in the
  memo row, it changes.
- **Fresh session.** A new session draws the wait again and keeps it across a
  rescan.
- **Completeness.** `PreparedWork` is incomplete while an item waits.

Vizor needs one change for D, carried in its pull request: show waiting items
as pending. Its checkpoint at each block picks them up once due.

### E. Pin the filter bound (wallet-pir, follow-up)

Increment 1 noted that a service could set every bit of its filters so that
every watched script matches. The filter format rules this out:

- A Golomb-coded filter with N elements maps each script into
  `[0, N·M)`. Validation rejects any value outside that range (wallet-pir
  `transparent-filter/src/validate.rs`, `validate_range_filter`).
- M comes from the profile compiled into the wallet: 1,024 for the
  production profile. The wallet refuses unknown profiles (`match_filter`,
  `transparent-wallet/src/sync.rs`).
- So a script the service does not know matches with probability at most
  1/M, however the N values are chosen.

No match-rate check is needed. What remains is targeted inclusion of a script
the service already knows, which is listed in section 1.

A test in `transparent-filter` pins the bound so a later format change cannot
reopen the leak:

- Build adversarial filters: dense values, the maximum count, and clustered
  values.
- Match them against 65,536 scripts from a seeded generator.
- Assert at most 1/M of the scripts match, within a stated tolerance.
- Mutation check: compute the range as M instead of N·M, and the test fails.

This is a small wallet-pir change outside the two increment 2 pull requests.

### F. Restore window (wallet-libraries)

Increment 1 made transparent recovery one counted pass per account per sync. A
pass that finds activity near the end of the address window grows it, and only
the next sync checks the new addresses. A restore whose used addresses run past
the gap limit took one sync per window step: receives at external indices 0, 9,
18 and 25 under the gap of 10 took 4 syncs.

While an account is a candidate, `AccountRecoveryAddresses::load`
(`zcash_client_sqlite/src/wallet/transparent_ledger/recovery/recovery_addresses.rs`)
now watches a fixed restore window: every external index below 50 and internal
index below 25. Ephemeral addresses keep their gap limit.

- The window is a constant in code. No reply, setting or migration changes it.
- The gap-limit window is kept apart from it. Window growth, the stored
  `tpir_candidate_windows` and activation follow the gap limits only, so
  activation makes only the gap-limit window the wallet's own. An active
  account's watch set follows the gap limits as before.
- Growth inside the restore window adds no address, so it is not reported as
  `window_grew` and starts no new work. Activity near the restore window's end
  grows the window by one gap, covered at the next sync.
- An account that becomes a candidate again, as after a public policy round
  trip, watches the restore window again and needs one pass covering it before
  it activates.

Cost: 60 more watched addresses during a restore (40 external, 20 internal). An
unused address costs a directory query only when a shard's filter matches it by
chance, at most 1 in 1,024 per shard (change E). That is about
60 × shards in range ÷ 1,024 extra directory queries per restore: about 2 from
genesis (33 shards). Filter downloads do not change.

Tests, in `zakura/pir-transparent/tests/private_recovery.rs`:

- **One sync.** Receives at 0, 9, 18 and 25 restore in one sync. Reverted, 4.
- **Past the window.** Receives at 0, 45, 52 and 60 take 4 syncs, one per
  window step. Reverted, the restore stops at index 0 in one sync.
- **Transcript.** The first sync's requests are the same whether or not a
  service forges a receive at the window's last address; only the next sync
  covers the grown window. Reverted, the forged receive is not watched.
- **Activation.** After activation the watch set ends one gap past the last used
  address. Reverted, the restore takes 4 syncs.

## 4. Cost of cover and padding

Increment 3 sends dummy queries so that the shards and sizes a wallet queries
stop following its activity. All of it adds server work. The figures come from
wallet-pir evidence and docs.

| Item | What it sends | Cost |
| --- | --- | --- |
| Enhance cover | Every round queries every shard since the birthday (`query_positions_with_cover`) | None today: production has one Enhance shard, and shard 0 is not full. Each later shard multiplies Enhance queries. One query costs 8.4–9.8 ms on the P4000 and uploads about 208 KB. Under Vizor's one-shard cache, each shard switch fetches 89 KB of session data again. |
| Transparent shard cover | One dummy directory query per shard in range whose filter did not match | From genesis that is about 33 directory shards: 12 archive and about 21 recent. Server time per restore is about 12 × 5.17 ms + 21 × 1.73 ms, so about 100 ms of CPU. Upload is about 12 × 128.5 KB + 21 × 21 KB, so about 2 MB. Steady state adds one query per changed, unmatched shard per sync. |
| Directory count padding | Every queried shard gets the same number of directory queries, rounded up to a power of two | Small for typical wallets: matched scripts per shard are usually 0 to 2 |
| History padding | Each entry sends a fixed minimum of page queries, rounded up to a power of two; the number of rounds is padded too | Runs per chain: archive p50 3, p95 16, p99 21, max 32; recent p50 1, p99 4. Fragments per run average 1.21 (archive) and 1.09 (recent). A page query costs 2.5 ms (recent) or 5.2 ms (archive). |

The transparent service passed its gate at 20 queries per second (p50 11 ms,
p99 38 ms). Its maximum has not been measured.

Questions for the PIR operators:

- When does Enhance shard 1 open?
- How much headroom does the transparent service have above the 20 QPS gate?
  Is a restore that sends 33 more directory queries acceptable?
- Can the census publish the number of fragments per chain as a
  distribution, not only means? The history-padding minimum needs it.

## 5. Order of pull requests

| Pull request | Repository | Contains | Base | Depends on |
| --- | --- | --- | --- | --- |
| This plan | wallet-libraries | This doc | `main` | None |
| Increment 2, library | wallet-libraries | Changes D and F | This plan's branch, then `main` | Increment 1 (#180–#182, merged) |
| Increment 2, Vizor | chainapsis/vizor-wallet, branch `transparent-privacy-inc2` | Changes B and C, D's waiting state, and a repin of every wallet-libraries dependency to the library pull request's tip | `transparent-privacy-inc1` | Vizor increment 1, and the library pull request's tip |
| Filter bound | wallet-pir | Change E | `main` | None |

The library and Vizor pull requests are worked in that order: Vizor pins the
library's tip and repins after it merges. The filter test can land at any
time. No crate is published and no wallet-pir release is tagged as part of
this work.

## 6. Later increments

**Increment 3, shard and size cover.** This turns on Enhance cover by
default, sends dummy directory queries to unmatched transparent shards in
range with per-shard count padding, and pads page queries per entry. It is
gated on the operators' answers in section 4. Enhance cover costs nothing
while there is one shard. Moving Vizor to `query_positions_with_cover` before
shard 1 opens would avoid a later change, but the cost then grows by itself.
That is a capacity decision to make with the operators.

**Increment 4, transport.** Tor or another relay by default hides the
network address. Separate circuits for the status, Enhance and transparent
services, with unlinked timing, stop traffic to the three from being linked.
None of the PIR changes above touches the transport.

## 7. What increment 2 does not build

- No random offset inside each poll interval and no random tail after
  mining. The fixed window already makes the stop independent of mining, and
  the start follows the broadcast, which the broadcast service sees anyway.
- No match-rate check on filters (change E shows it is not needed).
- No change to import discovery (`zakura/pir-transparent/src/discover.rs`).
  A forged event plus inflated pages can force another pass, but only once per
  import the user starts, and the service already sees the import range.
- No cover or padding queries, and no server change.
- No defence against forged content. A forged "mined" answer is still
  believed, as today. Increment 2 only stops it from steering what the wallet
  asks next.
- No durable Enhance failure count (see section 9).

## 8. Leaks left visible on purpose

| Leak | Why it stays |
| --- | --- |
| The start of status polling dates the broadcast | The broadcast service sees the broadcast itself |
| Filter downloads start at the birthday shard, exposing the recovery range | Needs downloads from genesis for every wallet; a later choice |
| Receipt lookups reveal the shard (from the mined height) and the hash bucket | The receipt service is sized so every lookup's anonymity set is at least 180,000 entries |
| Request counts and timing on every service | Needs the cover in increment 3 and the transport work in increment 4 |
| The network address without Tor | Increment 4 |
| Traffic to the three services can be linked | Increment 4 |
| A filter lists a script the service already knows | Needs shard cover (increment 3) |
| Discovery's extra passes | Once per import (section 7) |
| Vizor resubmits a recovered transaction after a status answer says it is missing | Only for transactions recovered by migration; not in the polling path |

## 9. Open questions

- **Durable Enhance cap.** #180 keeps Enhance content-failure counts in the
  open wallet's session. Reopening the wallet resets them. A service can
  therefore learn up to two bits per record per session, rather than two bits
  in all. A durable count needs one small table.
- **Is 2 minutes enough?** It was set from 10 minutes down to 2, so memos
  arrive about a minute after the sync on average. It spreads the first
  Enhance query over about 2 blocks. A longer delay hides the block better but
  holds memos back.

- **Should Enhance cover go on now, while it is free?** See section 6.
