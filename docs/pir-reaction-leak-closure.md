# Closing the PIR reaction leaks

Private information retrieval (PIR) hides which record a wallet reads. It does
not hide what the wallet does next. A dishonest service can therefore change
its answer for a chosen set of records and watch whether the wallet reacts. If
the wallet retries sooner, stops early, or starts another round of queries, the
service learns whether the wallet's record was in that set. Repeating this
with halved sets finds the record in a few dozen syncs.

This plan closes those reaction leaks first, for transparent recovery,
transparent receipts and Ironwood Enhance. Passive leaks, the patterns an
honest-looking service records without changing its answers, come in later
increments. Every change here is on the wallet side and needs no change on the
server or coordination with it.

## 1. The leaks, ranked

A **content outcome** is anything the wallet decodes from a private reply: a
record, "not in the table", or bytes that fail to decode or verify. A
**request outcome** is a refusal the server makes before or without evaluating
the private query: an HTTP status, overload, or a stale publication. The server
chooses a request outcome per request, without knowing which row the query
selects, so it reveals nothing about the row. Only content outcomes can be
aimed at chosen rows.

| Leak | Service needs to | What it learns | Fix lives in | Increment |
| --- | --- | --- | --- | --- |
| Transparent recovery starts another pass when a fake receive grows the address window | Forge a receive in chosen directory rows | Whether the wallet's directory row is in the set; repeated, the row | wallet-libraries `zakura/pir-transparent` | 1 |
| Transparent sync stops at the first bad reply and repeats it next sync | Corrupt chosen directory or page rows | The same, plus the failing shard from where the walk stopped | wallet-pir `transparent-wallet` | 1 |
| Receipt retries wait 30 s after a malformed reply and 1 h after "not in the table"; jitter is computed from the txid | Answer malformed for chosen rows, absent for the rest | Which bucket row is the wallet's; jitter alone lets the service confirm a guessed txid | wallet-libraries `zcash_client_sqlite` | 1 |
| A rejected Enhance record stays due and is asked again at every drain, without limit | Corrupt chosen rows of an Enhance shard | The wallet's note position, which links the wallet to its note | wallet-libraries `zcash_client_sqlite` | 1 |
| Status polling stops when a transaction is mined | Forge "mined" for chosen rows, or just watch | The mined height; with the broadcast time, often the transaction | wallet-libraries status work, Vizor schedule | 2 |
| Enhance queries start right after the sync that found the transaction | Watch | The block range holding the wallet's transactions | wallet-libraries Enhance queue | 2 |
| Page queries per directory entry equal the history's page count | Watch | History size per matched address and shard | wallet-pir `transparent-wallet` | 2 |
| Private queries go only to shards whose filter matched | Watch | The block ranges where the wallet probably has activity | wallet-pir `transparent-wallet` | 3 |

The first four rows come first for three reasons:

- **They identify, not describe.** Each one is a yes-or-no test the service
  can repeat until it has a single row. The passive leaks give a range, a
  size or a time, each shared by many wallets.
- **They are cheap to close.** The fixes add a handful of dummy queries at
  most. Shard cover, by contrast, multiplies server work by the number of
  shards in the wallet's range.
- **They can be tested exactly.** A test can run the same wallet against an
  honest service and a dishonest one and compare the two request transcripts
  byte for byte. Passive leaks need statistical arguments.

## 2. The rule increment 1 enforces

After increment 1, two properties hold for transparent recovery, transparent
receipts and Enhance.

**Within a sync, replies do not steer requests.** For a fixed wallet state and
a fixed publication, the requests the service sees in one sync are the same
whatever the private replies contained. The comparison covers each request's
route, table and body length, in order. Request outcomes are exempt: a wallet
may back off after a 503.

**Across syncs, a content failure changes later traffic at most three times.**
A record that failed on content is asked again at most twice more (three
attempts in all). Each retry waits a delay drawn from one schedule shared by
every content outcome, using the operating system's random source. After the
third failure the wallet stops asking until a rescan or a user action re-arms
it. For transparent entries and receipts the count is stored, so the bound
holds across restarts. For Enhance it is kept in the open wallet session, so the
bound holds per app session (see change D). A wallet that stops after the first, second or third attempt, or never
fails, gives the service one of four outcomes: at most two bits per record. The
record's anonymity set, which is today reduced to one row, stays at a quarter
of its size or more.

The cap applies per record: a transparent directory entry (one address in one
shard), a receipt txid, or an Enhance queue item. A dishonest service can
already deny service to any record by corrupting it, so stopping after three
attempts loses nothing a service could not take anyway. A given-up
transparent entry holds the account, and a given-up Enhance item is listed as
suspended, so Vizor can explain both. A given-up receipt reads as its own
state, `TransparentDisplayView::GaveUp`: Vizor presents it as unavailable, as a
failing one is today, but stops polling and prioritising it.

**The application schedules only on what the service already knows.** The
library rules hold only if the application around them keeps them. *When* a
query or a run happens may depend on new blocks, the service's own wait
requests (`Retry::After`, HTTP `Retry-After`), app open and resume, settings
changes and fixed timers. It must never depend on whether a reply was bad or
found more work: no immediate rerun after a sync that failed entries or grew
the address window, no faster polling of a receipt whose lookup failed on
content, no extra trigger for unfinished recovery. In Vizor, transparent
recovery runs on block cadence: one run after each foreground sync that
follows a new block. Work left over waits for the next block.

## 3. Changes

Each change ships as its own pull request with its own tests. The tests share
one technique: record every request the service receives as (route, table,
body length), run the same wallet against an honest service and a dishonest
one, and compare.

### A. One receipt schedule for every content outcome

Receipt lookups now back off by outcome
(`zcash_client_sqlite/src/wallet/transparent_ledger/details/schedule.rs:193`),
and the jitter is a hash of the txid and attempt count (`schedule.rs:173`).

- Content outcomes (`Absent`, `Protocol` from a reply that failed to decode,
  and `Contradiction`) use one schedule: one hour, doubling to a day, plus up
  to 25% jitter.
- Jitter comes from the wallet's random source for every outcome, so tests
  can seed it.
- HTTP 4xx refusals (`TxidError::Refused`) move from `Protocol` to
  `Unavailable` in `deferral` (`zakura/pir-transparent/src/txid/display_facts.rs:108`).
  The server refuses before it evaluates the query.
- A row's third content failure marks it given up. It leaves both the due list
  and the parked list. Without public authority its receipt reads as
  `TransparentDisplayView::GaveUp` (a follow-up to this change; it read as
  `Unavailable` at first), so an application can stop polling it while showing
  it as unavailable. Re-mining at a different height re-arms it, as it already
  resets the backoff, and the view follows the work again. Under public
  authority nothing is given up.
- `Contradiction` no longer waits for a changed display map. Parking it while
  `Absent` and `Protocol` retry on a timer would tell them apart.
- `NotYetPublished`, `NotCovered` and `Unsupported` keep their schedules. The
  wallet decides them from the public display map, not from a private reply.

Given-up state needs one column on `transparent_detail_work`. The PIR
migrations are published, so this is a new, additive migration.

Tests:

- `backoff` returns the same delay for `Absent`, `Protocol` and `Contradiction`
  given the same attempt count and the same seeded random source, and
  different delays for the same txid under different seeds.
- `deferral` maps `Refused(404)` to `Unavailable`.
- SQLite: after three content failures the row is in neither list. After a
  re-mine at a new height it is due again. Two request failures between content failures do
  not count toward the cap.
- End to end, with `testing::TxidPublication`: one service answers malformed
  for the wallet's row, another answers "not in the table". With the same seed,
  both wallets store the same next-attempt times and both stop after the third
  lookup.

### B. One recovery pass per sync

`PassPlan::next` (`zakura/pir-transparent/src/plan.rs:225`) starts another pass
at once when a settled commit grew the address window, when the watched
addresses changed, or when the pass ran out of budget (`Retry::More`). A
service that forges a receive near the end of the window triggers that next
pass.

- After a pass that counts, `next` returns `Step::Done` with the pass's retry.
  Window growth, changed addresses and `Retry::More` wait for the next sync,
  which reads the fresh watch set as usual.
- Publication lag and overload also end the sync. A pass may have read private
  replies before reporting either condition, so its retry delay schedules the
  next sync rather than another pass with a reply-expanded address window.
  `Step::Wait` is removed: `Retry::After` also gives `Step::Done`, and the
  application uses its delay when scheduling the next sync.
- `Step::Refresh` stays. A commit goes stale only through wallet or chain state
  (an account or address removed, a rewind, a superseded revision), never
  through reply content.
- `PassLimits::passes` has no remaining use and is removed. Vizor keeps its
  loop, which now ends after one pass.

The lookahead stays at the configured gap limits. With one pass per sync, the
same gap limits apply at every sync.

A service cannot defeat this by forging filters that match every watched
address: the filter format bounds the match rate for scripts the service does
not know (see `docs/pir-remaining-leaks-plan.md`, change E).

Tests:

- Unit tests for `next`: window growth, changed addresses, `Retry::More`, lag
  and overload each give `Step::Done`; stale refreshes remain bounded.
- End to end, with the in-process service (`testing::service`): service A adds
  a receive at the last watched address to the wallet's directory row; service
  B does not. The request transcripts of the two syncs are identical. The
  wallet served by A records the larger window, and its next sync checks the new
  addresses. The transcripts also match when the publication is below the wallet's
  target: both syncs end with the same delay, without a second pass after waiting.
- Restore cost: a wallet whose used addresses reach index 25, with an external
  gap of 10, finishes recovery in a stated number of syncs. The test asserts
  that number, so a change in restore latency is visible.

### C. The transparent walk finishes after a bad reply

`transparent_wallet::sync_into` (wallet-pir
`transparent/crates/transparent-wallet/src/sync.rs`) aborts the whole sync on
the first reply that fails to decode or verify, and the next sync resumes at
the same query. Shards are walked in ascending order, so the point where
requests stop names the shard. Within a shard, one bad walk also aborts the
round for every later walk.

A script's history is a chain of **runs**. The directory entry points to the
newest run; each run's first fragment says how many fragments the run holds
and links to an older run in an earlier page table. The wallet walks every
owed chain in shared rounds.

In wallet-pir:

- A content error fails one entry (one script in one shard). The walk
  continues through every remaining planned query, in the same order, and the
  shard's commit still lands for the other scripts.
- Directory stage: every planned directory query for the script is sent before
  any reply is decoded. A failed entry then sends no pages, as an honest entry
  whose history is inline, or whose filter match was a false positive, does.
- Run stage: after a failure, the walk still sends what earlier, valid replies
  had already committed it to, the remaining fragments of its current run, as
  dummy queries of the same length to the same table, and then stops. A link
  naming a table the shard does not declare is answered with one dummy to the
  current run's table. Nothing that depends on the bad reply is sent.
- Errors that do not come from a private reply still abort: a malformed shard
  map or manifest, a broken filter, a lost answer in a round. The service
  serves these to everyone alike.
- The store keeps a content-failure count per (shard, script). Success and new
  revisions do not reset it. An entry at three is not queried again, and the
  sync report lists failed entries with their counts.

In wallet-libraries, after repinning:

- A sync with failed entries settles everything else. The account stays
  inactive, because coverage is incomplete, and is not passed again until the
  next sync.
- An entry's third failure holds the account with a cause Vizor can show.
- A contradiction the wallet detects on commit already suspends the account's
  recovery for good. That is one observable event, within the bound, so it is
  unchanged.

Tests in wallet-pir, with a recording transport and a service that corrupts
chosen rows:

- A corrupt directory row in shard *i* of *n*: every shard after *i* is still
  queried. The transcript equals the honest transcript in which that entry is
  inline.
- A corrupt fragment in the middle of a run: each round sends as many queries
  as the honest walk does until that run ends.
- A link to an undeclared table, a fragment held twice, and a fragment owned by
  another entry: each fails one walk, and the other walks finish.
- A malformed shard map still aborts.
- The failure count survives a store reopen. After three failures, the entry
  is not queried.

Tests in wallet-libraries, end to end with the in-process service:

- A corrupt directory entry for the wallet's address: the account is not
  activated, other shards settle, and the third sync holds the account.
- The transcripts of an honest service and a corrupting one match when the
  wallet's entry is inline.

### D. Cap Enhance rejections

An Enhance record that fails verification returns `Rejected`
(`zcash_client_sqlite`, `apply_ironwood_enhance_records`). The whole batch
rolls back and nothing is recorded, so the item comes back at the next drain
and is queried again without limit.

- After the rollback, the wallet adds one to a rejection count for that
  record's lookup identity, in the open wallet's session memory. On the third, the position
  leaves the query work and is listed as a new suspension,
  `EnhancePirSuspension::Rejected`.
- Request outcomes (409, 410, 429, 503) never reach the wallet store, so they
  do not count.
- Requeuing the transaction on a rescan clears its counts, as it already
  clears `not_recoverable`.
- No table or migration is added for this session-scoped allowance.

Tests:

- SQLite: two rejected applications leave the item in the query work; the
  third lists it as suspended. A rejected batch still leaves no effects. The
  count survives syncs and shared handles, a fresh session resets it, and a rescan returns the item.

Enhance counts belong to the open wallet session, not the database. Retain the same
`EnhancePirSession` across syncs and serialized database handles. A fresh session
resets the allowance, so the limit bounds reactions within a session rather than
across wallet restarts: the three-strike bound holds per app session. A service
that also watches restarts can query a rejected position three more times per
app session; keeping the counts in memory was chosen over a stored count and
migration. Successful rescans and rewinds re-arm requests; failed or
rolled-back operations do not clear their counts.

## 4. Order

A, B and D are independent wallet-libraries pull requests and can be reviewed
in parallel; A and D each add a migration, so whichever merges second rebases
onto the other. C starts in wallet-pir on `main`. The wallet-libraries half
integrates against the wallet-pir commit, then repins to the next published
release candidate.

Vizor needs no protocol change. It picks up B (the recovery loop ends after
one pass, on block cadence), maps the new held state onto an existing stop
reason, shows the Enhance suspension, stops polling given-up receipts, and
recreates its transparent recovery cache for the store's new format, in the pin
bump that follows. Its own sync loop must also stop reacting to reply content
(section 2): no new screens, strings or settings are added for any of this.

## 5. What increment 1 does not build

- No dummy queries to shards whose filter did not match, and no Enhance cover
  rounds by default.
- No padding of page counts. Change C sends dummies only to complete a shape
  the wallet had already committed to.
- No change to Enhance query timing, status polling, or broadcast.
- No change to import discovery (`zakura/pir-transparent/src/discover.rs`). Its
  extra passes run once per import, which the service can see anyway.
- No check against a service that sets every filter bit to make all watched
  scripts match (see change B), and no defence against one that publishes fake
  funds. Vizor trusts the configured
  service for content, as before.
- No server changes, and no new configuration or limits beyond the fixed cap
  of three.

## 6. Later increments

The plan for what remains, with increment 2 in full, is in
`docs/pir-remaining-leaks-plan.md`.

**Increment 2, passive timing and size.**

- *Status.* The library hands out poll times on a fixed schedule with a random
  offset inside each interval. It keeps polling for a random number of
  intervals after a transaction is mined, so stopping does not date the block.
  Broadcast time already reaches the broadcast service, so this does not hide
  when polling starts.
- *Enhance.* Each queued item gets a random not-before time when it is queued,
  so the first query is not tied to the sync that found the transaction.
- *Runs.* Each directory entry sends a fixed minimum number of fragment
  queries, rounded up to the next power of two above it. The minimum is set
  from the run lengths in the mainnet publication.
- *Filters.* Test each downloaded filter against random scripts and refuse one
  that matches far more often than its published false-positive rate.

**Increment 3, shard cover.** Send dummy directory and page queries to shards
in the wallet's range whose filter did not match, so the set of queried shards
stops tracking activity. Turn on Enhance cover rounds by default. Both
multiply server work, so they need a capacity plan with the PIR operators
first.

## 7. Open questions

- Is three attempts right? Two bits per record is the bound at three. Two
  attempts give 1.6 bits but less tolerance for real transient corruption.
- Is restore at one pass per sync acceptable? Change B's restore test measures
  the cost. If it is too slow, a fixed restore lookahead larger than the gap
  limit would bring it down without reintroducing extra passes.
