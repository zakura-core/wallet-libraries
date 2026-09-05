# Ironwood-only Enhance PIR

This integration privately retrieves missing Ironwood memos and recovers outgoing
recipient, value, and memo data. It deliberately does not implement transparent
PIR, transparent spentness discovery, UTXO gating, or a new compact-block format.
Any transaction known to contain transparent, Sapling, or Orchard activity uses
ordinary lightwalletd (LWD) enhancement for the whole transaction.

This is the minimal replacement for [PR #18](https://github.com/zakura-core/wallet-libraries/pull/18).
Upstream compact transparent scanning can be integrated later at the scan-time
eligibility boundary; it is not a prerequisite for this version.

## Transaction routing

The database stores at most one routing row per transaction:

| State | Ordinary enhancement in private mode | Private work |
| --- | --- | --- |
| No row | Available | None |
| `PrivateCandidate` | Withheld | Incoming memos, outgoing candidates, and pending rediscovery |
| `LwdRequired` | Available | Cleared for the entire transaction |

`PrivateCandidate` is provisional, not a claim that transparent activity has
been cryptographically ruled out. Completion requires empty incoming, outgoing,
and discovery queues; there is no separate completed state. Later-discovered
funding can reopen enhancement even after earlier private completion.

Scanning stores all received notes, then reconciles private work once per wallet
transaction. An explicit transparent input/output, Sapling spend/output, or
Orchard action excludes the transaction. The compact source must include all
shielded pools: a stream filtered to Ironwood cannot safely establish eligibility.

An empty compact `vin`/`vout` does **not** establish transparent absence. For an
otherwise eligible transaction, the wallet privately fetches an Ironwood record
and consults its schema-v6 transparent-presence flags:

- Either input or output flag set: atomically mark the transaction `LwdRequired`,
  clear all its pending private work, and preserve its ordinary enhancement
  request. The existing LWD path obtains the full transaction and handles its
  transparent and other-pool data.
- Both flags clear: apply the validated Ironwood data. Retire the dormant ordinary
  enhancement request only after every incoming, outgoing, and discovery queue
  entry completes.
- Invalid, misaddressed, or stale record: no mutation and no public fallback.
  Transport failures also leave routing unchanged.

For example, a shielding transaction with transparent inputs and an Ironwood
output initially looks eligible if LWD omitted its transparent fields. The
record for the received Ironwood note reports the input flag; the wallet then
requests that transaction through ordinary LWD. An Ironwood spend paying a
transparent output follows the same transaction-wide rule using the output flag.

`LwdRequired` is sticky for that transaction ID, including across rescans and
reorgs. A late response with false flags cannot re-protect it. Already recovered
memos and sent outputs are not erased by fallback.

## Trust and privacy boundary

The two transparent flags are **trusted service metadata**. Note decryption does
not authenticate them, prove transparent absence, or bind them to the transaction
ID. This is an explicitly accepted limitation of schema v6: a malicious service
can force a txid fallback with a false positive, or suppress needed transparent
enhancement with a false negative. This version is not a malicious-server-secure
proof of transaction shape.

The response must nevertheless match pending wallet state before flags can alter
routing. Incoming decryption must reproduce the scanned V3 note. Outgoing records
must match the scanned ephemeral key and compact ciphertext prefix; outgoing
plaintext is accepted only if exactly one funding account's OVK recovers it.
Those checks authenticate note data, not the extra shape flags.

Every request captures `(tree position, txid, action index)` locally before
network I/O. Only the position selects the PIR item; the txid/action identity is
never sent to the service. A single backend application validates both incoming
and outgoing work, then a single SQL transaction rechecks the queue identities
before applying any data or routing change. Reorgs, full-transaction arrival,
duplicate replies, and another reply's fallback cannot make an old response
mutate a new position occupant.

PIR hides the selected item within its query domain, not service contact,
coarse shard routing, timing, or query volume. There is no cover traffic.
Ordinary transaction-status requests and existing transparent queries are
unchanged; this is enhancement privacy, not end-to-end wallet network privacy.
Mixed-transaction fallback intentionally exposes the transaction ID to LWD.

## Outgoing recovery and incomplete work

Wallet-funded transactions queue actions that were not already decrypted as
received notes. Received/change actions use incoming decryption, avoiding an
unrecoverable outgoing job for change encrypted under an internal OVK.

Compact scanning cannot distinguish padding dummies from potential outgoing
outputs. Padding is routine in default bundles, so wallet-funded transactions
queue every non-incoming action for recovery.

An outgoing record may match compact fields but fail OVK recovery because it is
a dummy, uses `OvkPolicy::Discard`, or contains corrupt server-supplied fields.
The wallet cannot distinguish these cases. As in ordinary enhancement, it discards
the candidate without storing a sent output. Deleting the outgoing row also removes
its candidate-account rows. The same SQL transaction retires ordinary Enhancement
intent only when all incoming, outgoing, and discovery work is complete.

This explicitly accepts a security tradeoff: compact matching authenticates the
ephemeral key and compact ciphertext prefix, not the remaining recovery fields.
A malicious server can corrupt those fields and cause a legitimate candidate to
be discarded. Discard is not proof that the action was a dummy. Compact mismatches,
incoming authentication failures, stale replies, and transport errors leave work
unchanged and never trigger public fallback.

An explicit rescan can reconstruct discarded candidates, using rediscovery when
funding nullifiers are already marked spent. New funding associations also reopen
discovery. Disabling private mode exposes outstanding ordinary enhancement requests;
it does not recreate requests retired after candidate discard.

### Out-of-order scanning and retroactive funding

Recent-first restores can scan a send before its funding note. The initial scan
may find only change and cannot yet enumerate outgoing recovery accounts. When
nullifier-map lookup later links the funding note to the send, the same SQL
transaction queues durable outgoing discovery and restores its ordinary
Enhancement request, even if a completed change memo previously retired it.
The request remains withheld in private mode. Scan order does not require LWD.

Discovery reconstructs action positions and compact validation fields from the
spending block, using the current database spend associations, including already
spent notes. It excludes received/change actions and previously recovered sent
outputs. Additional funding accounts reopen discovery and retry previously discarded
OVK candidates. An ordinary rescan cannot silently replace this obligation with an
empty candidate list just because the scanner loads only unspent nullifiers.
After a rewind, rescanning a retained spend link also restores discovery if its
private routing was cleared; repeated funding scans with intact routing remain inert.

Block identity, tree geometry, transaction locators, known received positions,
and funding nullifiers are checked before any queue changes. Invalid block-wide
identity, ordering, or tree geometry rejects the entire call without mutation.
Transaction-local failures do not block independently valid jobs at the same
height: valid plans commit together, while failed jobs retain their intent and
return individual reasons (`TransactionMissing` or `ContextMismatch`). A missing
txid in a supplied block is not evidence that the job can be deleted. SQL errors
still roll back every write in the call.

The block must come from the same trusted compact source as normal scanning:
comparing its claimed hash does not cryptographically authenticate compact
contents. Discovery errors never trigger public fallback. Full transaction
storage, positive mixed routing, and rewinds clear obsolete jobs.

Outgoing rows that lose all candidate accounts remain incomplete and are excluded
from PIR requests and response application until reconstructed. Losing keys is not
an authenticated non-recovery result.

Deleting an account cascades transactions that exclusively involved it. For
shared transactions that survive, discovery jobs with no remaining funding
associations are atomically marked suspended. They are excluded from automatic
block requests and active reconstruction, so they cannot block another job in
the same block. Defensive reconstruction also suspends any active orphan it
encounters. Losing keys does not prove outgoing recovery complete: the suspended
job still prevents retirement, preserves private protection, and keeps ordinary
Enhancement intent available if the user disables private mode. Applications can
read its `NoFundingAccounts` reason through
`suspended_ironwood_enhance_discoveries()`. Linking another funding note reactivates
the existing job. Reimporting a deleted funding key rewinds the wallet; rescanning
the funding and spending blocks reconstructs the required work. Deleting only
some funding accounts does not suspend a job that still has funding associations.

## Application integration

Compile with the `zakura-pir-enhance` Cargo feature in both runtime setting
states. The standalone `zakura-pir-enhance` crate's `wallet-integration` feature
provides `apply_record` for the backend. The facade's additive feature enables
the corresponding backend and SQLite APIs.

`EnhancementMode::Standard` remains the default. Reapply
`EnhancementMode::PrivateIronwood` when opening a wallet whose application
setting enables PIR; the setting is not persisted by the library. Set the mode
before obtaining ordinary enhancement requests. Applications must discard old
in-memory request batches when changing mode; a mode change cannot recall an
already dispatched LWD request.

Use `enhance_pir_requests()` to capture requests, query their positions with the
PIR client, and pass each original request and decoded record to `apply_record`.
Do not reconstruct identities from the database after receiving a response.

Also drain `ironwood_enhance_discovery_requests()` after scanning and on reopening.
Each request identifies one spending block by height and locally scanned hash;
jobs for the same block are grouped. Read that block from the cache, or obtain it
through the ordinary compact-block download path, then call
`rebuild_ironwood_enhancement(request, &block)`. Successful reconstruction queues
normal position-keyed PIR requests (or routes a newly identified mixed transaction
to LWD). `Rejected` means invalid block-wide context and no mutation.
`Incomplete { rebuilt, unresolved }` reports partial progress (possibly zero),
with transaction-local failure reasons. Retry unresolved active jobs according
to the application's retry policy; do not repeatedly feed the same invalid
cached data in a tight loop. `AlreadyResolved` means no active jobs for that
request, not that no suspended jobs remain.

Read `suspended_ironwood_enhance_discoveries()` on reopening and after account
deletion, and surface the missing-funding-key condition to the user instead of
retrying its block. Do not declare enhancement done merely because the active
request APIs are empty while discovery is pending or suspended.

Prefer cache reuse and normal batched downloads. Downloading a specific missing
block reveals interest in its height even though no target txid is sent. The
library performs no network I/O or automatic retries for this step.

The application owns scheduling, retries, cancellation, transport, and user-facing
incomplete-work status.

The database maintains routing and work regardless of runtime mode. Successful
private completion removes only enhancement intent, not transaction-status intent.
Turning PIR off exposes unfinished transactions; completed transactions remain
retired unless new funding reopens discovery. Full transaction storage clears
redundant private work. Rewinds prune private position claims before positions can
be reused, while preserving positive LWD decisions.

## Protocol and generation acceptance

The existing schema-v6 record is 725 bytes: 32-byte ephemeral key, 580-byte note
ciphertext, 32-byte net value commitment, 80-byte outgoing ciphertext, and one flag
byte at offset 724. Bit 0 means transparent inputs, bit 1 transparent outputs;
reserved bits are rejected. Nine records form a 6,525-byte row.

The client pins the setup seed, validates generation metadata and the
public-parameter digest, and binds queries and responses to one immutable
generation. Use the atomic `/v1/enhance/init` payload and randomized,
generation-pinned `/v1/enhance/query` requests. A shard's `worker` is an opaque
logical group identifier; replicas and failover are service concerns.

Before allocating setup, accept a generation only when:

- its anchor is at or below the wallet's fully scanned frontier;
- its exact block hash and Ironwood tree size match local metadata **at that
  anchor**, not necessarily at the wallet's current tip;
- its used/logical row counts have the canonical geometry for that tree size;
- its logical row count fits a locally configured resource limit.

With the HTTPS client, fetch a `PendingEnhancePirClient`, inspect its generation,
check `enhance_pir_snapshot_status`, and pass wallet-accepted
`GenerationAcceptance` plus `ClientResourceLimits` to `connect`.
Custom transports use the same acceptance with `QuerySession`.
Choose limits for the least-capable supported device, never from server fields.
Public-parameter decoding and deterministic setup remain deferred until acceptance.

## Upgrade and future scope

One migration creates five empty tables: incoming queue, outgoing queue, outgoing
candidate accounts, outgoing discovery queue, and transaction routing. It does not
backfill existing history: those transactions continue through ordinary enhancement
until the user explicitly rescans. Enabling the setting alone does not privatize old
history.

The local rediscovery prototype revises this unreleased migration, including the
discovery queue's `suspended` column and removal of the outgoing queue's former
non-recovery flag. Databases that applied any earlier version of this migration
are not upgraded by this prototype; use a separately backed-up fresh development
database or design a follow-up migration before deploying against those databases.
The tests initialize fresh temporary databases and do not modify an application wallet.

The experimental migrations from #18 were not released and are not supported as
an upgrade source. Development databases created by #18 need an independently
backed-up/fresh development database for this branch; the library never deletes or
resets one automatically.

Future upstream compact scanning can supply more explicit transparent information
to the existing eligibility decision. Transparent discovery/PIR, variable-length
address history, and private transparent spentness remain separate designs. No
future compact-block or service changes are required to land this integration.
