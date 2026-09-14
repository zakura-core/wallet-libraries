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
been cryptographically ruled out. Completion requires empty incoming, outgoing, metadata,
and discovery queues; there is no separate completed state. Later-discovered
funding can reopen enhancement even after earlier private completion.

Scanning stores all received notes, then reconciles private work once per wallet
transaction. An explicit transparent input/output, Sapling spend/output, or
Orchard action excludes the transaction. The compact source must include all
shielded pools: a stream filtered to Ironwood cannot safely establish eligibility.

An empty compact `vin`/`vout` does **not** establish transparent absence. For an
otherwise eligible transaction, the wallet privately fetches an Ironwood record
and consults its schema-v7 transparent-presence flags:

- Either input or output flag set: atomically mark the transaction `LwdRequired`,
  clear all its pending private work, and preserve its ordinary enhancement
  request. The existing LWD path obtains the full transaction and handles its
  transparent and other-pool data.
- Both flags clear: apply the validated Ironwood data. Retire the dormant ordinary
  enhancement request only after every incoming, outgoing, metadata, and discovery queue
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
ID. This is an explicitly accepted limitation of schema v7: a malicious service
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

Wallet-funded transactions queue every action except same-account change for
outgoing recovery. Cross-account wallet payments also need outgoing recovery to
restore the sender’s recipient, value, and memo, alongside the receiver’s incoming
note. Change uses incoming decryption, avoiding an unrecoverable outgoing job for
change encrypted under an internal OVK.

An outgoing record may match compact fields but fail OVK recovery because it is
a dummy, uses `OvkPolicy::Discard`, or contains corrupt server-supplied fields.
The wallet cannot distinguish these cases. It marks the row `not_recoverable`
and stops automatic retries, but retains the row as incomplete. Other successful
actions must not erase its ordinary fallback.

An explicit rescan requeues suspended candidates, using rediscovery when its
funding nullifiers are already marked spent. Disabling private mode exposes
outstanding ordinary enhancement requests. Neither non-recovery nor an error
automatically causes public fallback.

### Out-of-order scanning and retroactive funding

Recent-first restores can scan a send before its funding note. The initial scan
may find only change and cannot yet enumerate outgoing recovery accounts. When
nullifier-map lookup later links the funding note to the send, the same SQL
transaction repairs internal change flags for the linked funding accounts,
queues durable outgoing discovery, and restores its ordinary
Enhancement request, even if a completed change memo previously retired it.
The request remains withheld in private mode. Scan order does not require LWD.

Discovery reconstructs action positions and compact validation fields from the
spending block, using the current database spend associations, including already
spent notes. It excludes actions marked `is_change` and previously recovered sent
outputs. Additional funding accounts reopen discovery and retry suspended OVK
recovery. An ordinary rescan cannot silently replace this obligation with an
empty candidate list just because the scanner loads only unspent nullifiers.
After a rewind, rescanning a retained spend link also restores discovery if its
private routing was cleared; repeated funding scans with intact routing remain inert.

Block identity, tree geometry, transaction locators, known received positions,
and funding nullifiers are checked before any queue changes. Invalid block-wide
identity, ordering, or tree geometry rejects the entire call without mutation.
Reconstructed outgoing positions must not belong to another transaction, even
when the reconstructed transaction is mixed-pool. A conflict rejects the entire
call before any routing or queue changes.
Tree geometry requires the preceding block's Ironwood tree size in local metadata;
at a scan-range boundary, retain or scan that predecessor before reconstruction.
Jobs are not advertised for automatic reconstruction until both the spending
block's ending size and that predecessor anchor are available.
Transaction-local failures do not block independently valid jobs at the same
height: valid plans commit together, while failed jobs retain their intent and
return individual reasons (`TransactionMissing` or `ContextMismatch`). A missing
txid in a supplied block is not evidence that the job can be deleted. SQL errors
still roll back every write in the call.

The block must come from the same trusted compact source as normal scanning:
comparing its claimed hash does not cryptographically authenticate compact
contents. Discovery errors never trigger public fallback. Full transaction
storage, positive mixed routing, and rewinds clear obsolete jobs.

Deleting an account cascades transactions that exclusively involved it. For
shared transactions that survive, discovery jobs with no remaining funding
associations are atomically marked suspended. They are excluded from automatic
block requests and active reconstruction, so they cannot block another job in
the same block. Defensive reconstruction also suspends any active orphan it
encounters. Losing keys does not prove outgoing recovery complete: the suspended
job still prevents retirement, preserves private protection, and keeps ordinary
Enhancement intent available if the user disables private mode. Applications can
read its `NoFundingAccounts` reason through
the `Suspended(Discovery(...))` entries of `enhance_pir_work()`. The same API reports
`AnchorUnavailable` for an otherwise active job waiting for the spending block
and its predecessor's tree-size metadata; regular scanning makes that job
requestable without changing its queue row. Linking another funding note reactivates
an existing `NoFundingAccounts` job. Reimporting a deleted funding key rewinds the
wallet; rescanning the funding and spending blocks reconstructs the required work.
Deleting only some funding accounts does not suspend a job that still has funding
associations. Outgoing jobs with no candidate accounts are retained as
`OutgoingNotRecoverable` suspensions. Both updates run in the account-deletion
transaction even when compiled without `zakura-pir-enhance`. Full wallet
initialization also repairs orphaned jobs left by older builds, atomically and
without clearing pending enhancement intent.

Run `scripts/verify-pir-feature-transition.sh` to exercise a PIR-enabled database,
account deletion in a separately compiled PIR-disabled binary, and a PIR-enabled
reopen.

## Application integration

Compile with the `zakura-pir-enhance` Cargo feature in both runtime setting
states. The facade's additive feature enables the backend and SQLite APIs.
The standalone client and backend share `EnhanceRecord` from the small
`zakura-pir-enhance-types` crate; no record conversion or client integration
feature is needed.

Both `WalletDb::for_path` and `WalletDb::from_connection` take four arguments,
independent of Cargo features. With PIR compiled in, configure every new handle
using `set_enhancement_mode` or the chainable `with_enhancement_mode`, choosing
`EnhancementMode::Standard` or `EnhancementMode::PrivateIronwood`.
Until configured, both `transaction_data_requests()` and `enhance_pir_work()`
return `SqliteClientError::EnhancementModeNotConfigured`, even for an empty wallet.

Load the application preference before requesting work on every reopened handle;
the library does not persist a second preference. Transaction wrappers inherit
the handle's configuration. Enabling PIR transitively preserves constructor source
compatibility but introduces this runtime configuration requirement to prevent
accidental public enhancement. Use `set_enhancement_mode` when the preference
changes, and cancel or discard old in-memory network request batches. A mode
change cannot recall an already dispatched LWD request.

Read `EnhancePirRead::enhance_pir_work()` after scanning and on reopening. One
consistent read reports active and suspended obligations from the independent
queues, ordered as rediscovery by height, queries by position, discovery
suspensions by transaction location/identity, then outgoing suspensions by
position/identity. Enumeration remains available in either mode; schedule
private network work when the application enables private mode.

Handle each `EnhancePirWork` variant:

- `Query(request)`: query only its position with the PIR client, then call
  `db.apply_ironwood_enhance_record(request, &record)` through `EnhancePirWrite`.
  Keep the original request across network I/O; never reconstruct its identity
  after receiving a response. Record decoding rejects reserved flag bits but
  does not authenticate the record. The wallet binds and validates it before
  changing note data or routing.
- `Rediscover(request)`: read the compact block from the cache or the ordinary
  download path, then call `rebuild_ironwood_enhancement(request, &block)`.
  Requests are grouped by height and locally scanned block hash. Successful
  reconstruction queues position queries or routes mixed transactions to LWD;
  reread work after applying it. `Rejected` changes nothing, while
  `Incomplete { rebuilt, unresolved }` reports transaction-local failures and
  partial progress. Retry according to application policy, without repeatedly
  feeding invalid cached data in a tight loop.
- `Suspended(Discovery(failure))`: surface missing funding associations or
  adjacent tree metadata as incomplete. Funding linkage reactivates
  `NoFundingAccounts`; normal scanning can resolve `AnchorUnavailable`.
  Repeatedly downloading the spending block is not the remedy.
- `Suspended(OutgoingNotRecoverable(request))`: outgoing recovery failed and
  the durable action remains incomplete, including after reopening. Do not
  automatically query it again. New funding or scanning may reactivate it;
  disabling private mode exposes its ordinary enhancement request.

Suspensions are returned alongside active work. A transaction can have multiple
independent obligations; having no active queries does not mean enhancement is
complete. `AlreadyResolved` applies only to the supplied request, not the wallet
as a whole. Retryable `TransactionMissing` and `ContextMismatch` reconstruction
failures remain active work and are reported by the reconstruction result.

Custom storage backends implement the explicit `enhance_pir::storage` contract
on a transaction-scoped adapter. Its pending context, validation helper, and
validated commit type are implementation APIs; application traits do not expose
them. The adapter must keep context reads, validation, identity rechecks, and
all writes in one consistent transaction. SQLite uses a private adapter and
rolls back every write on a database error.

### Migrating application code

This is a coordinated Rust API break:

- Replace the three work-list calls with one match over `enhance_pir_work()`.
- Keep four-argument database constructors and configure each handle with
  `with_enhancement_mode` or `set_enhancement_mode` before requesting work.
  Remove reliance on `EnhancementMode::default()`.
- Remove the client's `wallet-integration` feature, `wallet_record`, and
  `apply_record` imports. Pass the shared record to the backend write method.
- Replace `IronwoodEnhanceRecord::from_parts(...)` with
  `EnhanceRecord::from_parts(EnhanceRecordParts { ... })`. Byte decoding uses
  fallible `EnhanceRecord::from_bytes`; flag accessors are now infallible.
- Custom scanners attach `IronwoodEnhancementPlan::Ineligible` or
  `Eligible { outgoing }` through `with_ironwood_enhancement_plan`. An empty
  outgoing list is valid eligibility, not proof of durable completion.

Schema 7 requires the metadata-queue database migration, an Enhance PIR server
update, and a canonical snapshot rebuild. Schema-6 servers and clients are not
compatible with this release. The shared record crate must be available before publishing backend
releases that depend on it.

Prefer cache reuse and normal batched downloads. Downloading a specific missing
block reveals interest in its height even though no target txid is sent. The
library performs no network I/O or automatic retries for this step.

The application owns scheduling, retries, cancellation, transport, and user-facing
incomplete-work status.

The database maintains routing and work regardless of runtime mode. Successful
private completion removes only enhancement intent, not transaction-status intent.
Turning PIR off exposes unfinished transactions; completed transactions remain
retired unless new funding reopens discovery. Full transaction storage clears
redundant private work. Rewinds prune
private position claims before positions can be reused, while preserving positive
LWD decisions.

## Protocol and generation acceptance

The schema-v7 record is 737 bytes: 32-byte ephemeral key, 580-byte note
ciphertext, 32-byte net value commitment, 80-byte outgoing ciphertext, a flag
byte at offset 724, a four-byte little-endian expiry height at offset 725, and an
eight-byte little-endian fee at offset 729. Bit 0 means transparent inputs, bit 1
transparent outputs, and bit 2 a present fee. Other bits are rejected. An absent
fee must have a zero payload; a present zero fee is distinct. Expiry zero means
expiry is disabled, not unknown. Nine records form a 6,633-byte row.

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

The original migration creates four empty tables: incoming queue, outgoing queue,
outgoing candidate accounts, and transaction routing. Existing ordinary history
continues through LWD until explicitly rescanned. Enabling the setting alone does
not privatize old history.

A separate follow-up migration adds the outgoing discovery queue. It also restores
discovery and ordinary enhancement intent for already protected, mined transactions
with known Ironwood funding and no full transaction data. This repairs work lost by
earlier rescans or recent-first restores. Reconstruction skips already recovered
outputs; private mode continues to withhold these ordinary requests. The migration
preserves memos, sent outputs, status requests, and sticky LWD routing.

Databases created by PR #20's original four-table migration upgrade in place.
Unreleased rediscovery prototypes that changed that migration's schema are not an
upgrade source. Tests use temporary databases and do not modify an application wallet.

The experimental migrations from #18 were not released and are not supported as
an upgrade source. Development databases created by #18 need an independently
backed-up/fresh development database for this branch; the library never deletes or
resets one automatically.

Future upstream compact scanning can supply more explicit transparent information
to the existing eligibility decision. Transparent discovery/PIR, variable-length
address history, and private transparent spentness remain separate designs. No
future compact-block or service changes are required to land this integration.

## Schema-7 fee and expiry completion

`EnhanceRecordParts` now requires `metadata: EnhanceTransactionMetadata`. Construct
it with `EnhanceTransactionMetadata::new(expiry_height, fee_zatoshis)`; the constructor
rejects heights at or above 500,000,000 and fees above the monetary range.
Byte decoding also rejects reserved flags and noncanonical absent-fee payloads.
The two clients require schema 7, protocol `ironwood-enhance-pir-v2`, and its pinned
setup seed. They do not downgrade to schema 6 or fall back publicly on errors.

The indexer derives a pure Ironwood transaction's actual fee from its public value
balance. These fields are trusted service metadata, like shape flags; note decryption
does not authenticate them. After action binding and current-identity checks, storage
fills fee and expiry atomically with action work. Conflicting known values reject the
whole response. Full-transaction storage remains authoritative.

A new durable metadata queue backfills protected mined transactions whose earlier
PIR enhancement retired without fee or expiry. Already stored memos are retained.
Work enumeration reuses action queries; a metadata-only incoming query validates
against the stored note even when its memo is complete. Missing outgoing-only
positions are rebuilt from the trusted compact source through `Rediscover`.
Metadata reconstruction does not require an outgoing recovery key. Suspended
outgoing work remains independently incomplete after metadata is stored.

The migration and cleanup run in PIR-disabled builds too. Rewinds invalidate position
bindings; account deletion converts lost incoming bindings into rediscovery work.
Ordinary unprotected history and sticky LWD routing are not reclassified.

`transactions.fee` and `transactions.expiry_height` feed the existing history API.
This release does not retrieve raw transactions: `get_transaction()` still returns
`None` when `transactions.raw` is absent. Raw export and parsed inspection remain
unavailable for those transactions. History displays can use the populated metadata.

Custom storage implementations now implement `pending_ironwood_metadata` and
consume the named `IronwoodEnhancementData` returned by `into_parts()`. Apply its
metadata alongside note, route and queue changes; encoding errors use
`InvalidEnhanceRecord` instead of the former flag-only error.
