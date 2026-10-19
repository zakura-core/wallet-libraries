# Block filter recovery state

`OneTimeRecoveryRead` and `OneTimeRecoveryWrite` store discovery independently of ordinary chain sync. Enable each eligible account explicitly. Preparation derives receivers in bounded chunks without reserving their addresses. Both purposes start with 100 indices and retain a window through the highest supported allocation plus 30. A sparse registered key always owes historical work even outside that window.

Accept a history only after validating the archive network and connected-chain anchor. A new archive identity or correction epoch replays retained filters. Capture a `FilterWork`, verify its complete filter range, then submit judgments. The database checks account, settings, history, key generation, cursor and range before atomically advancing the tested receivers and retaining every positive match. Ordinary scan height never advances a filter cursor. Reorgs fence callbacks and repair only the suffix after the fork.

A positive match is an obligation, not ownership evidence. Complete local trial decryption stores its exact key, height and hash alongside notes and the spend journal. A later matching filter can reuse that evidence after cache eviction or restart. Other matches remain pending for local scanning or compatible PIR recovery. Disabling discovery retains this state and rejects captured filter callbacks.

Only operations recorded locally before possible payment receive watch provenance. Existing operations receive none during migration. An accepted deadline is immutable. Selection requires the account enabled and wall time before that deadline plus 24 hours. Receipt-based closure requires a complete scan, terminal operations, at least one confirmed receipt and all expected value confirmed. Multiple unresolved receipt amounts keep the watch until its bound. Status corrections and affected reorgs can reopen it without extending the deadline.

This change adds state and local watch selection. It does not switch ordinary scanning, remove the old discovery scheduler, or wire the application toggle. The recovery and app cutovers must enforce the setting again when committing in-flight discoveries, consume pending matches, and retire the old pass and broad watches. Existing payment admission, spending and shipped migrations remain intact.

## Issuance and provider history

Before the first private operation, enable recovery for the account, prepare its receiver windows, and apply a validated provider `seen` capture with `record_one_time_provider_seen`. Pass the digest of those exact bytes. Each call checks at most 1024 receivers. Repeat preparation and membership checks while the supported window grows. A changed capture resets membership progress. Older captures cannot replace newer ones. Membership can register a receiver for filter history and block its reuse, but cannot create a payment lookup or local watch.

A refund quote now needs a request identity. Reserve the key, call `begin_refund_operation` before sending the provider request, then pass its returned request to `record_refund_operation`. A timed-out request stays unresolved. A late acceptance for a retired reservation returns a retryable policy refusal. Accepted refund instructions permanently block reuse of the key.

Incoming operations use the same exposure rule. Begin before sending the request, persist its outcome, and show only the deposit returned by `start_receive_operation`. Starting permanently blocks reuse. Expired requests can reuse an eligible abandoned address only after its filter history reaches the wallet tip and no pending match or payment remains. A pending match blocks allocation even before its key enters the registry.

Locally begun requests supply watch provenance. The requested deadline applies until the first accepted response fixes the watch deadline. Later responses and status polls cannot extend that accepted bound. Turning recovery off blocks new exposure and watch selection. The key and its historical recovery obligation remain stored.

This PR changes issuance and durable provenance. The scanner selection, transport scheduler, strict-toggle admission fences, application callers and old discovery/watch removal are separate required cutover work. These state APIs alone do not complete the feature.

## Independent filter requests

`zakura_pir_receiver::filters::accept_filter_head` verifies the archive against the wallet's connected frontier and accepts its correction identity. A missing anchor leaves work pending. `FilterRequest` owns a captured receiver group and its generation fence, so its network future borrows no wallet or scan lock. A complete immutable archive page is verified before membership is checked. `FilterResponse::commit` rechecks anchoring and atomically submits those judgments. Serialize only this short commit with wallet writers. Neither a negative result nor a positive match sends a receiver PIR request.

`fetch_seen` now reads the permanent provider-membership object advertised by the archive head, independently of PIR preparation. Pass `Seen::digest` when applying that capture to issuance state. Missing provider history fails closed, and malformed receivers are conservatively reported as held.

## Recent replay storage

The application owns one `RecentBlocks` instance per wallet/network, shared across accounts. Insert only successfully scanned compact blocks with their predecessor `ChainState`. The cache keeps at most the newest three heights, with a hard 16 MiB ceiling covering serialized compact data, all three predecessor commitment-tree frontiers and fixed bookkeeping. A smaller byte budget may evict sooner. An oversized block still advances the retention window. A cache entry is returned only for its exact height and hash.

Entries have no disk persistence. Disabling discovery clears the optimization. A chain rewind removes the affected suffix. The caller processes at most one decoded replay at a time and must not put decoded copies into pending queues. Missing or evicted bytes require PIR settlement of the durable match. Replaying a cache entry still requires normal cryptographic note admission and current setting/generation checks.

The transport and cache are foundations for the production scanner and application scheduler. Their unit and SQLite integration tests do not establish real publisher timing, cache-hit rate, or final note-admission behavior. Those integration gates remain required before cutover is complete.

## Exact block scanning

`scan_cached_blocks_with_recovery` performs local scanning without network requests. Before scanning, it captures each block's eligible own-swap keys, queued matches and caller-supplied `BlockHints`. A hint is bound to the downloaded block's height and hash. A verified positive hint can be used before the archive frontier is stored locally, but only the separately anchored filter commit can advance historical coverage. Receiver hints never create forward watches. Ordinary account keys continue scanning every block.

`OneTimeBlockScan` rechecks each account and key's captured discovery generation while committing. Turning discovery off, including off and back on, prevents in-flight work from admitting new receipts or recording complete scan evidence. Ordinary notes, commitments and chain progress still commit. Re-mining a previously known transaction remains allowed while disabled, but this permission cannot admit additional payments to the same key. Exact successful scans settle matching obligations and can close eligible local watches.

This API is opt-in until the application cutover. Cache replay orchestration, compatible PIR settlement, full-transaction discovery gating, the legacy scanner/discovery removal and real publisher integration tests remain required.

## Cached replay and historical transport

`RecentBlocks::get` returns an owned `ReplayBlock` implementing `BlockSource`, including the predecessor frontiers required by the normal scanner. A delayed exact-block match can pass that source and its hint to `scan_cached_blocks_with_recovery`. This performs normal note admission and persists whole-block scan evidence without a receiver query or a disk cache. Eviction and restart still require historical PIR recovery.

The receiver client's `history::SessionMetadata` binds archive coverage to the actual PIR manifest. It may connect for an older matched block while public filters are ahead of that publication. Its bounded history pages and common witnesses are inputs to wallet admission, never authority to credit notes or clear pending matches. The durable session/cursor/admission implementation and application integration remain required before removing the old discovery entry point.

## Durable historical completion

`OneTimePirRecovery` captures an account work generation, archive history, actual compatible session and canonical publication for each receiver with a pending positive match. Begin work only after a cache miss and independent session/chain validation. Persist each bounded page with its exact captured work. Compatible newer sessions may resume the cursor after checking its previous record. A settings change, correction or rewind invalidates old callbacks. Provider membership alone cannot start a receiver lookup.

Enumeration and admission are separate. Authenticated candidates wait for a candidate-specific witness and ordinary account spend coverage. Only a fully enumerated receiver with no remaining candidates can clear covered matches. False positives may finish with an empty history, but that never exempts the receiver from later filters. Retries persist across handle restarts. Revoking a work generation discards its uncredited responses and cursors, retaining positive match obligations for a fresh lookup. This prevents stale candidates from blocking later issuance indefinitely. Call local admission after ordinary scan progress and cancel network tasks when the feature is paused.

The block-filter queue reuses existing note authentication, canonical inclusion, witness installation and spend-journal admission. Legacy pending state is preserved during this intermediate PR, but has no authority over this queue. The subsequent direct caller cutover must remove legacy orchestration and migrate its remaining obligations before retiring old tables. The app scheduler and full-transaction admission cutover are still outstanding.
