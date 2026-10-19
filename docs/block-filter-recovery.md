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
