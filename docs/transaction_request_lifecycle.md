# Transaction request lifecycle

`TransactionDataRequest::GetStatus(txid)` and `Enhancement(txid)` are independent
obligations. A wallet may need both for the same transaction. Keep request
tracking keyed by operation and txid, and reread the queue after processing:
payload ingestion can discover additional parent transactions to retrieve.

## Completion contract

| Event | Status obligation | Enhancement obligation |
| --- | --- | --- |
| `set_transaction_status(txid, status)` | Update observation and scheduling | Preserve, even if raw bytes already exist |
| Successful `decrypt_and_store_transaction` | May update mined status or schedule needed observation; preserve durable status intent | Complete after successful processing, including an irrelevant transaction |
| `notify_transaction_enhancement_not_found(txid)` | Preserve status metadata and scheduling | Retire ordinary payload work; retain outstanding PIR-routed recovery |
| Transport error, cancellation, malformed response, unsupported service, or missing PIR coverage | Preserve | Preserve |
| Rediscovery queues enhancement again | Preserve | New payload work remains pending despite late status responses |

`notify_transaction_enhancement_not_found` is specifically a report of an
**explicit not-found response to an authorized payload lookup**. It is not a
status setter, a generic error handler, or permission to issue a public lookup.
Repeated notifications with no ordinary request pending are no-ops. A later
rediscovery may create new work; a negative result is not a permanent tombstone.

SQLite preserves incomplete work for either private protection or an explicit
PIR-to-public routing decision. An outstanding routing obligation with no raw
payload cannot be completed by a not-found notification. This check also applies
when reopening the database in a build without the PIR feature. Private record
acceptance and routing transitions retain their existing completion rules.

## Status scheduling and reorgs

A mined observation updates transaction metadata and makes an existing status
request dormant. SQLite retains that intent so a rewind that removes the mined
height can make it actionable again. Status updates do not create enhancement
work or delete existing enhancement work.

An unmined or unrecognized observation uses the existing expiry and certainty
rules to determine whether to retain a status request. Reaching a terminal status
may retire **that status request only**. An unrecognized txid is an observation,
not proof that a transaction was never broadcast.

## Atomicity and response ordering

The standalone SQLite write methods commit atomically. Calls through a
transactional wallet handle participate in the enclosing transaction; a later
failure rolls back both metadata and queue changes. No request is completed
merely by dispatching a network call.

Successful payload processing removes its enhancement request through the
low-level `delete_retrieval_queue_entries` hook in the same transaction as its
writes. That hook must not delete durable status intent. The high-level payload
processing path already calls it; consumers should not manually complete work
before ingestion succeeds.

Status and payload responses may arrive in either order. In particular, a status
response cannot erase enhancement queued while that observation was in flight,
nor can it erase payload work restored by a PIR routing transition. This change
does not add request-generation tokens or make stale payload results safe to
apply without their existing identity and wallet-context validation.

## Consumer migration

This is a behavioral change and adds a required `WalletWrite` method. Custom
store implementations must implement `notify_transaction_enhancement_not_found`;
there is no default that silently drops work or reports false success.

- Status-only lookups continue calling `set_transaction_status`.
- Payload success continues calling `decrypt_and_store_transaction`.
- Replace payload-not-found uses of `set_transaction_status(TxidNotRecognized)`
  with `notify_transaction_enhancement_not_found(txid)`. If the caller also has a
  valid status observation to record, apply it separately, optionally within the
  same transaction.
- Keep transient failures and inconclusive PIR responses pending. Do not turn
  either into a not-found notification.
- Remove workarounds that defer status persistence solely because enhancement
  is pending, once the consumer actually uses a library release with this contract.

No SQLite schema migration is needed. This does not add a status-only lightwalletd
RPC, a private-status client, or new disclosure-routing APIs.

## Regression coverage

`wallet::request_lifecycle_tests` runs with and without PIR. It covers every
status variant with and without stored bytes, terminal status, explicit payload
absence, idempotence, rediscovery, transaction rollback, both response orders for
successful payload processing, and reactivation after rewind. PIR-specific tests
also cover public fallback and private recovery state. The shared transparent
shielding test exercises the new notification for an unavailable parent payload.
