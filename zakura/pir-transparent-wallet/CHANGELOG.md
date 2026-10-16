# Changelog

## 0.1.0-rc.4 — 2026-10-13

- Row content that fails to decode or check out fails one directory entry,
  not the sync: the walk finishes every other planned query and commit, and
  a failed page walk sends only the dummies valid replies committed it to.
  The store counts failures per (shard, script); an entry at three is not
  queried again. A reply failing its length, binding or epoch check still
  fails the request, and an epoch mismatch drops the cached setup. New:
  `SyncError::Content`, `IncompleteReason::ContentFailed`,
  `SyncReport::failed_entries`, `WalletStore::entry_failures`,
  `WalletStore::drop_setup`, `ShardCommit::failed_entries`,
  `ClientError::SetupMismatch`.
- A failed page walk sends no query in a bad link's place when the honest
  walk would send none: when the chain promised no older run, or when the
  previous run is already cached.
- An overload retry asks again for entries that already failed in the sync
  and ignores their replies, so it sends the honest retry's queries and
  counts each failure once.
- The SQLite store moves to schema 7 and upgrades a schema 6 store in place,
  keeping its saved state.

## 0.1.0-rc.1 — 2026-10-12

- Recovery respects query and byte limits between page requests and saves checked
  fragments so one-query passes finish long histories after restarts.
- The reference SQLite store uses fresh format 6 for saved fragment progress.
  Earlier prototype companion stores must be recreated; there is no migration.
- Page requests with a finite byte budget run sequentially so at most one atomic
  response can cross the limit.
