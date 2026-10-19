# Previous companion fixture

`pre-packaging-companion.sql` is an immutable SQLite dump produced by
wallet-libraries commit `4631f32f815f160ccd561540e7ae92e026fc7ee5`, before the
PIR package moves. It contains only the synthetic `recovery-without-backend`
example: account 1, a locally accepted height of 1, no watched addresses and an
unacknowledged empty recovery batch. The service origin is `example.invalid`.

The compatibility test restores these old bytes, reopens the companion and
replays the unfinished work twice without making a network request. It checks
that the persisted schema is unchanged. This fixture does not replace the
existing populated recovery, migration and settlement tests.

To regenerate deliberately, run that commit's standalone recovery example with
its final directory cleanup omitted, then use Python SQLite `Connection.iterdump()`.
Do not regenerate it from the implementation being tested.
