# One-time IVK scenarios

A scenario suite for one-time IVKs: it issues swap addresses, pays them in many
patterns, and checks that every payment is found by the wallet that made the swap,
by that wallet after it was offline, and by a seed restore. Each run writes a report
that lists every simulated case and what happened in it.

## Running

```sh
python3 scripts/dev.py test --config one-time-ivk-scenarios
```

That runs the default set. To run everything, including the cases that wait months
of chain time, set `ONE_TIME_IVK_SLOW=1`. To pick cases, pass a scenario ID substring
(or a whole ID with `--exact`). `dev.py` lists the matching IDs before running them,
and a filter that names a slow scenario runs it:

```sh
ONE_TIME_IVK_SLOW=1 python3 scripts/dev.py test --config one-time-ivk-scenarios
python3 scripts/dev.py test --config one-time-ivk-scenarios E2-restore
```

A run writes `report.json` and `report.md` (short enough to paste into a PR) to
`ONE_TIME_IVK_REPORT_DIR`, or under Cargo's test temp directory by default. It exits
nonzero if any scenario fails or a filter selects none.

CI doesn't run the suite on PRs, since it takes about 45 minutes on a hosted runner.
The **One-time IVK scenarios** workflow runs everything, slow scenarios included,
nightly on `main` and on demand for any branch from the Actions tab, and keeps the
report as a run artifact. When a PR changes one-time IVK behavior, run the suite
locally or dispatch the workflow on its branch. The report is stamped with the
wallet-libraries commit and the wallet-pir revision it ran against.

## What is real and what is simulated

Real: the SQLite wallet store and its one-time IVK tables, compact scanning, the
receiver restore client (`zakura-pir-receiver`), the receiver directory's routes
and PIR (`receiver-pir-server`), Ironwood note encryption, and signed transactions
with proofs where a scenario needs them (swap funding, payouts that a reorg
returns).

Simulated:

- The chain. Blocks every 75 seconds at real heights, with background Ironwood
  traffic every ten blocks. Wallets checkpoint their trees only at blocks with
  shielded outputs, and restore sweeps need a recent checkpoint, so an empty chain
  would not behave like mainnet. Most payouts are fake compact outputs, which scan
  like real ones but have no full transaction behind them.
- NEAR. Quotes, deposit addresses, statuses (normalized through
  `zakura-near-intents`), payouts and refunds, and the seen and recent sets its
  explorer feed gives the directory, with a configurable read lag.
- The receiver directory. Publications are built from the chain's zero-OVK payments,
  two blocks behind the tip, the way the indexer builds them. Failures can be
  injected.
- Vizor's sync loop. Recovery maintenance at the start, scanning, maintenance again at
  the tip, closing finished keys, status and payload work served from the chain, then
  one restore sweep run per sync. Payload work goes over the public path, not Enhance
  PIR.
- Time. One clock follows the chain; a device can run fast or slow.

## Reading the outcomes

Every payment to a one-time key gets a class for each wallet that should see it:
found live (scanning while the key was open), found by sweep (a restore or the
paid-filter check of a closed key), found after recheck (only after Check swap
history), or missed. Each scenario states the class the documented contract predicts,
with the reason, and fails when the wallet does something else. A miss the library
documents passes and is listed under the documented gaps, because whether it is
acceptable is a product decision.

Checks cover what is not a payment: balances after settling, address reuse, key
states. Before a scenario is judged, every wallet keeps syncing until it is quiet, as
Vizor's polling would, so a find that needs another sync still counts.

Where finding a payment is not enough, a scenario then spends every one-time note the
wallet holds through ordinary sends. Each send is checked as consensus would check it:
its anchor is the Ironwood tree root at the end of some block, it reveals no nullifier
already on chain, and its proofs and signatures verify.

## Layout

- `src/`: the report model and its Markdown renderer.
- `tests/scenarios/harness/`: the chain, NEAR, the directory and the wallets.
- `tests/scenarios/catalog/`: the scenarios, one file per area.

## Limits

- Payload retrieval uses raw transactions, so refund memo recovery over Enhance PIR is
  covered by the store's own tests, not here.
- Vizor's own code (its policy gates, FRB calls and Dart flows) is covered by Vizor's
  tests and its regtest end-to-end tier.
- Timings are for comparison between scenarios on one machine, not device estimates.
