# Receiver library ownership and releases

Wallet-libraries owns receiver formats, cryptographic checks, inclusion proofs,
PIR framing and evaluation, and the HTTP publication and revocation contract.
Wallet-pir consumes those libraries; a wallet release never builds or updates a
node package or fetches a wallet-pir Git revision.

| Package | Responsibility |
| --- | --- |
| `zakura-pir-native` | Common P16/P8 packing, parsing and evaluation primitives; the existing wallet client facade remains available |
| `zakura-pir-admission` | Bounded body reception, per-client caps and cancellation-safe evaluation admission |
| `zakura-receiver-directory` | Canonical records, filters, snapshots and authenticated witness data |
| `zakura-receiver-pir` | Client, transport contract, fixed framing, publication identity and optional evaluator |
| `zakura-receiver-pir-server` | Immutable publications, atomic revocation and real wallet-facing HTTP handlers |

The implementation and fixed fixtures originate in wallet-pir at
`eeea0779c2bd44febc96308592c419c4e6052e2e`. Native profile golden tests are
retained alongside the wallet client's independent rounding expectations.
Fixture expectations must not be regenerated as part of this ownership move.

Wallet-pir retains its indexer's SQLite store, node block ingestion, RocksDB
access, provider polling, process identity, metrics, startup, deployment and
configuration. Its existing package names become service-side adapters, so
production callers use the same protocol handlers as wallet recovery and
scenario tests. Protocol health fields accept caller-provided operator fields;
the production adapter adds the existing process identity and metrics routes.

## Release ordering

Publish native primitives and HTTP admission first, then receiver directory,
receiver PIR and receiver server support. The wallet packages follow their
ordinary dependency ordering in `scripts/publish-crates.py`. The receiver
packages have independent versions and exact requirements for sibling releases.
No wallet-pir tag or node upgrade is a prerequisite for this ordering.

The consumer PR uses exact Git revisions with explicit release versions while
these packages are unpublished. After separate authorization publishes them,
replace the consumer's Git revisions with the matching registry requirements
and regenerate its lockfile. An isolated path override is useful for local
joint validation but must never enter a commit or release receipt.

Wallet-pir can keep its previously tested library release while a newer wallet
release upgrades Common. When wallet-pir adopts that release, it must validate
its own node dependencies and production contracts. This ownership move does
not qualify a node database upgrade or deploy a service.

## Validation

`receiver-libraries` exercises the extracted packages, fixed wire fixtures,
shared native profiles and actual HTTP refusals, rotation and revocation.
`pir-receiver` exercises wallet restoration against these handlers, and
`one-time-ivk-scenarios` covers complete wallet/provider/reorg flows.
`verify --only receiver-consumers` builds fresh client and server consumers with
new lockfiles and checks their Common family and dependency direction.

The lightweight and repository graph gates run
`check-receiver-dependencies.py`. It rejects wallet-pir Git edges anywhere in
normal, optional, target-specific and development dependencies, rejects node
packages, and rejects receiver packages still owned by wallet-pir even when
packaged for a registry. Existing independently published transparent protocol
packages remain outside this receiver ownership change.
