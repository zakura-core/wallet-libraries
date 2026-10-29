# PIR packages

Enhance, Status, Transparent and Receiver use the same package structure. Select
products with `enhance`, `status`, `transparent` and `receiver`; defaults select none.

| Consumer | Entry package | Main modules |
| --- | --- | --- |
| Wallet or probe | `zakura-pir-client` | `enhance`, `status`, `transparent`, `receiver` |
| Publication builder | `zakura-pir-publisher` | `enhance`, `status`, `transparent`, `receiver` |
| Query server | `zakura-pir-query-server` | `enhance`, `status`, `transparent`, `receiver` |
| Shared formats | `zakura-pir-protocol` | records, manifests, codecs and identities |

Publishers and query servers independently use `zakura-pir-server-core` for
hint and packing preparation. Some query servers rebuild that material when
loading a publication. The shared preparation package contains neither wallet
orchestration nor publication placement and sealing. Publisher and query-server
do not depend on each other.

The protocol package owns serialized records and native profile descriptions.
Its `native` feature enables runtime parameter and public setup derivation;
record-only users need only the appropriate product feature. Wallet recovery
records additionally select `recovery`; the client and backend enable that
capability when needed. Server-only Transparent formats do not compile Common. Pure script
matching is selected internally by the client. Publishers compile it only for
tests that validate their filter output.

## Client capabilities

Start with the product features. `transparent` includes the transport-free
retrieval engine and txid client. `engine-store` adds the SQLite engine store;
`recovery` adds standalone candidate recovery and companion storage without the
wallet backend. `wallet` enables wallet adapters for the selected products;
Transparent additionally selects `transparent-wallet`, which includes recovery
and the backend's transparent inputs. `sqlite` adds Transparent settlement into
the SQLite wallet. Storage and conformance remain independently selectable.

`reqwest` opts into bundled HTTP transports. `lightwalletd` enables the explicit
public transaction status source under `status::policy::lightwalletd`. With no
lightwalletd feature, status policy and private queries have no bundled public
transport. Applications retain ownership of route policy, timeouts and cancellation.

`testing` opts into fixture builders and real in-process query evaluation.
Production consumers must not select it. It activates server packages only for
the selected products. The optional `cli` feature builds the Transparent filter
command-line tool.

## API layout

Use product entry modules rather than depending on implementation packages:

```rust,ignore
use zakura_pir_client::transparent::{TransparentHistoryRecovery, Companion};
use zakura_pir_publisher::transparent::DirectoryBuilder;
use zakura_pir_query_server::transparent::native::TableQueryExt;
```

Native encryption and response decoding live in the client. Query parsing and
response packing live in query-server. Extension traits attach those operations
to shared parameter descriptions without making one role depend on another.
Shared contracts remain independently usable by the wallet backend.

Receiver's formats, sessions and inventories live in `zakura-pir-protocol`; its
`receiver-crypto` feature adds address, record and zero-OVK recovery validation, which
the wallet and the publisher share. The publisher's `receiver-crypto` feature adds
witness path construction. `receiver-wallet` in the client adds the recovery queue's
network steps. See [Receiver PIR](receiver-pir.md). The generic filter codec remains
in `zakura-filters`. Node readers are owned by wallet-pir
and are selected explicitly by ingestion/publisher
consumers. Operational services, HTTP routing, activation and cache policy remain
in wallet-pir.

Transparent and Receiver share their directory primitives. The protocol's `directory`
module holds choice tables, bucket rows and tag salts, and the publisher's holds
two-choice placement and its checks. Each format passes its own domains, keys, seed
policy and overflow policy, and keeps its own row codec.

## Compatibility

Package names and Rust imports change; database and protocol representations do
not. Engine-store schema 7, the v3 recovery companion and Transparent shard v12
remain unchanged. Serialized field order, profile identities, seeds, routes and
query framing are compatibility contracts. Candidate recovery still needs wallet
validation and durable settlement before it can affect financial state.

The development lanes `pir-protocol`, `pir-client` and `pir-server` cover the
consolidated packages. Existing product and wallet integration lanes retain their
behavioral coverage. Fresh external consumers verify normal/build dependencies
without workspace test-feature unification.

The [trust and privacy contracts](pir-security.md) apply across all roles.

Configured service endpoints use the shared `endpoint` module; its [syntax contract](pir-endpoints.md) is selected with `http-endpoint`.
