# `zakura-wallet-lib`

Re-exports the Zakura wallet stack under stable names: `client_backend`,
`client_sqlite`, `keys`, `orchard`, `pczt` and `primitives`.

The default `zakura` feature includes Orchard, the explicit Halo 2 proof
backend, wallet storage, lightwalletd transport and PCZT signing/finalization.
Consumers disabling default features must explicitly enable `zakura`.
The Common family uses compatible version requirements so consumers can select
compatible updates.

Applications using Enhance PIR depend directly on `zakura-client-backend` and
`zakura-client-sqlite` with Orchard storage enabled, plus `zakura-pir-client`
with its `enhance` and `wallet` features. This facade does not expose that client.

The name is reserved on crates.io as `zakura-wallet-lib`. See `src/lib.rs` for
examples and `scripts/verify-wallet-lib-modes.sh` for fresh consumer and MSRV
checks.
