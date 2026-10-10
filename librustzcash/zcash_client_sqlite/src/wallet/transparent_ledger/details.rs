//! Transparent txid enhancement: durable work, validated display facts and the detail view.
//!
//! Work rows (`transparent_detail_work`) are written where the wallet records a transaction of
//! ours without its raw bytes: ledger projection and the Enhance PIR route-2 marker. Storing raw
//! bytes deletes them. Display facts (`transparent_tx_display*`) are display only: no balance,
//! spendability or history query reads them. See `docs/transparent-txid-enhancement.md`.

mod codes;
mod queue;
mod schedule;
mod script;
mod sql;
mod store;
mod validate;
mod view;

#[cfg(any(feature = "transparent-inputs", feature = "orchard"))]
pub(crate) use queue::enqueue_tx;
#[cfg(feature = "transparent-inputs")]
pub(crate) use queue::enqueue_txid;
pub(crate) use queue::{enqueue_mined_route_two, enqueue_route_two};
#[cfg(all(test, feature = "transparent-inputs"))]
pub(crate) use schedule::{PARKED_BACKSTOP, backoff};
pub(crate) use schedule::{defer, parked_work, work};
pub(crate) use store::{clear, store};
pub(crate) use view::view;
