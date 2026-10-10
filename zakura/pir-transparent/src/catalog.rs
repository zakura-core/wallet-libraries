//! The companion's revision catalog: stable revision identities, what each
//! source has published, and which revisions a batch may have handed to the
//! wallet.
//!
//! Identities are derived, never counted, so any companion bound to the same
//! account, origin and schema derives the triples the wallet already holds. The
//! catalog lets a pass tell a publication that is merely behind (`Pending`) from
//! one that contradicts what this companion recorded (`Withdrawn`); only a
//! `Ready` pass returns commits.
//!
//! A re-cut the map declares keeps the identities the wallet holds: a sealed
//! revision it superseded stays current, and facts stored under it are still
//! exported under it. Only an undeclared change of sealed content withdraws.

mod exports;
mod identity;
mod layout;
mod pass;
mod recut;
mod store_tables;

pub(crate) use exports::{acknowledge, exported_any};
#[cfg(feature = "sqlite")]
pub(crate) use exports::{acknowledge_in_transaction, acknowledgment_transaction};
#[cfg(test)]
pub(crate) use identity::source;
pub(crate) use identity::{Published, binding};
pub(crate) use layout::prepare;
pub(crate) use pass::Pass;
#[cfg(test)]
pub(crate) use recut::declaration_conflict;
pub(crate) use recut::recut_epoch;
pub(crate) use store_tables::reset;
