//! SQLite storage for the transparent ledger (`tpir_*` tables).
//!
//! Projection origins record why each transparent output and spend exists in the wallet, so
//! that invalidating one source never removes a record another source still supports. Legacy
//! and local origins are provenance only; they never constitute ledger coverage.
//!
//! Handle configuration and the durable policy are enforced here. A candidate account's recovery
//! (`recovery`) is isolated from the projection. Promotion projects a complete, qualified ledger
//! (`projection`) and makes the account active; under `PrivateRequired`, only active accounts
//! whose ledger is complete through the chain tip can authorize transparent inputs.

mod authority;
pub(crate) mod details;
mod history;
mod origins;
mod policy;
#[cfg(feature = "transparent-inputs")]
mod projection;
mod reader_version;
mod recovery;
mod snapshot;
mod transactions;

#[cfg(any(test, not(feature = "transparent-inputs")))]
pub(crate) use authority::check_transparent_authority;
#[cfg(feature = "transparent-inputs")]
pub(crate) use authority::{
    InputAuthority, check_address_owners, check_public_discovery, grants_private_authority,
    input_authority, pending_result, public_discovery_permitted, refuse_unadmitted_input,
    refuse_unplaced_input,
};
pub(crate) use authority::{
    has_transparent_inputs, refused, transparent_funds_current, transparent_funds_refusal,
};
pub(crate) use history::transaction_history_details;
pub(crate) use origins::output_observation_condition;
#[cfg(feature = "transparent-inputs")]
pub(crate) use origins::{
    ProjectionOrigin, record_local_origins_for_tx, record_output_origin, record_spend_origin,
};
pub(crate) use policy::{
    applied_transparent_policy, apply_transparent_policy, capture_policy_generation,
    check_transparent_policy_generation, durable_policy, pending_private_transparent_details,
    resolve_mode, retains_public_authority,
};
#[cfg(all(test, feature = "transparent-inputs"))]
pub(crate) use reader_version::TPIR_READER_VERSION;
#[cfg(feature = "transparent-inputs")]
pub(crate) use reader_version::{
    ACTIVATION_READER_VERSION, METADATA_READER_VERSION, RECOVERY_READER_VERSION,
    REVISION_READER_VERSION, SHARED_DERIVATION_READER_VERSION, require_reader_version,
};
#[cfg(all(feature = "transparent-inputs", feature = "transparent-key-import"))]
pub(crate) use recovery::forget_other_candidates;
#[cfg(all(
    feature = "transparent-inputs",
    any(test, feature = "test-dependencies")
))]
pub(crate) use recovery::qualify_revision;
#[cfg(feature = "transparent-inputs")]
pub(crate) use recovery::{
    CommitTrust, activate_recovered_ledger, apply_commit, candidate_recovery, forget_ledger,
    forget_reattributed_script, watch_set,
};
pub(crate) use recovery::{clear_pending_pages, truncate_recovery};
pub(crate) use snapshot::ledger_snapshot;
#[cfg(feature = "transparent-inputs")]
use transactions::atomically;
pub(crate) use transactions::with_read_snapshot;

#[cfg(all(test, feature = "transparent-inputs"))]
mod tests;
