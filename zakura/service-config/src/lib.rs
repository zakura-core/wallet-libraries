//! Static and dynamic service config resolution shared by Zakura applications.
//!
//! An application ships a *static config source*: an HTTPS URL, optionally
//! pinned to the SHA-256 of the document it serves. The static document names
//! the *dynamic config* mirrors and the trust material that authenticates
//! them. This crate turns bytes the application fetched into checked,
//! fingerprinted documents:
//!
//! ```text
//!   source string ──parse──▶ ConfigSource ──verify pin──▶ ResolvedStatic<S>
//!                                                            │
//!   mirror bytes ──decode──▶ profile validation ──attest──▶ ResolvedDynamic<D, V>
//!                     ▲                                      │
//!        resolve_from_mirrors walks mirrors in order          ▼
//!                                                       LastGoodConfig<T>
//! ```
//!
//! The application owns everything with a side effect: transport, routing,
//! cancellation, response limits, deadlines, refresh scheduling and
//! persistence. Nothing here performs I/O or needs an async runtime, so the
//! same calls work from a wallet, a server or a test.
//!
//! Each application describes its documents with a [`ConfigProfile`] and
//! registers the attestation methods it accepts in an [`AttestationPolicy`].
//! A static document may select one of those registered methods and supply
//! public trust data for it; it can never introduce a method the application
//! did not register. Verifiers receive the raw dynamic bytes as well as the
//! decoded document, so a method may authenticate individual entries, a
//! detached signature, or rely on the HTTPS transport alone
//! ([`HttpsTransport`]).
//!
//! The crate does not choose between servers a document advertises. Routing
//! and server selection remain application policy; only config *mirrors*
//! (copies of the same dynamic document) are walked in order.

mod attestation;
mod endpoint;
mod fingerprint;
mod mirror;
mod profile;
mod refresh;
mod source;
mod url;

pub use attestation::{
    AttestationError, AttestationMethod, AttestationPolicy, AttestationSelection,
    AttestationSubject, AttestationVerifier, Attested, HttpsTransport, TransportAuthenticated,
};
pub use endpoint::{EndpointListError, LabeledEndpoint, validate_labeled_endpoints};
pub use fingerprint::{fingerprint_bytes, fingerprint_json};
pub use mirror::{
    AttemptFailure, CandidateRank, MirrorAttempt, MirrorError, MirrorFailure, MirrorResolution,
    resolve_from_mirrors,
};
pub use profile::{
    ConfigProfile, ResolveError, ResolvedDynamic, ResolvedStatic, resolve_dynamic, resolve_static,
};
pub use refresh::{LastGoodConfig, RefreshOutcome};
pub use source::{ConfigSource, PinCheck, PinMismatch, SourceError};
pub use url::{UrlError, UrlErrorKind, validate_https_url};
