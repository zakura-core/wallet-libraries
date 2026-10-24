//! Ordered walk over dynamic config mirrors.
//!
//! Mirrors are copies of the same dynamic document at different URLs. Walking
//! them widens availability, not trust: every candidate goes through the same
//! resolution and attestation, so a mirror can be stale but cannot forge.

use std::fmt;

use serde::{Deserialize, Serialize};

/// One mirror's fetch outcome, reported by the application's transport.
///
/// `fetched` holds the response bytes, or the transport's error message
/// (including a timeout the application enforced) for a mirror it could not
/// read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorAttempt {
    pub url: String,
    pub fetched: Result<Vec<u8>, String>,
}

impl MirrorAttempt {
    pub fn fetched(url: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            url: url.into(),
            fetched: Ok(bytes),
        }
    }

    pub fn failed(url: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            fetched: Err(error.into()),
        }
    }
}

/// How much the application prefers a candidate that resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CandidateRank {
    /// Use it and stop walking.
    Preferred,
    /// Usable, but try later mirrors first; `reason` is reported for it if a
    /// later mirror wins.
    Fallback { reason: String },
}

/// A mirror that was passed over, with a human-readable reason.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorFailure {
    pub url: String,
    pub reason: String,
}

/// The candidate chosen by [`resolve_from_mirrors`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MirrorResolution<T> {
    pub value: T,
    /// URL of the mirror that produced `value`.
    pub url: String,
    /// Mirrors tried before `url`, in order. Empty when the first mirror won.
    pub passed_over: Vec<MirrorFailure>,
}

/// Why the last mirror tried did not resolve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttemptFailure<E> {
    /// The transport reported this error.
    Transport(String),
    /// The bytes arrived but resolution rejected them.
    Resolve(E),
}

/// No mirror produced a usable candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MirrorError<E> {
    /// The application supplied no attempts.
    NoAttempts,
    /// Every attempt failed. `failures` lists each mirror in order; `last` is
    /// the final mirror's failure, for callers that report a single cause.
    Exhausted {
        failures: Vec<MirrorFailure>,
        last: AttemptFailure<E>,
    },
}

impl<E> MirrorError<E> {
    /// `url: reason` for each failed mirror, joined with `; `.
    pub fn summary(&self) -> String {
        match self {
            Self::NoAttempts => "no mirrors attempted".to_string(),
            Self::Exhausted { failures, .. } => failures
                .iter()
                .map(|failure| format!("{}: {}", failure.url, failure.reason))
                .collect::<Vec<_>>()
                .join("; "),
        }
    }
}

/// Resolves the first preferred candidate from ordered mirror attempts.
///
/// Walks `attempts` in order. A transport failure or a `resolve` error passes
/// the mirror over. A resolved candidate ranked [`CandidateRank::Preferred`]
/// is returned immediately; the first one ranked [`CandidateRank::Fallback`]
/// is kept and returned only if no later mirror produces a preferred one. In
/// that case `passed_over` lists only the mirrors before the fallback, since
/// those after it were not preferred to it.
///
/// Reasons are `fetch failed: <transport error>`, the `resolve` error's
/// `Display`, or the fallback rank's reason.
pub fn resolve_from_mirrors<T, E: fmt::Display>(
    attempts: impl IntoIterator<Item = MirrorAttempt>,
    mut resolve: impl FnMut(&str, &[u8]) -> Result<T, E>,
    mut rank: impl FnMut(&T) -> CandidateRank,
) -> Result<MirrorResolution<T>, MirrorError<E>> {
    let mut failures = Vec::new();
    let mut last = None;
    // First fallback candidate, its URL, and how many failures preceded it.
    let mut fallback: Option<(T, String, usize)> = None;

    for attempt in attempts {
        let bytes = match attempt.fetched {
            Ok(bytes) => bytes,
            Err(error) => {
                failures.push(MirrorFailure {
                    url: attempt.url,
                    reason: format!("fetch failed: {error}"),
                });
                last = Some(AttemptFailure::Transport(error));
                continue;
            }
        };
        match resolve(&attempt.url, &bytes) {
            Ok(value) => match rank(&value) {
                CandidateRank::Preferred => {
                    return Ok(MirrorResolution {
                        value,
                        url: attempt.url,
                        passed_over: failures,
                    });
                }
                CandidateRank::Fallback { reason } => {
                    if fallback.is_none() {
                        fallback = Some((value, attempt.url.clone(), failures.len()));
                    }
                    failures.push(MirrorFailure {
                        url: attempt.url,
                        reason,
                    });
                }
            },
            Err(error) => {
                failures.push(MirrorFailure {
                    url: attempt.url,
                    reason: error.to_string(),
                });
                last = Some(AttemptFailure::Resolve(error));
            }
        }
    }

    if let Some((value, url, failures_before)) = fallback {
        failures.truncate(failures_before);
        return Ok(MirrorResolution {
            value,
            url,
            passed_over: failures,
        });
    }
    match last {
        Some(last) => Err(MirrorError::Exhausted { failures, last }),
        None => Err(MirrorError::NoAttempts),
    }
}
