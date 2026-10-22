//! Keeping the last accepted config across refreshes.

/// What a refresh did to the accepted config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefreshOutcome<E> {
    /// The candidate became the accepted config.
    Accepted,
    /// The candidate equals the accepted config; nothing changed.
    Unchanged,
    /// The refresh failed and the previously accepted config is kept.
    KeptPrevious { error: E },
    /// The refresh failed and there is no accepted config yet.
    Unavailable { error: E },
}

/// The most recently accepted config of an application.
///
/// A failed refresh, whether the fetch failed or the candidate was invalid,
/// never replaces or clears an accepted config. Persisting the accepted value
/// and scheduling refreshes are left to the application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LastGoodConfig<T> {
    accepted: Option<T>,
}

impl<T> Default for LastGoodConfig<T> {
    fn default() -> Self {
        Self { accepted: None }
    }
}

impl<T: PartialEq> LastGoodConfig<T> {
    /// Starts from a previously persisted config, or none.
    pub fn new(accepted: Option<T>) -> Self {
        Self { accepted }
    }

    pub fn accepted(&self) -> Option<&T> {
        self.accepted.as_ref()
    }

    pub fn into_accepted(self) -> Option<T> {
        self.accepted
    }

    /// Applies the result of one refresh attempt.
    pub fn refresh<E>(&mut self, candidate: Result<T, E>) -> RefreshOutcome<E> {
        match (candidate, &self.accepted) {
            (Ok(candidate), Some(accepted)) if *accepted == candidate => RefreshOutcome::Unchanged,
            (Ok(candidate), _) => {
                self.accepted = Some(candidate);
                RefreshOutcome::Accepted
            }
            (Err(error), Some(_)) => RefreshOutcome::KeptPrevious { error },
            (Err(error), None) => RefreshOutcome::Unavailable { error },
        }
    }
}
