//! The scenario catalog, grouped as in the suite plan.

mod incoming;
mod refund;

use crate::harness::Ctx;

pub const FUNDING: &str = "B. Funding and refunds";
pub const LIVE: &str = "C. Live detection";
pub const OFFLINE: &str = "D. Offline and clocks";
pub const RESTORE: &str = "E. Restore from seed";
pub const STATUSES: &str = "H. Provider statuses";

/// One scenario: a world the run builds, what it does in it, and what the documented
/// contract says should happen.
pub struct Scenario {
    /// Stable identifier, unique in the catalog.
    pub id: String,
    pub group: &'static str,
    pub title: String,
    /// What the scenario shows and why it matters.
    pub summary: String,
    pub params: Vec<(String, String)>,
    /// Too slow for the default run; selected by `--slow` or by naming it.
    pub slow: bool,
    pub run: Box<dyn Fn(&mut Ctx) + Send + Sync>,
}

/// Every scenario, in report order.
pub fn all() -> Vec<Scenario> {
    let mut scenarios = Vec::new();
    scenarios.extend(incoming::all());
    scenarios.extend(refund::all());
    let mut ids = std::collections::BTreeSet::new();
    for scenario in &scenarios {
        assert!(ids.insert(scenario.id.clone()), "duplicate id {}", scenario.id);
    }
    scenarios
}

/// Steps a scenario schedules by time, run in order.
pub struct Schedule<S> {
    steps: Vec<(i64, u32, S)>,
    order: u32,
}

impl<S> Schedule<S> {
    pub fn new() -> Self {
        Self {
            steps: Vec::new(),
            order: 0,
        }
    }

    /// Schedules `step` at Unix time `at`. Steps at one time run in the order added.
    pub fn at(&mut self, at: i64, step: S) {
        self.order += 1;
        self.steps.push((at, self.order, step));
    }

    /// The steps in time order.
    pub fn into_steps(mut self) -> Vec<(i64, S)> {
        self.steps.sort_by_key(|(at, order, _)| (*at, *order));
        self.steps.into_iter().map(|(at, _, s)| (at, s)).collect()
    }
}

/// Formats a duration in seconds the way the report names gaps.
pub fn span(secs: i64) -> String {
    use crate::harness::chain::{BLOCK_SECS, DAY, HOUR, MINUTE};
    if secs % DAY == 0 && secs >= DAY {
        format!("{}d", secs / DAY)
    } else if secs % HOUR == 0 && secs >= HOUR {
        format!("{}h", secs / HOUR)
    } else if secs % MINUTE == 0 && secs >= MINUTE {
        format!("{}m", secs / MINUTE)
    } else {
        format!("{}blk", secs / BLOCK_SECS)
    }
}
