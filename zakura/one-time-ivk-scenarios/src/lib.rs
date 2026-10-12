//! The report of the one-time IVK scenario suite.
//!
//! The scenarios themselves are this crate's `scenarios` test target (see the README).
//! Each run writes a [`Report`] as JSON and renders it as Markdown and HTML, so a
//! reader can see every simulated case, what happened in it, and whether that matched
//! the documented behavior of one-time IVKs.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod html;
mod markdown;

pub use html::render_html;
pub use markdown::render_markdown;

use serde::{Deserialize, Serialize};

/// One run of the suite.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Report {
    /// What the run tested and where.
    pub meta: Meta,
    /// Every scenario that ran, in catalog order.
    pub scenarios: Vec<ScenarioResult>,
}

/// What a run tested and where.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Meta {
    /// Unix time the run started.
    pub started_unix: i64,
    /// Wall time of the whole run, in milliseconds.
    pub duration_ms: u64,
    /// Revisions under test, such as the wallet-libraries commit, as name and value.
    pub revisions: Vec<(String, String)>,
    /// The scenario filter, if the run was not the whole catalog.
    pub filter: Option<String>,
    /// Worker threads the scenarios ran on.
    pub jobs: usize,
}

/// How a payment to a one-time key was found by one wallet, or why it was not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Class {
    /// Credited by scanning while its key was open.
    FoundLive,
    /// Credited by an automatic receiver-directory sweep: the restore of a lookahead or
    /// refund key, or the paid-filter check of a closed key.
    FoundBySweep,
    /// Credited only after the user's "Check swap history".
    FoundAfterRecheck,
    /// Not credited, which the library documents.
    MissedDocumented,
    /// Not credited. As an expectation this never appears; as an outcome it means the
    /// wallet missed a payment the documented contract says it finds.
    Missed,
}

impl Class {
    /// Whether the wallet credited the payment.
    pub fn found(self) -> bool {
        matches!(
            self,
            Self::FoundLive | Self::FoundBySweep | Self::FoundAfterRecheck
        )
    }

    /// A short label for tables.
    pub fn label(self) -> &'static str {
        match self {
            Self::FoundLive => "found live",
            Self::FoundBySweep => "found by sweep",
            Self::FoundAfterRecheck => "found after recheck",
            Self::MissedDocumented => "missed (documented)",
            Self::Missed => "missed",
        }
    }

    /// Whether an outcome satisfies this expectation. A documented miss is satisfied
    /// only by a miss.
    pub fn satisfied_by(self, actual: Class) -> bool {
        match self {
            Self::MissedDocumented => !actual.found(),
            expected => expected == actual,
        }
    }
}

/// The verdict on one scenario.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    /// Every payment and check matched the documented contract.
    Pass,
    /// Some payment or check did not.
    Fail,
    /// The scenario could not run to the end, for example because a wallet call failed.
    Error,
}

/// One scenario's result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScenarioResult {
    /// Stable identifier, such as `C3-incoming-twice-21d`.
    pub id: String,
    /// The catalog group, such as `C. Live detection`.
    pub group: String,
    /// One-line title.
    pub title: String,
    /// What the scenario shows and why it matters.
    pub summary: String,
    /// The parameters this case was generated with.
    pub params: Vec<(String, String)>,
    /// The verdict.
    pub outcome: Outcome,
    /// Why the scenario stopped early, for [`Outcome::Error`].
    pub error: Option<String>,
    /// Wall time, in milliseconds.
    pub duration_ms: u64,
    /// What happened, in order.
    pub timeline: Vec<Event>,
    /// Every payment to a one-time key, per observing wallet.
    pub payments: Vec<PaymentResult>,
    /// Other assertions, such as balances and address privacy.
    pub checks: Vec<Check>,
    /// Measurements, such as PIR lookups or open keys.
    pub metrics: Vec<Metric>,
}

impl ScenarioResult {
    /// Payments whose outcome did not satisfy their expectation.
    pub fn mismatches(&self) -> impl Iterator<Item = &PaymentResult> {
        self.payments
            .iter()
            .filter(|p| !p.expected.satisfied_by(p.actual))
    }
}

/// One timeline entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    /// Days since the scenario's chain started.
    pub day: f64,
    /// The chain tip when it happened.
    pub height: u32,
    /// Who acted: a wallet, NEAR, the directory or the chain.
    pub actor: String,
    /// What happened.
    pub text: String,
}

/// One payment to a one-time key, as one wallet saw it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentResult {
    /// The scenario's name for the payment, such as `payout 2`.
    pub payment: String,
    /// The key it paid, such as `I0` (incoming 0) or `R3` (refund 3).
    pub key: String,
    /// The wallet observing it.
    pub wallet: String,
    /// Value in zatoshis.
    pub value: u64,
    /// The block that mined it.
    pub height: u32,
    /// Days since the chain started when it was mined.
    pub day: f64,
    /// Who paid and how, such as `NEAR (zero OVK)`.
    pub payer: String,
    /// What the documented contract predicts.
    pub expected: Class,
    /// What happened.
    pub actual: Class,
    /// Why the expectation holds, citing the contract.
    pub rationale: String,
}

/// One assertion other than a payment's class.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Check {
    /// What was checked.
    pub name: String,
    /// Whether it held.
    pub ok: bool,
    /// The observed value, or why it failed.
    pub detail: String,
}

/// One measurement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Metric {
    /// What was measured.
    pub name: String,
    /// The value.
    pub value: f64,
    /// Its unit, such as `lookups` or `ms`.
    pub unit: String,
}

/// Totals across a report.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Totals {
    /// Scenarios that passed.
    pub passed: usize,
    /// Scenarios that failed.
    pub failed: usize,
    /// Scenarios that stopped with an error.
    pub errors: usize,
    /// Payment observations, by outcome class, in [`Class`] order.
    pub by_class: Vec<(Class, usize)>,
    /// Payment observations whose outcome did not match the contract.
    pub mismatches: usize,
}

impl Report {
    /// Totals across every scenario.
    pub fn totals(&self) -> Totals {
        let mut totals = Totals::default();
        let mut by_class = std::collections::BTreeMap::new();
        for scenario in &self.scenarios {
            match scenario.outcome {
                Outcome::Pass => totals.passed += 1,
                Outcome::Fail => totals.failed += 1,
                Outcome::Error => totals.errors += 1,
            }
            for payment in &scenario.payments {
                *by_class.entry(payment.actual).or_insert(0) += 1;
            }
            totals.mismatches += scenario.mismatches().count();
        }
        totals.by_class = by_class.into_iter().collect();
        totals
    }

    /// The catalog groups in first-seen order.
    pub fn groups(&self) -> Vec<&str> {
        let mut groups: Vec<&str> = Vec::new();
        for scenario in &self.scenarios {
            if !groups.contains(&scenario.group.as_str()) {
                groups.push(&scenario.group);
            }
        }
        groups
    }
}

/// Formats zatoshis as ZEC with up to eight decimals, trimming trailing zeros.
pub fn zec(zatoshis: u64) -> String {
    let whole = zatoshis / 100_000_000;
    let fraction = zatoshis % 100_000_000;
    if fraction == 0 {
        return format!("{whole} ZEC");
    }
    let digits = format!("{fraction:08}");
    format!("{whole}.{} ZEC", digits.trim_end_matches('0'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expectations_and_amounts() {
        assert!(Class::MissedDocumented.satisfied_by(Class::Missed));
        assert!(!Class::MissedDocumented.satisfied_by(Class::FoundBySweep));
        assert!(!Class::FoundLive.satisfied_by(Class::FoundBySweep));
        assert!(Class::FoundAfterRecheck.satisfied_by(Class::FoundAfterRecheck));
        assert_eq!(zec(150_000_000), "1.5 ZEC");
        assert_eq!(zec(100_000_000), "1 ZEC");
        assert_eq!(zec(1), "0.00000001 ZEC");
    }
}
