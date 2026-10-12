//! The Markdown rendering of a [`Report`], short enough to paste into a PR or chat.

use std::fmt::Write as _;

use crate::{Class, Outcome, Report, zec};

/// Renders `report` as Markdown: totals, every mismatch, then one table per group.
pub fn render_markdown(report: &Report) -> String {
    let mut out = String::new();
    let totals = report.totals();
    let _ = writeln!(out, "# One-time IVK scenario report\n");
    for (name, value) in &report.meta.revisions {
        let _ = writeln!(out, "- {name}: `{value}`");
    }
    if let Some(filter) = &report.meta.filter {
        let _ = writeln!(out, "- Filter: `{filter}`");
    }
    let _ = writeln!(
        out,
        "- {} scenarios in {:.1} s on {} threads\n",
        report.scenarios.len(),
        report.meta.duration_ms as f64 / 1000.0,
        report.meta.jobs
    );
    let _ = writeln!(
        out,
        "**{} passed, {} failed, {} errors.** {} payment observations did not match the documented contract.\n",
        totals.passed, totals.failed, totals.errors, totals.mismatches
    );
    let _ = writeln!(out, "| Outcome | Payment observations |\n|---|---:|");
    for (class, count) in &totals.by_class {
        let _ = writeln!(out, "| {} | {count} |", class.label());
    }
    let _ = writeln!(out);

    let problems: Vec<_> = report
        .scenarios
        .iter()
        .filter(|s| s.outcome != Outcome::Pass)
        .collect();
    if !problems.is_empty() {
        let _ = writeln!(out, "## Needs attention\n");
        for scenario in problems {
            let _ = writeln!(out, "- **{}** {}", scenario.id, scenario.title);
            if let Some(error) = &scenario.error {
                let _ = writeln!(out, "  - error: {error}");
            }
            for p in scenario.mismatches() {
                let _ = writeln!(
                    out,
                    "  - {} on {} ({}) to {}: expected {}, got {}",
                    p.payment,
                    p.wallet,
                    zec(p.value),
                    p.key,
                    p.expected.label(),
                    p.actual.label()
                );
            }
            for c in scenario.checks.iter().filter(|c| !c.ok) {
                let _ = writeln!(out, "  - check failed: {}: {}", c.name, c.detail);
            }
        }
        let _ = writeln!(out);
    }

    let documented: Vec<_> = report
        .scenarios
        .iter()
        .flat_map(|s| s.payments.iter().map(move |p| (s, p)))
        .filter(|(_, p)| p.expected == Class::MissedDocumented)
        .collect();
    let gaps: Vec<_> = report
        .scenarios
        .iter()
        .flat_map(|s| s.checks.iter().map(move |c| (s, c)))
        .filter(|(_, c)| c.documented_gap)
        .collect();
    if !documented.is_empty() || !gaps.is_empty() {
        let _ = writeln!(out, "## Documented misses\n");
        let _ = writeln!(
            out,
            "Payments the library documents it does not find. Each is a product decision, not a bug.\n"
        );
        for (s, p) in documented {
            let _ = writeln!(
                out,
                "- {}: {} to {} on {}. {}",
                s.id, p.payment, p.key, p.wallet, p.rationale
            );
        }
        for (s, c) in gaps {
            let _ = writeln!(out, "- {}: {}. {}", s.id, c.name, c.detail);
        }
        let _ = writeln!(out);
    }

    for group in report.groups() {
        let _ = writeln!(out, "## {group}\n");
        let _ = writeln!(out, "| Scenario | Result | Payments | Title |\n|---|---|---|---|");
        for s in report.scenarios.iter().filter(|s| s.group == group) {
            let result = match s.outcome {
                Outcome::Pass => "pass",
                Outcome::Fail => "**fail**",
                Outcome::Error => "**error**",
            };
            let payments = s
                .payments
                .iter()
                .map(|p| format!("{} {}: {}", p.wallet, p.payment, p.actual.label()))
                .collect::<Vec<_>>()
                .join("; ");
            let _ = writeln!(out, "| `{}` | {result} | {payments} | {} |", s.id, s.title);
        }
        let _ = writeln!(out);
    }
    out
}
