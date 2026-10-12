//! The HTML rendering of a [`Report`]: one self-contained page.

use crate::Report;

/// Renders `report` as a self-contained HTML page that embeds the report as JSON and
/// draws it in the browser.
pub fn render_html(report: &Report) -> String {
    let json = serde_json::to_string(report)
        .expect("a report serializes")
        // Keep the embedded JSON from closing its script element.
        .replace("</", "<\\/");
    TEMPLATE.replace("__REPORT_JSON__", &json)
}

const TEMPLATE: &str = include_str!("report.html");
