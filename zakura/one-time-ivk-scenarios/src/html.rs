//! The HTML rendering of a [`Report`]: one self-contained page that embeds the report as
//! JSON and draws it in the browser.

use crate::Report;

/// Renders `report` as a standalone HTML document, for opening from disk.
pub fn render_html(report: &Report) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1, viewport-fit=cover\">\n</head>\n<body>\n{}\n</body>\n</html>\n",
        render_html_page(report)
    )
}

/// Renders `report` as the body of a page, without the document skeleton, for hosts that
/// supply their own (such as a published artifact).
pub fn render_html_page(report: &Report) -> String {
    let json = serde_json::to_string(report)
        .expect("a report serializes")
        // Keep the embedded JSON from closing its script element.
        .replace("</", "<\\/");
    TEMPLATE.replace("__REPORT_JSON__", &json)
}

const TEMPLATE: &str = include_str!("report.html");
