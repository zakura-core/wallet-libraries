//! HTTPS URL shape checks for config sources and advertised endpoints.

use thiserror::Error;

/// Why a value is not an acceptable HTTPS URL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UrlErrorKind {
    /// The value does not start with `https://`.
    NotHttps,
    /// The authority is empty or carries `user@` credentials.
    InvalidHost,
}

/// A rejected URL, naming the config field it came from.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{field} {}", match kind {
    UrlErrorKind::NotHttps => "must use https",
    UrlErrorKind::InvalidHost => "must include a valid host",
})]
pub struct UrlError {
    /// Config field path, such as `dynamic_config_urls[1]`.
    pub field: String,
    pub kind: UrlErrorKind,
}

/// Checks that `value` is an `https://` URL with a non-empty host and no
/// embedded credentials.
///
/// This is a shape check, not a full URL parse: it guarantees the transport is
/// TLS and that a host is present, and leaves path and query to the caller.
pub fn validate_https_url(value: &str, field: &str) -> Result<(), UrlError> {
    let error = |kind| UrlError {
        field: field.to_string(),
        kind,
    };
    let rest = value
        .strip_prefix("https://")
        .ok_or_else(|| error(UrlErrorKind::NotHttps))?;
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if host.is_empty() || host.contains('@') {
        return Err(error(UrlErrorKind::InvalidHost));
    }
    Ok(())
}
