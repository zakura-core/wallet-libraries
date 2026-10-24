//! Static config source strings and their optional SHA-256 pins.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    fingerprint::fingerprint_json,
    url::{UrlError, validate_https_url},
};

const CHECKSUM_QUERY_NAME: &str = "checksum";
const SHA256_CHECKSUM_PREFIX: &str = "sha256:";

/// A static config location chosen by the application.
///
/// Written as `https://host/path[?query][&checksum=sha256:<hex>]`. The
/// `checksum` query item is a pin: it is removed from [`Self::url`], the URL
/// to fetch, and the fetched bytes must hash to it. Other query items are kept
/// in their original order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigSource {
    /// The trimmed source string as supplied.
    pub raw: String,
    /// The URL to fetch, without the `checksum` item.
    pub url: String,
    /// Expected lowercase hex SHA-256 of the static document, when pinned.
    pub sha256: Option<String>,
}

/// A source string that cannot be used.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SourceError {
    #[error(transparent)]
    Url(#[from] UrlError),
    /// The `checksum` item names an algorithm other than SHA-256.
    #[error("checksum must start with sha256:")]
    UnsupportedChecksum,
    /// The SHA-256 pin is not 64 lowercase hex characters.
    #[error("sha256 must be 64 lowercase hex characters")]
    MalformedSha256,
}

/// Outcome of checking fetched bytes against a source's pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinCheck {
    /// The bytes hash to the pinned digest.
    Verified,
    /// The source carried no pin, so the bytes were trusted as fetched.
    Unpinned,
}

/// Fetched bytes that do not hash to the source's pin.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("hash-pin mismatch: expected {expected}, got {actual}")]
pub struct PinMismatch {
    pub expected: String,
    pub actual: String,
}

impl ConfigSource {
    /// Parses an HTTPS source string with an optional
    /// `checksum=sha256:<hex>` query item.
    ///
    /// Surrounding whitespace is ignored. When several `checksum` items are
    /// present, the last one wins.
    pub fn parse(raw: &str) -> Result<Self, SourceError> {
        let trimmed = raw.trim();
        validate_https_url(trimmed, "static config source")?;

        let (base, query) = match trimmed.split_once('?') {
            Some((base, query)) => (base, Some(query)),
            None => (trimmed, None),
        };
        let mut kept_query_items = Vec::new();
        let mut sha256 = None;
        for item in query
            .into_iter()
            .flat_map(|q| q.split('&'))
            .filter(|s| !s.is_empty())
        {
            let (name, value) = item.split_once('=').unwrap_or((item, ""));
            if name != CHECKSUM_QUERY_NAME {
                kept_query_items.push(item);
                continue;
            }
            let hex = value
                .strip_prefix(SHA256_CHECKSUM_PREFIX)
                .ok_or(SourceError::UnsupportedChecksum)?;
            if !is_lowercase_hex_32(hex) {
                return Err(SourceError::MalformedSha256);
            }
            sha256 = Some(hex.to_string());
        }

        let url = if kept_query_items.is_empty() {
            base.to_string()
        } else {
            format!("{}?{}", base, kept_query_items.join("&"))
        };
        Ok(Self {
            raw: trimmed.to_string(),
            url,
            sha256,
        })
    }

    /// Checks `bytes` against the pin, if any.
    pub fn verify_pin(&self, bytes: &[u8]) -> Result<PinCheck, PinMismatch> {
        let Some(expected) = &self.sha256 else {
            return Ok(PinCheck::Unpinned);
        };
        let actual = hex::encode(Sha256::digest(bytes));
        if actual == *expected {
            Ok(PinCheck::Verified)
        } else {
            Err(PinMismatch {
                expected: expected.clone(),
                actual,
            })
        }
    }

    /// Stable fingerprint of the source, including its pin.
    pub fn fingerprint(&self) -> String {
        fingerprint_json(self)
    }
}

fn is_lowercase_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
