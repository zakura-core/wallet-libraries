//! Canonical identity of an advertised wallet PIR server.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zakura_pir_protocol::endpoint::{Endpoint, InvalidEndpoint};

/// The normalized HTTPS base URL of one wallet PIR server.
///
/// Parsed with the PIR clients' own endpoint syntax: ASCII DNS names or
/// standard IP literals only, no credentials, query or fragment. Scheme and
/// host case, the default port, dot segments and a trailing `/` are
/// normalized away, so `HTTPS://Server.Example:443/pir/` and
/// `https://server.example/pir` are the same server. This is the identity a
/// selection persists; labels are display text only.
///
/// Serializes as its canonical string and re-validates when deserialized.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ServerBase {
    canonical: String,
    endpoint: Endpoint,
}

/// Why a server URL is not a usable wallet PIR base.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum InvalidServerBase {
    #[error("{0}")]
    Syntax(InvalidEndpoint),
    /// Wallet PIR queries are private; plain HTTP is never accepted, even for
    /// loopback hosts.
    #[error("server base must use https")]
    NotHttps,
    /// `//` in a base path makes appended product routes ambiguous.
    #[error("server base path must not contain empty segments")]
    EmptyPathSegment,
}

impl ServerBase {
    /// Validates and normalizes a server base URL.
    pub fn parse(url: &str) -> Result<Self, InvalidServerBase> {
        let endpoint = Endpoint::parse(url).map_err(InvalidServerBase::Syntax)?;
        if !endpoint.is_https() {
            return Err(InvalidServerBase::NotHttps);
        }
        // `join` normalizes the base path and drops its trailing slashes
        // before appending, so joining the root route yields the base path
        // exactly as the product clients will extend it.
        let root = endpoint.join("/").map_err(InvalidServerBase::Syntax)?;
        let canonical = root.strip_suffix('/').unwrap_or(&root).to_string();
        let path = canonical
            .strip_prefix("https://")
            .and_then(|rest| rest.split_once('/'))
            .map_or("", |(_, path)| path);
        if !path.is_empty() && path.split('/').any(str::is_empty) {
            return Err(InvalidServerBase::EmptyPathSegment);
        }
        Ok(Self {
            canonical,
            endpoint,
        })
    }

    /// The canonical URL, without a trailing `/`.
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    /// The parsed endpoint that product routes are joined onto.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
}

impl PartialEq for ServerBase {
    fn eq(&self, other: &Self) -> bool {
        self.canonical == other.canonical
    }
}

impl Eq for ServerBase {}

impl Hash for ServerBase {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.canonical.hash(state);
    }
}

impl PartialOrd for ServerBase {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ServerBase {
    fn cmp(&self, other: &Self) -> Ordering {
        self.canonical.cmp(&other.canonical)
    }
}

impl fmt::Display for ServerBase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical)
    }
}

impl TryFrom<String> for ServerBase {
    type Error = InvalidServerBase;

    fn try_from(url: String) -> Result<Self, Self::Error> {
        Self::parse(&url)
    }
}

impl From<ServerBase> for String {
    fn from(base: ServerBase) -> Self {
        base.canonical
    }
}

/// A server from a resolved dynamic config: its display label and identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdvertisedServer {
    /// Display text from the config. Never used to identify the server.
    pub label: String,
    pub base: ServerBase,
}
