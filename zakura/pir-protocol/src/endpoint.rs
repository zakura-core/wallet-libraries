//! Configured HTTP endpoints without browser URL syntax or Unicode hostname conversion.
//!
//! Hosts must be ASCII DNS names (including punycode), dotted-decimal IPv4 or
//! bracketed IPv6. Paths use ASCII URI syntax; encode non-ASCII characters first.
//! Credentials, queries, fragments, backslashes and embedded whitespace are refused.
//! Surrounding ASCII whitespace, scheme/host case, default ports and dot path
//! segments are normalized. This crate does not open network connections.

use std::net::{Ipv4Addr, Ipv6Addr};

/// A validated endpoint, with a normalized authority and base path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    authority: String,
    path: String,
    https: bool,
    loopback: bool,
}

/// The input is outside the supported HTTP endpoint syntax.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidEndpoint;

impl std::fmt::Display for InvalidEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("expected an HTTP(S) endpoint with an ASCII DNS name or standard IP literal, without credentials, query or fragment")
    }
}

impl std::error::Error for InvalidEndpoint {}

impl Endpoint {
    /// Validate a configured endpoint and normalize its authority and path.
    ///
    /// Hostname resolution belongs to the caller's transport. `is_loopback`
    /// recognizes only literal loopback IPs and the exact name `localhost`.
    pub fn parse(input: &str) -> Result<Self, InvalidEndpoint> {
        let input = input.trim_matches(|c: char| c.is_ascii_whitespace());
        if !input.is_ascii()
            || input
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
            || input.contains(['\\', '?', '#'])
        {
            return Err(InvalidEndpoint);
        }
        // Require an explicit authority instead of browser shorthand such as
        // `https:example.org` or `https:///example.org`.
        let (scheme, rest) = input.split_once("://").ok_or(InvalidEndpoint)?;
        let https = if scheme.eq_ignore_ascii_case("https") {
            true
        } else if scheme.eq_ignore_ascii_case("http") {
            false
        } else {
            return Err(InvalidEndpoint);
        };
        let uri: http::Uri = format!("{}://{rest}", if https { "https" } else { "http" })
            .parse()
            .map_err(|_| InvalidEndpoint)?;
        let authority = uri.authority().ok_or(InvalidEndpoint)?;
        if authority.as_str().contains('@') {
            return Err(InvalidEndpoint);
        }
        let raw_host = authority.host();
        let (host, loopback) = normalize_host(raw_host)?;
        let port = &authority.as_str()[raw_host.len()..];
        let port = if port.is_empty() {
            None
        } else {
            let digits = port.strip_prefix(':').ok_or(InvalidEndpoint)?;
            if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return Err(InvalidEndpoint);
            }
            Some(digits.parse::<u16>().map_err(|_| InvalidEndpoint)?)
        };
        let authority = match port {
            Some(port) if port != if https { 443 } else { 80 } => format!("{host}:{port}"),
            _ => host,
        };
        let path = normalize_path(uri.path())?;
        Ok(Self {
            authority,
            path,
            https,
            loopback,
        })
    }

    /// Whether this endpoint uses HTTPS.
    pub fn is_https(&self) -> bool {
        self.https
    }

    /// Whether the host is a loopback IP literal or exactly `localhost`.
    pub fn is_loopback(&self) -> bool {
        self.loopback
    }

    /// Append an absolute route to the base path, preserving encoded separators.
    ///
    /// The route is a path, never a second authority, query or fragment. Dot
    /// segments are normalized after concatenation, just as in the base path.
    pub fn join(&self, route: &str) -> Result<String, InvalidEndpoint> {
        if !route.starts_with('/') {
            return Err(InvalidEndpoint);
        }
        let path = normalize_path(&format!("{}{route}", self.path.trim_end_matches('/')))?;
        Ok(format!(
            "{}://{}{path}",
            if self.https { "https" } else { "http" },
            self.authority
        ))
    }
}

fn normalize_host(host: &str) -> Result<(String, bool), InvalidEndpoint> {
    if let Some(ip) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        let ip: Ipv6Addr = ip.parse().map_err(|_| InvalidEndpoint)?;
        return Ok((format!("[{ip}]"), ip.is_loopback()));
    }
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok((ip.to_string(), ip.is_loopback()));
    }
    let host = host.to_ascii_lowercase();
    let name = host.strip_suffix('.').unwrap_or(&host);
    // A numeric final label can be interpreted by browser transports as a
    // shortened, octal or hexadecimal IPv4 address. Require standard IPv4 above.
    let last = name.rsplit('.').next().ok_or(InvalidEndpoint)?;
    let numeric = last.bytes().all(|b| b.is_ascii_digit())
        || last
            .strip_prefix("0x")
            .is_some_and(|n| n.bytes().all(|b| b.is_ascii_hexdigit()));
    if name.is_empty()
        || numeric
        || !name.split('.').all(|label| {
            !label.is_empty()
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(InvalidEndpoint);
    }
    let loopback = host == "localhost";
    Ok((host, loopback))
}

fn normalize_path(path: &str) -> Result<String, InvalidEndpoint> {
    if !path.is_empty() && !path.starts_with('/') {
        return Err(InvalidEndpoint);
    }
    let mut bytes = path.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            if !bytes.next().is_some_and(|b| b.is_ascii_hexdigit())
                || !bytes.next().is_some_and(|b| b.is_ascii_hexdigit())
            {
                return Err(InvalidEndpoint);
            }
        } else if !(byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/".contains(&byte)) {
            return Err(InvalidEndpoint);
        }
    }
    let segments: Vec<_> = path.split('/').skip(1).collect();
    let mut normalized = Vec::new();
    for (i, segment) in segments.iter().enumerate() {
        let dot = *segment == "." || segment.eq_ignore_ascii_case("%2e");
        let parent = *segment == ".."
            || segment.eq_ignore_ascii_case(".%2e")
            || segment.eq_ignore_ascii_case("%2e.")
            || segment.eq_ignore_ascii_case("%2e%2e");
        if parent {
            normalized.pop();
        }
        if !dot && !parent {
            normalized.push(*segment);
        } else if i + 1 == segments.len() {
            normalized.push("");
        }
    }
    Ok(format!("/{}", normalized.join("/")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_endpoints_match_the_previous_url_parser() {
        for base in [
            "https://example.org",
            "  HTTPS://EXAMPLE.ORG:443/a/../base/  ",
            "https://example.org/a%2Fb",
            "https://example.org/a/%2e%2E/base/",
            "https://example.org//a///base/",
            "https://example.org/a/.",
            "https://example.org/a/..",
            "https://example.org/../../base/",
            "https://example.org/a%20b",
            "https://example.org/a%3Fb%23c",
            "https://xn--bcher-kva.example/",
            "https://EXAMPLE.ORG./base/",
            "http://127.0.0.1:8080",
            "http://127.2.3.4:080/base/",
            "http://LOCALHOST:80/base",
            "https://[2001:0db8::1]:443/base/",
            "http://[0:0:0:0:0:0:0:1]:8080/base/",
            "https://example.org:0/",
        ] {
            for route in ["/v1/enhance/init", "/v1/unit/42", "/a%2Fb", "/../query"] {
                let mut old = url::Url::parse(base).unwrap();
                old.set_path(&format!("{}{route}", old.path().trim_end_matches('/')));
                assert_eq!(
                    Endpoint::parse(base).unwrap().join(route).unwrap(),
                    old.as_str(),
                    "{base}, {route}"
                );
            }
        }
    }

    #[test]
    fn rejects_ambiguous_or_unsupported_endpoint_syntax() {
        for base in [
            "",
            "example.org",
            "https:example.org",
            "https:///example.org",
            "//example.org",
            "ftp://example.org",
            "https://",
            "https://user@example.org",
            "https://@example.org",
            "https://example.org?",
            "https://example.org/#",
            "https://example.org/?q=1",
            "https://example.org\\@evil.example/",
            "https://example.org/\npath",
            "https://example.org/\tpath",
            "https://exam ple.org",
            "https://example.org/a b",
            "https://bücher.example/",
            "https://example.org/é",
            "https://%65xample.org/",
            "http://127.1",
            "http://2130706433",
            "http://0177.0.0.1",
            "http://0x7f000001",
            "http://127.0.0.01",
            "https://example.123",
            "http://[::1%25lo0]",
            "https://example.org:",
            "https://example.org:abc",
            "https://example.org:65536",
            "https://[::zzz]",
            "https://[::1]:abc",
            "https://-example.org",
            "https://example..org",
            "https://example.org/%",
            "https://example.org/%gg",
            "https://example.org/%a",
        ] {
            assert!(Endpoint::parse(base).is_err(), "accepted {base:?}");
        }
    }

    #[test]
    fn only_explicit_loopback_hosts_allow_local_http_policy() {
        for host in ["localhost", "LOCALHOST", "127.0.0.1", "127.2.3.4", "[::1]"] {
            let endpoint = Endpoint::parse(&format!("http://{host}/")).unwrap();
            assert!(!endpoint.is_https());
            assert!(endpoint.is_loopback(), "{host}");
        }
        for host in [
            "example.org",
            "localhost.",
            "localhost.example.org",
            "128.0.0.1",
            "[::ffff:127.0.0.1]",
        ] {
            assert!(
                !Endpoint::parse(&format!("http://{host}/"))
                    .unwrap()
                    .is_loopback(),
                "{host}"
            );
        }
    }

    #[test]
    fn routes_cannot_add_queries_fragments_or_credentials() {
        let endpoint = Endpoint::parse("https://example.org/base/").unwrap();
        for route in [
            "relative",
            "?q=1",
            "/path?q=1",
            "/path#fragment",
            "/\\evil.example",
            "/a b",
            "/%",
        ] {
            assert!(endpoint.join(route).is_err(), "accepted {route}");
        }
        assert_eq!(
            endpoint.join("//evil.example/path").unwrap(),
            "https://example.org/base//evil.example/path"
        );
    }
}
