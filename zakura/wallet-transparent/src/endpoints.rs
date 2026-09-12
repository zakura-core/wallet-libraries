//! Where the two halves of a transparent sync are fetched from.

/// The services a transparent sync reads from.
///
/// Two, and required to be two. Public filter bytes are identical for every
/// wallet and reveal nothing about which one asked; the private queries that
/// follow reveal which chain ranges had probable activity. Taking both from one
/// host lets whoever runs it join those two facts together, which no property
/// of the protocol prevents.
///
/// Nothing is defaulted. A default would be a host this wallet talks to because
/// nobody chose otherwise, which is the opposite of the decision being made
/// deliberately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    /// Where the shard map and the public activity filters come from.
    pub filters_url: String,
    /// Where private retrieval is answered.
    pub shards_url: String,
}

impl Endpoints {
    /// Names the two services.
    pub fn new(filters_url: impl Into<String>, shards_url: impl Into<String>) -> Self {
        Self {
            filters_url: filters_url.into().trim_end_matches('/').to_owned(),
            shards_url: shards_url.into().trim_end_matches('/').to_owned(),
        }
    }

    /// Whether both halves would be fetched from the same host.
    ///
    /// Not refused, because a developer running both services on one machine is
    /// a legitimate thing to do and refusing it would only teach people to work
    /// around the check. It is reported so that a wallet shipping this
    /// configuration is doing so knowingly.
    pub fn shares_a_host(&self) -> bool {
        host_of(&self.filters_url) == host_of(&self.shards_url)
    }
}

/// The scheme-and-authority prefix of a URL, for comparison only.
fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    rest.split('/').next().unwrap_or(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_trailing_slash_does_not_change_an_endpoint() {
        assert_eq!(
            Endpoints::new("https://a.example/", "https://b.example"),
            Endpoints::new("https://a.example", "https://b.example"),
        );
    }

    #[test]
    fn one_host_serving_both_halves_is_reported() {
        assert!(Endpoints::new("http://127.0.0.1:8090", "http://127.0.0.1:8090").shares_a_host());
        // A different port is a different service, and that is the case a
        // developer running both locally is actually in.
        assert!(!Endpoints::new("http://127.0.0.1:8090", "http://127.0.0.1:8092").shares_a_host());
        assert!(!Endpoints::new("https://a.example", "https://b.example").shares_a_host());
    }
}
