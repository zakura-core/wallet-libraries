//! Canonical Transparent PIR routes.
//!
//! Every Transparent request (the shard map and filters, shard init,
//! manifests, setup and queries, txid display, and the BIP-158 filter
//! service's metadata and ranges) addresses one product operation, such as
//! `/shards/init`, below the Transparent route namespace
//! ([`PirProduct::Transparent`], `/transparent/v1`). This module is the one
//! place that namespace is applied: transports bound to an origin send
//! [`origin_path`]s, and the reference HTTP adapters, given a server base URL,
//! send [`url`]s, which keep the base's path prefix. Nothing probes or falls
//! back to another route.

use zakura_pir_protocol::endpoint::PirProduct;
#[cfg(feature = "reqwest")]
use zakura_pir_protocol::endpoint::{Endpoint, InvalidEndpoint};

/// The origin-relative path of a Transparent product `operation`.
///
/// `operation` is product-relative and starts with `/`, as in
/// `/shards/{id}/revisions/{rev}/manifest`.
pub(crate) fn origin_path(operation: &str) -> String {
    debug_assert!(operation.starts_with('/'), "{operation}");
    format!("{}{operation}", PirProduct::Transparent.route_prefix())
}

/// The URL of a Transparent product `operation` below the server `base`.
///
/// Refuses an operation whose dot segments would leave the namespace.
#[cfg(feature = "reqwest")]
pub(crate) fn url(base: &Endpoint, operation: &str) -> Result<String, InvalidEndpoint> {
    base.product_url(PirProduct::Transparent, operation)
}

/// [`origin_path`] of a literal operation, as a `&'static str`, for log
/// templates and fixed routes.
macro_rules! static_origin_path {
    ($operation:literal) => {{
        const PREFIX: &str =
            ::zakura_pir_protocol::endpoint::PirProduct::Transparent.route_prefix();
        const LEN: usize = PREFIX.len() + $operation.len();
        const BYTES: [u8; LEN] = {
            let (prefix, operation) = (PREFIX.as_bytes(), $operation.as_bytes());
            let mut bytes = [0; LEN];
            let mut at = 0;
            while at < LEN {
                bytes[at] = if at < prefix.len() {
                    prefix[at]
                } else {
                    operation[at - prefix.len()]
                };
                at += 1;
            }
            bytes
        };
        const PATH: &str = match ::std::str::from_utf8(&BYTES) {
            Ok(path) => path,
            Err(_) => panic!("route prefix and operation are ASCII"),
        };
        PATH
    }};
}
pub(crate) use static_origin_path;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operations_land_below_the_transparent_namespace() {
        assert_eq!(origin_path("/shards/init"), "/transparent/v1/shards/init");
        assert_eq!(
            static_origin_path!("/txid/map"),
            origin_path("/txid/map").as_str()
        );
    }

    #[cfg(feature = "reqwest")]
    #[test]
    fn urls_keep_the_base_path_and_stay_in_the_namespace() {
        let base = Endpoint::parse("https://pir.example/edge/").unwrap();
        assert_eq!(
            url(&base, "/filters/shards/7/filter").unwrap(),
            "https://pir.example/edge/transparent/v1/filters/shards/7/filter"
        );
        assert!(url(&base, "/../../v2/shards/init").is_err());
    }
}
