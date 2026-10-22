//! Source parsing, hash pins and static document decoding.

mod support;

use support::{STATIC_JSON, StaticDocument, sha256_hex};
use zakura_service_config::{
    ConfigSource, PinCheck, ResolveError, SourceError, UrlErrorKind, resolve_static,
};

#[test]
fn checksum_is_removed_from_the_fetch_url_and_other_query_items_are_kept() {
    let pin = "a".repeat(64);
    let source = ConfigSource::parse(&format!(
        " https://cfg.example/s.json?v=2&checksum=sha256:{pin}&x=1 "
    ))
    .unwrap();
    assert_eq!(source.url, "https://cfg.example/s.json?v=2&x=1");
    assert_eq!(source.sha256.as_deref(), Some(pin.as_str()));
    assert!(source.raw.starts_with("https://"));
}

#[test]
fn malformed_sources_are_rejected_with_distinct_errors() {
    let not_https = ConfigSource::parse("http://cfg.example/s.json").unwrap_err();
    assert!(matches!(not_https, SourceError::Url(ref e) if e.kind == UrlErrorKind::NotHttps));
    assert_eq!(not_https.to_string(), "static config source must use https");

    let credentials = ConfigSource::parse("https://user@cfg.example/").unwrap_err();
    assert!(matches!(credentials, SourceError::Url(ref e) if e.kind == UrlErrorKind::InvalidHost));

    assert_eq!(
        ConfigSource::parse("https://cfg.example/?checksum=md5:00").unwrap_err(),
        SourceError::UnsupportedChecksum
    );
    let upper = "A".repeat(64);
    assert_eq!(
        ConfigSource::parse(&format!("https://cfg.example/?checksum=sha256:{upper}")).unwrap_err(),
        SourceError::MalformedSha256
    );
}

#[test]
fn pinned_bytes_verify_and_unpinned_sources_say_so() {
    let pinned = format!(
        "https://cfg.example/s.json?checksum=sha256:{}",
        sha256_hex(STATIC_JSON.as_bytes())
    );
    let resolved = resolve_static::<StaticDocument>(&pinned, STATIC_JSON.as_bytes()).unwrap();
    assert_eq!(resolved.pin, PinCheck::Verified);
    assert_eq!(resolved.document.dynamic_config_urls.len(), 2);
    assert_eq!(resolved.source_fingerprint, resolved.source.fingerprint());

    let unpinned =
        resolve_static::<StaticDocument>("https://cfg.example/s.json", STATIC_JSON.as_bytes())
            .unwrap();
    assert_eq!(unpinned.pin, PinCheck::Unpinned);
    assert_ne!(unpinned.source_fingerprint, resolved.source_fingerprint);
}

#[test]
fn pin_mismatch_is_reported_before_decoding() {
    let pinned = format!(
        "https://cfg.example/s.json?checksum=sha256:{}",
        "0".repeat(64)
    );
    let error = resolve_static::<StaticDocument>(&pinned, b"not json").unwrap_err();
    let ResolveError::PinMismatch(mismatch) = &error else {
        panic!("expected pin mismatch, got {error:?}");
    };
    assert_eq!(mismatch.actual, sha256_hex(b"not json"));
    assert!(
        error
            .to_string()
            .starts_with("static config hash-pin mismatch: expected 000")
    );
}

#[test]
fn malformed_static_json_is_a_static_decode_error() {
    let error = resolve_static::<StaticDocument>("https://cfg.example/s.json", b"{\"network\":1}")
        .unwrap_err();
    assert!(matches!(error, ResolveError::StaticDecode(_)));
    assert!(
        error
            .to_string()
            .starts_with("static config decode failed: ")
    );
}
