//! Endpoint normalization checked against the previous independent URL parser.

use candidate_protocol::endpoint::Endpoint;

fn main() {
    let mut comparisons = 0;
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
            comparisons += 1;
            let mut old = url::Url::parse(base).unwrap();
            old.set_path(&format!("{}{route}", old.path().trim_end_matches('/')));
            assert_eq!(
                Endpoint::parse(base).unwrap().join(route).unwrap(),
                old.as_str(),
                "{base}, {route}"
            );
        }
    }
    assert_eq!(comparisons, 72);
    println!("endpoint: {comparisons} comparisons with the previous URL parser passed");
}
