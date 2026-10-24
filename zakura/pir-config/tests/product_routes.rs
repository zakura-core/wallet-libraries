//! A single advertised server serves every wallet PIR product.

mod support;

use support::mainnet_config;
use zakura_pir_config::ServerBase;
use zakura_pir_protocol::endpoint::PirProduct;

#[test]
fn an_explicit_server_choice_routes_every_product_under_its_base_path() {
    let config = mainnet_config(&[
        ("First server", "https://first.example"),
        ("Chosen server", "https://chosen.example/wallet-pir"),
    ]);
    let selection = config
        .select_server(&ServerBase::parse("HTTPS://CHOSEN.EXAMPLE/wallet-pir/").unwrap())
        .unwrap();
    let server = config.server(&selection).unwrap();

    for (product, operation, expected_url) in [
        (
            PirProduct::Enhance,
            "/init",
            "https://chosen.example/wallet-pir/enhance/v1/init",
        ),
        (
            PirProduct::Status,
            "/init",
            "https://chosen.example/wallet-pir/status/v1/init",
        ),
        (
            PirProduct::Transparent,
            "/shards/init",
            "https://chosen.example/wallet-pir/transparent/v1/shards/init",
        ),
        (
            PirProduct::Receiver,
            "/inventory",
            "https://chosen.example/wallet-pir/receiver/v1/inventory",
        ),
    ] {
        assert_eq!(
            server
                .base
                .endpoint()
                .product_url(product, operation)
                .unwrap(),
            expected_url
        );
    }
}
