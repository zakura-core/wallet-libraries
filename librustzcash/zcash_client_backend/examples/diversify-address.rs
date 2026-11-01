use clap::Parser;
use sapling::zip32::ExtendedFullViewingKey;
use zcash_address::constants as address_constants;
use zcash_keys::{
    constants as key_constants,
    encoding::{decode_extended_full_viewing_key, encode_payment_address},
};
use zip32::DiversifierIndex;

fn parse_viewing_key(s: &str) -> Result<(ExtendedFullViewingKey, bool), &'static str> {
    decode_extended_full_viewing_key(
        key_constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
        s,
    )
    .map(|vk| (vk, true))
    .or_else(|_| {
        decode_extended_full_viewing_key(
            key_constants::testnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            s,
        )
        .map(|vk| (vk, false))
    })
    .map_err(|_| "Invalid Sapling viewing key")
}

fn parse_diversifier_index(s: &str) -> Result<DiversifierIndex, &'static str> {
    let i: u128 = s.parse().map_err(|_| "Diversifier index is not a number")?;
    DiversifierIndex::try_from(i).map_err(|_| "Diversifier index too large")
}

fn encode_diversifier_index(di: &DiversifierIndex) -> u128 {
    (*di).into()
}

#[derive(Debug, Parser)]
#[command(name = "diversify-address")]
struct MyOptions {
    #[arg(
        help = "The Sapling viewing key to generate diversified addresses from",
        value_parser = parse_viewing_key
    )]
    viewing_key: Option<(ExtendedFullViewingKey, bool)>,

    #[arg(
        help = "The index of the diversified address to generate (default 0). Some indices don't have a corresponding address.",
        default_value = "0",
        value_parser = parse_diversifier_index
    )]
    diversifier_index: DiversifierIndex,
}

fn main() {
    let opts = MyOptions::parse();

    let (extfvk, is_mainnet) = if let Some(res) = opts.viewing_key {
        res
    } else {
        eprintln!("Missing Sapling viewing key");
        return;
    };

    let (diversifier_index, address) = extfvk.find_address(opts.diversifier_index).unwrap();
    println!(
        "# Diversifier index: {}",
        encode_diversifier_index(&diversifier_index)
    );
    println!(
        "{}",
        encode_payment_address(
            if is_mainnet {
                address_constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS
            } else {
                address_constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS
            },
            &address
        )
    );
}
