use sapling::zip32::ExtendedFullViewingKey;
use std::ffi::{OsStr, OsString};
use zcash_keys::encoding::{decode_extended_full_viewing_key, encode_payment_address};
use zcash_protocol::constants::{mainnet, testnet};
use zip32::DiversifierIndex;

fn parse_viewing_key(s: &str) -> Result<(ExtendedFullViewingKey, bool), &'static str> {
    decode_extended_full_viewing_key(mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY, s)
        .map(|vk| (vk, true))
        .or_else(|_| {
            decode_extended_full_viewing_key(testnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY, s)
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

#[derive(Debug)]
struct MyOptions {
    viewing_key: Option<(ExtendedFullViewingKey, bool)>,
    diversifier_index: DiversifierIndex,
}

const HELP: &str = r##"Usage: {program} [VIEWING_KEY] [DIVERSIFIER_INDEX]

Arguments:
  [VIEWING_KEY]        The Sapling viewing key to generate diversified addresses from
  [DIVERSIFIER_INDEX]  The index of the diversified address to generate (default 0). Some indices don't have a corresponding address. [default: 0]

Options:
  -h, --help  Print help
"##;

fn parse_args(arguments: impl IntoIterator<Item = OsString>) -> Result<Option<MyOptions>, String> {
    let mut options = MyOptions {
        viewing_key: None,
        diversifier_index: DiversifierIndex::default(),
    };
    let mut literal = false;
    let mut position = 0;
    for argument in arguments {
        if !literal && argument == "--" {
            literal = true;
            continue;
        }
        if !literal && (argument == "--help" || argument.as_encoded_bytes().starts_with(b"-h")) {
            return Ok(None);
        }
        if !literal && argument != "-" && argument.as_encoded_bytes().starts_with(b"-") {
            return Err("unexpected argument; use --help for usage".into());
        }
        let text = argument.to_str().ok_or("invalid UTF-8 in argument")?;
        match position {
            0 => options.viewing_key = Some(parse_viewing_key(text)?),
            1 => options.diversifier_index = parse_diversifier_index(text)?,
            _ => return Err("too many positional arguments".into()),
        }
        position += 1;
    }
    Ok(Some(options))
}

fn main() {
    let mut arguments = std::env::args_os();
    let executable = arguments.next().unwrap_or_default();
    let program = std::path::Path::new(&executable)
        .file_name()
        .unwrap_or(OsStr::new("diversify-address"))
        .to_string_lossy();
    let opts = match parse_args(arguments) {
        Ok(Some(options)) => options,
        Ok(None) => {
            print!("{}", HELP.replace("{program}", &program));
            return;
        }
        Err(error) => {
            eprintln!("error: {error}\n\n{}", HELP.replace("{program}", &program));
            std::process::exit(2);
        }
    };

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
                mainnet::HRP_SAPLING_PAYMENT_ADDRESS
            } else {
                testnet::HRP_SAPLING_PAYMENT_ADDRESS
            },
            &address
        )
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAINNET_KEY: &str = concat!(
        "zxviews1qqqqqqqqqqqqqq8n3zjjmvhhr854uy3qhpda3ml34haf0x388z5r7h4st4kpsf",
        "6qy3zw4wc246aw9rlfyg5ndlwvne7mwdq0qe6vxl42pqmcf8pvmmd5slmjxduqa9evgej6",
        "wa3th2505xq4nggrxdm93rxk4rpdjt5nmq2vn44e2uhm7h0hsagfvkk4n7n6nfer6u57v9",
        "cac84t7nl2zth0xpyfeg0w2p2wv2yn6jn923aaz0vdaml07l60ahapk6efchyxwysrvjsx",
        "mansf",
    );
    const TESTNET_KEY: &str = concat!(
        "zxviewtestsapling1qqqqqqqqqqqqqq8n3zjjmvhhr854uy3qhpda3ml34haf0x388z5r",
        "7h4st4kpsf6qy3zw4wc246aw9rlfyg5ndlwvne7mwdq0qe6vxl42pqmcf8pvmmd5slmjxd",
        "uqa9evgej6wa3th2505xq4nggrxdm93rxk4rpdjt5nmq2vn44e2uhm7h0hsagfvkk4n7n6",
        "nfer6u57v9cac84t7nl2zth0xpyfeg0w2p2wv2yn6jn923aaz0vdaml07l60ahapk6efch",
        "yxwysrvjs8evfkz",
    );
    const MAX_INDEX: &str = "309485009821345068724781055";

    fn parse(arguments: &[&str]) -> Result<Option<MyOptions>, String> {
        parse_args(arguments.iter().map(OsString::from))
    }

    #[test]
    fn positional_defaults_and_both_networks() {
        let missing = parse(&[]).unwrap().unwrap();
        assert!(missing.viewing_key.is_none());
        assert_eq!(encode_diversifier_index(&missing.diversifier_index), 0);
        for (key, mainnet) in [(MAINNET_KEY, true), (TESTNET_KEY, false)] {
            let options = parse(&[key]).unwrap().unwrap();
            assert_eq!(options.viewing_key.unwrap().1, mainnet);
            assert_eq!(encode_diversifier_index(&options.diversifier_index), 0);
        }
        let max = parse(&[MAINNET_KEY, MAX_INDEX]).unwrap().unwrap();
        assert_eq!(
            encode_diversifier_index(&max.diversifier_index),
            MAX_INDEX.parse::<u128>().unwrap()
        );
        let literal = parse(&["--", MAINNET_KEY, "1"]).unwrap().unwrap();
        assert_eq!(encode_diversifier_index(&literal.diversifier_index), 1);
    }

    #[test]
    fn positional_validation_precedes_later_help() {
        for arguments in [
            vec!["invalid", "--help"],
            vec![MAINNET_KEY, "bad", "--help"],
            vec![MAINNET_KEY, "309485009821345068724781056"],
            vec![MAINNET_KEY, "340282366920938463463374607431768211456"],
            vec![MAINNET_KEY, "-1"],
            vec![MAINNET_KEY, "--", "-1"],
            vec![MAINNET_KEY, "0", "extra"],
            vec!["--unknown", "--help"],
        ] {
            assert!(parse(&arguments).is_err(), "{arguments:?}");
        }
        for arguments in [vec!["--help", "invalid"], vec!["-hfoo"]] {
            assert!(parse(&arguments).unwrap().is_none());
        }
    }
}
