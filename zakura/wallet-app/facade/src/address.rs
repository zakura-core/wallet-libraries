//! Turning an address somebody typed into one the builder can pay.
//!
//! Nothing in the core decodes an address: the transaction builder takes an
//! `orchard::Address` and the store hands back a `UnifiedAddress`. An
//! application, though, deals in strings — pasted, scanned from a QR code, or
//! read out loud — so the decoding and the "can this wallet pay it" question
//! belong here, at the boundary where the answer is needed.

use zcash_keys::address::Address;
use zcash_protocol::consensus::Parameters;

use crate::error::Error;

/// Parses an address and returns the Orchard receiver this wallet would pay.
///
/// Two failures are kept apart deliberately, because they are different
/// problems for whoever typed it: [`Error::BadAddress`] means the text is not
/// an address at all, or belongs to another network, and
/// [`Error::UnsupportedAddress`] means it is a real address this wallet has no
/// way to pay — a transparent or Sapling-only one. Collapsing them would send
/// somebody hunting for a typo that is not there.
pub fn parse<P: Parameters>(params: &P, address: &str) -> Result<orchard::Address, Error> {
    let parsed = Address::decode(params, address)
        .ok_or_else(|| Error::BadAddress("could not be decoded for this network".to_owned()))?;

    match parsed {
        Address::Unified(ua) => ua.orchard().copied().ok_or(Error::UnsupportedAddress),
        // A bare Orchard address has no encoding of its own; everything else
        // this wallet cannot pay, because it builds no transparent or Sapling
        // outputs.
        _ => Err(Error::UnsupportedAddress),
    }
}

#[cfg(test)]
mod tests {
    use zakura_wallet_scan::testing::test_params;
    use zakura_wallet_store::testing::test_db;
    use zcash_protocol::consensus::BlockHeight;

    use super::*;
    use crate::error::ErrorCode;

    fn issued_address() -> String {
        let mut db = test_db().unwrap();
        let id = db
            .create_account(
                &test_params(),
                &[7u8; 32],
                zip32::AccountId::try_from(0).unwrap(),
                BlockHeight::from_u32(1_000),
            )
            .unwrap();
        let (address, _) = db
            .next_address(
                &test_params(),
                id,
                zakura_wallet_core::KeyScope::External,
                None,
            )
            .unwrap();
        address.encode(&test_params())
    }

    /// The addresses this wallet hands out are the ones it must be able to pay.
    #[test]
    fn an_address_the_wallet_issued_parses() {
        let address = issued_address();
        assert!(parse(&test_params(), &address).is_ok());
    }

    #[test]
    fn nonsense_is_a_bad_address() {
        let code = parse(&test_params(), "not an address")
            .err()
            .map(|e| e.code());
        assert_eq!(code, Some(ErrorCode::BadAddress));
    }

    #[test]
    fn an_empty_string_is_a_bad_address() {
        let code = parse(&test_params(), "").err().map(|e| e.code());
        assert_eq!(code, Some(ErrorCode::BadAddress));
    }

    /// An address for another network is refused rather than paid.
    ///
    /// Paying a mainnet address with testnet funds is impossible, but the
    /// failure has to happen here rather than as a rejected transaction.
    #[test]
    fn an_address_from_another_network_is_refused() {
        let address = issued_address();
        let code = parse(&zcash_protocol::consensus::Network::MainNetwork, &address)
            .err()
            .map(|e| e.code());
        assert_eq!(code, Some(ErrorCode::BadAddress));
    }

    /// A transparent address is a real address this wallet cannot pay, which is
    /// a different problem from a typo and must read differently.
    #[test]
    fn a_transparent_address_is_unsupported_rather_than_invalid() {
        // A valid testnet P2PKH address.
        let code = parse(&test_params(), "tm9iMLAuYMzJ6jtFLcA7rzUmfreGuKvr7Ma")
            .err()
            .map(|e| e.code());
        assert_eq!(code, Some(ErrorCode::UnsupportedAddress));
    }
}
