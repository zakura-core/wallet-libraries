//! Ironwood receivers carried in unified addresses.
use super::{Error, Receiver};
use zcash_address::{
    ConversionError, ToAddress, TryFromAddress, ZcashAddress,
    unified::{self, Container, Encoding},
};
use zcash_protocol::consensus::NetworkType;

/// The network an address is encoded for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Network {
    Main,
    Test,
    Regtest,
}

impl From<Network> for NetworkType {
    fn from(network: Network) -> Self {
        match network {
            Network::Main => NetworkType::Main,
            Network::Test => NetworkType::Test,
            Network::Regtest => NetworkType::Regtest,
        }
    }
}

impl Receiver {
    /// The Ironwood receiver of a unified address encoded for `network`. Any other
    /// address, an address for another network, a unified address without an
    /// Ironwood receiver, or receiver bytes that are not a valid address are
    /// [`Error::Malformed`].
    pub fn from_unified_address(address: &str, network: Network) -> Result<Self, Error> {
        struct Ironwood([u8; 43]);
        impl TryFromAddress for Ironwood {
            type Error = ();
            fn try_from_unified(
                _: NetworkType,
                address: unified::Address,
            ) -> Result<Self, ConversionError<()>> {
                address
                    .items()
                    .into_iter()
                    .find_map(|item| match item {
                        unified::Receiver::Orchard(bytes) => Some(Self(bytes)),
                        _ => None,
                    })
                    .ok_or(ConversionError::User(()))
            }
        }
        let Ironwood(bytes) = ZcashAddress::try_from_encoded(address)
            .map_err(|_| Error::Malformed)?
            .convert_if_network(network.into())
            .map_err(|_| Error::Malformed)?;
        Self::from_bytes(bytes)
    }

    /// A unified address for `network` holding only this receiver.
    pub fn to_unified_address(&self, network: Network) -> String {
        let address =
            unified::Address::try_from_items(vec![unified::Receiver::Orchard(*self.as_bytes())])
                .expect("one shielded receiver is a valid unified address");
        ZcashAddress::from_unified(network.into(), address).encode()
    }
}
