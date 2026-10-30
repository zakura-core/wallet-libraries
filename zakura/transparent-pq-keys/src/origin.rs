use crate::Error;

/// The implemented experimental derivation version.
pub const DERIVATION_VERSION: u8 = 1;
/// Version, network, big-endian account, branch, and big-endian index.
pub const ORIGIN_BYTES: usize = 11;

/// Independent wallet derivation namespaces, not consensus activation selectors.
///
/// All regtest instances share the regtest namespace. Applications needing distinct
/// regtest wallets must use different seeds or accounts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Network {
    /// Mainnet, encoded as 0.
    Mainnet,
    /// Testnet, encoded as 1.
    Testnet,
    /// Regtest, encoded as 2.
    Regtest,
}

/// Independent child sequences for incoming payments and returned change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Branch {
    /// Receiving keys, encoded as 0.
    Receive,
    /// Change keys, encoded as 1.
    Change,
}

/// Public metadata required, together with the wallet seed, to recover one key.
///
/// Accounts and indices use the full `u32` range. This is private derivation, not
/// BIP 32: no high bit encodes hardening and no public child derivation is provided.
/// Reusing an origin with the same seed intentionally recovers the same key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyOrigin {
    network: Network,
    account: u32,
    branch: Branch,
    index: u32,
}

impl KeyOrigin {
    /// Identifies a key under derivation version 1 without allocating its index.
    pub fn new(network: Network, account: u32, branch: Branch, index: u32) -> Self {
        Self {
            network,
            account,
            branch,
            index,
        }
    }

    /// The derivation version that must be retained with a backup.
    pub fn version(self) -> u8 {
        DERIVATION_VERSION
    }

    /// The wallet's network namespace.
    pub fn network(self) -> Network {
        self.network
    }

    /// The wallet account number.
    pub fn account(self) -> u32 {
        self.account
    }

    /// The receiving or change sequence.
    pub fn branch(self) -> Branch {
        self.branch
    }

    /// The child index within the account and branch.
    pub fn index(self) -> u32 {
        self.index
    }

    /// Encodes the exact versioned origin used as HKDF's `info` input.
    ///
    /// This is key-recovery metadata, not an address, an xpub, or an authenticated
    /// association with a public key. Callers must authenticate imported metadata.
    pub fn to_bytes(self) -> [u8; ORIGIN_BYTES] {
        let mut encoded = [0; ORIGIN_BYTES];
        encoded[0] = DERIVATION_VERSION;
        encoded[1] = match self.network {
            Network::Mainnet => 0,
            Network::Testnet => 1,
            Network::Regtest => 2,
        };
        encoded[2..6].copy_from_slice(&self.account.to_be_bytes());
        encoded[6] = match self.branch {
            Branch::Receive => 0,
            Branch::Change => 1,
        };
        encoded[7..11].copy_from_slice(&self.index.to_be_bytes());
        encoded
    }

    /// Decodes an origin, rejecting unknown versions/codes and non-exact lengths.
    pub fn from_bytes(encoded: &[u8]) -> Result<Self, Error> {
        let encoded: &[u8; ORIGIN_BYTES] = encoded
            .try_into()
            .map_err(|_| Error::InvalidOriginLength(encoded.len()))?;
        if encoded[0] != DERIVATION_VERSION {
            return Err(Error::UnsupportedVersion(encoded[0]));
        }
        let network = match encoded[1] {
            0 => Network::Mainnet,
            1 => Network::Testnet,
            2 => Network::Regtest,
            other => return Err(Error::UnsupportedNetwork(other)),
        };
        let branch = match encoded[6] {
            0 => Branch::Receive,
            1 => Branch::Change,
            other => return Err(Error::UnsupportedBranch(other)),
        };
        Ok(Self {
            network,
            account: u32::from_be_bytes([encoded[2], encoded[3], encoded[4], encoded[5]]),
            branch,
            index: u32::from_be_bytes([encoded[7], encoded[8], encoded[9], encoded[10]]),
        })
    }
}
