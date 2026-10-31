use transparent::address::{Script, TransparentAddress};
use transparent::pq::{self, p2sh};
use transparent::util::hash160;
use transparent_pq_keys::{Network, ParameterSet, PublicKey};
use zcash_protocol::consensus::NetworkType;
use zcash_script::script::Code;

const OP_CHECKSIG: u8 = 0xac;

/// The single-signer P2SH script for one PQ key: `<public key> OP_CHECKSIG` behind
/// Common's PQ header.
///
/// The exact bytes are part of the recovery contract: the address commits to them, so
/// a restored key finds its funds only if this template is rebuilt unchanged.
#[derive(Clone, Debug)]
pub struct PqScript {
    parameters: ParameterSet,
    redeem: Code,
}

impl PartialEq for PqScript {
    fn eq(&self, other: &Self) -> bool {
        self.parameters == other.parameters && self.redeem.0 == other.redeem.0
    }
}

impl Eq for PqScript {}

impl PqScript {
    /// Builds the script for `public_key`, pushing the key directly (its length is
    /// below 76 bytes for both parameter sets).
    pub fn single_signer(public_key: &PublicKey) -> Self {
        let key = public_key.as_bytes();
        let mut body = Vec::with_capacity(key.len() + 2);
        body.push(u8::try_from(key.len()).expect("PQ public keys are 32 or 48 bytes"));
        body.extend_from_slice(key);
        body.push(OP_CHECKSIG);
        let redeem = p2sh::redeem_script(common_parameters(public_key.parameters()), &Code(body))
            .expect("a single-signer body is far below the redeem script limit");
        Self {
            parameters: public_key.parameters(),
            redeem,
        }
    }

    /// The parameter set the script's header selects.
    pub fn parameters(&self) -> ParameterSet {
        self.parameters
    }

    /// The complete redeem script, header included, as revealed when spending.
    pub fn redeem_script(&self) -> &[u8] {
        &self.redeem.0
    }

    /// The P2SH address committing to the redeem script.
    pub fn address(&self) -> TransparentAddress {
        TransparentAddress::ScriptHash(hash160::hash(&self.redeem.0))
    }

    /// The output script that pays this address.
    pub fn script_pubkey(&self) -> Script {
        self.address().script().into()
    }

    /// The address in the network's ordinary P2SH encoding.
    pub fn encode(&self, network: Network) -> String {
        self.address()
            .to_zcash_address(network_type(network))
            .encode()
    }

    pub(crate) fn redeem_code(&self) -> &Code {
        &self.redeem
    }
}

pub(crate) fn common_parameters(parameters: ParameterSet) -> pq::ParameterSet {
    match parameters {
        ParameterSet::Sha2_128f => pq::ParameterSet::Sha2_128f,
        ParameterSet::Sha2_192s => pq::ParameterSet::Sha2_192s,
    }
}

fn network_type(network: Network) -> NetworkType {
    match network {
        Network::Mainnet => NetworkType::Main,
        Network::Testnet => NetworkType::Test,
        Network::Regtest => NetworkType::Regtest,
    }
}
