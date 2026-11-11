use transparent::address::Script;
use transparent::pq::{self, single_key};
use transparent_pq_keys::{Network, ParameterSet, PublicKey};
use zcash_protocol::consensus::NetworkType;
use zcash_script::script::Code;

/// Where one PQ key is paid: the script it will spend with, and the output that commits
/// to it.
///
/// The output carries a format byte, a scheme byte and `SHA-256` of the body, and nothing
/// else; the body itself stays with the wallet until the money is spent. The body's exact
/// bytes are therefore part of the recovery contract — a restored key finds its funds only
/// if the same body is rebuilt — so this crate commits to Common's canonical single-key
/// body and nothing else.
#[derive(Clone, Debug)]
pub struct PqDestination {
    parameters: ParameterSet,
    body: Code,
    commitment: [u8; 32],
}

// `Code` carries no equality, and the commitment already stands for the body it hashes.
impl PartialEq for PqDestination {
    fn eq(&self, other: &Self) -> bool {
        self.parameters == other.parameters && self.commitment == other.commitment
    }
}

impl Eq for PqDestination {}

impl PqDestination {
    /// The destination paying `public_key` alone: `PUSH<pk> OP_CHECKSIG`, committed.
    pub fn single_signer(public_key: &PublicKey) -> Self {
        let parameters = public_key.parameters();
        let common = common_parameters(parameters);
        // `PublicKey` holds a key of exactly its parameter set's length, which is the one
        // thing the body builder rejects.
        let body = single_key::body(common, public_key.as_bytes())
            .expect("a PQ public key has its parameter set's length");
        let commitment = single_key::commitment(common, public_key.as_bytes())
            .expect("a PQ public key has its parameter set's length");
        Self {
            parameters,
            body,
            commitment,
        }
    }

    /// The parameter set the output's scheme selects.
    pub fn parameters(&self) -> ParameterSet {
        self.parameters
    }

    /// The script that says who may spend, revealed when the money is spent.
    pub fn body(&self) -> &[u8] {
        &self.body.0
    }

    /// `SHA-256` of the body: what the output commits to, and what an address publishes.
    pub fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }

    /// The thirty-five byte output script that pays this destination.
    pub fn script_pubkey(&self) -> Script {
        Script(pq::output::output_script_from_commitment(
            common_parameters(self.parameters),
            &self.commitment,
        ))
    }

    pub(crate) fn body_code(&self) -> &Code {
        &self.body
    }
}

/// The output script paying a commitment published by a PQ receiver.
///
/// This is the sender's side of an address: the receiver publishes the commitment, and the
/// payer writes the output its format and scheme name, byte for byte.
pub fn output_script(parameters: ParameterSet, commitment: &[u8; 32]) -> Script {
    Script(pq::output::output_script_from_commitment(
        common_parameters(parameters),
        commitment,
    ))
}

pub(crate) fn common_parameters(parameters: ParameterSet) -> pq::ParameterSet {
    match parameters {
        ParameterSet::Sha2_128f => pq::ParameterSet::Sha2_128f,
        ParameterSet::Sha2_192s => pq::ParameterSet::Sha2_192s,
    }
}

pub(crate) fn network_type(network: Network) -> NetworkType {
    match network {
        Network::Mainnet => NetworkType::Main,
        Network::Testnet => NetworkType::Test,
        Network::Regtest => NetworkType::Regtest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two crates each carry their own copy of the parameter set's lengths — the keys
    /// crate deliberately does not depend on Common — so they are checked against each
    /// other here, where both are in scope.
    #[test]
    fn the_parameter_sets_agree_with_commons() {
        for parameters in [ParameterSet::Sha2_128f, ParameterSet::Sha2_192s] {
            let common = common_parameters(parameters);
            assert_eq!(parameters.public_key_bytes(), common.public_key_bytes());
            assert_eq!(parameters.signature_bytes(), common.signature_bytes());
        }
    }
}
