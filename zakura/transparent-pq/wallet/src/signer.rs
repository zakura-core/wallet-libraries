use core::fmt;

use transparent::pq::output;
use transparent_pq_keys::{KeyOrigin, PublicKey, WalletSeed};
use transparent_pq_pool::{KeyRange, PublicKeySource};

use crate::output::{common_parameters, network_type};
use crate::{PqDestination, UnsignedTransaction};

/// Everything a signer needs for one spend, in a single interaction.
pub struct SigningRequest<'a> {
    /// The transaction to sign; the signer computes each signature hash from it.
    pub transaction: &'a UnsignedTransaction,
    /// The key that spends each input, in input order.
    pub input_keys: Vec<KeyOrigin>,
    /// Outputs the wallet claims as its own change: output index and key.
    pub change: Vec<(usize, KeyOrigin)>,
    /// Key ranges the wallet's pool wants refilled.
    pub replenish: Vec<KeyRange>,
}

/// A signer's answer to a [`SigningRequest`].
pub struct SigningResponse {
    /// One SLH-DSA signature per input, without the signature-hash byte.
    pub signatures: Vec<Vec<u8>>,
    /// Public keys answering the request's refill ranges.
    pub public_keys: Vec<(KeyOrigin, PublicKey)>,
}

/// Signs PQ spends: software from the seed now, hardware devices later.
///
/// Implementations compute signature hashes themselves and check that every input
/// and change output belongs to one of their keys before signing.
pub trait PqSigner {
    /// Why the signer refused or failed.
    type Error;

    /// Signs every input and answers the refill ranges.
    fn sign(&mut self, request: &SigningRequest<'_>) -> Result<SigningResponse, Self::Error>;

    /// Answers refill ranges without signing.
    ///
    /// Spends call this only when the pool has no derived change key left, so the
    /// change output can still go to a fresh key; otherwise refills ride on
    /// [`Self::sign`].
    fn public_keys(
        &mut self,
        ranges: &[KeyRange],
    ) -> Result<Vec<(KeyOrigin, PublicKey)>, Self::Error>;
}

/// The software signer: derives each key from the wallet seed.
pub struct SeedSigner {
    seed: WalletSeed,
}

impl SeedSigner {
    /// Signs with keys derived from `seed`.
    pub fn new(seed: WalletSeed) -> Self {
        Self { seed }
    }
}

/// Why [`SeedSigner`] refused a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SeedSignerError {
    /// The request names a key for a different number of inputs than the transaction has.
    InputCount {
        /// Inputs in the transaction.
        inputs: usize,
        /// Keys named in the request.
        keys: usize,
    },
    /// The input's output script is not the named key's script.
    ForeignInput(usize),
    /// The claimed change output does not exist.
    MissingOutput(usize),
    /// The claimed change output does not pay the named key's script.
    ForeignChange(usize),
    /// Signing failed.
    Signing(transparent_pq_keys::Error),
}

impl fmt::Display for SeedSignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputCount { inputs, keys } => {
                write!(f, "{keys} keys named for {inputs} inputs")
            }
            Self::ForeignInput(index) => write!(f, "input {index} is not spendable by its key"),
            Self::MissingOutput(index) => write!(f, "change output {index} does not exist"),
            Self::ForeignChange(index) => write!(f, "output {index} is not the wallet's change"),
            Self::Signing(error) => write!(f, "signing failed: {error}"),
        }
    }
}

impl std::error::Error for SeedSignerError {}

impl PqSigner for SeedSigner {
    type Error = SeedSignerError;

    fn sign(&mut self, request: &SigningRequest<'_>) -> Result<SigningResponse, Self::Error> {
        let transaction = request.transaction;
        if request.input_keys.len() != transaction.input_count() {
            return Err(SeedSignerError::InputCount {
                inputs: transaction.input_count(),
                keys: request.input_keys.len(),
            });
        }
        for &(index, origin) in &request.change {
            let output = transaction
                .outputs()
                .get(index)
                .ok_or(SeedSignerError::MissingOutput(index))?;
            let destination =
                PqDestination::single_signer(&self.seed.derive_key(origin).public_key());
            if output.script_pubkey() != &destination.script_pubkey() {
                return Err(SeedSignerError::ForeignChange(index));
            }
        }
        let mut signatures = Vec::with_capacity(request.input_keys.len());
        for (index, &origin) in request.input_keys.iter().enumerate() {
            let key = self.seed.derive_key(origin);
            let destination = PqDestination::single_signer(&key.public_key());
            if transaction.input_script_pubkey(index) != &destination.script_pubkey() {
                return Err(SeedSignerError::ForeignInput(index));
            }
            // The context names the network, the output format and the scheme, so a
            // signature cannot be replayed on another network or under another pair.
            let context = output::signing_context(
                network_type(origin.network()),
                common_parameters(origin.parameters()),
            );
            let signature = key
                .sign(&transaction.sighash(index, &destination), context)
                .map_err(SeedSignerError::Signing)?;
            signatures.push(signature);
        }
        Ok(SigningResponse {
            signatures,
            public_keys: self.public_keys(&request.replenish)?,
        })
    }

    fn public_keys(
        &mut self,
        ranges: &[KeyRange],
    ) -> Result<Vec<(KeyOrigin, PublicKey)>, Self::Error> {
        let mut public_keys = Vec::new();
        for &range in ranges {
            let Ok(keys) = self.seed.public_keys(range);
            public_keys.extend(keys);
        }
        Ok(public_keys)
    }
}
