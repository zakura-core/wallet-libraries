use core::fmt;

use transparent::address::{Script, TransparentAddress};
use transparent::bundle::{OutPoint, TxOut};
use transparent_pq_keys::{Branch, KeyOrigin, PublicKey};
use transparent_pq_pool::{AccountPool, Issued};
use zcash_primitives::transaction::fees::FeeRule as _;
use zcash_primitives::transaction::fees::transparent::InputSize;
use zcash_primitives::transaction::fees::zip317::{FeeError, FeeRule};
use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::consensus::{BlockHeight, BranchId, Parameters};
use zcash_protocol::value::Zatoshis;

use crate::transaction::{self, Header, UnsignedTransaction, VerifyError};
use crate::{PqScript, PqSigner, SigningRequest};

/// Blocks after the target height at which an unmined transaction expires (ZIP 203).
const EXPIRY_DELTA: u32 = 40;

/// A PQ output the wallet can spend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqUtxo {
    /// The output being spent.
    pub outpoint: OutPoint,
    /// Its value.
    pub value: Zatoshis,
    /// The key that controls it.
    pub origin: KeyOrigin,
    /// That key's public key, which determines the output script.
    pub public_key: PublicKey,
}

/// An amount paid to a transparent address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payment {
    /// The recipient.
    pub address: TransparentAddress,
    /// The amount.
    pub value: Zatoshis,
}

/// A signed transaction ready to broadcast.
#[derive(Debug)]
pub struct SignedSpend {
    /// The transaction.
    pub transaction: Transaction,
    /// The fee it pays.
    pub fee: Zatoshis,
    /// The change key it pays, if change was worth keeping. `fresh` is false when the
    /// pool had no unused change key and repeated the last one.
    pub change: Option<Issued>,
    /// Every output the transaction spends, in input order, for [`crate::verify_inputs`].
    pub spent: Vec<TxOut>,
}

/// Why a spend could not be built.
#[derive(Debug)]
#[non_exhaustive]
pub enum SpendError<E> {
    /// No inputs were supplied.
    NoInputs,
    /// The inputs do not cover the payments and the fee.
    InsufficientFunds {
        /// Total input value.
        available: Zatoshis,
        /// Payments plus the fee without change.
        required: Zatoshis,
    },
    /// An input's public key does not match its origin's parameter set.
    KeyMismatch(usize),
    /// An amount overflowed.
    Overflow,
    /// The fee rule rejected the sizes.
    Fee(FeeError),
    /// The change pool refused to issue a key or to take the signer's refill.
    Pool(transparent_pq_pool::Error),
    /// The signer refused or failed.
    Signer(E),
    /// The signer returned a different number of signatures than inputs.
    SignatureCount {
        /// Inputs in the transaction.
        expected: usize,
        /// Signatures returned.
        actual: usize,
    },
    /// A signed input failed verification.
    Verification(VerifyError),
    /// The finished transaction pays a different fee than was computed.
    FeeChanged,
    /// The transaction could not be serialized.
    Encoding(std::io::Error),
}

impl<E: fmt::Display> fmt::Display for SpendError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoInputs => f.write_str("no inputs to spend"),
            Self::InsufficientFunds {
                available,
                required,
            } => write!(
                f,
                "inputs hold {} zatoshis but {} are required",
                u64::from(*available),
                u64::from(*required)
            ),
            Self::KeyMismatch(index) => {
                write!(f, "input {index}'s public key does not match its origin")
            }
            Self::Overflow => f.write_str("amount overflow"),
            Self::Fee(error) => write!(f, "fee: {error}"),
            Self::Pool(error) => write!(f, "change pool: {error}"),
            Self::Signer(error) => write!(f, "signer: {error}"),
            Self::SignatureCount { expected, actual } => {
                write!(
                    f,
                    "signer returned {actual} signatures for {expected} inputs"
                )
            }
            Self::Verification(error) => write!(f, "{error}"),
            Self::FeeChanged => f.write_str("signed transaction size changed its fee"),
            Self::Encoding(error) => write!(f, "encoding: {error}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for SpendError<E> {}

/// Spends `inputs` to `payments`, sending what remains to a fresh change key.
///
/// Change comes from `change_pool` and is skipped when it would be dust; the pool also
/// receives the keys the signer returns for its refill ranges. Save the pool's state
/// before broadcasting. The fee is ZIP 317's conventional fee for the exact sizes.
pub fn build_spend<P: Parameters, S: PqSigner>(
    params: &P,
    target_height: BlockHeight,
    inputs: &[PqUtxo],
    payments: &[Payment],
    change_pool: &mut AccountPool,
    signer: &mut S,
) -> Result<SignedSpend, SpendError<S::Error>> {
    if inputs.is_empty() {
        return Err(SpendError::NoInputs);
    }
    let scripts = inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            if input.public_key.parameters() != input.origin.parameters() {
                return Err(SpendError::KeyMismatch(index));
            }
            Ok(PqScript::single_signer(&input.public_key))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let input_sizes: Vec<usize> = scripts.iter().map(input_size).collect();
    let mut outputs: Vec<TxOut> = payments
        .iter()
        .map(|payment| TxOut::new(payment.value, payment.address.script().into()))
        .collect();

    let available = sum(inputs.iter().map(|input| input.value))?;
    let paid = sum(payments.iter().map(|payment| payment.value))?;
    let fee = |outputs: &[TxOut]| -> Result<Zatoshis, SpendError<S::Error>> {
        FeeRule::standard()
            .fee_required(
                params,
                target_height,
                input_sizes.iter().map(|&size| InputSize::Known(size)),
                outputs.iter().map(output_size),
                0,
                0,
                0,
                0,
            )
            .map_err(SpendError::Fee)
    };

    let fee_without_change = fee(&outputs)?;
    let required = (paid + fee_without_change).ok_or(SpendError::Overflow)?;
    if available < required {
        return Err(SpendError::InsufficientFunds {
            available,
            required,
        });
    }
    // Every P2SH output has the same size, so any P2SH script prices the change.
    let mut with_change = outputs.clone();
    with_change.push(TxOut::new(Zatoshis::ZERO, p2sh_template()));
    let fee_with_change = fee(&with_change)?;
    // No change when the inputs cannot also pay for its output, or when what remains
    // is dust; the remainder then goes to the fee.
    let change_value = (paid + fee_with_change)
        .and_then(|spent| available - spent)
        .filter(|value| !is_dust(*value));

    let change = match change_value {
        Some(value) => {
            let issued = change_pool
                .issue(Branch::Change)
                .map_err(SpendError::Pool)?;
            let script = PqScript::single_signer(&issued.public_key).script_pubkey();
            outputs.push(TxOut::new(value, script));
            Some(issued)
        }
        None => None,
    };
    let fee = (available - paid)
        .and_then(|fee| fee - change_value.unwrap_or(Zatoshis::ZERO))
        .ok_or(SpendError::Overflow)?;

    let header = Header {
        version: TxVersion::V5,
        branch_id: BranchId::for_height(params, target_height),
        expiry_height: target_height + EXPIRY_DELTA,
    };
    let spent: Vec<TxOut> = scripts
        .iter()
        .zip(inputs)
        .map(|(script, input)| TxOut::new(input.value, script.script_pubkey()))
        .collect();
    let unsigned = UnsignedTransaction::new(transaction::assemble(
        header,
        inputs
            .iter()
            .map(|input| (input.outpoint.clone(), Script::default()))
            .collect(),
        outputs,
        spent.clone(),
    ));

    let change_output = change
        .as_ref()
        .map(|issued| (unsigned.outputs().len() - 1, issued.origin));
    let request = SigningRequest {
        transaction: &unsigned,
        input_keys: inputs.iter().map(|input| input.origin).collect(),
        change: change_output.into_iter().collect(),
        replenish: [Branch::Receive, Branch::Change]
            .into_iter()
            .filter_map(|branch| change_pool.replenish_request(branch))
            .collect(),
    };
    let response = signer.sign(&request).map_err(SpendError::Signer)?;
    if response.signatures.len() != inputs.len() {
        return Err(SpendError::SignatureCount {
            expected: inputs.len(),
            actual: response.signatures.len(),
        });
    }
    change_pool
        .apply_batch(&response.public_keys)
        .map_err(SpendError::Pool)?;

    let script_sigs = response
        .signatures
        .iter()
        .zip(&scripts)
        .map(|(signature, script)| transaction::script_sig(signature, script))
        .collect::<Vec<_>>();
    if script_sigs
        .iter()
        .zip(&input_sizes)
        .any(|(script_sig, &size)| txin_size(script_sig) != size)
    {
        return Err(SpendError::FeeChanged);
    }
    let signed = transaction::with_script_sigs(unsigned.data, script_sigs);
    transaction::verify_data(&signed).map_err(SpendError::Verification)?;
    let transaction = transaction::freeze(signed).map_err(SpendError::Encoding)?;
    Ok(SignedSpend {
        transaction,
        fee,
        change,
        spent,
    })
}

/// The serialized size of an input spending `script`, with its final scriptSig.
fn input_size(script: &PqScript) -> usize {
    let placeholder = vec![0; script.parameters().signature_bytes()];
    txin_size(&transaction::script_sig(&placeholder, script))
}

/// Outpoint (32 + 4 bytes), the length-prefixed scriptSig, and the sequence.
fn txin_size(script_sig: &Script) -> usize {
    36 + script_sig.serialized_size() + 4
}

/// Value (8 bytes) and the length-prefixed output script.
fn output_size(output: &TxOut) -> usize {
    8 + output.script_pubkey().serialized_size()
}

fn p2sh_template() -> Script {
    TransparentAddress::ScriptHash([0; 20]).script().into()
}

/// Zcash's relay dust rule for a P2SH output: below three times the cost of spending
/// it at 100 zatoshis per 1000 bytes, counting a 148-byte spend (54 zatoshis).
fn is_dust(value: Zatoshis) -> bool {
    let size = (8 + p2sh_template().serialized_size()) as u64;
    u64::from(value) < 3 * (100 * (size + 148) / 1000)
}

fn sum<E>(mut values: impl Iterator<Item = Zatoshis>) -> Result<Zatoshis, SpendError<E>> {
    values
        .try_fold(Zatoshis::ZERO, |total, value| total + value)
        .ok_or(SpendError::Overflow)
}
